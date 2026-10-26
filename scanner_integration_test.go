package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// These tests use only a loopback listener, synthetic credentials, and a
// temporary filesystem. The server rejects and records every disk mutation,
// including an attempted create/delete probe that would leave no final file.
func TestScanTargetReadOnlyPermissions(t *testing.T) {
	const fullAccess = uint32(0x001f01ff)
	const readAccess = uint32(0x00120089)
	tests := []struct {
		name       string
		shareMask  uint32
		objectMask uint32
		context    string
		denyList   bool
		wantRead   string
		wantWrite  string
		wantOpens  int
	}{
		{"root_write_reported", fullAccess, fullAccess, "success", false, Allowed, Allowed, 1},
		{"filesystem_denies_write", fullAccess, readAccess, "success", false, Allowed, Denied, 1},
		{"share_denies_write", readAccess, fullAccess, "success", false, Allowed, Denied, 1},
		{"metadata_absent", fullAccess, 0, "absent", false, Allowed, Unknown, 1},
		{"metadata_query_failed", fullAccess, fullAccess, "failed", false, Allowed, Unknown, 1},
		{"metadata_malformed", fullAccess, fullAccess, "malformed", false, Allowed, Unknown, 1},
		{"context_unsupported_fallback", fullAccess, fullAccess, "unsupported", false, Allowed, Unknown, 2},
		{"context_invalid_parameter_fallback", fullAccess, fullAccess, "invalid_parameter", false, Allowed, Unknown, 2},
		{"share_denial_without_metadata", readAccess, 0, "absent", false, Allowed, Denied, 1},
		{"write_only_root", fullAccess, 0x82, "success", true, Denied, Allowed, 2},
		{"generic_share_write", 0x40000000, fullAccess, "success", false, Allowed, Allowed, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, tc.shareMask, tc.objectMask, tc.context, tc.denyList)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := scanTarget(ctx, fixture.target, fixture.options)
			if !result.Reachable || result.Authentication != "authenticated" || result.Enumeration != "ok" {
				t.Fatalf("scan did not authenticate and enumerate: %+v", result)
			}
			shares := make(map[string]ShareResult)
			for _, share := range result.Shares {
				shares[share.Name] = share
			}
			if len(shares) != 3 {
				t.Fatalf("want data$, IPC$, printer; got %+v", result.Shares)
			}
			disk := shares["data$"]
			if disk.Accessible != Allowed || disk.Read != tc.wantRead || disk.Write != tc.wantWrite {
				t.Errorf("disk result = %+v; want accessible=%s read=%s write=%s", disk, Allowed, tc.wantRead, tc.wantWrite)
			}
			for _, name := range []string{"IPC$", "printer"} {
				share, ok := shares[name]
				if !ok || share.Read != NotApplicable || share.Write != NotApplicable {
					t.Errorf("non-disk share %q should have n/a read/write: %+v", name, share)
				}
			}
			fixture.assertUnchanged(t, tc.wantOpens)
		})
	}
}

func TestScanTargetAuthenticationFailureDoesNotProbeShares(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	fixture.options.Password = "incorrect-test-password"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := scanTarget(ctx, fixture.target, fixture.options)
	if result.Authentication != "failed" || len(result.Shares) != 0 {
		t.Errorf("wrong-password result = %+v; want denied authentication and no shares", result)
	}
	fixture.assertUnchanged(t, 0)
}

func TestScanTargetAuthenticationRejectionStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status uint32
		auth   string
	}{
		{"expired_account", 0xc0000193, "failed"},
		{"restricted_logon_hours", 0xc000006f, "failed"},
		{"restricted_workstation", 0xc0000070, "failed"},
		{"unsupported_server_operation", 0xc00000bb, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
			fixture.guard.mu.Lock()
			fixture.guard.authenticationStatus = tc.status
			fixture.guard.mu.Unlock()
			result := scanTarget(context.Background(), fixture.target, fixture.options)
			if !result.Reachable || result.Authentication != tc.auth || !result.authenticationComplete || result.TimedOut {
				t.Errorf("authentication rejection = %+v; want completed %s", result, tc.auth)
			}
			if result.Enumeration != "not_attempted" || len(result.Shares) != 0 {
				t.Errorf("authentication rejection probed shares: %+v", result)
			}
			if !strings.Contains(result.Error, fmt.Sprintf("0x%08x", tc.status)) {
				t.Errorf("authentication rejection lost server status: %+v", result)
			}
			fixture.assertUnchanged(t, 0)
		})
	}
}

func TestScanTargetReportsEnumerationCleanupDenial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command uint16
	}{
		{"pipe close", 6},
		{"IPC$ disconnect", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
			fixture.guard.mu.Lock()
			fixture.guard.deniedIPCCleanup = tc.command
			fixture.guard.mu.Unlock()
			result := scanTarget(context.Background(), fixture.target, fixture.options)
			if result.Enumeration != "ok" || !result.enumerationComplete || len(result.Shares) != 3 || result.TimedOut {
				t.Fatalf("cleanup denial changed completed enumeration: %+v", result)
			}
			if !strings.Contains(result.Error, "enumeration") || !strings.Contains(result.Error, "0xc0000022") {
				t.Fatalf("cleanup denial was discarded: %+v", result)
			}
			for _, share := range result.Shares {
				if share.Name == "data$" && (share.Read != Allowed || share.Write != Allowed) {
					t.Errorf("normal cleanup status prevented remaining share checks: %+v", share)
				}
			}
			fixture.assertUnchanged(t, 1)
		})
	}
}

func TestScanTargetGuestIdentity(t *testing.T) {
	tests := []struct {
		name         string
		serverMode   string
		explicit     bool
		wrongUser    bool
		wantAuth     string
		wantFallback bool
		wantScan     bool
	}{
		{"ordinary_user_on_guest_capable_server", "map_guest", false, false, "authenticated", false, true},
		{"invalid_credentials_mapped_to_guest", "map_guest", false, true, "guest", true, true},
		{"explicit_guest_ignores_supplied_credentials", "map_guest", true, false, "guest", false, true},
		{"explicit_guest_not_accepted_as_user", "guest_as_user", true, false, "authenticated", false, false},
		{"credential_login_mapped_to_anonymous", "force_anonymous", false, false, "anonymous", false, false},
		{"explicit_guest_mapped_to_anonymous", "force_anonymous", true, false, "anonymous", false, false},
		{"mixed_guest_and_null_rejected", "mixed_guest_null", false, false, "error", false, false},
		{"mixed_guest_and_encryption_rejected", "mixed_guest_encryption", false, false, "error", false, false},
		{"unknown_session_flag_rejected", "unknown_session_flag", false, false, "error", false, false},
		{"encryption_flag_on_smb21_rejected", "smb21_encryption_flag", false, false, "error", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false, tc.serverMode)
			fixture.options.Guest = tc.explicit
			if tc.wrongUser {
				fixture.options.Username = "does-not-exist"
				fixture.options.Password = "wrong-password"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := scanTarget(ctx, fixture.target, fixture.options)
			if !result.Reachable || result.ServerIP != "127.0.0.1" || result.Authentication != tc.wantAuth || result.GuestFallback != tc.wantFallback {
				t.Errorf("identity result = %+v; want auth=%s fallback=%t and loopback IP", result, tc.wantAuth, tc.wantFallback)
			}
			wantOpens := 0
			if tc.wantScan {
				wantOpens = 1
				if result.Enumeration != "ok" || len(result.Shares) != 3 {
					t.Errorf("accepted identity did not enumerate: %+v", result)
				}
				var disk ShareResult
				for _, share := range result.Shares {
					if share.Name == "data$" {
						disk = share
					}
				}
				wantWrite := Allowed
				if tc.wantAuth == "guest" {
					wantWrite = Denied // Fixture Guest has distinct read-only rights.
				}
				if disk.Accessible != Allowed || disk.Read != Allowed || disk.Write != wantWrite {
					t.Errorf("permissions do not reflect actual identity: %+v; want write=%s", disk, wantWrite)
				}
			} else if result.Enumeration != "not_attempted" || len(result.Shares) != 0 || result.Error == "" {
				t.Errorf("unexpected identity must stop before enumeration: %+v", result)
			}
			fixture.guard.mu.Lock()
			users := append([]string(nil), fixture.guard.wireUsers...)
			domains := append([]string(nil), fixture.guard.wireDomains...)
			emptyProof := fixture.guard.guestEmptyPasswordVerified
			guestOpens := fixture.guard.guestOpens
			fixture.guard.mu.Unlock()
			if tc.explicit {
				if len(users) != 1 || users[0] != "" || !emptyProof || len(domains) != 1 || domains[0] == fixture.options.Domain {
					t.Errorf("explicit guest reused supplied credentials: users=%q domains=%q empty-password-proof=%t", users, domains, emptyProof)
				}
			} else if len(users) != 1 || users[0] != fixture.options.Username {
				t.Errorf("original credential attempt was replaced or retried: users=%q", users)
			}
			wantGuestOpens := 0
			if tc.wantScan && tc.wantAuth == "guest" {
				wantGuestOpens = 1
			}
			if guestOpens != wantGuestOpens {
				t.Errorf("root opens under actual Guest identity=%d, want %d", guestOpens, wantGuestOpens)
			}
			fixture.assertUnchanged(t, wantOpens)
		})
	}
}

type enumerationFixture struct {
	target  Target
	options Options
	root    string
	before  map[string]fixtureFile
	guard   *guardedEnumerationVFS
}

type fixtureFile struct {
	Mode    fs.FileMode
	Size    int64
	ModTime int64
	Digest  [32]byte
}

func snapshotFixture(t *testing.T, root string) map[string]fixtureFile {
	t.Helper()
	snapshot := make(map[string]fixtureFile)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value := fixtureFile{Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.Digest = sha256.Sum256(data)
		}
		snapshot[rel] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// The fixture owns its wire encoders and authentication verifier. It intentionally
// does not import the client implementation: a shared codec could make the same
// mistake at both ends and conceal a protocol regression.
func newEnumerationFixture(t *testing.T, shareMask, objectMask uint32, contextMode string, denyList bool, authModes ...string) *enumerationFixture {
	t.Helper()
	authMode := ""
	if len(authModes) > 0 {
		authMode = authModes[0]
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("existing contents must remain unchanged\n"), 0600); err != nil {
		t.Fatal(err)
	}
	guard := &guardedEnumerationVFS{denyList: denyList}
	if contextMode == "unsupported" {
		guard.rejectFirstOpen = 0xc00000bb
	}
	if contextMode == "invalid_parameter" {
		guard.rejectFirstOpen = 0xc000000d
	}
	fixture := &enumerationFixture{root: root, before: snapshotFixture(t, root), guard: guard,
		options: Options{Username: "audit-user", Password: "synthetic-fixture-password", Domain: "LAB", Timeout: 2 * time.Second}}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.target = Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			guard.mu.Lock()
			guard.connections++
			guard.mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				server := &fixtureSMBServer{fixture: fixture, conn: conn, shareMask: shareMask, objectMask: objectMask,
					contextMode: contextMode, authMode: authMode, handles: make(map[uint64]*os.File), nextHandle: 2}
				defer server.closeHandles()
				server.serve()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return fixture
}

func (f *enumerationFixture) assertUnchanged(t *testing.T, wantOpens int) {
	t.Helper()
	f.guard.mu.Lock()
	defer f.guard.mu.Unlock()
	if len(f.guard.unexpected) != 0 {
		t.Errorf("scanner attempted unexpected operations: %v", f.guard.unexpected)
	}
	if f.guard.opens != wantOpens {
		t.Errorf("root open attempts = %d, want %d", f.guard.opens, wantOpens)
	}
	if f.guard.connections != 1 || f.guard.authAttempts != 1 {
		t.Errorf("want exactly one TCP connection and authentication attempt; got connections=%d attempts=%d", f.guard.connections, f.guard.authAttempts)
	}
	if f.guard.successful != f.guard.closed {
		t.Errorf("opened %d handles but closed %d", f.guard.successful, f.guard.closed)
	}
	if after := snapshotFixture(t, f.root); !reflect.DeepEqual(f.before, after) {
		t.Errorf("fixture contents/metadata changed: before=%+v after=%+v", f.before, after)
	}
}

type guardedEnumerationVFS struct {
	mu                                                               sync.Mutex
	denyList                                                         bool
	authenticationStatus                                             uint32
	enumerationStatus                                                uint32
	malformedEnumeration                                             bool
	rejectFirstOpen                                                  uint32
	deniedIPCCleanup                                                 uint16
	opens, successful, closed, connections, authAttempts, guestOpens int
	unexpected, wireUsers, wireDomains                               []string
	guestEmptyPasswordVerified                                       bool
}

func (v *guardedEnumerationVFS) record(message string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.unexpected = append(v.unexpected, message)
}

type fixtureSMBServer struct {
	fixture                                     *enumerationFixture
	conn                                        net.Conn
	shareMask, objectMask                       uint32
	contextMode, authMode                       string
	sessionKey, negotiate, challenge, pipeReply []byte
	sessionFlags                                uint16
	authenticated                               bool
	handles                                     map[uint64]*os.File
	nextHandle                                  uint64
}

func fxU16(p []byte) uint16      { return binary.LittleEndian.Uint16(p) }
func fxU32(p []byte) uint32      { return binary.LittleEndian.Uint32(p) }
func fxU64(p []byte) uint64      { return binary.LittleEndian.Uint64(p) }
func fxPut16(p []byte, x uint16) { binary.LittleEndian.PutUint16(p, x) }
func fxPut32(p []byte, x uint32) { binary.LittleEndian.PutUint32(p, x) }
func fxPut64(p []byte, x uint64) { binary.LittleEndian.PutUint64(p, x) }
func fxUTF16(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		fxPut16(out[i*2:], u)
	}
	return out
}
func fxText(data []byte) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = fxU16(data[i*2:])
	}
	return string(utf16.Decode(units))
}
func fxBounds(packet []byte, offset, length uint32) ([]byte, error) {
	if uint64(offset)+uint64(length) > uint64(len(packet)) {
		return nil, errors.New("out-of-bounds request field")
	}
	return packet[int(offset):int(offset+length)], nil
}
func fxDER(tag byte, data []byte) []byte {
	out := []byte{tag}
	switch {
	case len(data) < 128:
		out = append(out, byte(len(data)))
	case len(data) < 256:
		out = append(out, 0x81, byte(len(data)))
	default:
		out = append(out, 0x82, byte(len(data)>>8), byte(len(data)))
	}
	return append(out, data...)
}
func fxSPNEGO(token []byte, complete bool) []byte {
	state := byte(1)
	if complete {
		state = 0
	}
	inner := fxDER(0xa0, fxDER(0x0a, []byte{state}))
	if token != nil {
		inner = append(inner, fxDER(0xa1, []byte{6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 2, 10})...)
		inner = append(inner, fxDER(0xa2, fxDER(4, token))...)
	}
	return fxDER(0xa1, fxDER(0x30, inner))
}
func fxHMACMD5(key []byte, pieces ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range pieces {
		h.Write(p)
	}
	return h.Sum(nil)
}
func fxSignature(key, raw []byte) []byte {
	copyRaw := append([]byte(nil), raw...)
	clear(copyRaw[48:64])
	h := hmac.New(sha256.New, key)
	h.Write(copyRaw)
	return h.Sum(nil)[:16]
}
func (s *fixtureSMBServer) closeHandles() {
	for id, h := range s.handles {
		_ = h.Close()
		delete(s.handles, id)
		s.fixture.guard.mu.Lock()
		s.fixture.guard.closed++
		s.fixture.guard.mu.Unlock()
	}
}
func (s *fixtureSMBServer) serve() {
	for {
		_ = s.conn.SetDeadline(time.Now().Add(5 * time.Second))
		var prefix [4]byte
		if _, err := io.ReadFull(s.conn, prefix[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(prefix[:])
		if n < 64 || n > 4<<20 {
			s.fixture.guard.record("invalid SMB frame length")
			return
		}
		request := make([]byte, n)
		if _, err := io.ReadFull(s.conn, request); err != nil {
			return
		}
		if string(request[:4]) != "\xfeSMB" || fxU16(request[4:]) != 64 {
			s.fixture.guard.record("invalid SMB header")
			return
		}
		if fxU32(request[20:]) != 0 {
			s.fixture.guard.record("unexpected compound SMB request")
			return
		}
		command := fxU16(request[12:])
		if s.authenticated && len(s.sessionKey) > 0 {
			if fxU32(request[16:])&8 == 0 || !hmac.Equal(request[48:64], fxSignature(s.sessionKey, request)) {
				s.fixture.guard.record("missing or incorrect request signature")
				return
			}
		}
		body, status, tree, err := s.dispatch(command, request)
		if err != nil {
			s.fixture.guard.record(err.Error())
			return
		}
		s.fixture.guard.mu.Lock()
		if tree == 1 && command == s.fixture.guard.deniedIPCCleanup {
			status = 0xc0000022
		}
		s.fixture.guard.mu.Unlock()
		if status != 0 && status != 0xc0000016 {
			body = make([]byte, 8)
			fxPut16(body, 9)
		}
		reply := make([]byte, 64+len(body))
		copy(reply, "\xfeSMB")
		fxPut16(reply[4:], 64)
		fxPut16(reply[6:], 1)
		fxPut32(reply[8:], status)
		fxPut16(reply[12:], command)
		fxPut16(reply[14:], 32)
		fxPut32(reply[16:], 1)
		copy(reply[24:32], request[24:32])
		fxPut32(reply[36:], tree)
		if command != 0 {
			fxPut64(reply[40:], 1)
		}
		copy(reply[64:], body)
		if s.authenticated && len(s.sessionKey) > 0 {
			fxPut32(reply[16:], 9)
			copy(reply[48:], fxSignature(s.sessionKey, reply))
		}
		binary.BigEndian.PutUint32(prefix[:], uint32(len(reply)))
		if _, err := s.conn.Write(append(prefix[:], reply...)); err != nil {
			return
		}
		if command == 2 {
			return
		}
	}
}
func (s *fixtureSMBServer) dispatch(command uint16, p []byte) ([]byte, uint32, uint32, error) {
	tree := fxU32(p[36:])
	guard := s.fixture.guard
	if tree == 2 && command != 5 && command != 6 && command != 4 {
		return nil, 0, tree, fmt.Errorf("unexpected disk SMB command %#x", command)
	}
	switch command {
	case 0: // NEGOTIATE: SMB 2.1, signing enabled/required, no encryption.
		if len(p) < 100 {
			return nil, 0, 0, errors.New("short NEGOTIATE")
		}
		b := make([]byte, 64)
		fxPut16(b, 65)
		fxPut16(b[2:], 3)
		fxPut16(b[4:], 0x0210)
		copy(b[8:24], []byte("fixture-smb-guid!"))
		fxPut32(b[28:], 65536)
		fxPut32(b[32:], 65536)
		fxPut32(b[36:], 65536)
		fxPut64(b[40:], 133000000000000000)
		fxPut64(b[48:], 133000000000000000)
		return b, 0, 0, nil
	case 1:
		return s.sessionSetup(p)
	case 2:
		b := make([]byte, 4)
		fxPut16(b, 4)
		return b, 0, 0, nil
	case 3:
		if len(p) < 72 {
			return nil, 0, 0, errors.New("short TREE_CONNECT")
		}
		path, err := fxBounds(p, uint32(fxU16(p[68:])), uint32(fxU16(p[70:])))
		if err != nil {
			return nil, 0, 0, err
		}
		parts := strings.Split(fxText(path), "\\")
		name := parts[len(parts)-1]
		b := make([]byte, 16)
		fxPut16(b, 16)
		switch strings.ToLower(name) {
		case "ipc$":
			tree = 1
			b[2] = 2
			fxPut32(b[12:], 0x001f01ff)
		case "data$":
			tree = 2
			b[2] = 1
			mask := s.shareMask
			if s.sessionFlags&1 != 0 {
				mask = 0x00120089
			}
			fxPut32(b[12:], mask)
		default:
			return nil, 0, 0, fmt.Errorf("unexpected share %q", name)
		}
		return b, 0, tree, nil
	case 4:
		b := make([]byte, 4)
		fxPut16(b, 4)
		return b, 0, tree, nil
	case 5:
		return s.create(p, tree)
	case 6:
		if len(p) < 88 {
			return nil, 0, tree, errors.New("short CLOSE")
		}
		id := fxU64(p[72:])
		if tree == 2 {
			h, ok := s.handles[id]
			if !ok {
				return nil, 0, tree, errors.New("closing unknown disk handle")
			}
			_ = h.Close()
			delete(s.handles, id)
			guard.mu.Lock()
			guard.closed++
			guard.mu.Unlock()
		}
		b := make([]byte, 60)
		fxPut16(b, 60)
		return b, 0, tree, nil
	case 9: // WRITE is only permitted to the already-existing srvsvc pipe.
		if tree != 1 || len(p) < 112 || fxU64(p[80:]) != 1 {
			return nil, 0, tree, errors.New("unexpected SMB WRITE")
		}
		data, err := fxBounds(p, uint32(fxU16(p[66:])), fxU32(p[68:]))
		if err != nil {
			return nil, 0, tree, err
		}
		s.pipeReply, err = fxRPCReply(data)
		if err != nil {
			return nil, 0, tree, err
		}
		guard.mu.Lock()
		enumerationStatus := guard.enumerationStatus
		malformedEnumeration := guard.malformedEnumeration
		guard.mu.Unlock()
		if data[2] == 0 && enumerationStatus != 0 {
			fxPut32(s.pipeReply[len(s.pipeReply)-4:], enumerationStatus)
		}
		if data[2] == 0 && malformedEnumeration {
			fxPut32(s.pipeReply[24:], 2) // Invalid level in the NDR response stub.
		}
		b := make([]byte, 16)
		fxPut16(b, 17)
		fxPut32(b[4:], uint32(len(data)))
		return b, 0, tree, nil
	case 8:
		if tree != 1 || len(p) < 112 || fxU64(p[80:]) != 1 || len(s.pipeReply) == 0 {
			return nil, 0, tree, errors.New("unexpected SMB READ")
		}
		n := len(s.pipeReply)
		if n > int(fxU32(p[68:])) {
			n = int(fxU32(p[68:]))
		}
		b := make([]byte, 16+n)
		fxPut16(b, 17)
		b[2] = 80
		fxPut32(b[4:], uint32(n))
		copy(b[16:], s.pipeReply[:n])
		s.pipeReply = s.pipeReply[n:]
		return b, 0, tree, nil
	default:
		return nil, 0, tree, fmt.Errorf("unexpected SMB command %#x", command)
	}
}
func (s *fixtureSMBServer) sessionSetup(p []byte) ([]byte, uint32, uint32, error) {
	if len(p) < 88 {
		return nil, 0, 0, errors.New("short SESSION_SETUP")
	}
	token, err := fxBounds(p, uint32(fxU16(p[76:])), uint32(fxU16(p[78:])))
	if err != nil {
		return nil, 0, 0, err
	}
	token, err = fxNTLMToken(token)
	if err != nil {
		return nil, 0, 0, err
	}
	typ := fxU32(token[8:])
	status := uint32(0)
	var security []byte
	if typ == 1 {
		if s.negotiate != nil {
			return nil, 0, 0, errors.New("duplicate NTLM negotiation")
		}
		s.negotiate = append([]byte(nil), token...)
		s.challenge = fxNTLMChallenge()
		security = fxSPNEGO(s.challenge, false)
		status = 0xc0000016
	} else if typ == 3 {
		if s.challenge == nil {
			return nil, 0, 0, errors.New("authentication without challenge")
		}
		user, domain, key, valid, empty, err := fxVerifyNTLM(s.negotiate, s.challenge, token, "synthetic-fixture-password")
		if err != nil {
			return nil, 0, 0, err
		}
		guard := s.fixture.guard
		guard.mu.Lock()
		guard.authAttempts++
		guard.wireUsers = append(guard.wireUsers, user)
		guard.wireDomains = append(guard.wireDomains, domain)
		guard.guestEmptyPasswordVerified = empty
		authenticationStatus := guard.authenticationStatus
		guard.mu.Unlock()
		ordinary := valid && user == "audit-user" && domain == "LAB"
		switch {
		case authenticationStatus != 0:
			status = authenticationStatus
		case s.authMode == "mixed_guest_null":
			s.sessionFlags = 3
		case s.authMode == "mixed_guest_encryption":
			s.sessionFlags = 5
		case s.authMode == "unknown_session_flag":
			s.sessionFlags = 8
			s.sessionKey = key
		case s.authMode == "smb21_encryption_flag":
			s.sessionFlags = 4
			s.sessionKey = key
		case s.authMode == "force_anonymous":
			s.sessionFlags = 2
		case s.authMode == "guest_as_user" && empty:
			s.sessionKey = key
		case ordinary:
			s.sessionKey = key
		case s.authMode == "map_guest":
			s.sessionFlags = 1
		default:
			status = 0xc000006d
		}
		s.authenticated = status == 0
		security = fxSPNEGO(nil, true)
	} else {
		return nil, 0, 0, fmt.Errorf("unexpected NTLM message type %d", typ)
	}
	b := make([]byte, 8+len(security))
	fxPut16(b, 9)
	fxPut16(b[2:], s.sessionFlags)
	fxPut16(b[4:], 72)
	fxPut16(b[6:], uint16(len(security)))
	copy(b[8:], security)
	return b, status, 0, nil
}

// Decode the ASN.1 framing independently so an accompanying mechListMIC never
// becomes part of the NTLM transcript used for the Type3 MIC check.
func fxNTLMToken(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte("NTLMSSP\x00")) {
		return data, nil
	}
	var token []byte
	var walk func([]byte, int) error
	walk = func(data []byte, depth int) error {
		if depth > 8 {
			return errors.New("fixture SPNEGO nesting exceeded")
		}
		for len(data) > 0 {
			if len(data) < 2 {
				return errors.New("truncated fixture SPNEGO header")
			}
			tag, n, header := data[0], int(data[1]), 2
			if n&128 != 0 {
				count := n & 127
				if count == 0 || count > 3 || len(data) < 2+count {
					return errors.New("invalid fixture SPNEGO length")
				}
				n = 0
				for _, b := range data[2 : 2+count] {
					n = n*256 + int(b)
				}
				header += count
			}
			if n > len(data)-header {
				return errors.New("truncated fixture SPNEGO field")
			}
			value := data[header : header+n]
			if tag == 4 && bytes.HasPrefix(value, []byte("NTLMSSP\x00")) {
				if token != nil {
					return errors.New("duplicate fixture NTLM token")
				}
				token = value
			} else if tag&32 != 0 {
				if err := walk(value, depth+1); err != nil {
					return err
				}
			}
			data = data[header+n:]
		}
		return nil
	}
	if err := walk(data, 0); err != nil {
		return nil, err
	}
	if len(token) < 12 {
		return nil, errors.New("missing NTLM authentication token")
	}
	return token, nil
}

func fxNTLMChallenge() []byte {
	target := fxUTF16("LAB")
	var info []byte
	for _, av := range []struct {
		id    uint16
		value []byte
	}{{2, fxUTF16("LAB")}, {1, fxUTF16("LOOPBACK-TEST")}, {7, make([]byte, 8)}, {0, nil}} {
		if av.id == 7 {
			fxPut64(av.value, uint64(time.Now().UnixNano()/100+116444736000000000))
		}
		header := make([]byte, 4)
		fxPut16(header, av.id)
		fxPut16(header[2:], uint16(len(av.value)))
		info = append(info, header...)
		info = append(info, av.value...)
	}
	out := make([]byte, 56+len(target)+len(info))
	copy(out, "NTLMSSP\x00")
	fxPut32(out[8:], 2)
	fxPut16(out[12:], uint16(len(target)))
	fxPut16(out[14:], uint16(len(target)))
	fxPut32(out[16:], 56)
	fxPut32(out[20:], 0xe2888215)
	copy(out[24:32], []byte{1, 35, 69, 103, 137, 171, 205, 239})
	fxPut16(out[40:], uint16(len(info)))
	fxPut16(out[42:], uint16(len(info)))
	fxPut32(out[44:], uint32(56+len(target)))
	copy(out[48:56], []byte{10, 0, 0x63, 0x45, 0, 0, 0, 15})
	copy(out[56:], target)
	copy(out[56+len(target):], info)
	return out
}
func fxVerifyNTLM(negotiate, challenge, auth []byte, password string) (user, domain string, key []byte, valid, empty bool, err error) {
	if len(auth) < 64 {
		err = errors.New("short NTLM AUTHENTICATE")
		return
	}
	field := func(at int) ([]byte, error) { return fxBounds(auth, fxU32(auth[at+4:]), uint32(fxU16(auth[at:]))) }
	nt, e := field(20)
	if e != nil {
		err = e
		return
	}
	d, e := field(28)
	if e != nil {
		err = e
		return
	}
	u, e := field(36)
	if e != nil {
		err = e
		return
	}
	encrypted, e := field(52)
	if e != nil {
		err = e
		return
	}
	if len(u)%2 != 0 || len(d)%2 != 0 || len(nt) < 48 {
		err = errors.New("invalid NTLMv2 fields")
		return
	}
	user, domain = fxText(u), fxText(d)
	check := func(secret string) ([]byte, bool) {
		h := md4.New()
		h.Write(fxUTF16(secret))
		responseKey := fxHMACMD5(h.Sum(nil), fxUTF16(strings.ToUpper(user)+domain))
		expected := fxHMACMD5(responseKey, challenge[24:32], nt[16:])
		if !hmac.Equal(expected, nt[:16]) {
			return nil, false
		}
		base := fxHMACMD5(responseKey, nt[:16])
		exported := base
		if fxU32(auth[60:])&0x40000000 != 0 {
			if len(encrypted) != 16 {
				return nil, false
			}
			stream, e := rc4.NewCipher(base)
			if e != nil {
				return nil, false
			}
			exported = make([]byte, 16)
			stream.XORKeyStream(exported, encrypted)
		}
		// Timestamp in the challenge requires a MIC. Independently check all three
		// NTLM messages and the exact client AUTHENTICATE bytes with its MIC zeroed.
		micOffset := 64
		if fxU32(auth[60:])&0x02000000 != 0 {
			micOffset = 72
		}
		if len(auth) < micOffset+16 {
			return nil, false
		}
		cleared := append([]byte(nil), auth...)
		clear(cleared[micOffset : micOffset+16])
		mic := fxHMACMD5(exported, negotiate, challenge, cleared)
		if !hmac.Equal(mic, auth[micOffset:micOffset+16]) {
			return nil, false
		}
		return exported, true
	}
	key, valid = check(password)
	if user == "" {
		var emptyKey []byte
		emptyKey, empty = check("")
		if empty {
			key = emptyKey
		}
	}
	return
}
func (s *fixtureSMBServer) create(p []byte, tree uint32) ([]byte, uint32, uint32, error) {
	if len(p) < 120 {
		return nil, 0, tree, errors.New("short CREATE")
	}
	path, err := fxBounds(p, uint32(fxU16(p[108:])), uint32(fxU16(p[110:])))
	if err != nil {
		return nil, 0, tree, err
	}
	desired, disposition, options := fxU32(p[88:]), fxU32(p[100:]), fxU32(p[104:])
	id := uint64(1)
	var contexts []byte
	if tree == 1 {
		if strings.TrimPrefix(fxText(path), "\\") != "srvsvc" || disposition != 1 || desired&^uint32(0x00100003) != 0 {
			return nil, 0, tree, errors.New("unexpected pipe open")
		}
	} else if tree == 2 {
		guard := s.fixture.guard
		guard.mu.Lock()
		guard.opens++
		attempt := guard.opens
		if s.sessionFlags&1 != 0 {
			guard.guestOpens++
		}
		guard.mu.Unlock()
		if len(path) != 0 || disposition != 1 || options != 1 || (desired != 1 && desired != 0x80) || p[67] != 0 || fxU32(p[96:]) != 7 {
			return nil, 0, tree, errors.New("root open requested mutation, child access, or exclusive locking")
		}
		cc, err := fxBounds(p, fxU32(p[112:]), fxU32(p[116:]))
		if err != nil {
			return nil, 0, tree, err
		}
		if attempt > 1 && guard.rejectFirstOpen != 0 {
			if len(cc) != 0 {
				return nil, 0, tree, errors.New("unsupported-metadata fallback included contexts")
			}
		} else if len(cc) < 20 || string(cc[16:20]) != "MxAc" || fxU32(cc[12:]) != 0 {
			return nil, 0, tree, errors.New("root open did not request fresh MxAc metadata")
		}
		if attempt == 1 && guard.rejectFirstOpen != 0 {
			return nil, guard.rejectFirstOpen, tree, nil
		}
		if guard.denyList && desired == 1 {
			return nil, 0xc0000022, tree, nil
		}
		handle, err := os.Open(s.fixture.root)
		if err != nil {
			return nil, 0, tree, err
		}
		id = s.nextHandle
		s.nextHandle++
		s.handles[id] = handle
		guard.mu.Lock()
		guard.successful++
		guard.mu.Unlock()
		if s.contextMode != "absent" && s.contextMode != "unsupported" && s.contextMode != "invalid_parameter" {
			contexts = make([]byte, 32)
			fxPut16(contexts[4:], 16)
			fxPut16(contexts[6:], 4)
			fxPut16(contexts[10:], 24)
			fxPut32(contexts[12:], 8)
			copy(contexts[16:], "MxAc")
			mask := s.objectMask
			if s.sessionFlags&1 != 0 {
				mask = 0x00120089
			}
			fxPut32(contexts[28:], mask)
			if s.contextMode == "failed" {
				fxPut32(contexts[24:], 0xc0000022)
			}
			if s.contextMode == "malformed" {
				contexts = contexts[:28]
			}
		}
	} else {
		return nil, 0, tree, errors.New("CREATE on unknown tree")
	}
	b := make([]byte, 88+len(contexts))
	fxPut16(b, 89)
	fxPut32(b[4:], 1)
	fxPut64(b[64:], id)
	if len(contexts) > 0 {
		fxPut32(b[80:], 152)
		fxPut32(b[84:], uint32(len(contexts)))
		copy(b[88:], contexts)
	}
	return b, 0, tree, nil
}

func fxRPCReply(request []byte) ([]byte, error) {
	if len(request) < 16 || request[0] != 5 || request[1] != 0 || request[3]&3 != 3 || int(fxU16(request[8:])) != len(request) {
		return nil, errors.New("invalid or fragmented fixture RPC request")
	}
	var body []byte
	packetType := byte(0)
	switch request[2] {
	case 11: // bind_ack accepting NDR32 v2 context zero.
		if len(request) < 72 {
			return nil, errors.New("short RPC bind")
		}
		srvsvcID := []byte{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}
		ndrID := []byte{4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96}
		if request[24] != 1 || fxU16(request[28:]) != 0 || request[30] != 1 || !bytes.Equal(request[32:48], srvsvcID) || fxU32(request[48:]) != 3 || !bytes.Equal(request[52:68], ndrID) || fxU32(request[68:]) != 2 {
			return nil, errors.New("RPC bind did not request SRVSVC v3 over NDR32 v2")
		}
		packetType = 12
		body = make([]byte, 40)
		fxPut16(body, 4280)
		fxPut16(body[2:], 4280)
		body[12] = 1
		copy(body[20:36], []byte{4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96})
		fxPut32(body[36:], 2)
	case 0:
		if len(request) < 24 || fxU16(request[20:]) != 0 || fxU16(request[22:]) != 15 {
			return nil, errors.New("unexpected RPC operation")
		}
		packetType = 2
		stub := fxShareList()
		body = make([]byte, 8+len(stub))
		fxPut32(body, uint32(len(stub)))
		copy(body[8:], stub)
	default:
		return nil, fmt.Errorf("unexpected RPC packet type %d", request[2])
	}
	out := make([]byte, 16+len(body))
	out[0] = 5
	out[2] = packetType
	out[3] = 3
	out[4] = 16
	fxPut16(out[8:], uint16(len(out)))
	copy(out[12:16], request[12:16])
	copy(out[16:], body)
	return out, nil
}
func fxShareList() []byte {
	// NDR32: level/switch, unique container, count, unique conformant array,
	// the fixed SHARE_INFO_1 records, then their deferred strings.
	var out []byte
	put := func(n uint32) { b := make([]byte, 4); fxPut32(b, n); out = append(out, b...) }
	put(1)
	put(1)
	put(0x20000)
	put(3)
	put(0x20004)
	put(3)
	shares := []struct {
		name    string
		kind    uint32
		comment string
	}{{"data$", 0x80000000, "fixture disk"}, {"IPC$", 0x80000003, "fixture RPC"}, {"printer", 1, "must not be probed"}}
	for i, share := range shares {
		put(uint32(0x20008 + i*8))
		put(share.kind)
		put(uint32(0x2000c + i*8))
	}
	for _, share := range shares {
		for _, text := range []string{share.name, share.comment} {
			data := fxUTF16(text + "\x00")
			put(uint32(len(data) / 2))
			put(0)
			put(uint32(len(data) / 2))
			out = append(out, data...)
			for len(out)%4 != 0 {
				out = append(out, 0)
			}
		}
	}
	put(3)
	put(0x20030)
	put(0)
	put(0)
	return out
}
