package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvc "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcserver "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/filevfs"
	smbunicode "github.com/jfjallid/go-smb/smb/unicode"
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
		{"credential_login_mapped_to_anonymous", "force_anonymous", false, false, "unverified", false, false},
		{"explicit_guest_mapped_to_anonymous", "force_anonymous", true, false, "unverified", false, false},
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
	vfs, err := filevfs.New(filevfs.Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	guard := &guardedEnumerationVFS{VFS: vfs, denyList: denyList}
	if contextMode == "unsupported" {
		guard.rejectFirstOpen = smb.StatusNotSupported
	} else if contextMode == "invalid_parameter" {
		guard.rejectFirstOpen = smb.StatusInvalidParameter
	}
	fixture := &enumerationFixture{
		root: root, before: snapshotFixture(t, root), guard: guard,
		options: Options{Username: "audit-user", Password: "synthetic-fixture-password", Domain: "LAB", Timeout: 2 * time.Second},
	}
	var treesMu sync.Mutex
	diskTrees := make(map[uint32]bool)
	guestTrees := make(map[uint32]bool)
	isDiskTree := func(id uint32) bool {
		treesMu.Lock()
		defer treesMu.Unlock()
		return diskTrees[id]
	}
	isGuestTree := func(id uint32) bool {
		treesMu.Lock()
		defer treesMu.Unlock()
		return guestTrees[id]
	}
	srv := &server.Server{Config: &server.ServerConfig{
		// Signing remains enabled and required. Encryption is not advertised
		// so the request hook can inspect actual operations in this fixture.
		SigningRequired: true,
		Authenticator: &server.MapAuthenticator{
			Domain: fixture.options.Domain,
			Accounts: map[string]*server.Account{
				fixture.options.Username: {NTHash: ntlmssp.Ntowfv1(fixture.options.Password)},
			},
		},
		OnConnect: func(_ *server.Conn) error {
			guard.mu.Lock()
			guard.connections++
			guard.mu.Unlock()
			return nil
		},
		OnSessionSetup: func(conn *server.Conn, session *server.Session, _ []byte, stage server.SessionSetupStage) (*server.Status, error) {
			if stage != server.SessionSetupStageAuthenticate {
				return nil, nil
			}
			guard.mu.Lock()
			guard.authAttempts++
			guard.mu.Unlock()
			original := session.AuthAcceptor.Verify
			session.AuthAcceptor.Verify = func(auth *ntlmssp.Authenticate, challenge [8]byte) ([]byte, uint32) {
				user, userErr := smbunicode.FromUnicodeString(auth.UserName)
				domain, domainErr := smbunicode.FromUnicodeString(auth.DomainName)
				if userErr != nil || domainErr != nil {
					guard.record("invalid authentication identity encoding")
				}
				emptyVerifier := &server.MapAuthenticator{Accounts: map[string]*server.Account{"": {NTHash: ntlmssp.Ntowfv1("")}}}
				emptyKey, emptyStatus := emptyVerifier.Verify(conn, auth, challenge)
				guard.mu.Lock()
				guard.wireUsers = append(guard.wireUsers, user)
				guard.wireDomains = append(guard.wireDomains, domain)
				guard.guestEmptyPasswordVerified = user == "" && emptyStatus == smb.StatusOk
				guard.mu.Unlock()
				if authMode == "force_anonymous" {
					session.Flags |= smb.SessionFlagIsNull
					return nil, smb.StatusOk
				}
				if authMode == "guest_as_user" {
					return emptyKey, emptyStatus // Normal authenticated session, without Guest flag.
				}
				key, status := original(auth, challenge)
				if status != smb.StatusOk && authMode == "map_guest" {
					// Set the flag before the acceptor constructs its final token,
					// so both SMB and SPNEGO report acceptance, without a session key.
					session.Flags |= smb.SessionFlagIsGuest
					return nil, smb.StatusOk
				}
				return key, status
			}
			return nil, nil
		},
		OnTreeConnect: func(_ *server.Conn, session *server.Session, name string, _ *smb.TreeConnectReq, response *smb.TreeConnectRes) (*server.Status, error) {
			if strings.EqualFold(name, "data$") {
				treesMu.Lock()
				diskTrees[response.Header.TreeID] = true
				guestTrees[response.Header.TreeID] = session.Flags&smb.SessionFlagIsGuest != 0
				treesMu.Unlock()
				if session.Flags&smb.SessionFlagIsGuest != 0 {
					response.MaximalAccess = 0x00120089
					if len(session.SessionKey) != 0 {
						guard.record("fixture Guest unexpectedly has a session key")
					}
				}
			}
			if strings.EqualFold(name, "printer") {
				guard.record("unexpected printer tree connect")
			}
			return nil, nil
		},
		OnRawRequest: func(_ *server.Conn, raw []byte) (bool, error) {
			if len(raw) < 64 || string(raw[:4]) != smb.ProtocolSmb2 {
				return false, nil
			}
			var header smb.Header
			if err := header.UnmarshalBinary(raw); err != nil {
				return false, err
			}
			if !isDiskTree(header.TreeID) {
				return false, nil // IPC$ requests are SRVSVC RPC, not disk writes.
			}
			switch header.Command {
			case smb.CommandCreate:
				var req smb.CreateReq
				if err := req.UnmarshalBinary(raw); err != nil {
					return false, err
				}
				if req.RequestedOplockLevel != smb.OpLockLevelNone || req.ShareAccess != smb.FileShareRead|smb.FileShareWrite|smb.FileShareDelete {
					guard.record(fmt.Sprintf("open may lock other clients: oplock=%d share-access=%#x", req.RequestedOplockLevel, req.ShareAccess))
				}
				contexts, err := req.CreateReqContexts()
				if err != nil {
					return false, err
				}
				guard.mu.Lock()
				fallback := guard.rejectFirstOpen != 0 && guard.opens == 1
				guard.mu.Unlock()
				if fallback {
					if len(contexts) != 0 {
						guard.record("unsupported-metadata fallback still included create contexts")
					}
				} else if len(contexts) < 20 || string(contexts[16:20]) != "MxAc" || binary.LittleEndian.Uint32(contexts[12:16]) != 0 {
					guard.record("root open did not request fresh MxAc metadata")
				}
			case smb.CommandClose, smb.CommandTreeDisconnect:
			default:
				guard.record(fmt.Sprintf("unexpected disk SMB command %#x", header.Command))
				return false, fmt.Errorf("fixture refuses disk operation %#x", header.Command)
			}
			return false, nil
		},
		OnRawResponse: func(_ *server.Conn, raw []byte) ([]byte, error) {
			if len(raw) < 64 || string(raw[:4]) != smb.ProtocolSmb2 {
				return raw, nil
			}
			var header smb.Header
			if err := header.UnmarshalBinary(raw); err != nil {
				return nil, err
			}
			if header.Command != smb.CommandCreate || header.Status != smb.StatusOk || !isDiskTree(header.TreeID) {
				return raw, nil
			}
			var response smb.CreateRes
			if err := response.UnmarshalBinary(raw); err != nil {
				return nil, err
			}
			response.Buffer = nil
			if contextMode != "absent" && contextMode != "unsupported" && contextMode != "invalid_parameter" {
				// Independent fixture wire encoding: 16-byte context header,
				// four-byte name, padding, QueryStatus, and MaximalAccess.
				cc := make([]byte, 32)
				binary.LittleEndian.PutUint16(cc[4:6], 16)
				binary.LittleEndian.PutUint16(cc[6:8], 4)
				binary.LittleEndian.PutUint16(cc[10:12], 24)
				binary.LittleEndian.PutUint32(cc[12:16], 8)
				copy(cc[16:20], "MxAc")
				mask := objectMask
				if isGuestTree(header.TreeID) {
					mask = 0x00120089
				}
				binary.LittleEndian.PutUint32(cc[28:32], mask)
				if contextMode == "failed" {
					binary.LittleEndian.PutUint32(cc[24:28], smb.StatusAccessDenied)
				}
				if contextMode == "malformed" {
					cc = cc[:28] // Advertised data extends past the context.
				}
				response.Buffer = cc
			}
			return response.MarshalBinary()
		},
	}}
	srv.RegisterShare("data$", server.Share{Type: smb.ShareTypeDisk, VFS: guard, MaximalAccess: shareMask})
	svc := &srvsvc.Service{ServerName: "LOOPBACK-TEST", Shares: []srvsvc.ShareEntry{
		{Name: "data$", Type: mssrvs.StypeDisktree | mssrvs.StypeSpecial, Comment: "fixture disk"},
		{Name: "IPC$", Type: mssrvs.StypeIPC | mssrvs.StypeSpecial, Comment: "fixture RPC"},
		{Name: "printer", Type: mssrvs.StypePrintq, Comment: "must not be probed"},
	}}
	srv.Config.PipeOpener = &server.MapPipeOpener{Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
		"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
			return dcserver.NewPipeHandler("srvsvc", svc), nil
		},
	}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.target = Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("fixture shutdown: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil && err != server.ErrServerClosed {
				t.Errorf("fixture serve: %v", err)
			}
		case <-ctx.Done():
			t.Error("fixture server did not stop")
		}
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
	server.VFS
	mu                         sync.Mutex
	denyList                   bool
	rejectFirstOpen            uint32
	opens                      int
	successful                 int
	closed                     int
	unexpected                 []string
	connections                int
	authAttempts               int
	wireUsers                  []string
	wireDomains                []string
	guestEmptyPasswordVerified bool
	guestOpens                 int
}

func (v *guardedEnumerationVFS) record(message string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.unexpected = append(v.unexpected, message)
}

func (v *guardedEnumerationVFS) Create(ctx context.Context, session *server.Session, req server.CreateRequest) (server.CreateResult, uint32, error) {
	v.mu.Lock()
	v.opens++
	attempt := v.opens
	if session.Flags&smb.SessionFlagIsGuest != 0 {
		v.guestOpens++
	}
	v.mu.Unlock()
	if (req.Path != "" && req.Path != "\\") || req.CreateDisposition != smb.FileOpen || req.CreateOptions != smb.FileDirectoryFile ||
		(req.DesiredAccess != smb.DAccMaskFileListDirectory && req.DesiredAccess != smb.DAccMaskFileReadAttributes) {
		v.record(fmt.Sprintf("unexpected filesystem open: %+v", req))
		return server.CreateResult{}, smb.StatusAccessDenied, nil
	}
	if attempt == 1 && v.rejectFirstOpen != 0 {
		return server.CreateResult{}, v.rejectFirstOpen, nil
	}
	if v.denyList && req.DesiredAccess == smb.DAccMaskFileListDirectory {
		return server.CreateResult{}, smb.StatusAccessDenied, nil
	}
	result, status, err := v.VFS.Create(ctx, session, req)
	if status == smb.StatusOk && err == nil {
		v.mu.Lock()
		v.successful++
		v.mu.Unlock()
	}
	return result, status, err
}

func (v *guardedEnumerationVFS) Close(ctx context.Context, handle server.Handle) error {
	v.mu.Lock()
	v.closed++
	v.mu.Unlock()
	return v.VFS.Close(ctx, handle)
}

func (v *guardedEnumerationVFS) Write(context.Context, server.Handle, int64, []byte) (int, uint32, error) {
	v.record("filesystem Write")
	return 0, smb.StatusAccessDenied, nil
}

func (v *guardedEnumerationVFS) SetFileInfo(context.Context, server.Handle, byte, []byte) (uint32, error) {
	v.record("filesystem SetFileInfo (rename/delete/truncate/attribute change)")
	return smb.StatusAccessDenied, nil
}

func (v *guardedEnumerationVFS) Ioctl(context.Context, server.Handle, uint32, []byte, uint32) ([]byte, uint32, error) {
	v.record("filesystem IOCTL")
	return nil, smb.StatusAccessDenied, nil
}

func (v *guardedEnumerationVFS) Read(context.Context, server.Handle, int64, []byte) (int, uint32, error) {
	v.record("unexpected file contents read")
	return 0, smb.StatusAccessDenied, nil
}

func (v *guardedEnumerationVFS) QueryDirectory(context.Context, server.Handle, string, bool) ([]server.DirEntry, uint32, error) {
	v.record("unexpected child listing")
	return nil, smb.StatusAccessDenied, nil
}
