package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/golog"
)

func TestScanTargetHostDeadlineClosesNegotiationSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	target := Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	started := time.Now()
	result := scanTarget(context.Background(), target, Options{Timeout: time.Minute, HostTimeout: 80 * time.Millisecond})
	if !result.TimedOut || !result.Reachable || result.Authentication != TimedOut || result.Enumeration != TimedOut {
		t.Fatalf("host deadline did not classify unfinished negotiation: %+v", result)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("host deadline took %s despite a long I/O timeout", elapsed)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("host deadline left the TCP connection open")
	}
}

func TestScanTargetTimeoutPreservesCompletedResults(t *testing.T) {
	// The local SMB server shares the dependency's global logger. Silence it
	// before starting its goroutines, including when this test runs alone.
	silenceLogs.Do(func() { golog.SetAll(golog.LevelNone, 0, golog.NoOutput, golog.NoOutput) })
	tests := []struct {
		name      string
		stall     string
		metadata  string
		denyList  bool
		guest     bool
		ioTimeout bool
		wantRead  string
		wantWrite string
		wantOpens int
	}{
		{"host_deadline_during_root_open", "root", "success", false, false, false, TimedOut, TimedOut, 0},
		{"io_timeout_during_root_open", "root", "success", false, false, true, TimedOut, TimedOut, 0},
		{"guest_identity_and_share_denial_survive", "root", "success", false, true, false, TimedOut, Denied, 0},
		{"denied_list_survives_metadata_timeout", "attributes", "success", true, false, false, Denied, TimedOut, 1},
		{"missing_metadata_stays_unknown_on_cleanup_timeout", "logoff", "absent", false, false, false, Allowed, Unknown, 1},
		{"known_permissions_survive_cleanup_timeout", "logoff", "success", false, false, false, Allowed, Allowed, 1},
		{"enumeration_timeout_retains_authentication", "rpc", "success", false, false, false, "", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, tc.metadata, tc.denyList, "map_guest")
			fixture.options.HostTimeout = 300 * time.Millisecond
			if tc.ioTimeout {
				fixture.options.Timeout = 150 * time.Millisecond
				fixture.options.HostTimeout = 3 * time.Second
			}
			if tc.guest {
				fixture.options.Username = "unknown-test-user"
			}
			proxy, stalled, done := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
				if len(raw) < 64 || string(raw[:4]) != smb.ProtocolSmb2 {
					return false
				}
				command := binary.LittleEndian.Uint16(raw[12:14])
				if tc.stall == "logoff" {
					return command == smb.CommandLogoff
				}
				if tc.stall == "rpc" {
					return command == smb.CommandIOCtl
				}
				if command != smb.CommandCreate {
					return false
				}
				var req smb.CreateReq
				if err := req.UnmarshalBinary(raw); err != nil {
					return false
				}
				return req.NameLength == 0 && (tc.stall == "root" || req.DesiredAccess == smb.FAccMaskFileReadAttributes)
			})
			started := time.Now()
			result := scanTarget(context.Background(), proxy, fixture.options)
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("timeout did not bound the entire scan: %s", elapsed)
			}
			select {
			case <-stalled:
			default:
				t.Fatalf("scan did not reach intended stall: %+v", result)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("timed-out scan did not close its connection")
			}
			wantAuth := "authenticated"
			if tc.guest {
				wantAuth = "guest"
			}
			if !result.TimedOut || !result.Reachable || result.Authentication != wantAuth || result.GuestFallback != tc.guest {
				t.Errorf("timeout lost established identity: %+v", result)
			}
			if tc.stall == "rpc" {
				if result.Enumeration != TimedOut || len(result.Shares) != 0 {
					t.Errorf("unfinished enumeration was not marked timeout: %+v", result)
				}
			} else {
				if result.Enumeration != "ok" || len(result.Shares) != 3 {
					t.Fatalf("timeout lost successful enumeration: %+v", result)
				}
				for _, share := range result.Shares {
					if share.Name == "data$" {
						if share.Accessible != Allowed || share.Read != tc.wantRead || share.Write != tc.wantWrite {
							t.Errorf("root permissions after timeout: %+v; want read=%s write=%s", share, tc.wantRead, tc.wantWrite)
						}
					} else if share.Read != NotApplicable || share.Write != NotApplicable {
						t.Errorf("non-disk share should stay n/a after timeout: %+v", share)
					}
				}
			}
			fixture.assertUnchanged(t, tc.wantOpens)
		})
	}
}

func TestMarkHostTimeoutPreservesKnownAndCompletedUnknownResults(t *testing.T) {
	result := Result{
		Authentication: "guest", GuestFallback: true, Enumeration: "ok",
		Shares: []ShareResult{
			{Name: "completed", Accessible: Allowed, Read: Allowed, Write: Unknown, probeComplete: true},
			{Name: "partially_answered", Accessible: Allowed, Read: Denied, Write: Unknown},
			{Name: "unprobed", Accessible: Unknown, Read: Unknown, Write: Unknown},
			{Name: "nondisk", Accessible: NotApplicable, Read: NotApplicable, Write: NotApplicable},
		},
	}
	markHostTimeout(&result)
	if !result.TimedOut || result.Authentication != "guest" || !result.GuestFallback || result.Enumeration != "ok" {
		t.Fatalf("known host results changed: %+v", result)
	}
	if got := result.Shares[0]; got.Read != Allowed || got.Write != Unknown {
		t.Errorf("completed missing metadata was relabeled: %+v", got)
	}
	if got := result.Shares[1]; got.Accessible != Allowed || got.Read != Denied || got.Write != TimedOut {
		t.Errorf("partial result not retained: %+v", got)
	}
	if got := result.Shares[2]; got.Accessible != TimedOut || got.Read != TimedOut || got.Write != TimedOut {
		t.Errorf("remaining checks not marked timeout: %+v", got)
	}
	if got := result.Shares[3]; got.Read != NotApplicable || got.Write != NotApplicable {
		t.Errorf("non-disk result changed: %+v", got)
	}
}

func TestDialerTimeoutClassificationUsesTypedErrors(t *testing.T) {
	dialer := &boundedDialer{ctx: context.Background()}
	dialer.recordTimeout(errors.New("the server says timeout"))
	if dialer.timedOut() {
		t.Fatal("untrusted error text was treated as a transport timeout")
	}
	dialer.recordTimeout(&net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded})
	if !dialer.timedOut() || !errors.Is(dialer.arm(), context.DeadlineExceeded) {
		t.Fatal("typed timeout was lost or another operation was permitted")
	}
}

// Proxy only loopback fixture traffic, forwarding bytes unchanged until the
// selected request. Withhold that one request, then watch for client EOF. This
// exercises real signed SMB sessions without weakening the read-only guard.
func newStallingSMBProxy(t *testing.T, upstream Target, shouldStall func([]byte) bool) (Target, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stalled := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		downstream, err := listener.Accept()
		if err != nil {
			return
		}
		defer downstream.Close()
		_ = downstream.SetDeadline(time.Now().Add(3 * time.Second))
		remote, err := net.DialTimeout("tcp", upstream.String(), time.Second)
		if err != nil {
			return
		}
		defer remote.Close()
		_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
		copyDone := make(chan struct{})
		go func() {
			defer close(copyDone)
			_, _ = io.Copy(downstream, remote)
			_ = downstream.Close()
		}()
		defer func() {
			_ = remote.Close()
			<-copyDone
		}()
		for {
			prefix := make([]byte, 4)
			if _, err := io.ReadFull(downstream, prefix); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(prefix)
			if size > 4<<20 {
				return
			}
			raw := make([]byte, size)
			if _, err := io.ReadFull(downstream, raw); err != nil {
				return
			}
			if shouldStall(raw) {
				close(stalled)
				_, _ = io.Copy(io.Discard, downstream)
				return
			}
			if _, err := io.Copy(remote, bytes.NewReader(append(prefix, raw...))); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("loopback proxy did not stop")
		}
	})
	return Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, stalled, done
}
