package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/golog"
)

// The dependency's receiver panic handler does not shut down its credit
// manager. Closing the socket alone therefore cannot release subsequent
// credit reservations, including the TreeDisconnect performed by Close.
func TestScanTargetReceiverPanicWithNoCreditsReturnsPromptly(t *testing.T) {
	// The fixture server also uses these package loggers; configure them before
	// starting it so isolated race-test runs do not reconfigure active loggers.
	silenceLogs.Do(func() { golog.SetAll(golog.LevelNone, 0, golog.NoOutput, golog.NoOutput) })
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false, "map_guest")
	fixture.options.Username = "unrecognized-guest-fixture-user"
	fixture.options.HostTimeout = 300 * time.Millisecond
	fixture.options.Timeout = 2 * time.Second
	target, injected, proxyDone := newReceiverPanicSMBProxy(t, fixture.target)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan Result, 1)
	started := time.Now()
	go func() { resultCh <- scanTarget(ctx, target, fixture.options) }()
	select {
	case result := <-resultCh:
		if result.Authentication != "guest" || !result.GuestFallback {
			t.Fatalf("fixture did not establish the guest session: %+v", result)
		}
		if result.Enumeration != "error" || !strings.Contains(result.Error, "runReceiver panic") {
			t.Errorf("wanted the dependency receiver-panic error, got %+v", result)
		}
		if result.TimedOut {
			t.Errorf("receiver panic or depleted credits was mislabeled as a transport timeout: %+v", result)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Errorf("receiver panic cleanup exceeded host budget plus scheduling tolerance: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not return after its host deadline; cleanup may be waiting for credits")
	}
	select {
	case <-injected:
	default:
		t.Error("fixture did not inject the malformed encrypted reply")
	}
	select {
	case <-proxyDone:
	case <-time.After(time.Second):
		t.Error("scan did not close its socket after receiver panic")
	}
	fixture.assertUnchanged(t, 0)
}

// Restrict the guest client to one credit, then replace its pipe-open reply
// with an encrypted frame. Guest has no encryption key, so v0.12.0 recovers a
// nil-decrypter panic with zero credits and an IPC$ tree still cached.
func newReceiverPanicSMBProxy(t *testing.T, upstream Target) (Target, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	injected := make(chan struct{})
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
		forwardDone := make(chan struct{})
		go func() {
			defer close(forwardDone)
			_, _ = io.Copy(remote, downstream)
			_ = remote.Close()
		}()
		defer func() {
			_ = downstream.Close()
			_ = remote.Close()
			<-forwardDone
		}()
		for {
			prefix := make([]byte, 4)
			if _, err := io.ReadFull(remote, prefix); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(prefix)
			if size < 64 || size > 4<<20 {
				return
			}
			raw := make([]byte, size)
			if _, err := io.ReadFull(remote, raw); err != nil {
				return
			}
			command := binary.LittleEndian.Uint16(raw[12:14])
			binary.LittleEndian.PutUint16(raw[14:16], 0)
			if command == smb.CommandTreeConnect {
				// The initial connection credit bought TREE_CONNECT. Give back
				// exactly one for the pipe open, which receives no credit grant.
				binary.LittleEndian.PutUint16(raw[14:16], 1)
			}
			if command == smb.CommandCreate {
				transform := make([]byte, 52)
				copy(transform, []byte(smb.ProtocolTransformHdr))
				binary.LittleEndian.PutUint16(transform[42:44], 1)
				copy(transform[44:52], raw[40:48])
				raw = transform
				binary.BigEndian.PutUint32(prefix, uint32(len(raw)))
			}
			if _, err := io.Copy(downstream, bytes.NewReader(append(prefix, raw...))); err != nil {
				return
			}
			if command == smb.CommandCreate {
				close(injected)
				<-forwardDone
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("receiver-panic proxy did not stop")
		}
	})
	return Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, injected, done
}
