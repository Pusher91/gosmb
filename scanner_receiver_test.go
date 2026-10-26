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
)

// A malformed transform on a guest session must fail promptly, without a panic,
// credential retry, timeout misclassification, or leaked connection.
func TestScanTargetMalformedTransformReturnsPromptly(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false, "map_guest")
	fixture.options.Username = "unrecognized-guest-fixture-user"
	fixture.options.HostTimeout = 300 * time.Millisecond
	fixture.options.Timeout = 2 * time.Second
	target, injected, proxyDone := newMalformedTransformSMBProxy(t, fixture.target)
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
		if result.Enumeration != "error" || result.Error == "" {
			t.Errorf("wanted malformed-response error, got %+v", result)
		}
		if result.TimedOut {
			t.Errorf("malformed response or depleted credits was mislabeled as a transport timeout: %+v", result)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Errorf("malformed response cleanup exceeded host budget plus scheduling tolerance: %s", elapsed)
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
		t.Error("scan did not close its socket after malformed response")
	}
	fixture.assertUnchanged(t, 0)
}

// Replace a guest pipe-open response with an encrypted transform even though
// no encryption key was established. Credits remain valid through negotiation.
func newMalformedTransformSMBProxy(t *testing.T, upstream Target) (Target, <-chan struct{}, <-chan struct{}) {
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
			binary.LittleEndian.PutUint16(raw[14:16], 1)
			if command == 5 {
				transform := make([]byte, 52)
				copy(transform, []byte("\xfdSMB"))
				binary.LittleEndian.PutUint16(transform[42:44], 1)
				copy(transform[44:52], raw[40:48])
				raw = transform
				binary.BigEndian.PutUint32(prefix, uint32(len(raw)))
			}
			if _, err := io.Copy(downstream, bytes.NewReader(append(prefix, raw...))); err != nil {
				return
			}
			if command == 5 {
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
			t.Error("malformed-response proxy did not stop")
		}
	})
	return Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, injected, done
}

func TestScanTargetRejectsTamperedSignedReply(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	fixture.options.HostTimeout = time.Second
	target, injected, done := newTamperedSMBReplyProxy(t, fixture.target, 3, 0, 76)
	result := scanTarget(context.Background(), target, fixture.options)
	if result.Authentication != "authenticated" || result.Enumeration != "error" || result.TimedOut || len(result.Shares) != 0 {
		t.Errorf("tampered signed reply was trusted or misclassified: %+v", result)
	}
	if !strings.Contains(result.Error, "signature") {
		t.Errorf("wanted signature rejection, got %q", result.Error)
	}
	select {
	case <-injected:
	default:
		t.Fatal("test did not reach the signed share reply")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("signature rejection left a connection open")
	}
	fixture.assertUnchanged(t, 0)
}

func TestScanTargetReportsTamperedCleanupWithoutErasingPermissions(t *testing.T) {
	for _, tc := range []struct {
		name           string
		command        uint16
		tree           uint32
		wantPermission string
		wantOpens      int
	}{
		{"logoff", 2, 0, Allowed, 1},
		{"tree_disconnect", 4, 2, Allowed, 1},
		{"enumeration_pipe_close", 6, 1, Unknown, 0},
		{"enumeration_tree_disconnect", 4, 1, Unknown, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
			fixture.options.HostTimeout = time.Second
			target, injected, done := newTamperedSMBReplyProxy(t, fixture.target, tc.command, tc.tree, 64)
			result := scanTarget(context.Background(), target, fixture.options)
			if result.Authentication != "authenticated" || result.Enumeration != "ok" || result.TimedOut || result.Error == "" {
				t.Fatalf("cleanup failure was lost or changed completed phases: %+v", result)
			}
			var disk ShareResult
			for _, share := range result.Shares {
				if share.Name == "data$" {
					disk = share
				}
			}
			if disk.Accessible != tc.wantPermission || disk.Read != tc.wantPermission || disk.Write != tc.wantPermission {
				t.Fatalf("cleanup failure erased completed permissions: %+v", disk)
			}
			diagnostic, phase := result.Error, "logoff"
			if tc.tree == 1 {
				phase = "enumeration"
			} else if tc.command == 4 {
				diagnostic, phase = disk.Error, "disconnect share"
			}
			if !strings.Contains(diagnostic, phase) || !strings.Contains(diagnostic, "signature") {
				t.Fatalf("cleanup failure lost its precise diagnostic: %q", diagnostic)
			}
			select {
			case <-injected:
			default:
				t.Fatal("scan did not reach intended cleanup response")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cleanup failure left the connection open")
			}
			fixture.assertUnchanged(t, tc.wantOpens)
		})
	}
}

// Mutate one byte covered by an existing signature on the selected command.
// A zero tree matches any tree. Credits and authentication bytes stay intact.
func newTamperedSMBReplyProxy(t *testing.T, upstream Target, command uint16, tree uint32, offset int) (Target, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	injected, done := make(chan struct{}), make(chan struct{})
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
		go func() { defer close(forwardDone); _, _ = io.Copy(remote, downstream); _ = remote.Close() }()
		defer func() { _ = downstream.Close(); _ = remote.Close(); <-forwardDone }()
		for {
			var prefix [4]byte
			if _, err := io.ReadFull(remote, prefix[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(prefix[:])
			if n < 64 || n > 4<<20 {
				return
			}
			packet := make([]byte, n)
			if _, err := io.ReadFull(remote, packet); err != nil {
				return
			}
			mutate := binary.LittleEndian.Uint16(packet[12:]) == command && (tree == 0 || binary.LittleEndian.Uint32(packet[36:]) == tree)
			if mutate {
				if len(packet) <= offset || binary.LittleEndian.Uint32(packet[16:])&8 == 0 {
					return
				}
				packet[offset] ^= 2
			}
			if _, err := io.Copy(downstream, bytes.NewReader(append(prefix[:], packet...))); err != nil {
				return
			}
			if mutate {
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
			t.Error("tamper proxy did not stop")
		}
	})
	return Target{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, injected, done
}
