package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	smb "gosmb/internal/smbwire"
)

func TestConnectionRejectionSurvivesLaterInterruption(t *testing.T) {
	for _, stage := range []struct {
		name       string
		command    uint16
		status     uint32
		auth, want string
	}{
		{"negotiate", 0, smb.StatusNotSupported, "error", "NEGOTIATE_FAILED"},
		{"session setup", 1, smb.StatusNotSupported, "error", "SMB_FAILED"},
		{"known authentication rejection", 1, smb.StatusLogonFailure, "failed", "AUTH_FAILED"},
	} {
		for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
			t.Run(stage.name+"/"+cause.Error(), func(t *testing.T) {
				fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
				fixture.guard.mu.Lock()
				if stage.command == 0 {
					fixture.guard.negotiationStatus = stage.status
				} else {
					fixture.guard.authenticationStatus = stage.status
				}
				fixture.guard.mu.Unlock()
				var ready atomic.Bool
				target, _, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
					if len(raw) >= 64 && binary.LittleEndian.Uint16(raw[12:14]) == stage.command &&
						(stage.command == 0 || bytes.Contains(raw[64:], []byte("NTLMSSP\x00\x03\x00\x00\x00"))) {
						ready.Store(true)
					}
					return false
				})
				parent, cancel := context.WithCancelCause(context.Background())
				defer cancel(context.Canceled)
				// Let the server rejection arrive before bookkeeping observes the
				// interruption, without relying on wall-clock timing.
				ctx := interruptWhenReadyContext{parent, &ready, cancel, cause}
				result := scanTarget(ctx, target, fixture.options)
				if !ready.Load() || !errors.Is(ctx.Err(), cause) || !result.Reachable {
					t.Fatalf("did not interrupt after receiving a server rejection: %+v", result)
				}
				if result.Authentication != stage.auth || !result.authenticationComplete || tableStatus(result, nil) != stage.want {
					t.Errorf("interruption changed the received connection rejection: status=%s result=%+v", tableStatus(result, nil), result)
				}
				wantEnumeration := "not_attempted"
				if errors.Is(cause, context.DeadlineExceeded) {
					wantEnumeration = TimedOut
				}
				if result.TimedOut != errors.Is(cause, context.DeadlineExceeded) ||
					result.Enumeration != wantEnumeration || len(result.Shares) != 0 ||
					!strings.Contains(result.Error, fmt.Sprintf("0x%08x", stage.status)) {
					t.Errorf("interruption changed diagnostics or unfinished enumeration: %+v", result)
				}
				fixture.assertUnchanged(t, 0)
			})
		}
	}
}

func TestEnumerationRejectionSurvivesLaterInterruption(t *testing.T) {
	for _, rejection := range []struct {
		name        string
		status      uint32
		enumeration string
		want        string
	}{
		{"unsupported IPC$", smb.StatusNotSupported, "error", "ENUM_FAILED"},
		{"denied IPC$", smb.StatusAccessDenied, "denied", "ENUM_DENIED"},
	} {
		for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
			t.Run(rejection.name+"/"+cause.Error(), func(t *testing.T) {
				fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
				fixture.guard.mu.Lock()
				fixture.guard.ipcConnectStatus = rejection.status
				fixture.guard.mu.Unlock()
				var ready atomic.Bool
				target, _, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
					if len(raw) >= 72 && binary.LittleEndian.Uint16(raw[12:14]) == 3 &&
						strings.HasSuffix(fxText(raw[72:]), "\\IPC$") {
						ready.Store(true)
					}
					return false
				})
				parent, cancel := context.WithCancelCause(context.Background())
				defer cancel(context.Canceled)
				// IPC$ rejection returns before enumeration installs its cleanup
				// bookkeeping. It still completed the request before interruption.
				ctx := interruptWhenReadyContext{parent, &ready, cancel, cause}
				result := scanTarget(ctx, target, fixture.options)
				if !ready.Load() || !errors.Is(ctx.Err(), cause) || !result.Reachable ||
					result.Authentication != "authenticated" || !result.authenticationComplete {
					t.Fatalf("did not interrupt after receiving the IPC$ rejection: %+v", result)
				}
				if result.Enumeration != rejection.enumeration || !result.enumerationComplete ||
					tableStatus(result, nil) != rejection.want || len(result.Shares) != 0 ||
					result.TimedOut != errors.Is(cause, context.DeadlineExceeded) ||
					!strings.Contains(result.Error, fmt.Sprintf("0x%08x", rejection.status)) {
					t.Errorf("interruption changed the received enumeration rejection: status=%s result=%+v", tableStatus(result, nil), result)
				}
				fixture.assertUnchanged(t, 0)
			})
		}
	}
}

func TestUnansweredSessionSetupRemainsTimeout(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	fixture.options.Timeout = 300 * time.Millisecond
	target, stalled, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
		return len(raw) >= 64 && binary.LittleEndian.Uint16(raw[12:14]) == 1 &&
			bytes.Contains(raw[64:], []byte("NTLMSSP\x00\x03\x00\x00\x00"))
	})
	result := scanTarget(context.Background(), target, fixture.options)
	select {
	case <-stalled:
	default:
		t.Fatalf("did not reach the final authentication request: %+v", result)
	}
	if !result.Reachable || !result.TimedOut || result.authenticationComplete ||
		result.Authentication != TimedOut || result.Enumeration != TimedOut ||
		tableStatus(result, nil) != "SMB_TIMEOUT" || len(result.Shares) != 0 {
		t.Errorf("unanswered authentication was treated as a completed rejection: %+v", result)
	}
}

func TestShareRejectionSurvivesLaterInterruption(t *testing.T) {
	for _, stage := range []struct {
		name       string
		command    uint16
		accessible string
		opens      int
	}{
		{"tree connect", 3, Unknown, 0},
		{"root open", 5, Allowed, 1},
	} {
		for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
			t.Run(stage.name+"/"+cause.Error(), func(t *testing.T) {
				fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
				const rejected = uint32(0xc0000034) // STATUS_OBJECT_NAME_NOT_FOUND.
				fixture.guard.mu.Lock()
				if stage.command == 3 {
					fixture.guard.diskConnectStatus = rejected
				} else {
					fixture.guard.rejectFirstOpen = rejected
				}
				fixture.guard.mu.Unlock()
				var ready atomic.Bool
				target, _, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
					if len(raw) < 72 || binary.LittleEndian.Uint16(raw[12:14]) != stage.command {
						return false
					}
					if stage.command == 5 && binary.LittleEndian.Uint32(raw[36:40]) == 2 ||
						stage.command == 3 && strings.HasSuffix(fxText(raw[72:]), "\\data$") {
						ready.Store(true)
					}
					return false
				})
				parent, cancel := context.WithCancelCause(context.Background())
				defer cancel(context.Canceled)
				// The signed rejection arrives before the next context check.
				// Interrupt bookkeeping/cleanup without racing a wall-clock timer.
				ctx := interruptWhenReadyContext{parent, &ready, cancel, cause}
				result := scanTarget(ctx, target, fixture.options)
				if !ready.Load() || !errors.Is(ctx.Err(), cause) || len(result.Shares) != 3 {
					t.Fatalf("did not reach the interruption after a server rejection: %+v", result)
				}
				if result.Authentication != "authenticated" || result.Enumeration != "ok" ||
					result.TimedOut != errors.Is(cause, context.DeadlineExceeded) {
					t.Fatalf("interruption changed completed host outcomes: %+v", result)
				}
				for _, share := range result.Shares {
					if share.Type != "disk" {
						want := "OK"
						if stage.command == 3 {
							// TREE_CONNECT rejection leaves the client open; the
							// client observes the later interruption during logoff.
							want = "CANCELED"
							if errors.Is(cause, context.DeadlineExceeded) {
								want = "CLEANUP_TIMEOUT"
							}
						}
						if got := tableStatus(result, &share); got != want {
							t.Errorf("unrelated share %q status = %s; want %s", share.Name, got, want)
						}
						continue
					}
					if got := tableStatus(result, &share); got != "CHECK_FAILED" || !share.probeComplete ||
						share.Accessible != stage.accessible || share.Read != Unknown || share.Write != Unknown {
						t.Errorf("completed server rejection became %s: %+v", got, share)
					}
					if !strings.Contains(share.Error, "0xc0000034") {
						t.Errorf("lost the primary server rejection: %+v", share)
					}
				}
				fixture.assertUnchanged(t, stage.opens)
			})
		}
	}
}

func TestUnansweredFallbackRetainsInterruptionStatus(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", true)
			var ready atomic.Bool
			target, _, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
				if len(raw) >= 64 && binary.LittleEndian.Uint16(raw[12:14]) == 5 && binary.LittleEndian.Uint32(raw[36:40]) == 2 {
					ready.Store(true)
				}
				return false
			})
			parent, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			// LIST is denied, then cancellation/deadline prevents the metadata
			// fallback from receiving a response. The initial denial does not
			// make the unanswered fallback a completed server rejection.
			ctx := interruptWhenReadyContext{parent, &ready, cancel, cause}
			result := scanTarget(ctx, target, fixture.options)
			if !ready.Load() || !errors.Is(ctx.Err(), cause) || len(result.Shares) != 3 {
				t.Fatalf("did not interrupt the denied-LIST fallback: %+v", result)
			}
			wantStatus, wantWrite := "CANCELED", Unknown
			if errors.Is(cause, context.DeadlineExceeded) {
				wantStatus, wantWrite = "CHECK_TIMEOUT", TimedOut
			}
			for _, share := range result.Shares {
				if share.Type == "disk" && (tableStatus(result, &share) != wantStatus ||
					share.Accessible != Allowed || share.Read != Denied || share.Write != wantWrite) {
					t.Errorf("interrupted fallback lost its actual outcome: status=%s share=%+v", tableStatus(result, &share), share)
				}
			}
			fixture.assertUnchanged(t, 1)
		})
	}
}

func TestOperationStatusPreservesServerReplyBeforeTransportInterruption(t *testing.T) {
	denied := fmt.Errorf("close root handle: %w", &smb.NTStatusError{Command: 6, Status: smb.StatusAccessDenied})
	for _, tc := range []struct {
		name      string
		err       error
		transport error
		want      scanStatus
	}{
		{"received rejection before deadline", denied, context.DeadlineExceeded, statusCleanupFailed},
		{"received rejection before cancellation", denied, context.Canceled, statusCleanupFailed},
		{"joined cleanup timeout", errors.Join(denied, context.DeadlineExceeded), nil, statusCleanupTimeout},
		{"joined cleanup cancellation", errors.Join(denied, context.Canceled), nil, statusCanceled},
		{"unanswered operation timeout", context.DeadlineExceeded, context.DeadlineExceeded, statusCleanupTimeout},
		{"unanswered operation cancellation", context.Canceled, context.Canceled, statusCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := operationStatus(tc.err, tc.transport, statusCleanupFailed, statusCleanupTimeout); got != tc.want {
				t.Errorf("operation status = %s; want %s", statusLabels[got], statusLabels[tc.want])
			}
		})
	}
}
