package main

import (
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
)

// Interrupt at the next context check after a fixture marks an operation ready.
// Its response finishes normally before bookkeeping or the next operation sees
// the interruption, without racing a timer. Err exposes either a user
// cancellation or a host deadline, as selected by the test.
type interruptWhenReadyContext struct {
	context.Context
	ready  *atomic.Bool
	cancel context.CancelCauseFunc
	cause  error
}

func (c interruptWhenReadyContext) Err() error {
	if c.ready.Load() {
		c.cancel(c.cause)
	}
	if c.Context.Err() != nil {
		return context.Cause(c.Context)
	}
	return nil
}

func TestInterruptionBeforeLogoffDoesNotReportSuccessfulRows(t *testing.T) {
	for _, tc := range []struct {
		name               string
		cause              error
		metadata           string
		priorCleanupFailed bool
		want               string
	}{
		{"canceled after checks", context.Canceled, "success", false, "CANCELED"},
		{"deadline after checks", context.DeadlineExceeded, "success", false, "CLEANUP_TIMEOUT"},
		{"canceled after missing metadata", context.Canceled, "absent", false, "CANCELED"},
		{"deadline after missing metadata", context.DeadlineExceeded, "absent", false, "CLEANUP_TIMEOUT"},
		{"retain earlier cleanup failure", context.DeadlineExceeded, "success", true, "CLEANUP_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, tc.metadata, false)
			if tc.priorCleanupFailed {
				fixture.guard.mu.Lock()
				fixture.guard.deniedIPCCleanup = 6
				fixture.guard.mu.Unlock()
			}
			var ready atomic.Bool
			target, _, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
				if len(raw) >= 64 && binary.LittleEndian.Uint16(raw[12:14]) == 4 && binary.LittleEndian.Uint32(raw[36:40]) == 2 {
					ready.Store(true)
				}
				return false
			})
			parent, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			ctx := interruptWhenReadyContext{parent, &ready, cancel, tc.cause}
			result := scanTarget(ctx, target, fixture.options)
			if !ready.Load() || !errors.Is(ctx.Err(), tc.cause) || result.Error == "" {
				t.Fatalf("did not reach interruption after completed checks: %+v", result)
			}
			if !result.Reachable || result.Authentication != "authenticated" || result.Enumeration != "ok" ||
				!result.authenticationComplete || !result.enumerationComplete || len(result.Shares) != 3 ||
				result.TimedOut != errors.Is(tc.cause, context.DeadlineExceeded) {
				t.Fatalf("late interruption changed completed host results: %+v", result)
			}
			for _, share := range result.Shares {
				wantStatus := tc.want
				wantRead, wantWrite := NotApplicable, NotApplicable
				if share.Type == "disk" {
					wantRead, wantWrite = Allowed, Allowed
					if tc.metadata == "absent" {
						wantStatus, wantWrite = "CHECK_FAILED", Unknown
					}
				}
				if got := tableStatus(result, &share); got != wantStatus {
					t.Errorf("share %q status = %q; want %q (host error %q)", share.Name, got, wantStatus, result.Error)
				}
				if !share.probeComplete || share.Read != wantRead || share.Write != wantWrite {
					t.Errorf("late interruption erased completed permissions: %+v", share)
				}
			}
			fixture.assertUnchanged(t, 1)
		})
	}
}
