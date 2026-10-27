package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestDeadlineAfterSuccessfulLogoffReportsScanTimeout(t *testing.T) {
	for _, metadata := range []string{"success", "absent"} {
		t.Run(metadata, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, metadata, false)
			var ready atomic.Bool
			target, _, _ := newStallingSMBProxy(t, fixture.target, func(raw []byte) bool {
				if len(raw) >= 64 && binary.LittleEndian.Uint16(raw[12:14]) == 2 {
					ready.Store(true)
				}
				return false
			})
			parent, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			// LOGOFF receives its successful response before final bookkeeping
			// observes the deadline. No cleanup request remains unanswered.
			ctx := interruptWhenReadyContext{parent, &ready, cancel, context.DeadlineExceeded}
			result := scanTarget(ctx, target, fixture.options)
			if !ready.Load() || !result.TimedOut || result.Error != "scan timed out" ||
				result.Authentication != "authenticated" || result.Enumeration != "ok" ||
				!result.authenticationComplete || !result.enumerationComplete || len(result.Shares) != 3 {
				t.Fatalf("late deadline changed completed phases or cleanup: %+v", result)
			}
			var aligned, tsv bytes.Buffer
			if err := writeAlignedResult(&aligned, result, false); err != nil {
				t.Fatal(err)
			}
			if err := writeTextResult(&tsv, result); err != nil {
				t.Fatal(err)
			}
			rows := strings.Split(strings.TrimSuffix(aligned.String(), "\n"), "\n")
			machineRows := parseTestTSV(t, tsv.String())
			if len(rows) != 3 || len(machineRows) != 3 {
				t.Fatalf("late timeout changed output row counts: %q %q", aligned.String(), tsv.String())
			}
			for i, share := range result.Shares {
				wantStatus, wantRead, wantWrite := "SCAN_TIMEOUT", NotApplicable, NotApplicable
				readText, writeText := "N/A", "N/A"
				if share.Type == "disk" {
					wantRead, wantWrite, readText, writeText = Allowed, Allowed, "TRUE", "TRUE"
					if metadata == "absent" {
						wantStatus, wantWrite, writeText = "CHECK_FAILED", Unknown, "UNKNOWN"
					}
				}
				if !share.probeComplete || share.Read != wantRead || share.Write != wantWrite {
					t.Errorf("late timeout erased completed permissions: %+v", share)
				}
				fields := strings.Fields(rows[i])
				if len(fields) != 7 || fields[2] != readText || fields[3] != writeText || fields[4] != "FALSE" || fields[5] != wantStatus {
					t.Errorf("interactive row lost permissions or completion status: %q", rows[i])
				}
				if machineRows[i][2] != readText || machineRows[i][3] != writeText || machineRows[i][4] != "FALSE" || machineRows[i][5] != wantStatus {
					t.Errorf("late timeout changed TSV permissions, guest fallback, or completion status: %q", machineRows[i])
				}
			}
			fixture.assertUnchanged(t, 1)
		})
	}
}

func TestSchedulerTimeoutAfterCompletedResult(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		expired, empty, publicFieldsOnly, unanswered bool
	}{
		{"within budget", false, false, false, false},
		{"deadline after completed checks", true, false, false, false},
		{"deadline after empty enumeration", true, true, false, false},
		{"hook without private metadata", true, false, true, false},
		{"hook with unanswered check", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				outcome := runHostScan(context.Background(), Target{"server", 445}, Options{HostTimeout: time.Second},
					func(ctx context.Context, target Target, _ Options) Result {
						result := schedulerSuccess(target)
						result.Shares[0].Accessible = Allowed
						if tc.unanswered {
							result.Shares[0].Write = Unknown
						}
						if tc.empty {
							result.Shares = nil
						}
						if !tc.publicFieldsOnly {
							result.status, result.authenticationComplete, result.enumerationComplete = statusOK, true, true
							for i := range result.Shares {
								result.Shares[i].status, result.Shares[i].probeComplete = statusOK, true
							}
						}
						if tc.expired {
							<-ctx.Done()
						}
						return result
					})
				result := outcome.result
				wantStatus, wantError := "OK", ""
				if tc.expired {
					wantStatus, wantError = "SCAN_TIMEOUT", "scan timed out"
					if tc.unanswered {
						wantStatus = "CHECK_TIMEOUT"
					}
					// Scanner and scheduler may both normalize the same deadline.
					markHostTimeout(&result)
				}
				if !outcome.completed || !outcome.started || result.TimedOut != tc.expired || result.Error != wantError ||
					result.Authentication != "authenticated" || result.Enumeration != "ok" {
					t.Fatalf("deadline normalization changed completed result: %+v", outcome)
				}
				var share *ShareResult
				if !tc.empty {
					share = &result.Shares[0]
					wantWrite := Denied
					if tc.unanswered {
						wantWrite = TimedOut
					}
					if share.Read != Allowed || share.Write != wantWrite {
						t.Errorf("scheduler timeout changed completed permissions: %+v", share)
					}
				}
				if got := tableStatus(result, share); got != wantStatus {
					t.Errorf("completion status = %s; want %s", got, wantStatus)
				}
			})
		})
	}
}

func TestScanTimeoutFallbackPreservesEarlierFailures(t *testing.T) {
	for _, completion := range []scanStatus{statusUnset, statusCleanupFailed, statusCleanupTimeout} {
		result := Result{Authentication: "authenticated", Enumeration: "ok", Error: "earlier failure",
			status: statusOK, completionStatus: completion,
			Shares: []ShareResult{
				{Read: Allowed, Write: Unknown, status: statusCheckFailed, probeComplete: true},
				{Read: Allowed, Write: Denied, status: statusOK, probeComplete: true},
			}}
		markHostTimeout(&result)
		if result.Error != "earlier failure" || result.completionStatus != completion || tableStatus(result, &result.Shares[0]) != "CHECK_FAILED" {
			t.Fatalf("new timeout replaced an earlier failure: %+v", result)
		}
		want := "OK"
		if completion != statusUnset {
			want = statusLabels[completion]
		}
		if got := tableStatus(result, &result.Shares[1]); got != want {
			t.Errorf("new timeout changed an unrelated completed row: got %s; want %s", got, want)
		}
	}
}
