package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestScanSummaryCountsHostsAndShareFindings(t *testing.T) {
	attempts := []struct {
		result    Result
		completed bool
	}{
		{Result{Target: "private-host", Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{
			{Name: "private-share", Read: Allowed, Write: Allowed},
			{Read: Allowed, Write: Denied},
			{Type: "ipc", Read: NotApplicable, Write: NotApplicable},
		}}, true},
		{Result{Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{
			{Read: Unknown, Write: Unknown, Error: "private-diagnostic"},
			{Read: TimedOut, Write: TimedOut},
		}}, true},
		{Result{Authentication: "guest", Enumeration: "ok", Shares: []ShareResult{{Read: TimedOut, Write: Unknown}}}, true},
		{Result{Authentication: "guest", Enumeration: "error", Error: "private-partial-error", Shares: []ShareResult{
			{Read: Allowed, Write: Unknown},
			{Read: Unknown, Write: Unknown},
		}}, true},
		{Result{status: statusConnectRefused}, true},
		// An interrupted host can retain known permissions, but must not be
		// counted as OK or NO_SHARES merely because no failure was recorded.
		{Result{Authentication: "guest", Enumeration: "ok", Shares: []ShareResult{{Read: Allowed, Write: Allowed}}}, false},
		{Result{Authentication: "guest", Enumeration: "ok"}, false},
		{Result{Authentication: "failed", Error: "private-auth-error"}, false},
		{Result{Authentication: "guest", Enumeration: "ok"}, true},
	}
	const want = "Summary: 6/12 hosts completed; 3 interrupted; 3 not started; elapsed 3s; 2.0 hosts/s\n" +
		"Host outcomes: OK=1 NO_SHARES=1 CONNECT_REFUSED=1 AUTH_FAILED=1 ENUM_PARTIAL=1 CHECK_FAILED=1 CHECK_TIMEOUT=1 CANCELED=2\n" +
		"Shares: 9 found; 4 readable; 2 writable (metadata)\n"
	for _, reverse := range []bool{false, true} {
		var summary scanSummary
		for i := range attempts {
			if reverse {
				i = len(attempts) - 1 - i
			}
			attempt := attempts[i]
			summary.Add(attempt.result, attempt.completed)
		}
		var out bytes.Buffer
		if err := summary.Print(&out, 12, 3*time.Second); err != nil {
			t.Fatal(err)
		}
		if out.String() != want {
			t.Fatalf("reverse=%t: host/share accounting or deterministic summary changed:\ngot %q\nwant %q", reverse, out.String(), want)
		}
	}
}

func TestScanSummaryPreservesStatusPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		host       scanStatus
		completion scanStatus
		share      ShareResult
		want       scanStatus
	}{
		{"share failure before cleanup timeout", statusOK, statusCleanupTimeout,
			ShareResult{Read: Unknown, Write: Unknown, status: statusCheckFailed}, statusCheckFailed},
		{"share timeout before scan timeout", statusOK, statusScanTimeout,
			ShareResult{Read: TimedOut, Write: TimedOut, status: statusCheckTimeout}, statusCheckTimeout},
		{"inferred share failure before cleanup timeout", statusOK, statusCleanupTimeout,
			ShareResult{Read: Unknown, Write: Unknown, Error: "root check failed"}, statusCheckFailed},
		{"primary host failure before share and cleanup", statusEnumPartial, statusCleanupTimeout,
			ShareResult{Read: Unknown, Write: Unknown, status: statusCheckFailed}, statusEnumPartial},
		{"cleanup timeout without share failure", statusOK, statusCleanupTimeout,
			ShareResult{Read: Denied, Write: Denied, status: statusOK}, statusCleanupTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := Result{Authentication: "authenticated", Enumeration: "ok", status: tc.host,
				completionStatus: tc.completion, Shares: []ShareResult{
					// A healthy first share must not select the host's cleanup
					// failure before the later share check is considered.
					{Read: Allowed, Write: Allowed, status: statusOK},
					tc.share,
					{Read: Allowed, Write: Denied, status: statusOK},
				}}
			var summary scanSummary
			summary.Add(result, true)
			if summary.outcomes[tc.want] != 1 {
				t.Errorf("host outcomes = %v; want one %s", summary.outcomes, statusLabels[tc.want])
			}
			if summary.attempted != 1 || summary.completed != 1 || summary.shares != 3 || summary.readable != 2 || summary.writable != 1 {
				t.Errorf("outcome selection changed host or permission counts: %+v", summary)
			}
		})
	}
}

func TestScanSummaryEmptyAndRemainingTargets(t *testing.T) {
	var summary scanSummary
	var out bytes.Buffer
	if err := summary.Print(&out, 3, 0); err != nil {
		t.Fatal(err)
	}
	const empty = "Summary: 0/3 hosts completed; 0 interrupted; 3 not started; elapsed 0s; 0.0 hosts/s\n" +
		"Host outcomes: none\nShares: 0 found; 0 readable; 0 writable (metadata)\n"
	if out.String() != empty {
		t.Fatalf("empty summary invented attempts or outcomes: %q", out.String())
	}
	summary.Add(Result{Authentication: "guest", Enumeration: "ok"}, true)
	summary.Add(Result{Authentication: "guest", Enumeration: "ok"}, false)
	out.Reset()
	if err := summary.Print(&out, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "Summary: 1/1 hosts completed; 1 interrupted; 0 not started; elapsed 1s; 1.0 hosts/s\n") {
		t.Fatalf("remaining target count was negative: %q", out.String())
	}
}

func TestScanSummaryPropagatesOutputFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		var summary scanSummary
		want := io.ErrClosedPipe
		if short {
			want = io.ErrShortWrite
		}
		out := outputWriteFunc(func(data []byte) (int, error) {
			if short {
				return len(data) / 2, nil
			}
			return 0, io.ErrClosedPipe
		})
		if err := summary.Print(out, 1, time.Second); !errors.Is(err, want) {
			t.Fatalf("short=%t: output error=%v; want %v", short, err, want)
		}
	}
}

func TestScanSummaryElapsedAndCompletedRate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		want    string
	}{
		{"zero", 0, "0s; 0.0 hosts/s"},
		{"negative", -time.Second, "0s; 0.0 hosts/s"},
		{"fractional", 1500 * time.Millisecond, "1.5s; 0.7 hosts/s"},
		{"minutes", 83 * time.Second, "1m23s; 0.0 hosts/s"},
		{"submillisecond", 400 * time.Microsecond, "<1ms; 2500.0 hosts/s"},
		{"unrounded rate", 1500 * time.Microsecond, "2ms; 666.7 hosts/s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var summary scanSummary
			summary.Add(Result{Authentication: "guest", Enumeration: "ok"}, true)
			summary.Add(Result{Authentication: "guest", Enumeration: "ok"}, false)
			var out bytes.Buffer
			if err := summary.Print(&out, 3, tc.elapsed); err != nil {
				t.Fatal(err)
			}
			line, _, _ := strings.Cut(out.String(), "\n")
			if want := "Summary: 1/3 hosts completed; 1 interrupted; 1 not started; elapsed " + tc.want; line != want {
				t.Fatalf("summary timing=%q; want %q", line, want)
			}
		})
	}
}
