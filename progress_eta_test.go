package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestProgressMaxETAUsesRemainingScanBudget(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		total, completed, concurrency int
		timeout, delay                time.Duration
		want                          string
	}{
		{"large default scan", 5113, 0, 40, 30 * time.Second, 0, "1h04m"},
		{"user settings", 6067, 0, 40, 30 * time.Second, 250 * time.Millisecond, "1h17m"},
		{"launch delay dominates", 6067, 0, 40, 5 * time.Second, 250 * time.Millisecond, "25m22s"},
		{"remaining targets", 6067, 6, 40, 5 * time.Second, 250 * time.Millisecond, "25m21s"},
		{"partial final batch", 8, 0, 3, 10 * time.Second, 2 * time.Second, "32s"},
		{"no launch delay", 10, 0, 3, 10 * time.Second, 0, "40s"},
		{"idle slot still awaiting launch interval", 2, 1, 1, time.Second, 10 * time.Second, "11s"},
		{"fewer targets than workers", 1, 0, 40, 30 * time.Second, 0, "30s"},
		{"negative count clamped", 1, -1, 1, time.Second, 0, "1s"},
		{"finished", 10, 10, 3, time.Second, 0, "0s"},
		{"overcount clamped", 10, 11, 3, time.Second, 0, "0s"},
		{"empty scan", 0, 0, 3, time.Second, 0, "0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProgress(io.Discard, true, tc.total)
			p.SetScanBudget(tc.concurrency, tc.timeout, tc.delay)
			if got := p.liveLabel(tc.completed); !strings.HasSuffix(got, " | Max ETA: "+tc.want) {
				t.Fatalf("progress = %q; want Max ETA: %s", got, tc.want)
			}
		})
	}
}

func TestProgressMaxETAHandlesLargeBudgetsAndRounding(t *testing.T) {
	for _, tc := range []struct {
		seconds float64
		want    string
	}{
		{0, "0s"}, {0.001, "1s"}, {59.01, "1m00s"}, {3599.1, "1h00m"},
		{3600.1, "1h01m"}, {86400.1, "1d01h"},
	} {
		if got := formatMaxETA(tc.seconds); got != tc.want {
			t.Errorf("%g seconds = %q; want %q", tc.seconds, got, tc.want)
		}
	}
	p := newProgress(io.Discard, true, 65536)
	p.SetScanBudget(1, 365*24*time.Hour, 0)
	// The aggregate exceeds time.Duration's range, but remains representable
	// as an estimate and must not wrap into a short or negative duration.
	if got := p.liveLabel(0); !strings.HasSuffix(got, " | Max ETA: 23920640d00h") {
		t.Fatalf("large scan budget overflowed: %q", got)
	}
}

func TestCLIMaxETAUsesHostTimeoutAndStaysOffStdout(t *testing.T) {
	path := schedulerHostFile(t, "one", "two", "three", "four", "five", "six", "seven", "eight")
	for _, terminal := range []bool{false, true} {
		var out, diagnostics bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		deps := testCLIDeps(&out, &diagnostics)
		deps.stdoutIsTerminal, deps.stderrIsTerminal = terminal, true
		deps.scan = func(_ context.Context, target Target, options Options) Result {
			if options.Timeout != 5*time.Second || options.HostTimeout != 12*time.Second {
				t.Errorf("scan timeout settings changed: %+v", options)
			}
			cancel() // Inspect the initial budget without waiting on launch delays.
			return Result{Target: target.String(), Authentication: "guest", Enumeration: "ok"}
		}
		code := runCLI(ctx, []string{path, "--guest", "--timeout=5s", "--host-timeout=12",
			"--concurrency=3", "--delay=2s"}, deps)
		if code != 1 || !strings.Contains(diagnostics.String(), "Progress: 0% (0/8 hosts completed) | Max ETA: 38s") {
			t.Fatalf("initial max ETA lost configured host budget: exit=%d stderr=%q", code, diagnostics.String())
		}
		finalOutput := out.String()
		if terminal {
			finalOutput = diagnostics.String()
		}
		index := strings.LastIndex(finalOutput, "Progress:")
		if index < 0 {
			t.Fatalf("stopped scan lost its final summary: %q", finalOutput)
		}
		final := finalOutput[index:]
		if !strings.Contains(final, "(interrupted)") || strings.Contains(final, "Max ETA:") {
			t.Errorf("stopped scan retained a completion estimate: %q", final)
		}
		if strings.Contains(out.String(), "ETA:") || strings.ContainsAny(out.String(), "\r\x1b") {
			t.Errorf("estimate or progress controls leaked into stdout: %q", out.String())
		}
	}
}
