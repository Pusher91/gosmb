package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Other summary tests check exact counts without depending on wall-clock speed.
// Timing values and the interval measured by the CLI have dedicated tests.
func cliSummaryWithoutTiming(t *testing.T, output string) string {
	t.Helper()
	before, timing, ok := strings.Cut(output, "; elapsed ")
	if !ok {
		t.Fatalf("summary omitted elapsed time: %q", output)
	}
	_, after, ok := strings.Cut(timing, " hosts/s\n")
	if !ok {
		t.Fatalf("summary omitted completed hosts/s: %q", output)
	}
	return before + "\n" + after
}

func TestCLISummaryFollowsProgressAndHonorsOutputModes(t *testing.T) {
	path := schedulerHostFile(t, "first", "second")
	for _, mode := range []struct {
		name, flag           string
		stdoutTTY, stderrTTY bool
		disabled             bool
	}{
		{"terminal table", "", true, true, false},
		{"piped table", "", false, true, false},
		{"TSV", "--tsv", false, true, false},
		{"JSON", "--json", false, true, false},
		{"no progress", "--no-progress", false, true, true},
		{"redirected stderr", "", false, false, true},
		{"dumb terminal", "", false, true, true},
		{"unsupported terminal", "", true, true, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.stdoutIsTerminal, deps.stderrIsTerminal = mode.stdoutTTY, mode.stderrTTY
			if mode.name == "dumb terminal" {
				deps.lookupEnv = func(key string) (string, bool) { return "dumb", key == "TERM" }
			}
			if mode.name == "unsupported terminal" {
				deps.enableProgress = func() (func(), bool) { return nil, false }
			}
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				if target.Host == "second" {
					return Result{Target: target.String(), Authentication: "failed", Error: "private authentication detail"}
				}
				return Result{Target: target.String(), Authentication: "guest", Enumeration: "ok", Shares: []ShareResult{
					{Name: "data", Read: Allowed, Write: Allowed},
					{Name: "denied", Accessible: Denied, Read: Denied, Write: Denied},
					{Name: "IPC$", Read: NotApplicable, Write: NotApplicable},
				}}
			}
			args := []string{path, "--guest"}
			if mode.flag != "" {
				args = append(args, mode.flag)
			}
			if code := runCLI(context.Background(), args, deps); code != 1 {
				t.Fatalf("authentication failure exit code=%d", code)
			}
			const summary = "Summary: 2/2 hosts completed; 0 interrupted; 0 not started\n" +
				"Host outcomes: OK=1 AUTH_FAILED=1\nShares: 3 found; 1 readable; 1 writable (metadata)\n"
			if mode.disabled {
				if diagnostics.Len() != 0 {
					t.Fatalf("disabled progress emitted summary or diagnostics: %q", diagnostics.String())
				}
			} else if !strings.HasSuffix(cliSummaryWithoutTiming(t, diagnostics.String()), summary) ||
				strings.Count(diagnostics.String(), "Summary:") != 1 ||
				strings.LastIndex(diagnostics.String(), "Progress:") >= strings.Index(diagnostics.String(), "Summary:") {
				t.Fatalf("summary did not follow final progress exactly once: %q", diagnostics.String())
			}
			if strings.Contains(out.String(), "Summary:") || strings.Contains(out.String(), "Host outcomes:") || strings.Contains(out.String(), "Progress:") {
				t.Fatalf("summary changed saved output: %q", out.String())
			}
			if mode.flag == "--json" {
				var results []Result
				if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 2 {
					t.Fatalf("summary changed JSON results: %q, %v", out.String(), err)
				}
			} else if mode.flag == "--tsv" {
				if rows := parseTestTSV(t, out.String()); len(rows) != 5 {
					t.Fatalf("summary changed TSV row count: %d", len(rows))
				}
			} else if strings.Count(out.String(), "\n") != 5 {
				t.Fatalf("summary changed table rows: %q", out.String())
			}
		})
	}
}

func TestCLISummaryRetainsInterruptionRecordAndCountsQueuedHosts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, diagnostics bytes.Buffer
	deps := testCLIDeps(&out, &diagnostics)
	deps.stderrIsTerminal = true
	calls := 0
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		calls++
		if target.Host == "second" {
			cancel()
		}
		return schedulerSuccess(target)
	}
	path := schedulerHostFile(t, "first", "second", "queued")
	if code := runCLI(ctx, []string{path, "-u", "fixture", "-p", "", "--concurrency=1"}, deps); code != 1 || calls != 2 {
		t.Fatalf("interruption changed scheduling: code=%d scans=%d", code, calls)
	}
	const summary = "Summary: 1/3 hosts completed; 1 interrupted; 1 not started\n" +
		"Host outcomes: OK=1 CANCELED=1\nShares: 2 found; 2 readable; 0 writable (metadata)\n"
	if !strings.HasSuffix(cliSummaryWithoutTiming(t, diagnostics.String()), summary) || strings.Contains(diagnostics.String(), "(interrupted)") {
		t.Fatalf("interrupted run lost aggregate summary or duplicated its progress record: %q", diagnostics.String())
	}
	if !strings.HasSuffix(out.String(), "Progress: 33% (1/3 hosts completed) (interrupted)\n") ||
		!strings.Contains(out.String(), "second-share") || strings.Contains(out.String(), "Summary:") {
		t.Fatalf("aggregate summary changed saved interrupted results: %q", out.String())
	}
}

func TestCLISummaryIsAbsentBeforeScanningStarts(t *testing.T) {
	for _, phase := range []string{"header", "initial progress"} {
		t.Run(phase, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			stdout := outputWriteFunc(func(data []byte) (int, error) {
				if phase == "header" {
					return 0, io.ErrClosedPipe
				}
				return out.Write(data)
			})
			stderr := outputWriteFunc(func(data []byte) (int, error) {
				if phase == "initial progress" && bytes.Contains(data, []byte("Progress:")) {
					return 0, io.ErrClosedPipe
				}
				return diagnostics.Write(data)
			})
			deps := testCLIDeps(stdout, stderr)
			deps.stderrIsTerminal = true
			deps.scan = func(context.Context, Target, Options) Result {
				t.Fatal("started a scan after initial output failed")
				return Result{}
			}
			if code := runCLI(context.Background(), []string{"host", "--guest"}, deps); code != 1 {
				t.Fatalf("output failure exit code=%d", code)
			}
			if strings.Contains(diagnostics.String(), "Summary:") {
				t.Fatalf("reported a scan that never started: %q", diagnostics.String())
			}
		})
	}
}

func TestCLISummaryOutputFailureOrCancellationReturnsFailure(t *testing.T) {
	for _, mode := range []string{"short write", "write error", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostics bytes.Buffer
			attempts := 0
			stderr := outputWriteFunc(func(data []byte) (int, error) {
				if bytes.HasPrefix(data, []byte("Summary:")) {
					attempts++
					switch mode {
					case "short write":
						return len(data) / 2, nil
					case "write error":
						return 0, io.ErrClosedPipe
					case "cancellation":
						cancel()
					}
				}
				return diagnostics.Write(data)
			})
			deps := testCLIDeps(&out, stderr)
			deps.stderrIsTerminal = true
			deps.scan = func(_ context.Context, target Target, _ Options) Result { return schedulerSuccess(target) }
			if code := runCLI(ctx, []string{"host", "-u", "fixture", "-p", ""}, deps); code != 1 || attempts != 1 {
				t.Fatalf("summary failure retried or returned success: code=%d attempts=%d", code, attempts)
			}
			if !strings.Contains(out.String(), "host-share") {
				t.Fatalf("summary failure discarded results: %q", out.String())
			}
		})
	}
}

func TestCLISummaryDrainsActiveAttemptsAfterOutputFailure(t *testing.T) {
	for _, mode := range []string{"table write", "table progress", "JSON progress"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				path := schedulerHostFile(t, "first", "second", "queued")
				secondStarted := make(chan struct{})
				var scans atomic.Int32
				var out, diagnostics bytes.Buffer
				failed := false
				stdout := outputWriteFunc(func(data []byte) (int, error) {
					if mode == "table write" && bytes.Contains(data, []byte("first-share")) {
						failed = true
						return 0, io.ErrClosedPipe
					}
					if mode != "JSON progress" && failed {
						t.Error("retried text output while draining after output failure")
					}
					return out.Write(data)
				})
				stderr := outputWriteFunc(func(data []byte) (int, error) {
					if mode != "table write" && !failed && string(data) == clearProgressLine {
						failed = true
						return 0, io.ErrClosedPipe
					}
					return diagnostics.Write(data)
				})
				deps := testCLIDeps(stdout, stderr)
				deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
				deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
					scans.Add(1)
					switch target.Host {
					case "first":
						<-secondStarted
					case "second":
						close(secondStarted)
						<-scanCtx.Done()
					default:
						t.Error("queued host started after output failure")
					}
					return schedulerSuccess(target)
				}
				args := []string{path, "-u", "fixture", "-p", "", "--concurrency=2"}
				if mode == "JSON progress" {
					args = append(args, "--json")
				}
				if code := runCLI(context.Background(), args, deps); code != 1 || !failed || scans.Load() != 2 {
					t.Fatalf("output failure did not stop launches and drain active work: code=%d failed=%t scans=%d", code, failed, scans.Load())
				}
				const summary = "Summary: 1/3 hosts completed; 1 interrupted; 1 not started\n" +
					"Host outcomes: OK=1 CANCELED=1\nShares: 2 found; 2 readable; 0 writable (metadata)\n"
				if !strings.HasSuffix(cliSummaryWithoutTiming(t, diagnostics.String()), summary) || strings.Contains(diagnostics.String(), "gosmb: canceled") {
					t.Fatalf("output failure miscounted active work or claimed user cancellation: %q", diagnostics.String())
				}
				if mode == "JSON progress" {
					var results []Result
					if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 2 || results[1].Target != "second:445" {
						t.Fatalf("progress failure discarded the active JSON result: %q, %v", out.String(), err)
					}
				}
			})
		})
	}
}

func TestCLISummaryMeasuresScanAndStreamingTime(t *testing.T) {
	for _, mode := range []struct {
		name, flag, timing string
	}{
		{"table", "", "750ms; 1.3 hosts/s"},
		{"JSON", "--json", "250ms; 4.0 hosts/s"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var out, diagnostics bytes.Buffer
				stdout := outputWriteFunc(func(data []byte) (int, error) {
					if bytes.HasPrefix(data, []byte("TARGET_IP")) {
						time.Sleep(time.Second)
					}
					if bytes.Contains(data, []byte("host-share")) {
						time.Sleep(500 * time.Millisecond)
					}
					return out.Write(data)
				})
				deps := testCLIDeps(stdout, &diagnostics)
				deps.stderrIsTerminal = true
				deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
					time.Sleep(2 * time.Second)
					return "fixture", nil
				}
				deps.scan = func(_ context.Context, target Target, _ Options) Result {
					time.Sleep(250 * time.Millisecond)
					return schedulerSuccess(target)
				}
				args := []string{"host", "-u", "fixture"}
				if mode.flag != "" {
					args = append(args, mode.flag)
				}
				if code := runCLI(context.Background(), args, deps); code != 0 {
					t.Fatalf("successful scan exit code=%d; stderr=%q", code, diagnostics.String())
				}
				want := "Summary: 1/1 hosts completed; 0 interrupted; 0 not started; elapsed " + mode.timing + "\n" +
					"Host outcomes: OK=1\nShares: 1 found; 1 readable; 0 writable (metadata)\n"
				if !strings.HasSuffix(diagnostics.String(), want) {
					t.Fatalf("summary included setup/final JSON time or omitted streaming stalls: got %q; want suffix %q", diagnostics.String(), want)
				}
			})
		})
	}
}
