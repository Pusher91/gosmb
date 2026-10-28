package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIPipedTableSavesInterruptionSummary(t *testing.T) {
	for _, mode := range []string{"terminal", "redirected stderr", "dumb terminal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.stdoutIsTerminal = false
			deps.stderrIsTerminal = mode != "redirected stderr"
			if mode == "dumb terminal" {
				deps.lookupEnv = func(name string) (string, bool) { return "dumb", name == "TERM" }
			}
			calls := 0
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				calls++
				if calls == 2 {
					cancel()
				}
				return schedulerSuccess(target)
			}
			path := schedulerHostFile(t, "first", "second", "queued")
			code := runCLI(ctx, []string{path, "--guest", "--concurrency=1"}, deps)
			const summary = "Progress: 33% (1/3 hosts completed) (interrupted)\n"
			if code != 1 || calls != 2 || !strings.HasSuffix(out.String(), summary) || strings.Count(out.String(), "Progress:") != 1 {
				t.Fatalf("interruption summary missing, duplicated, or miscounted: exit=%d scans=%d output=%q", code, calls, out.String())
			}
			rows := strings.Split(strings.TrimSuffix(out.String(), summary), "\n")
			if len(rows) != 4 || !strings.Contains(rows[1], "first") || !strings.Contains(rows[2], "second") || rows[3] != "" {
				t.Fatalf("summary did not follow every result row: %q", out.String())
			}
			if strings.ContainsAny(out.String(), "\r\x1b") || strings.Contains(out.String(), "ETA:") || strings.Contains(diagnostics.String(), "(interrupted)") {
				t.Fatalf("saved progress controls or duplicate terminal summary: stdout=%q stderr=%q", out.String(), diagnostics.String())
			}
			if strings.Contains(diagnostics.String(), "gosmb: canceled") != (mode != "terminal") {
				t.Fatalf("cancellation diagnostic did not follow progress availability: %q", diagnostics.String())
			}
		})
	}
}

func TestCLIInterruptionSummaryPreservesOtherOutputModes(t *testing.T) {
	for _, mode := range []string{"normal completion", "tsv", "json", "no-progress", "direct terminal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.stdoutIsTerminal = mode == "direct terminal"
			deps.stderrIsTerminal = true
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				if mode != "normal completion" {
					cancel()
				}
				return Result{Target: target.String(), Authentication: "guest", Enumeration: "ok", Shares: []ShareResult{}}
			}
			args := []string{"host", "--guest"}
			if mode == "tsv" || mode == "json" || mode == "no-progress" {
				args = append(args, "--"+mode)
			}
			code := runCLI(ctx, args, deps)
			wantCode := 1
			if mode == "normal completion" {
				wantCode = 0
			}
			if code != wantCode || strings.Contains(out.String(), "Progress:") || strings.Contains(out.String(), "(interrupted)") {
				t.Fatalf("changed output format or exit status: exit=%d output=%q", code, out.String())
			}
			if strings.Contains(diagnostics.String(), "gosmb: canceled") != (mode == "no-progress") {
				t.Fatalf("cancellation diagnostic was duplicated or missing without progress: %q", diagnostics.String())
			}
			if mode == "json" {
				var results []Result
				if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 {
					t.Fatalf("interruption broke JSON: %q, %v", out.String(), err)
				}
			}
		})
	}
}

func TestCLIInterruptionSummaryWriteFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, diagnostics bytes.Buffer
	attempts := 0
	deps := testCLIDeps(outputWriteFunc(func(data []byte) (int, error) {
		if bytes.HasPrefix(data, []byte("Progress:")) {
			attempts++
			return 3, nil // A short write must not be retried or report success.
		}
		return out.Write(data)
	}), &diagnostics)
	deps.stdoutIsTerminal = false
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		cancel()
		return schedulerSuccess(target)
	}
	if code := runCLI(ctx, []string{"host", "--guest"}, deps); code != 1 || attempts != 1 || !strings.Contains(out.String(), "host") {
		t.Fatalf("summary failure retried, lost rows, or returned success: exit=%d attempts=%d output=%q", code, attempts, out.String())
	}
}
