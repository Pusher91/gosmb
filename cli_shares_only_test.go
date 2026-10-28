package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLISharesOnlyPreservesDiscoveredSharesAndFullSummary(t *testing.T) {
	path := schedulerHostFile(t, "rejected", "empty", "denied", "ipc", "partial", "check")
	for _, format := range []string{"table", "tsv", "json"} {
		t.Run(format, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			deps := testCLIDeps(&out, &diagnostics)
			deps.stderrIsTerminal = true
			calls := 0
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				calls++
				r := Result{Target: target.String(), ServerIP: "192.0.2.1", Reachable: true, Authentication: "guest", Enumeration: "ok"}
				switch target.Host {
				case "rejected":
					r.Authentication, r.Enumeration = "failed", "not_attempted"
				case "denied":
					r.Shares = []ShareResult{{Name: "denied-share", Accessible: Denied, Read: Denied, Write: Denied}}
				case "ipc":
					r.Shares = []ShareResult{{Name: "IPC$", Type: "ipc", Read: NotApplicable, Write: NotApplicable}}
				case "partial":
					r.Enumeration, r.Error = "error", "partial enumeration"
					r.Shares = []ShareResult{{Name: "partial-share", Read: Allowed, Write: Denied}}
				case "check":
					r.Shares = []ShareResult{{Name: "check-share", Read: Unknown, Write: Unknown, Error: "metadata unavailable"}}
				}
				return r
			}
			args := []string{path, "--guest", "--shares-only", "--concurrency=1"}
			if format != "table" {
				args = append(args, "--"+format)
			}
			if code := runCLI(context.Background(), args, deps); code != 1 || calls != 6 {
				t.Fatalf("filter changed scan execution: code=%d scans=%d", code, calls)
			}
			if strings.Contains(out.String(), "rejected") || strings.Contains(out.String(), "empty") {
				t.Fatalf("host without shares survived filter: %q", out.String())
			}
			if format == "json" {
				var results []Result
				if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 4 {
					t.Fatalf("filtered JSON: %q, %v", out.String(), err)
				}
				for i, host := range []string{"denied", "ipc", "partial", "check"} {
					if results[i].Target != host+":445" || len(results[i].Shares) != 1 || results[i].GuestFallback {
						t.Fatalf("unexpected filtered result: %+v", results[i])
					}
				}
				if results[2].Error != "partial enumeration" || results[3].Shares[0].Error != "metadata unavailable" {
					t.Fatalf("filter lost JSON error details: %+v", results)
				}
			} else {
				var rows [][]string
				if format == "tsv" {
					rows = parseTestTSV(t, out.String())
				} else {
					for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
						rows = append(rows, strings.Fields(line))
					}
				}
				if len(rows) != 5 {
					t.Fatalf("filtered rows=%d, want header and four shares: %q", len(rows), out.String())
				}
				for i, want := range []struct{ share, read, write, status, host string }{
					{"denied-share", "FALSE", "FALSE", "OK", "denied"},
					{"IPC$", "N/A", "N/A", "OK", "ipc"},
					{"partial-share", "TRUE", "FALSE", "ENUM_PARTIAL", "partial"},
					{"check-share", "UNKNOWN", "UNKNOWN", "CHECK_FAILED", "check"},
				} {
					row := rows[i+1]
					if len(row) != 7 || row[1] != want.share || row[2] != want.read || row[3] != want.write || row[4] != "N/A" || row[5] != want.status || row[6] != want.host {
						t.Fatalf("share row lost data: %q", row)
					}
				}
			}
			for _, want := range []string{
				"Progress: 100% (6/6 hosts completed)",
				"Summary: 6/6 hosts completed; 0 interrupted; 0 not started",
				"Host outcomes: OK=2 NO_SHARES=1 AUTH_FAILED=1 ENUM_PARTIAL=1 CHECK_FAILED=1\n",
				"Shares: 4 found; 1 readable; 0 writable (metadata)\n",
			} {
				if !strings.Contains(diagnostics.String(), want) {
					t.Fatalf("filter changed progress or summary; missing %q in %q", want, diagnostics.String())
				}
			}
		})
	}
}

func TestCLISharesOnlyWithNoFindings(t *testing.T) {
	for _, format := range []string{"table", "tsv", "json"} {
		for _, failed := range []bool{false, true} {
			t.Run(format+map[bool]string{false: "/empty", true: "/failed"}[failed], func(t *testing.T) {
				var out, diagnostics bytes.Buffer
				deps := testCLIDeps(&out, &diagnostics)
				deps.stderrIsTerminal = true
				deps.scan = func(_ context.Context, target Target, _ Options) Result {
					r := Result{Target: target.String(), Authentication: "guest", Enumeration: "ok"}
					if failed {
						r.Authentication, r.Enumeration = "failed", "not_attempted"
					}
					return r
				}
				args := []string{"host", "--guest", "--shares-only", "--no-header", "--no-progress"}
				if format != "table" {
					args = append(args, "--"+format)
				}
				wantCode := 0
				if failed {
					wantCode = 1
				}
				if code := runCLI(context.Background(), args, deps); code != wantCode {
					t.Fatalf("hidden host changed exit code: got %d, want %d", code, wantCode)
				}
				wantOutput := ""
				if format == "json" {
					wantOutput = "[]\n"
				}
				if out.String() != wantOutput || diagnostics.Len() != 0 {
					t.Fatalf("unexpected empty filtered output: stdout=%q stderr=%q", out.String(), diagnostics.String())
				}
			})
		}
	}
}

func TestCLISharesOnlyKeepsInterruptedPartialShares(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, diagnostics bytes.Buffer
	deps := testCLIDeps(&out, &diagnostics)
	deps.stderrIsTerminal = true
	calls := 0
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		calls++
		r := Result{Target: target.String(), Authentication: "guest", Enumeration: "ok"}
		if target.Host == "second" {
			r.Shares = []ShareResult{{Name: "discovered-share", Read: Allowed, Write: Unknown}}
			cancel()
		}
		return r
	}
	path := schedulerHostFile(t, "first", "second", "queued")
	if code := runCLI(ctx, []string{path, "--guest", "--shares-only", "--concurrency=1"}, deps); code != 1 || calls != 2 {
		t.Fatalf("interruption changed scheduling: code=%d scans=%d", code, calls)
	}
	if !strings.Contains(out.String(), "discovered-share") || strings.Contains(out.String(), "first") || strings.Contains(out.String(), "queued") ||
		!strings.HasSuffix(out.String(), "Progress: 33% (1/3 hosts completed) (interrupted)\n") || strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("interrupted filter lost shares or progress: %q", out.String())
	}
	for _, want := range []string{
		"Summary: 1/3 hosts completed; 1 interrupted; 1 not started",
		"Host outcomes: NO_SHARES=1 CANCELED=1\n",
		"Shares: 1 found; 1 readable; 0 writable (metadata)\n",
	} {
		if !strings.Contains(diagnostics.String(), want) {
			t.Fatalf("filter changed interrupted totals; missing %q in %q", want, diagnostics.String())
		}
	}
}

func TestParseCLISharesOnly(t *testing.T) {
	for _, args := range [][]string{
		{"--shares-only", "host", "--guest"},
		{"host", "--guest", "--shares-only"},
	} {
		cfg, err := parseCLI(context.Background(), args)
		if err != nil || !cfg.sharesOnly {
			t.Fatalf("shares-only option %q: enabled=%t err=%v", args, cfg.sharesOnly, err)
		}
	}
	if _, err := parseCLI(context.Background(), []string{"host", "--guest", "--shares-only=true"}); err == nil {
		t.Fatal("boolean shares-only flag accepted a value")
	}
}
