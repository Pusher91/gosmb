package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestInteractiveStatusReplacesDuplicateScanDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result Result
		status string
		code   int
	}{
		{"host failure", Result{Reachable: true, Authentication: "failed", Enumeration: "not_attempted", Error: "username or password was rejected"}, "AUTH_FAILED", 1},
		{"share failure", Result{Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{
			{Name: "data", Accessible: Allowed, Read: Allowed, Write: Unknown, Error: "root maximum-access metadata unavailable"},
		}}, "CHECK_FAILED", 0},
		{"no shares", Result{Reachable: true, Authentication: "authenticated", Enumeration: "ok"}, "NO_SHARES", 0},
	} {
		for _, progress := range []bool{false, true} {
			name := tc.name + "/no-progress"
			if progress {
				name = tc.name + "/progress"
			}
			t.Run(name, func(t *testing.T) {
				var out, diagnostics bytes.Buffer
				deps := testCLIDeps(&out, &diagnostics)
				deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
				deps.scan = func(_ context.Context, target Target, _ Options) Result {
					result := tc.result
					result.Target, result.ServerIP = target.String(), "192.0.2.1"
					return result
				}
				args := []string{"fileserver", "-u", "alice", "-p", "", "--no-header"}
				if !progress {
					args = append(args, "--no-progress")
				}
				if code := runCLI(context.Background(), args, deps); code != tc.code {
					t.Errorf("exit code = %d; want %d", code, tc.code)
				}
				fields := strings.Fields(out.String())
				if strings.Count(out.String(), "\n") != 1 || len(fields) != 7 || fields[5] != tc.status || fields[6] != "fileserver" {
					t.Fatalf("interactive result lost its status or table shape: %q", out.String())
				}
				if strings.Contains(out.String(), "Progress:") || strings.Contains(diagnostics.String(), "gosmb:") ||
					strings.Contains(diagnostics.String(), "metadata") || strings.Contains(diagnostics.String(), "password") ||
					strings.Contains(diagnostics.String(), "no shares returned") {
					t.Errorf("scan diagnostic duplicated the table or progress leaked into it: stdout=%q stderr=%q", out.String(), diagnostics.String())
				}
				if progress {
					if !strings.Contains(diagnostics.String(), "Progress: 0% (0/1 hosts completed)") ||
						!strings.HasSuffix(diagnostics.String(), "Progress: 100% (1/1 hosts completed)\n") {
						t.Errorf("completed scan lost progress: %q", diagnostics.String())
					}
				} else if diagnostics.Len() != 0 {
					t.Errorf("interactive scan produced duplicate diagnostics: %q", diagnostics.String())
				}
			})
		}
	}
}
