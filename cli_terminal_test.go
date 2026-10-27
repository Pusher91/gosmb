package main

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestCLIProgressPreparesStderrIndependentlyOfColor(t *testing.T) {
	for _, tc := range []struct {
		name, flag, noColor, term string
		stdoutTTY, unsupported    bool
		color, prepare, progress  bool
	}{
		{name: "redirected stdout", progress: true},
		{name: "piped unsupported VT", unsupported: true, progress: true},
		{name: "forced TSV", stdoutTTY: true, flag: "--tsv", prepare: true, progress: true},
		{name: "JSON", stdoutTTY: true, flag: "--json", prepare: true, progress: true},
		{name: "NO_COLOR", stdoutTTY: true, noColor: "1", prepare: true, progress: true},
		{name: "shared console", stdoutTTY: true, color: true, prepare: true, progress: true},
		{name: "unsupported stderr", stdoutTTY: true, noColor: "1", unsupported: true, prepare: true},
		{name: "dumb terminal", stdoutTTY: true, term: "dumb"},
		{name: "piped dumb terminal", term: "dumb"},
		{name: "no progress", stdoutTTY: true, flag: "--no-progress", color: true},
		{name: "piped no progress", flag: "--no-progress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			var events []string
			// Model stdout and stderr sharing a Windows screen buffer. Every
			// ANSI write must happen after preparation and before restoration.
			virtualTerminal := false
			writer := func(buffer *bytes.Buffer) outputWriteFunc {
				return func(data []byte) (int, error) {
					if bytes.ContainsRune(data, '\x1b') && !virtualTerminal {
						t.Errorf("ANSI output reached an unprepared terminal: %q", data)
					}
					return buffer.Write(data)
				}
			}
			deps := testCLIDeps(writer(&out), writer(&diagnostics))
			deps.stdoutIsTerminal, deps.stderrIsTerminal = tc.stdoutTTY, true
			deps.lookupEnv = func(key string) (string, bool) {
				switch key {
				case "NO_COLOR":
					return tc.noColor, tc.noColor != ""
				case "TERM":
					return tc.term, tc.term != ""
				default:
					t.Fatalf("unexpected environment lookup: %s", key)
					return "", false
				}
			}
			prepare := func(name string, supported bool) (func(), bool) {
				events = append(events, "prepare "+name)
				original := virtualTerminal
				if supported {
					virtualTerminal = true
				}
				return func() {
					events = append(events, "restore "+name)
					if tc.progress && (!strings.Contains(diagnostics.String(), "Progress: 100% (1/1 hosts completed)") ||
						tc.stdoutTTY && !strings.HasSuffix(diagnostics.String(), "\n")) {
						t.Error("terminal mode restored before final progress")
					}
					virtualTerminal = original
				}, supported
			}
			deps.enableColor = func() (func(), bool) { return prepare("stdout", true) }
			deps.enableProgress = func() (func(), bool) { return prepare("stderr", !tc.unsupported) }
			deps.scan = func(_ context.Context, target Target, _ Options) Result {
				return Result{Target: target.String(), Reachable: true, Authentication: "authenticated", Enumeration: "ok",
					Shares: []ShareResult{{Name: "data", Accessible: Allowed, Read: Allowed, Write: Denied}}}
			}
			args := []string{"host", "-u", "alice", "-p", ""}
			if tc.flag != "" {
				args = append(args, tc.flag)
			}
			if code := runCLI(context.Background(), args, deps); code != 0 {
				t.Fatalf("scan failed: code=%d stderr=%q", code, diagnostics.String())
			}
			if strings.Contains(out.String(), "\x1b[32mTRUE\x1b[0m") != tc.color {
				t.Errorf("unexpected stdout color policy: %q", out.String())
			}
			if strings.Contains(diagnostics.String(), "Progress:") != tc.progress {
				t.Errorf("unexpected stderr progress policy: %q", diagnostics.String())
			}
			if !tc.stdoutTTY && strings.ContainsAny(diagnostics.String(), "\r\x1b") {
				t.Errorf("piped progress used terminal controls: %q", diagnostics.String())
			}
			var wantEvents []string
			if tc.color {
				wantEvents = append(wantEvents, "prepare stdout")
			}
			if tc.prepare {
				wantEvents = append(wantEvents, "prepare stderr", "restore stderr")
			}
			if tc.color {
				wantEvents = append(wantEvents, "restore stdout")
			}
			if !reflect.DeepEqual(events, wantEvents) || virtualTerminal {
				t.Errorf("terminal lifecycle = %v, mode=%t; want %v and restored mode", events, virtualTerminal, wantEvents)
			}
		})
	}
}

func TestCLIPipedTableMatchesTerminalAndTeeSavesCleanStatuses(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		result       Result
	}{
		{"connection refused", "CONNECT_REFUSED", Result{Authentication: "not_attempted", Enumeration: "not_attempted", Error: "connection failed: refused", status: statusConnectRefused}},
		{"connection timeout", "CONNECT_TIMEOUT", Result{Authentication: TimedOut, Enumeration: TimedOut, TimedOut: true, Error: "connection timed out"}},
		{"authentication failed", "AUTH_FAILED", Result{Reachable: true, Authentication: "failed", Enumeration: "not_attempted", Error: "guest authentication failed"}},
		{"authentication timeout", "SMB_TIMEOUT", Result{Reachable: true, Authentication: TimedOut, Enumeration: TimedOut, TimedOut: true, Error: "authentication timed out"}},
		{"enumeration timeout", "ENUM_TIMEOUT", Result{Reachable: true, Authentication: "guest", Enumeration: TimedOut, TimedOut: true, Error: "enumeration timed out"}},
		{"successful guest", "OK", Result{Reachable: true, Authentication: "guest", Enumeration: "ok", Shares: []ShareResult{{Name: "share-name-that-exceeds-the-column", Read: Allowed, Write: Denied}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var terminal, piped, saved, diagnostics bytes.Buffer
			for _, tty := range []bool{true, false} {
				diagnostics.Reset()
				var out io.Writer = &terminal
				if !tty {
					// tee copies the same pipe bytes to the terminal and saved file.
					out = io.MultiWriter(&piped, &saved)
				}
				deps := testCLIDeps(out, &diagnostics)
				deps.stdoutIsTerminal, deps.stderrIsTerminal = tty, true
				deps.lookupEnv = func(key string) (string, bool) {
					if key == "NO_COLOR" {
						return "1", true
					}
					return "", false
				}
				deps.enableColor = func() (func(), bool) {
					t.Fatal("plain table output attempted to enable color")
					return nil, false
				}
				deps.enableProgress = func() (func(), bool) {
					t.Fatal("plain piped or disabled progress prepared stderr")
					return nil, false
				}
				deps.scan = func(_ context.Context, target Target, _ Options) Result {
					result := tc.result
					result.Target = target.String()
					return result
				}
				args := []string{"fileserver", "--guest"}
				if tty {
					args = append(args, "--no-progress")
				}
				wantCode := 1
				if tc.status == "OK" {
					wantCode = 0
				}
				if code := runCLI(context.Background(), args, deps); code != wantCode {
					t.Errorf("stdout tty=%t: exit=%d; want %d", tty, code, wantCode)
				}
				if tty {
					if diagnostics.Len() != 0 {
						t.Errorf("explicitly disabled progress wrote stderr: %q", diagnostics.String())
					}
				} else if !strings.HasPrefix(diagnostics.String(), "Progress: 0% (0/1 hosts completed) | Max ETA:") ||
					!strings.Contains(diagnostics.String(), "\nProgress: 100% (1/1 hosts completed)\nSummary:") ||
					strings.Count(diagnostics.String(), "\n") != 5 ||
					strings.ContainsAny(diagnostics.String(), "\r\x1b") || strings.Contains(diagnostics.String(), "gosmb:") {
					t.Errorf("piped scan lost plain initial/final progress or duplicated diagnostics: %q", diagnostics.String())
				}
			}
			if terminal.String() != piped.String() || piped.String() != saved.String() {
				t.Fatalf("tee changed the default table: terminal=%q piped=%q saved=%q", terminal.String(), piped.String(), saved.String())
			}
			if strings.ContainsAny(saved.String(), "\t\r\x1b") || strings.Contains(saved.String(), "Progress:") {
				t.Fatalf("saved table contains tabs, progress, or ANSI controls: %q", saved.String())
			}
			lines := strings.Split(strings.TrimSuffix(saved.String(), "\n"), "\n")
			if len(lines) != 2 {
				t.Fatalf("saved table lost its header or row: %q", saved.String())
			}
			if fields := strings.Fields(lines[0]); !reflect.DeepEqual(fields, []string{"TARGET_IP", "SHARE", "READ", "WRITE", "GUEST", "STATUS", "HOSTNAME"}) {
				t.Errorf("saved table header = %q", lines[0])
			}
			if fields := strings.Fields(lines[1]); len(fields) != 7 || fields[4] != "N/A" || fields[5] != tc.status || fields[6] != "fileserver" {
				t.Errorf("saved row lost explicit guest semantics or failure status: %q", lines[1])
			}
		})
	}
}
