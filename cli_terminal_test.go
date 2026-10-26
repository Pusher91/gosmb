package main

import (
	"bytes"
	"context"
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
		{name: "redirected stdout", prepare: true, progress: true},
		{name: "forced TSV", stdoutTTY: true, flag: "--tsv", prepare: true, progress: true},
		{name: "JSON", stdoutTTY: true, flag: "--json", prepare: true, progress: true},
		{name: "NO_COLOR", stdoutTTY: true, noColor: "1", prepare: true, progress: true},
		{name: "shared console", stdoutTTY: true, color: true, prepare: true, progress: true},
		{name: "unsupported stderr", unsupported: true, prepare: true},
		{name: "dumb terminal", stdoutTTY: true, term: "dumb"},
		{name: "no progress", stdoutTTY: true, flag: "--no-progress", color: true},
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
					if tc.progress && !strings.HasSuffix(diagnostics.String(), "Progress: 100% (1/1 hosts completed)\n") {
						t.Error("terminal mode restored before the final progress footer")
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
