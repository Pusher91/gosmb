package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPipedProgressWithRealTeePreservesRows(t *testing.T) {
	teePath, err := exec.LookPath("tee")
	if err != nil {
		t.Skip("external tee is unavailable")
	}
	shellPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	for _, interrupted := range []bool{false, true} {
		name := "completed"
		if interrupted {
			name = "SIGINT"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false, "map_guest")
			// A bound, non-listening wildcard socket reserves the same refused
			// port across several loopback addresses without contacting a LAN.
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
				t.Fatal(err)
			}
			address, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			port := address.(*unix.SockaddrInet4).Port
			targets := []string{fixture.target.String()}
			for host := 2; host <= 8; host++ {
				targets = append(targets, fmt.Sprintf("127.0.0.%d:%d", host, port))
			}
			targetFile := filepath.Join(t.TempDir(), "targets")
			if err := os.WriteFile(targetFile, []byte(strings.Join(targets, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}

			p := newPromptTerminal(t)
			savedPath := filepath.Join(t.TempDir(), "saved-table.txt")
			// The shell and both pipeline children share the foreground group,
			// so terminal-generated Ctrl-C reaches tee as well as the scanner.
			p.cmd = exec.Command(shellPath, "--noprofile", "--norc", "-o", "pipefail", "-c",
				`"$1" -test.run=^TestPasswordPromptProcess$ -- "$2" --guest --delay=150ms --timeout=1s | "$3" "$4"`,
				"gosmb-tee-test", os.Args[0], targetFile, teePath, savedPath)
			// Kill the entire pipeline on failure, including orphaned children
			// if the shell has already exited, and bound the wait for a full PTY.
			// Mark p finished so the shared helper never waits a second time.
			t.Cleanup(func() {
				if p.cmd.Process != nil && (!p.finished || t.Failed()) {
					_ = unix.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
					if !p.finished {
						select {
						case <-p.done:
						case <-time.After(3 * time.Second):
							t.Error("could not reap pipeline subprocess")
						}
						p.finished = true
					}
				}
			})
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "GOSMB_TEST_PROMPT_PROCESS=") && !strings.HasPrefix(value, "GOSMB_PASSWORD=") &&
					!strings.HasPrefix(value, "TERM=") && !strings.HasPrefix(value, "NO_COLOR=") &&
					!strings.HasPrefix(value, "BASH_ENV=") && !strings.HasPrefix(value, "ENV=") {
					p.cmd.Env = append(p.cmd.Env, value)
				}
			}
			p.cmd.Env = append(p.cmd.Env, "GOSMB_TEST_PROMPT_PROCESS=1", "TERM=xterm")
			p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = p.slave, p.slave, p.slave
			p.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := p.cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go func() { p.done <- p.cmd.Wait() }()

			deadline := time.Now().Add(8 * time.Second)
			for {
				p.readTerminal(t, 20)
				terminal := p.terminal.String()
				if strings.Contains(terminal, "Progress: 0% (0/8 hosts completed)") && strings.Contains(terminal, "CONNECT_REFUSED") {
					if !strings.Contains(terminal, "Max ETA:") {
						t.Fatal("live piped progress lost its configured scan budget")
					}
					if strings.Contains(terminal, "Progress: 100%") {
						t.Fatal("progress was only observable after the scan finished")
					}
					break
				}
				select {
				case err := <-p.done:
					p.finished = true
					t.Fatalf("pipeline exited without live piped progress: %v; terminal=%q", err, terminal)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatalf("live progress or tee rows did not arrive: %q", terminal)
				}
			}
			var savedPrefix string
			if interrupted {
				// tee may forward a buffer to the terminal before saving it.
				// Interrupt only after the header and fixture rows are on disk.
				for {
					saved, err := os.ReadFile(savedPath)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Count(string(saved), "\n") >= 4 {
						savedPrefix = string(saved[:strings.LastIndexByte(string(saved), '\n')+1])
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("tee did not save completed rows before interruption")
					}
					p.readTerminal(t, 20)
				}
				if group, err := unix.IoctlGetInt(p.master, unix.TIOCGPGRP); err != nil || group != p.cmd.Process.Pid {
					t.Fatalf("pipeline is not the terminal's foreground group: group=%d err=%v", group, err)
				}
				p.write(t, "\x03")
			}
			for !p.finished {
				p.readTerminal(t, 20)
				select {
				case <-p.done:
					p.finished = true
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("pipeline did not exit promptly")
				}
			}
			p.readTerminal(t, 0)
			if code := p.cmd.ProcessState.ExitCode(); (!interrupted && code != 1) || (interrupted && code == 0) {
				t.Errorf("pipeline exit code=%d; want 1 for refused hosts or nonzero for interruption", code)
			}
			terminal := p.terminal.String()
			if strings.ContainsRune(terminal, '\x1b') {
				t.Errorf("plain tee progress used ANSI terminal controls: %q", terminal)
			}
			if interrupted {
				if strings.Contains(terminal, "Progress: 100%") {
					t.Errorf("interrupted pipeline reported completion: %q", terminal)
				}
			} else if strings.Count(terminal, "Progress: 100% (8/8 hosts completed)") != 1 {
				t.Errorf("completed scan lost final progress: %q", terminal)
			}
			if !interrupted && strings.Count(terminal, "Progress:") != 2 {
				t.Errorf("piped scan printed more than initial and final progress: %q", terminal)
			}
			after, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
			if err != nil || !reflect.DeepEqual(after, p.before) {
				t.Errorf("progress changed terminal modes: %v", err)
			}

			saved, err := os.ReadFile(savedPath)
			if err != nil {
				t.Fatal(err)
			}
			if interrupted && !strings.HasPrefix(string(saved), savedPrefix) {
				t.Fatalf("interruption changed already-saved rows: before=%q after=%q", savedPrefix, saved)
			}
			if strings.ContainsAny(string(saved), "\t\r\x1b") ||
				strings.Contains(string(saved), "ETA:") || strings.Contains(string(saved), "gosmb:") {
				t.Fatalf("tee saved progress controls or diagnostics instead of a clean table: %q", saved)
			}
			lastNewline := strings.LastIndexByte(string(saved), '\n')
			if lastNewline < 0 || (!interrupted && lastNewline != len(saved)-1) {
				t.Fatalf("tee lost complete output lines: %q", saved)
			}
			// Ordinary tee can exit on Ctrl-C before saving an interruption
			// summary or the tail of its current write. Check completed lines.
			lines := strings.Split(string(saved[:lastNewline]), "\n")
			if interrupted && strings.HasPrefix(lines[len(lines)-1], "Progress:") {
				summary := lines[len(lines)-1]
				var percent, completed int
				_, err := fmt.Sscanf(summary, "Progress: %d%% (%d/8 hosts completed) (interrupted)", &percent, &completed)
				if err != nil || completed < 2 || completed >= 8 || percent != completed*100/8 ||
					summary != fmt.Sprintf("Progress: %d%% (%d/8 hosts completed) (interrupted)", percent, completed) ||
					strings.Count(string(saved), "Progress:") != 1 {
					t.Fatalf("saved interruption summary is malformed or duplicated: %q", saved)
				}
				lines = lines[:len(lines)-1]
			} else if !interrupted && strings.Contains(string(saved), "Progress:") {
				t.Fatalf("tee saved normal completion progress: %q", saved)
			}
			if len(lines) < 4 || (!interrupted && len(lines) != 11) || (interrupted && len(lines) >= 11) {
				t.Fatalf("tee lost completed rows or continued after SIGINT: %q", saved)
			}
			if fields := strings.Fields(lines[0]); !reflect.DeepEqual(fields, []string{"TARGET_IP", "SHARE", "READ", "WRITE", "GUEST", "STATUS", "HOSTNAME"}) {
				t.Errorf("saved header lost STATUS: %q", lines[0])
			}
			for _, line := range lines[1:] {
				fields := strings.Fields(line)
				if len(fields) != 7 || fields[4] != "N/A" || (fields[5] != "OK" && fields[5] != "CONNECT_REFUSED") || fields[6] != "-" {
					t.Errorf("saved row lost guest semantics or scan status: %q", line)
				}
			}
			fixture.assertUnchanged(t, 1)
		})
	}
}
