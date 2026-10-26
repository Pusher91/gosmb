package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRepeatedSignalsTerminateBlockedOutput(t *testing.T) {
	// Reserve a port without listening: every loopback connection is refused,
	// and another process cannot acquire the port while the child scans it.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		t.Fatal(err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("127.0.0.0/24:%d", address.(*unix.SockaddrInet4).Port)
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			if _, err := unix.FcntlInt(writer.Fd(), unix.F_SETPIPE_SZ, 4096); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPasswordPromptProcess$", "--", target,
				"--guest", "--json", "--delay=0", "--concurrency=32", "--no-progress")
			cmd.Env = append(os.Environ(), "GOSMB_TEST_PROMPT_PROCESS=1")
			cmd.Stdout, cmd.Stderr = writer, io.Discard
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			finished := false
			t.Cleanup(func() {
				if !finished {
					_ = cmd.Process.Kill()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("could not reap blocked output process")
					}
				}
			})
			if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var first [1]byte
			if _, err := io.ReadFull(reader, first[:]); err != nil || first[0] != '[' {
				t.Fatalf("child did not reach final JSON output: byte=%q error=%v", first, err)
			}
			// Leave the pipe full. The first signal requests orderly cancellation;
			// later signals must work even though its output cannot finish.
			if err := cmd.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			signals := 1
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			for {
				select {
				case err := <-done:
					finished = true
					status := cmd.ProcessState.Sys().(syscall.WaitStatus)
					if signals < 2 || !status.Signaled() || status.Signal() != signal {
						t.Fatalf("unexpected exit after %d signals: status=%v error=%v", signals, status, err)
					}
					return
				case <-ticker.C:
					if err := cmd.Process.Signal(signal); err != nil && !errors.Is(err, os.ErrProcessDone) {
						t.Fatal(err)
					}
					signals++
				case <-deadline.C:
					t.Fatal("repeated signals did not terminate blocked output")
				}
			}
		})
	}
}
