package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run the real entry point in a child with its own controlling terminal, so
// terminal-generated Ctrl-C and main's signal handler are both exercised.
func TestPasswordPromptProcess(t *testing.T) {
	if os.Getenv("GOSMB_TEST_PROMPT_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"gosmb"}, os.Args[i+1:]...)
			main()
		}
	}
	t.Fatal("missing child CLI arguments")
}

type promptProcess struct {
	master   int
	slave    *os.File
	before   *unix.Termios
	cmd      *exec.Cmd
	done     chan error
	finished bool
	stdout   bytes.Buffer
	terminal strings.Builder
}

func startPromptProcess(t *testing.T, target, username string) *promptProcess {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := &promptProcess{master: master, done: make(chan error, 1)}
	t.Cleanup(func() {
		if p.cmd != nil && p.cmd.Process != nil && !p.finished {
			_ = p.cmd.Process.Kill()
			<-p.done
		}
		if p.slave != nil {
			_ = p.slave.Close()
		}
		_ = unix.Close(p.master)
	})
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	p.slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	p.before, err = unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if p.before.Lflag&unix.ECHO == 0 {
		t.Fatal("test terminal must initially echo input")
	}
	p.cmd = exec.Command(os.Args[0], "-test.run=^TestPasswordPromptProcess$", "--", target,
		"-u", username, "--no-progress", "--timeout=1s")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOSMB_PASSWORD=") && !strings.HasPrefix(value, "GOSMB_TEST_PROMPT_PROCESS=") {
			p.cmd.Env = append(p.cmd.Env, value)
		}
	}
	p.cmd.Env = append(p.cmd.Env, "GOSMB_TEST_PROMPT_PROCESS=1")
	p.cmd.Stdin, p.cmd.Stderr, p.cmd.Stdout = p.slave, p.slave, &p.stdout
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.readTerminal(t, 20)
		state, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(p.terminal.String(), "Password:") && state.Lflag&unix.ECHO == 0 {
			return p
		}
		select {
		case err := <-p.done:
			p.finished = true
			t.Fatalf("process exited before password prompt: %v; terminal=%q", err, p.terminal.String())
		default:
		}
	}
	t.Fatal("password prompt did not become ready")
	return nil
}

func (p *promptProcess) readTerminal(t *testing.T, timeoutMS int) {
	t.Helper()
	for {
		fds := []unix.PollFd{{Fd: int32(p.master), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, timeoutMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 || fds[0].Revents&unix.POLLIN == 0 {
			return
		}
		var buf [1024]byte
		n, err = unix.Read(p.master, buf[:])
		if err != nil {
			t.Fatal(err)
		}
		p.terminal.Write(buf[:n])
		timeoutMS = 0
	}
}

func (p *promptProcess) write(t *testing.T, value string) {
	t.Helper()
	n, err := unix.Write(p.master, []byte(value))
	if err != nil || n != len(value) {
		t.Fatalf("write terminal input: n=%d, err=%v", n, err)
	}
}

func (p *promptProcess) wait(t *testing.T, wantCode int, secret string) {
	t.Helper()
	select {
	case <-p.done:
		p.finished = true
	case <-time.After(3 * time.Second):
		t.Fatal("process did not exit promptly without further terminal input")
	}
	p.readTerminal(t, 0)
	if code := p.cmd.ProcessState.ExitCode(); code != wantCode {
		t.Fatalf("exit code=%d, want %d; stdout=%q terminal=%q", code, wantCode, p.stdout.String(), p.terminal.String())
	}
	after, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, p.before) {
		t.Fatalf("terminal settings were not restored: before=%+v after=%+v", p.before, after)
	}
	if strings.Contains(p.stdout.String()+p.terminal.String(), secret) {
		t.Fatal("password appeared in output")
	}
}

func TestPasswordPromptSignalsCancelAndRestoreTerminal(t *testing.T) {
	for _, name := range []string{"ctrl_c", "sigint", "sigterm"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			p := startPromptProcess(t, listener.Addr().String(), "prompt-test-user")
			const secret = "partially-typed-test-password"
			p.write(t, secret)
			if name == "ctrl_c" {
				p.write(t, "\x03")
			} else {
				signal := syscall.SIGINT
				if name == "sigterm" {
					signal = syscall.SIGTERM
				}
				if err := p.cmd.Process.Signal(signal); err != nil {
					t.Fatal(err)
				}
			}
			p.wait(t, 1, secret)
			if !strings.Contains(p.terminal.String(), "canceled") || p.stdout.Len() != 0 {
				t.Fatalf("unexpected cancellation output: stdout=%q terminal=%q", p.stdout.String(), p.terminal.String())
			}
			// A partially typed password must not become the shell's next input
			// line after cancellation restores canonical mode and echo.
			p.write(t, "\n")
			fds := []unix.PollFd{{Fd: int32(p.slave.Fd()), Events: unix.POLLIN}}
			if n, err := unix.Poll(fds, 1000); err != nil || n != 1 {
				t.Fatalf("checking for leftover password input: n=%d err=%v", n, err)
			}
			var remaining [256]byte
			if n, err := unix.Read(int(p.slave.Fd()), remaining[:]); err != nil || string(remaining[:n]) != "\n" {
				t.Fatal("password input remained queued after cancellation")
			}
			_ = listener.SetDeadline(time.Now().Add(50 * time.Millisecond))
			conn, err := listener.Accept()
			if err == nil {
				conn.Close()
				t.Fatal("canceled password prompt initiated a network connection")
			}
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("checking for unexpected connection: %v", err)
			}
		})
	}
}

func TestPasswordPromptEnterAuthenticatesAndRestoresTerminal(t *testing.T) {
	fixture := newEnumerationFixture(t, 0x001f01ff, 0x001f01ff, "success", false)
	p := startPromptProcess(t, fixture.target.String(), fixture.options.Domain+`\`+fixture.options.Username)
	p.write(t, fixture.options.Password+"\n")
	p.wait(t, 0, fixture.options.Password)
	if !strings.Contains(p.stdout.String(), "data$") {
		t.Fatalf("normal password entry did not complete share scan: %q", p.stdout.String())
	}
	fixture.assertUnchanged(t, 1)
}
