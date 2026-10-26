package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// The first signal requests orderly cancellation. Restore normal signal
	// handling so another can terminate even if an output writer is blocked.
	context.AfterFunc(ctx, stop)
	code := runCLI(ctx, os.Args[1:], cliDependencies{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		stdoutIsTerminal: term.IsTerminal(int(os.Stdout.Fd())),
		stderrIsTerminal: term.IsTerminal(int(os.Stderr.Fd())),
		enableColor: func() (func(), bool) {
			return enableTerminalColor(os.Stdout.Fd())
		},
		enableProgress: func() (func(), bool) {
			return enableTerminalColor(os.Stderr.Fd())
		},
		lookupEnv: os.LookupEnv, prompt: promptPassword, scan: scanTarget,
	})
	stop()
	os.Exit(code)
}
