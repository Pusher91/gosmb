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
	code := runCLI(ctx, os.Args[1:], cliDependencies{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		stdoutIsTerminal: term.IsTerminal(int(os.Stdout.Fd())),
		stderrIsTerminal: term.IsTerminal(int(os.Stderr.Fd())),
		lookupEnv:        os.LookupEnv, prompt: promptPassword, scan: scanTarget,
	})
	stop()
	os.Exit(code)
}
