package main

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestCLIHelpAlwaysShowsFullUsageWithoutSideEffects(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--help"},
		{"-h"},
		{"--help", "server", "-u", "alice", "-p", "secret", "--json"},
		{"server", "-u", "alice", "--help"},
		{"server", "--guest", "-u", "alice", "--json", "--tsv", "-h"},
		{"--timeout", "invalid", "server", "--help"},
		{"--unknown", "server", "-h"},
		{"--help", "--unknown"},
		{"--help=value", "-h"},
		{"server", "--concurrency", "-1", "--help"},
		{"-h", "--password"},
		{"::/0", "--help"},
		{"server", "-u", "alice", "-p", "--", "--help"},
	} {
		var out, errOut bytes.Buffer
		deps := testCLIDeps(&out, &errOut)
		lookups, prompts, scans := 0, 0, 0
		deps.lookupEnv = func(string) (string, bool) {
			lookups++
			return "", false
		}
		deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
			prompts++
			return "", nil
		}
		deps.scan = func(context.Context, Target, Options) Result {
			scans++
			return Result{Authentication: "authenticated", Enumeration: "ok"}
		}
		code := runCLI(context.Background(), args, deps)
		if code != 0 || out.String() != usage || errOut.Len() != 0 {
			t.Errorf("args=%q: code=%d stdout=%q stderr=%q; want exact full usage and exit 0", args, code, out.String(), errOut.String())
		}
		if lookups != 0 || prompts != 0 || scans != 0 {
			t.Errorf("args=%q: help had side effects: lookups=%d prompts=%d scans=%d", args, lookups, prompts, scans)
		}
	}
}

func TestCLIHelpPrecedesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{nil, {"--help"}, {"0.0.0.0/0", "--guest", "--help"}} {
		var out, diagnostics bytes.Buffer
		deps := testCLIDeps(&out, &diagnostics)
		deps.lookupEnv = func(string) (string, bool) {
			t.Fatal("help accessed credentials")
			return "", false
		}
		deps.prompt = func(context.Context, io.Reader, io.Writer) (string, error) {
			t.Fatal("help prompted for a password")
			return "", nil
		}
		deps.scan = func(context.Context, Target, Options) Result {
			t.Fatal("help started a scan")
			return Result{}
		}
		if code := runCLI(ctx, args, deps); code != 0 || out.String() != usage || diagnostics.Len() != 0 {
			t.Fatalf("cancellation hid help: exit=%d stdout=%q stderr=%q", code, out.String(), diagnostics.String())
		}
	}
}

func TestHelpTokensRemainOptionValues(t *testing.T) {
	for _, tt := range []struct {
		args                   []string
		user, password, domain string
	}{
		{[]string{"host", "-u", "alice", "-p", "--help"}, "alice", "--help", ""},
		{[]string{"host", "-u", "alice", "-p=-h"}, "alice", "-h", ""},
		{[]string{"host", "--user", "--help", "-p", ""}, "--help", "", ""},
		{[]string{"host", "--user=-h", "--password=--help"}, "-h", "--help", ""},
		{[]string{"host", "-u", "alice", "-d", "-h", "-p", ""}, "alice", "", "-h"},
	} {
		cfg, err := parseCLI(context.Background(), tt.args)
		if err != nil || cfg.help || cfg.options.Username != tt.user || cfg.options.Password != tt.password || cfg.options.Domain != tt.domain {
			t.Errorf("args=%q: option value was interpreted as help or altered: config=%#v err=%v", tt.args, cfg, err)
		}
	}
}

func TestHelpValuesAndEndOfOptionsDoNotRequestHelp(t *testing.T) {
	for _, args := range [][]string{
		{"--help=value"},
		{"-h=false"},
		{"host", "--guest", "--timeout", "--help"},
		{"host", "--guest", "--concurrency", "-h"},
		{"host", "--guest", "--host-timeout", "--help"},
		{"host", "--guest", "--delay", "-h"},
		{"--", "--help"},
		{"host", "--guest", "--", "-h"},
	} {
		cfg, err := parseCLI(context.Background(), args)
		if err == nil || cfg.help {
			t.Errorf("args=%q: invalid input was accepted or interpreted as help: help=%v err=%v", args, cfg.help, err)
		}
	}
}

func TestCLIHelpRejectsShortOutput(t *testing.T) {
	var diagnostics bytes.Buffer
	deps := testCLIDeps(shortOutputWriter{}, &diagnostics)
	if code := runCLI(context.Background(), []string{"--help"}, deps); code != 1 {
		t.Fatalf("truncated help returned success: exit=%d", code)
	}
}
