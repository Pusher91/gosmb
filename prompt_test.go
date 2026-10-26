package main

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReadPromptLinePreservesPasswordBytes(t *testing.T) {
	carriageReturnPassword := "secret\r"
	if runtime.GOOS == "windows" {
		carriageReturnPassword = "secret"
	}
	for _, tc := range []struct {
		name, input, want string
		wantErr           error
	}{
		{"literal whitespace and unicode", "  p\täss word  \n", "  p\täss word  ", nil},
		{"empty", "\n", "", nil},
		{"platform carriage return", "secret\r\n", carriageReturnPassword, nil},
		{"literal backspace", "pä\bss\n", "pä\bss", nil},
		{"empty EOF", "", "", io.EOF},
		{"partial EOF", "secret", "secret", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPromptLine(context.Background(), strings.NewReader(tc.input))
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("password bytes were altered or wrong error: %v", err)
			}
		})
	}
}

type promptReadFailure struct {
	data string
	err  error
}

func (r *promptReadFailure) Read(p []byte) (int, error) {
	if r.err == nil {
		return 0, io.EOF
	}
	err := r.err
	r.err = nil
	return copy(p, r.data), err
}

func TestReadPromptLineDoesNotIgnoreErrorWithData(t *testing.T) {
	readErr := errors.New("terminal read failed")
	for _, tc := range []struct {
		name, prefix, last, want string
		readErr, wantErr         error
	}{
		{"data with error", "", "x", "", readErr, readErr},
		{"newline with error", "secret", "\n", "", readErr, readErr},
		{"carriage return with error", "secret", "\r", "", readErr, readErr},
		{"newline with cancellation", "secret", "\n", "", context.Canceled, context.Canceled},
		{"data with EOF", "", "x", "x", io.EOF, nil},
		{"newline with EOF", "secret", "\n", "secret", io.EOF, nil},
		{"empty password with EOF", "", "\n", "", io.EOF, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := io.MultiReader(strings.NewReader(tc.prefix), &promptReadFailure{data: tc.last, err: tc.readErr})
			password, err := readPromptLine(context.Background(), input)
			if password != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("password length=%d, error=%v; want length=%d, error=%v", len(password), err, len(tc.want), tc.wantErr)
			}
		})
	}
}

type promptReadFunc func([]byte) (int, error)

func (f promptReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestReadPasswordCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	started := make(chan struct{})
	input := promptReadFunc(func(p []byte) (int, error) {
		close(started)
		return reader.Read(p)
	})
	done := make(chan struct{})
	var password string
	var err error
	go func() {
		password, err = readPassword(ctx, input)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("password read did not start")
	}
	cancel()
	select {
	case <-done:
		if password != "" || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled password read returned data or wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for terminal input")
	}
}

func TestReadPromptLineStopsReadingAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	input := promptReadFunc(func(p []byte) (int, error) {
		reads++
		if reads > 1 {
			t.Fatal("canceled password read consumed further input")
		}
		cancel()
		return copy(p, "x"), nil
	})
	password, err := readPromptLine(ctx, input)
	if password != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation did not discard password input: %v", err)
	}
	password, err = readPassword(ctx, input)
	if password != "" || !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatalf("already canceled prompt read input or returned data: %v", err)
	}
}
