package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadPromptLinePreservesPasswordBytes(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		wantErr           error
	}{
		{"literal whitespace and unicode", "  p\täss word  \n", "  p\täss word  ", nil},
		{"empty", "\n", "", nil},
		{"carriage return", "secret\r\n", "secret", nil},
		{"backspace", "secrex\bt\n", "secret", nil},
		{"empty EOF", "", "", io.EOF},
		{"partial EOF", "secret", "secret", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPromptLine(strings.NewReader(tc.input))
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
			password, err := readPromptLine(input)
			if password != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("password length=%d, error=%v; want length=%d, error=%v", len(password), err, len(tc.want), tc.wantErr)
			}
		})
	}
}
