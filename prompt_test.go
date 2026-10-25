package main

import (
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
