package main

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

func promptPassword(ctx context.Context, in io.Reader, out io.Writer) (password string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errors.New("password required: use -p or GOSMB_PASSWORD when stdin is not a terminal")
	}
	fd := int(f.Fd())
	// Set and restore modes in this goroutine. A background term.ReadPassword
	// could disable echo after cancellation had already restored the terminal.
	restore, err := passwordTerminalMode(fd)
	if err != nil {
		return "", errors.New("could not configure password terminal")
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil {
			password = ""
			err = errors.Join(err, errors.New("could not restore password terminal"))
		}
		if _, writeErr := writeOutputString(out, "\n"); writeErr != nil {
			password = ""
			err = errors.Join(err, writeErr)
		}
	}()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := writeOutputString(out, "Password: "); err != nil {
		return "", err
	}
	return readPassword(ctx, f)
}

// The terminal performs line editing. Read one byte at a time to preserve
// literal password bytes (including tabs) without consuming the next line.
func readPromptLine(ctx context.Context, in io.Reader) (string, error) {
	var password []byte
	var buf [1]byte
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := in.Read(buf[:])
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err != nil && !errors.Is(err, io.EOF) {
			// Report input failures even when the same read completes the line.
			return "", err
		}
		if n > 0 {
			// Unix canonical mode already maps Enter to LF; a remaining CR
			// was quoted and belongs to the password. Windows uses CRLF.
			if buf[0] == '\n' || (buf[0] == '\r' && runtime.GOOS == "windows") {
				return string(password), nil
			}
			password = append(password, buf[0])
		}
		if err != nil {
			if len(password) > 0 {
				return string(password), nil
			}
			return "", err
		}
	}
}

func readPassword(ctx context.Context, in io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	type readResult struct {
		password string
		err      error
	}
	ready := make(chan readResult, 1)
	go func() {
		// One goroutine owns the complete password buffer. Cancellation can
		// leave at most one byte read blocked until main exits; the loop checks
		// the context before reading again. It never changes terminal modes.
		password, err := readPromptLine(ctx, in)
		ready <- readResult{password, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-ready:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return result.password, result.err
	}
}
