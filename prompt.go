package main

import (
	"context"
	"errors"
	"io"
	"os"

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
	reader := &passwordInput{ctx: ctx, in: f}
	password, err = readPromptLine(reader)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return password, nil
}

// The terminal performs line editing. Read one byte at a time to preserve
// literal password bytes (including tabs) without consuming the next line.
func readPromptLine(in io.Reader) (string, error) {
	var password []byte
	var buf [1]byte
	for {
		n, err := in.Read(buf[:])
		if err != nil && !errors.Is(err, io.EOF) {
			// Report input failures even when the same read completes the line.
			return "", err
		}
		if n > 0 {
			switch buf[0] {
			case '\r', '\n':
				return string(password), nil
			case '\b':
				if len(password) > 0 {
					password = password[:len(password)-1]
				}
			default:
				password = append(password, buf[0])
			}
		}
		if err != nil {
			if len(password) > 0 {
				return string(password), nil
			}
			return "", err
		}
	}
}

type passwordInput struct {
	ctx context.Context
	in  io.Reader
}

func (r *passwordInput) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	type readResult struct {
		data []byte
		err  error
	}
	ready := make(chan readResult, 1)
	go func() {
		// Own the buffer so cancellation cannot leave a read modifying the
		// caller's memory. At most one stdin read can remain blocked until main
		// exits on cancellation; it never writes output or changes terminal modes.
		buf := make([]byte, len(p))
		n, err := r.in.Read(buf)
		ready <- readResult{buf[:n], err}
	}()
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	case result := <-ready:
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		return copy(p, result.data), result.err
	}
}
