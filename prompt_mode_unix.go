//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

func passwordTerminalMode(fd int) (restore func() error, err error) {
	original, err := unix.IoctlGetTermios(fd, passwordGetTermios)
	if err != nil {
		return nil, err
	}
	mode := *original
	// Keep the terminal's normal line editing and signal handling, including
	// its configured erase and interrupt characters, while hiding the password.
	mode.Lflag &^= unix.ECHO
	mode.Lflag |= unix.ICANON | unix.ISIG
	mode.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, passwordSetTermios, &mode); err != nil {
		return nil, err
	}
	return func() error {
		// Discard pending password/typeahead input before restoring echo so it
		// cannot become input to the invoking shell after the prompt exits.
		if err := unix.IoctlSetTermios(fd, passwordFlushTermios, original); err != nil {
			// Still attempt to restore echo if flushing is unsupported or fails.
			return errors.Join(err, unix.IoctlSetTermios(fd, passwordSetTermios, original))
		}
		return nil
	}, nil
}
