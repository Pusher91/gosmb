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
	// External processing bypasses the canonical input processing we rely on.
	mode.Lflag &^= unix.ECHO | passwordExternalProcessingFlag
	mode.Lflag |= unix.ICANON | unix.ISIG
	// Inherited byte mappings must not drop Enter, corrupt UTF-8, duplicate
	// 0xff bytes, or change password case. Keep only CR-to-NL normalization.
	mode.Iflag &^= unix.IGNCR | unix.INLCR | unix.ISTRIP | unix.PARMRK | passwordInputCaseFlag
	// UTF-8-aware erase removes an entire character rather than its final byte.
	mode.Iflag |= unix.ICRNL | passwordUTF8Flag
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
