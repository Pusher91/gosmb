package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

func passwordTerminalMode(fd int) (restore func() error, err error) {
	handle := windows.Handle(fd)
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		return nil, err
	}
	mode := original &^ windows.ENABLE_ECHO_INPUT
	mode |= windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		return nil, err
	}
	return func() error {
		// Always restore the mode, even when discarding queued input fails.
		flushErr := windows.FlushConsoleInputBuffer(handle)
		return errors.Join(flushErr, windows.SetConsoleMode(handle, original))
	}, nil
}
