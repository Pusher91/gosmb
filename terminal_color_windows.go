package main

import "golang.org/x/sys/windows"

// Windows consoles need virtual terminal processing for colors and cursor
// controls. Call separately for stdout and stderr, restoring in reverse order
// when the handles refer to the same console buffer.
func enableTerminalColor(fd uintptr) (restore func(), enabled bool) {
	restore = func() {}
	handle := windows.Handle(fd)
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		return restore, false
	}
	mode := original | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if mode == original {
		return restore, true
	}
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		return restore, false
	}
	return func() { _ = windows.SetConsoleMode(handle, original) }, true
}
