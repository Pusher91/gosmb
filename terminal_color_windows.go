package main

import "golang.org/x/sys/windows"

// Windows consoles need virtual terminal processing before ANSI colors can be
// emitted. Leave unsupported consoles unchanged and let the caller use plain text.
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
