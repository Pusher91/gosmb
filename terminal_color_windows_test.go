package main

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTerminalColorRestoresConsoleMode(t *testing.T) {
	// Use an inactive buffer so this test never changes the user's active console.
	createBuffer := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateConsoleScreenBuffer")
	const consoleTextModeBuffer = 1
	raw, _, err := createBuffer.Call(windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, 0, consoleTextModeBuffer, 0)
	handle := windows.Handle(raw)
	if handle == windows.InvalidHandle {
		t.Skipf("console screen buffer unavailable: %v", err)
	}
	defer windows.CloseHandle(handle)
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		t.Fatal(err)
	}
	const colorModes = windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	baseline := original &^ colorModes
	if err := windows.SetConsoleMode(handle, baseline|colorModes); err != nil {
		t.Skipf("console does not support virtual terminal processing: %v", err)
	}
	if err := windows.SetConsoleMode(handle, baseline); err != nil {
		t.Fatal(err)
	}
	restore, enabled := enableTerminalColor(raw)
	defer restore()
	if !enabled {
		t.Fatal("supported console did not enable colors")
	}
	var got uint32
	if err := windows.GetConsoleMode(handle, &got); err != nil || got != baseline|colorModes {
		t.Fatalf("enabled console mode = %#x, error %v; want %#x", got, err, baseline|colorModes)
	}
	restore()
	if err := windows.GetConsoleMode(handle, &got); err != nil || got != baseline {
		t.Fatalf("restored console mode = %#x, error %v; want %#x", got, err, baseline)
	}
}

func TestTerminalColorRejectsNonConsoleHandle(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	restore, enabled := enableTerminalColor(f.Fd())
	defer restore()
	if enabled {
		t.Fatal("regular file must not enable console colors")
	}
}
