//go:build !windows

package main

// The caller checks that output is a terminal and honors color preferences.
func enableTerminalColor(fd uintptr) (restore func(), enabled bool) {
	return func() {}, true
}
