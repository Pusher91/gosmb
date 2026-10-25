//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos && !windows

package main

import "errors"

func passwordTerminalMode(fd int) (func() error, error) {
	return nil, errors.New("password terminal mode is unsupported on this platform")
}
