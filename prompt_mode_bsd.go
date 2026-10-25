//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package main

import "golang.org/x/sys/unix"

const (
	passwordGetTermios   = unix.TIOCGETA
	passwordSetTermios   = unix.TIOCSETA
	passwordFlushTermios = unix.TIOCSETAF
)
