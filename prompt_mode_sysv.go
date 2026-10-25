//go:build aix || linux || solaris || zos

package main

import "golang.org/x/sys/unix"

const (
	passwordGetTermios   = unix.TCGETS
	passwordSetTermios   = unix.TCSETS
	passwordFlushTermios = unix.TCSETSF
)
