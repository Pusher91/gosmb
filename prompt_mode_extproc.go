//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import "golang.org/x/sys/unix"

const passwordExternalProcessingFlag = unix.EXTPROC
