//go:build darwin || linux

package main

import "golang.org/x/sys/unix"

const passwordUTF8Flag = unix.IUTF8
