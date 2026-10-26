//go:build aix || linux || openbsd || solaris

package main

import "golang.org/x/sys/unix"

const passwordInputCaseFlag = unix.IUCLC
