//go:build !windows

package main

import (
	"errors"
	"syscall"
)

func invalidListFilePath(err error) bool {
	return errors.Is(err, syscall.ENAMETOOLONG) || errors.Is(err, syscall.ENOTDIR)
}
