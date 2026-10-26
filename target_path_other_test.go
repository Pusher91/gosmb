//go:build !windows

package main

import (
	"io"
	"os"
	"syscall"
	"testing"
)

func TestInvalidListFilePathDoesNotHideIOFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{syscall.ENAMETOOLONG, true},
		{syscall.ENOTDIR, true},
		{syscall.EACCES, false},
		{syscall.EIO, false},
		{io.ErrUnexpectedEOF, false},
	} {
		err := &os.PathError{Op: "stat", Path: "target", Err: tc.err}
		if got := invalidListFilePath(err); got != tc.want {
			t.Fatalf("path classification for %v = %v, want %v", tc.err, got, tc.want)
		}
	}
}
