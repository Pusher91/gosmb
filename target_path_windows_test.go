package main

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestInvalidListFilePathDoesNotHideIOFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{windows.ERROR_INVALID_NAME, true},
		{windows.ERROR_BAD_PATHNAME, true},
		{windows.ERROR_FILENAME_EXCED_RANGE, true},
		{windows.ERROR_ACCESS_DENIED, false},
		{windows.ERROR_SHARING_VIOLATION, false},
		{windows.ERROR_IO_DEVICE, false},
	} {
		err := &os.PathError{Op: "stat", Path: "target", Err: tc.err}
		if got := invalidListFilePath(err); got != tc.want {
			t.Fatalf("path classification for %v = %v, want %v", tc.err, got, tc.want)
		}
	}
}
