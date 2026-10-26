package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

func invalidListFilePath(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_NAME) ||
		errors.Is(err, windows.ERROR_BAD_PATHNAME) ||
		errors.Is(err, windows.ERROR_FILENAME_EXCED_RANGE)
}
