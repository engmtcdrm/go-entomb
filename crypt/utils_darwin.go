//go:build darwin

package crypt

import (
	"strings"
)

// isValidPath checks for characters that are not allowed in Darwin file paths.
func isValidPath(path string) bool {
	return !isInvalidPath(path)
}

// isInvalidPath checks for characters that are not allowed in Darwin file paths.
func isInvalidPath(path string) bool {
	absPath, err := cleanAbsPath(path)
	if err != nil {
		return true
	}

	// Check for null byte
	return strings.Contains(absPath, "\x00")
}
