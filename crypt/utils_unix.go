//go:build unix

package crypt

import (
	"strings"
)

// isInvalidPath checks for characters that are not allowed in Linux file paths.
func isInvalidPath(path string) bool {
	// Check for null byte
	return strings.Contains(path, "\x00")
}
