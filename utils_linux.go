//go:build linux
// +build linux

package entomb

import (
	"os"
	"strings"
)

func machineId() ([]byte, error) {
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		mid, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil {
			return nil, err
		}
	}

	return mid, nil
}

// isValidPath checks for characters that are not allowed in Linux file paths.
func isValidPath(path string) bool {
	return !isInvalidPath(path)
}

// isInvalidPath checks for characters that are not allowed in Linux file paths.
func isInvalidPath(path string) bool {
	// Check for null byte
	return strings.Contains(path, "\x00")
}
