//go:build windows
// +build windows

package crypt

import (
	"path/filepath"
	"strings"
)

const (
	invalidDirFileChars = `<>:"/\|?*`
)

var reservedNames = []string{
	"CON",
	"PRN",
	"AUX",
	"NUL",
	"COM0",
	"COM1",
	"COM2",
	"COM3",
	"COM4",
	"COM5",
	"COM6",
	"COM7",
	"COM8",
	"COM9",
	"LPT0",
	"LPT1",
	"LPT2",
	"LPT3",
	"LPT4",
	"LPT5",
	"LPT6",
	"LPT7",
	"LPT8",
	"LPT9",
}

// isInvalidPath checks for characters and reserved names that are not allowed in Windows file paths.
func isInvalidPath(path string) bool {
	// Remove drive letter if present
	_, nonDrivePath, _ := strings.Cut(path, `:\`)

	// Check each component of the path for invalid characters
	paths := strings.Split(nonDrivePath, string(filepath.Separator))
	for _, pathComponent := range paths {
		if strings.ContainsAny(pathComponent, invalidDirFileChars) {
			return true
		}
	}

	// Check for reserved names in the last component of the path, e.g. C:\CON or C:\folder\CON
	base := filepath.Base(path)
	for _, reserved := range reservedNames {
		if strings.EqualFold(base, reserved) {
			return true
		}
	}

	return false
}
