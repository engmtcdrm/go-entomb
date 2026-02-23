package crypt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// cleanAndValidatePath takes a path, cleans it, resolves environment variables, expands tilde,
// and checks for invalid characters, finally returns the absolute path. It ensures that the
// path is in a standardized format for further processing.
func cleanAndValidatePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	cleanPath := filepath.Clean(strings.TrimSpace(path))
	resolvedPath := resolveEnvVars(cleanPath)
	expandedPath, err := expandTilde(resolvedPath)
	if err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(expandedPath)
	if err != nil {
		return "", err
	}

	if isInvalidPath(absPath) {
		return "", errors.New(ErrorInvalidPath)
	}

	return absPath, nil
}

// clearMsg overwrites the contents of a byte slice with zeros clearing sensitive data from memory.
func clearMsg(s *[]byte) {
	if s == nil {
		return
	}

	for i := range *s {
		(*s)[i] = 0
	}
}

// expandTilde expands the tilde (~) in the given path to the user's home directory.
func expandTilde(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, path[1:]), nil
}

func resolveEnvVars(path string) string {
	return os.ExpandEnv(path)
}

// isDirEmpty checks if a directory is empty.
func isDirEmpty(dirPath string) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, err
	}

	return len(entries) == 0, nil
}

// trimSpaceBytes trims leading and trailing ASCII whitespace from a byte slice in-place.
// Returns a subslice of the original slice, so the underlying array is not copied.
func trimSpaceBytes(b *[]byte) []byte {
	if b == nil {
		return nil
	}

	start := 0
	end := len(*b)

	// Trim leading spaces
	for start < end && ((*b)[start] == ' ' || (*b)[start] == '\t' || (*b)[start] == '\n' || (*b)[start] == '\r') {
		start++
	}
	// Trim trailing spaces
	for end > start && ((*b)[end-1] == ' ' || (*b)[end-1] == '\t' || (*b)[end-1] == '\n' || (*b)[end-1] == '\r') {
		end--
	}

	return (*b)[start:end]
}
