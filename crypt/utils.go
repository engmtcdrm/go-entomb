package crypt

import "path/filepath"

// cleanAbsPath takes a path, cleans it, and returns the absolute path.
// It returns an error if there is an issue getting the absolute path.
func cleanAbsPath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", err
	}

	return absPath, nil
}
