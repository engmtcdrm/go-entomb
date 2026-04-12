package testutils

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// CreateTempFile creates a temporary file using [os.CreateTemp] in the given
// directory with the specified name pattern if it contains a wildcard "*". If
// the name pattern does not contain a wildcard, a temporary file is created
// using [os.OpenFile] with the exact name. The function writes the base name of
// the temporary file to its contents and returns the created temporary file.
func CreateTempFile(dir, name string) (*os.File, error) {
	var tempFile *os.File
	var err error

	if name == "" || strings.Contains(name, "*") {
		tempFile, err = os.CreateTemp(dir, name)
	} else {
		tempFilePath := filepath.Join(dir, name)
		tempFile, err = os.OpenFile(tempFilePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	}

	if err != nil {
		return nil, err
	}
	defer tempFile.Close()

	_, err = tempFile.Write([]byte(filepath.Base(tempFile.Name())))
	if err != nil {
		return nil, err
	}

	slog.Debug(fmt.Sprintf("Created file %s", tempFile.Name()))

	return tempFile, err
}
