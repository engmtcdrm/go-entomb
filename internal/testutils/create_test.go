package testutils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for [CreateTempFile] function.
func Test_CreateTempFile(t *testing.T) {
	t.Run("create a 1 temp file", func(t *testing.T) {
		tempDir := t.TempDir()

		tempFile, err := CreateTempFile(tempDir, "testfile-*.txt")
		require.NoError(t, err)
		require.NotNil(t, tempFile)
	})

	t.Run("create empty name", func(t *testing.T) {
		tempDir := t.TempDir()

		tempFile, err := CreateTempFile(tempDir, "")
		require.NoError(t, err)
		require.NotNil(t, tempFile)
	})

	t.Run("error from os.CreateTemp", func(t *testing.T) {
		tempFile, err := CreateTempFile(os.DevNull, "testfile-*.txt")
		require.Error(t, err)
		require.Nil(t, tempFile)
	})
}
