package crypt

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for [cleanAbsPath] function.
func TestCleanAbsPath(t *testing.T) {
	t.Run("valid path with environment variable and tilde", func(t *testing.T) {
		err := os.Setenv("TEST_VAR", "testvalue")
		assert.NoError(t, err)

		cleanPath, err := cleanAndValidatePath("~/../$TEST_VAR/testdir")
		assert.NoError(t, err)
		assert.NotEmpty(t, cleanPath)
	})

	t.Run("valid path with empty path", func(t *testing.T) {

		cleanPath, err := cleanAndValidatePath("")
		assert.NoError(t, err)
		assert.Empty(t, cleanPath)
	})

	t.Run("valid path with no HOME env var", func(t *testing.T) {
		origHomeVar := os.Getenv("HOME")
		defer func() {
			err := os.Setenv("HOME", origHomeVar)
			assert.NoError(t, err)
		}()
		err := os.Unsetenv("HOME")
		assert.NoError(t, err)

		cleanPath, err := cleanAndValidatePath("~/testdir")
		assert.Error(t, err)
		assert.Empty(t, cleanPath)
	})

	t.Run("filepath.Abs error when cwd is deleted", func(t *testing.T) {
		tempDir := t.TempDir()
		testTmpDir, err := os.MkdirTemp(tempDir, "test")
		assert.NoError(t, err)

		// Save current directory to restore later
		origDir, err := os.Getwd()
		assert.NoError(t, err)
		defer func() {
			_ = os.Chdir(origDir)
		}()

		// Change to the temp directory
		err = os.Chdir(testTmpDir)
		assert.NoError(t, err)

		// Remove the directory we're currently in
		err = os.Remove(testTmpDir)
		assert.NoError(t, err)

		// Now filepath.Abs with a relative path should fail
		_, err = cleanAndValidatePath("relative/path")
		assert.Error(t, err)
	})
}

// Tests for [clearMsg] function.
func TestClearMsg(t *testing.T) {
	t.Run("valid byte slice with content", func(t *testing.T) {
		msg := []byte("sensitive data")
		expected := bytes.Repeat([]byte{0}, len(msg))

		clearMsg(&msg)
		assert.Equal(t, expected, msg)
	})

	t.Run("valid byte slice without content", func(t *testing.T) {
		msg := []byte("")
		expected := bytes.Repeat([]byte{0}, len(msg))

		clearMsg(&msg)
		assert.Equal(t, expected, msg)
	})

	t.Run("nil byte slice", func(t *testing.T) {
		// This test does not have anything to assert since nil value just skips doing anything
		clearMsg(nil)
	})
}

// Tests for [expandTilde] function.
func TestExpandTilde(t *testing.T) {
	t.Run("valid path with tilde for expansion", func(t *testing.T) {
		path, err := expandTilde("~/testdir")
		assert.NoError(t, err)
		assert.NotEmpty(t, path)
	})

	t.Run("valid path with no tilde for expansion", func(t *testing.T) {
		path, err := expandTilde("/tmp/testdir")
		assert.NoError(t, err)
		assert.NotEmpty(t, path)
	})

	t.Run("valid path with empty path", func(t *testing.T) {
		path, err := expandTilde("")
		assert.NoError(t, err)
		assert.Empty(t, path)
	})

	t.Run("valid path with only tilde", func(t *testing.T) {
		path, err := expandTilde("~")
		assert.NoError(t, err)
		assert.NotEmpty(t, path)
	})

	t.Run("invalid path with no HOME env var", func(t *testing.T) {
		err := os.Unsetenv("HOME")
		assert.NoError(t, err)

		path, err := expandTilde("~/testdir")
		assert.Error(t, err)
		assert.Empty(t, path)
	})
}

// Tests for [resolveEnvVars] function.
func TestResolveEnvVars(t *testing.T) {
	t.Run("valid path with env var exists", func(t *testing.T) {
		err := os.Setenv("TEST_VAR", "testvalue")
		assert.NoError(t, err)

		path := resolveEnvVars("$TEST_VAR/testdir")
		assert.Equal(t, "testvalue/testdir", path)
	})

	t.Run("valid path with env var does not exist", func(t *testing.T) {
		path := resolveEnvVars("$TEST_VAR2/testdir")
		assert.Equal(t, "/testdir", path)
	})

	t.Run("valid path with empty path", func(t *testing.T) {
		path := resolveEnvVars("")
		assert.Equal(t, "", path)
	})
}

// Tests for [isDirEmpty] function.
func TestIsDirEmpty(t *testing.T) {
	t.Run("valid path with empty directory", func(t *testing.T) {
		isEmpty, err := isDirEmpty(t.TempDir())
		assert.NoError(t, err)
		assert.True(t, isEmpty)
	})

	t.Run("valid path without empty directory", func(t *testing.T) {
		dir := t.TempDir()
		file, err := os.CreateTemp(dir, "testfile")
		assert.NoError(t, err)
		file.Close()

		isEmpty, err := isDirEmpty(dir)
		assert.NoError(t, err)
		assert.False(t, isEmpty)
	})

	t.Run("invalid path with non-existent directory", func(t *testing.T) {
		isEmpty, err := isDirEmpty(path.Join(t.TempDir(), "does-not-exist"))
		assert.Error(t, err)
		assert.False(t, isEmpty)
	})
}

// Tests for [trimSpaceBytes] function.
func TestTrimSpaceBytes(t *testing.T) {
	helloWorld := "Hello, World!"

	t.Run("byte slice with leading and trailing spaces", func(t *testing.T) {
		input := []byte("  \t\n  " + helloWorld + "  \n\t  ")
		expected := []byte(helloWorld)

		result := trimSpaceBytes(&input)
		assert.Equal(t, expected, result)
	})

	t.Run("byte slice with no leading or trailing spaces", func(t *testing.T) {
		input := []byte(helloWorld)
		expected := []byte(helloWorld)

		result := trimSpaceBytes(&input)
		assert.Equal(t, expected, result)
	})

	t.Run("byte slice with empty content", func(t *testing.T) {
		input := []byte("")
		expected := []byte("")

		result := trimSpaceBytes(&input)
		assert.Equal(t, expected, result)
	})

	t.Run("byte slice is nil", func(t *testing.T) {
		result := trimSpaceBytes(nil)
		assert.Nil(t, result)
	})
}
