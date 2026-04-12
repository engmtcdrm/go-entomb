package crypt

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for [cleanAbsPath] function.
func Test_cleanAndValidatePath(t *testing.T) {
	t.Run("valid path with environment variable and tilde", func(t *testing.T) {
		err := os.Setenv("TEST_VAR", "testvalue")
		require.NoError(t, err)

		cleanPath, err := cleanAndValidatePath("~/../$TEST_VAR/testdir")
		require.NoError(t, err)
		require.NotEmpty(t, cleanPath)
	})

	t.Run("valid path with empty path", func(t *testing.T) {

		cleanPath, err := cleanAndValidatePath("")
		require.NoError(t, err)
		require.Empty(t, cleanPath)
	})

	t.Run("valid path with no HOME env var", func(t *testing.T) {
		origHomeVar := os.Getenv("HOME")
		defer func() {
			err := os.Setenv("HOME", origHomeVar)
			require.NoError(t, err)
		}()

		origVarName, origVarValue := unsetHomeVariable(t)
		defer func() {
			os.Setenv(origVarName, origVarValue)
		}()

		cleanPath, err := cleanAndValidatePath("~/testdir")
		require.Error(t, err)
		require.Empty(t, cleanPath)
	})

	t.Run("filepath.Abs error when cwd is deleted", func(t *testing.T) {
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			t.Skip("Skipping test on macOS and Windows due to OS-specific behavior")
		}

		tempDir := t.TempDir()
		testTmpDir, err := os.MkdirTemp(tempDir, "test")
		require.NoError(t, err)

		// Save current directory to restore later
		origDir, err := os.Getwd()
		require.NoError(t, err)
		defer func() {
			_ = os.Chdir(origDir)
		}()

		// Change to the temp directory
		err = os.Chdir(testTmpDir)
		require.NoError(t, err)

		// Remove the directory we're currently in
		err = os.Remove(testTmpDir)
		require.NoError(t, err)

		// Now filepath.Abs with a relative path should fail
		_, err = cleanAndValidatePath("relative/path")
		require.Error(t, err)
	})
}

// Tests for [clearMsg] function.
func Test_clearMsg(t *testing.T) {
	t.Run("valid byte slice with content", func(t *testing.T) {
		msg := []byte("sensitive data")
		expected := bytes.Repeat([]byte{0}, len(msg))

		clearMsg(&msg)
		require.Equal(t, expected, msg)
	})

	t.Run("valid byte slice without content", func(t *testing.T) {
		msg := []byte("")
		expected := bytes.Repeat([]byte{0}, len(msg))

		clearMsg(&msg)
		require.Equal(t, expected, msg)
	})

	t.Run("nil byte slice", func(t *testing.T) {
		// This test does not have anything to assert since nil value just skips doing anything
		clearMsg(nil)
	})
}

// Tests for [expandTilde] function.
func Test_expandTilde(t *testing.T) {
	t.Run("valid path with tilde for expansion", func(t *testing.T) {
		path, err := expandTilde("~/testdir")
		require.NoError(t, err)
		require.NotEmpty(t, path)
	})

	t.Run("valid path with no tilde for expansion", func(t *testing.T) {
		path, err := expandTilde("/tmp/testdir")
		require.NoError(t, err)
		require.NotEmpty(t, path)
	})

	t.Run("valid path with empty path", func(t *testing.T) {
		path, err := expandTilde("")
		require.NoError(t, err)
		require.Empty(t, path)
	})

	t.Run("valid path with only tilde", func(t *testing.T) {
		path, err := expandTilde("~")
		require.NoError(t, err)
		require.NotEmpty(t, path)
	})

	t.Run("invalid path with no HOME env var", func(t *testing.T) {
		origVarName, origVarValue := unsetHomeVariable(t)
		defer func() {
			os.Setenv(origVarName, origVarValue)
		}()

		path, err := expandTilde("~/testdir")
		require.Error(t, err)
		require.Empty(t, path)
	})
}

// Tests for [resolveEnvVars] function.
func Test_resolveEnvVars(t *testing.T) {
	t.Run("valid path with env var exists", func(t *testing.T) {
		err := os.Setenv("TEST_VAR", "testvalue")
		require.NoError(t, err)

		path := resolveEnvVars("$TEST_VAR/testdir")
		require.Equal(t, "testvalue/testdir", path)
	})

	t.Run("valid path with env var does not exist", func(t *testing.T) {
		path := resolveEnvVars("$TEST_VAR2/testdir")
		require.Equal(t, "/testdir", path)
	})

	t.Run("valid path with empty path", func(t *testing.T) {
		path := resolveEnvVars("")
		require.Equal(t, "", path)
	})
}

// Tests for [isDirEmpty] function.
func Test_isDirEmpty(t *testing.T) {
	t.Run("valid path with empty directory", func(t *testing.T) {
		isEmpty, err := isDirEmpty(t.TempDir())
		require.NoError(t, err)
		require.True(t, isEmpty)
	})

	t.Run("valid path without empty directory", func(t *testing.T) {
		dir := t.TempDir()
		file, err := os.CreateTemp(dir, "testfile")
		require.NoError(t, err)
		file.Close()

		isEmpty, err := isDirEmpty(dir)
		require.NoError(t, err)
		require.False(t, isEmpty)
	})

	t.Run("invalid path with non-existent directory", func(t *testing.T) {
		isEmpty, err := isDirEmpty(filepath.Join(t.TempDir(), "does-not-exist"))
		require.Error(t, err)
		require.False(t, isEmpty)
	})
}

// Tests for [trimSpaceBytes] function.
func Test_trimSpaceBytes(t *testing.T) {
	helloWorld := "Hello, World!"

	t.Run("byte slice with leading and trailing spaces", func(t *testing.T) {
		input := []byte("  \t\n  " + helloWorld + "  \n\t  ")
		expected := []byte(helloWorld)

		result := trimSpaceBytes(&input)
		require.Equal(t, expected, result)
	})

	t.Run("byte slice with no leading or trailing spaces", func(t *testing.T) {
		input := []byte(helloWorld)
		expected := []byte(helloWorld)

		result := trimSpaceBytes(&input)
		require.Equal(t, expected, result)
	})

	t.Run("byte slice with empty content", func(t *testing.T) {
		input := []byte("")
		expected := []byte("")

		result := trimSpaceBytes(&input)
		require.Equal(t, expected, result)
	})

	t.Run("byte slice is nil", func(t *testing.T) {
		result := trimSpaceBytes(nil)
		require.Nil(t, result)
	})
}

// unsetHomeVariable is a helper function to store the original home variable
// name and value, unset it for testing, and return the original name and value
// for restoration after the test.
func unsetHomeVariable(t *testing.T) (string, string) {
	t.Helper()

	origVarName := "HOME"
	origVarValue := os.Getenv(origVarName)
	err := os.Unsetenv(origVarName)
	switch runtime.GOOS {
	case "windows":
		origVarName = "USERPROFILE"
		origVarValue = os.Getenv(origVarName)
		err = os.Unsetenv(origVarName)
	case "plan9":
		origVarName = "home"
		origVarValue = os.Getenv(origVarName)
		err = os.Unsetenv(origVarName)
	}
	require.NoError(t, err)

	return origVarName, origVarValue
}
