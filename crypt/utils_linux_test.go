//go:build linux

package crypt

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for isValidPath function.
func TestIsValidPath(t *testing.T) {
	t.Run("valid path", func(t *testing.T) {
		isValid := isValidPath(t.TempDir())
		assert.True(t, isValid)
	})

	t.Run("invalid path", func(t *testing.T) {
		invalidPath := filepath.Join(t.TempDir(), string([]byte("invalid\x00path")))
		isValid := isValidPath(invalidPath)
		assert.False(t, isValid)
	})
}

// Tests for isInvalidPath function.
func TestIsInvalidPath(t *testing.T) {
	t.Run("valid path", func(t *testing.T) {
		isInvalid := isInvalidPath(t.TempDir())
		assert.False(t, isInvalid)
	})

	t.Run("invalid path", func(t *testing.T) {
		invalidPath := filepath.Join(t.TempDir(), string([]byte("invalid\x00path")))
		isInvalid := isInvalidPath(invalidPath)
		assert.True(t, isInvalid)
	})
}
