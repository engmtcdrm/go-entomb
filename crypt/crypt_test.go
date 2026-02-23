package crypt

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testCryptKeyPath   = "crypt.key"
	testCryptTombsPath = "tombs"
)

// Tests for [NewCrypt] function.
func TestNewCrypt(t *testing.T) {
	t.Run("valid create crypt instance", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := path.Join(tempDir, testCryptKeyPath)
		tombsPath := path.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with empty keyPath", func(t *testing.T) {
		tempDir := t.TempDir()
		tombsPath := path.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt("", tombsPath, true, true)
		assert.Error(t, err)
		assert.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with invalid key path", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := path.Join(tempDir, "\x00"+testCryptKeyPath)
		tombsPath := path.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		assert.Error(t, err)
		assert.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with empty tombsPath", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := path.Join(tempDir, testCryptKeyPath)

		cryptInstance, err := NewCrypt(keyPath, "", true, true)
		assert.Error(t, err)
		assert.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with invalid tombsPath", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := path.Join(tempDir, testCryptKeyPath)
		tombsPath := path.Join(tempDir, "\x00"+testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		assert.Error(t, err)
		assert.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with key path that does not exist", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := path.Join("/does/not/exist", testCryptKeyPath)
		tombsPath := path.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		assert.Error(t, err)
		assert.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with tombs path that does not exist", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := path.Join(tempDir, testCryptKeyPath)
		tombsPath := path.Join("/does/not/exist", testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		assert.Error(t, err)
		assert.Nil(t, cryptInstance)
	})

	// t.Run("invalid create crypt instance with tomb file that has invalid name", func(t *testing.T) {
	// 	tempDir := t.TempDir()
	// 	keyPath := path.Join(tempDir, testCryptKeyPath)
	// 	tombsPath := path.Join(tempDir, testCryptTombsPath)
	// 	tombWithInvalidName := path.Join(tombsPath, "not.a.valid?name.tomb")

	// 	err := os.MkdirAll(tombsPath, DirFilePerms)
	// 	assert.NoError(t, err)

	// 	_, err = os.Create(tombWithInvalidName)
	// 	assert.NoError(t, err)

	// 	cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
	// 	assert.Error(t, err)
	// 	assert.Nil(t, cryptInstance)
	// })
}
