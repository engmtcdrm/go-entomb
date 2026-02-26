package crypt

import (
	"os"
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
		cryptInstance := initCrypt(t)
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

// Tests for [Crypt.ValidateTombNameFunc] function.
func TestCryptValidateTombNameFunc(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("nil func", func(t *testing.T) {
		c, err := cryptInstance.ValidateTombNameFunc(nil)
		assert.NoError(t, err)
		assert.NotNil(t, c)
	})

	t.Run("error from getTombs", func(t *testing.T) {
		cryptInstance.tombsPath = "\x00" + cryptInstance.tombsPath
		c, err := cryptInstance.ValidateTombNameFunc(nil)
		assert.Error(t, err)
		assert.Nil(t, c)
	})
}

// Tests for [Crypt.TombFileExt] function.
func TestCryptTombFileExt(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("valid extension", func(t *testing.T) {
		c, err := cryptInstance.TombFileExt(".newext")
		assert.NoError(t, err)
		assert.NotNil(t, c)
		assert.Equal(t, ".newext", c.tombFileExt)
	})

	t.Run("error from getTombs", func(t *testing.T) {
		cryptInstance.tombsPath = "\x00" + cryptInstance.tombsPath
		c, err := cryptInstance.TombFileExt(".newext2")
		assert.Error(t, err)
		assert.Nil(t, c)
	})
}

// Tests for [Crypt.Desecrate] function.
func TestCryptDesecrate(t *testing.T) {
	cryptInstance := initCrypt(t)
	_ = cryptInstance

	t.Run("delete existing tomb", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb", []byte("testdata"))
		assert.NoError(t, err)
		err = cryptInstance.Desecrate("testtomb")
		assert.NoError(t, err)
	})

	t.Run("delete non-existing tomb", func(t *testing.T) {
		err := cryptInstance.Desecrate("nonexistent")
		assert.Error(t, err)
	})

	t.Run("os.Remove error", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb2", []byte("testdata"))
		assert.NoError(t, err)

		// Delete the tomb file to simulate an error when trying to delete it again
		cryptInstance.tombsMu.RLock()
		tomb, exists := cryptInstance.tombs["testtomb2"]
		cryptInstance.tombsMu.RUnlock()
		assert.True(t, exists)
		err = os.Remove(tomb.Path())
		assert.NoError(t, err)

		err = cryptInstance.Desecrate("testtomb2")
		assert.Error(t, err)
	})
}

// Tests for [Crypt.DesecrateAll] function.
func TestCryptDesecrateAll(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("delete all tombs", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb1", []byte("testdata"))
		assert.NoError(t, err)
		err = cryptInstance.Entomb("testtomb2", []byte("testdata"))
		assert.NoError(t, err)

		err = cryptInstance.DesecrateAll()
		assert.NoError(t, err)

		cryptInstance.tombsMu.RLock()
		defer cryptInstance.tombsMu.RUnlock()
		assert.Empty(t, cryptInstance.tombs)
	})

	t.Run("os.RemoveAll error", func(t *testing.T) {
		// Comment from RemoveAll:
		// The rmdir system call does not permit removing ".",
		// so we don't permit it either.
		cryptInstance.tombsPath = "."
		err := cryptInstance.DesecrateAll()
		assert.Error(t, err)
	})
}

// Tests for [Crypt.Entomb] function.
func TestCryptEntomb(t *testing.T) {
	cryptInstance := initCrypt(t)
	testMsg := []byte("testdata")

	t.Run("valid entomb", func(t *testing.T) {
		expected := testMsg

		err := cryptInstance.Entomb("testtomb", expected)
		assert.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("empty tomb name", func(t *testing.T) {
		err := cryptInstance.Entomb("", testMsg)
		assert.Error(t, err)
	})

	t.Run("invalid tomb name", func(t *testing.T) {
		err := cryptInstance.Entomb("\x00not-valid", testMsg)
		assert.Error(t, err)
	})

	t.Run("invalid full tomb path", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = "\x00" + cryptInstance.tombsPath
		err := cryptInstance.Entomb("testtomb", testMsg)
		assert.Error(t, err)
	})

	t.Run("error from entomb.Encrypt", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.key = nil

		err := cryptInstance.Entomb("testtomb", testMsg)
		assert.Error(t, err)
	})

	t.Run("invalid tombs path", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = "/does/not/exist"

		err := cryptInstance.Entomb("testtomb", testMsg)
		assert.Error(t, err)
	})

	t.Run("bad tombs path permissions", func(t *testing.T) {
		cryptInstance := initCrypt(t)

		err := os.Chmod(cryptInstance.tombsPath, 0000)
		assert.NoError(t, err)
		defer os.Chmod(cryptInstance.tombsPath, 0755)

		err = cryptInstance.Entomb("testtomb", testMsg)
		assert.Error(t, err)
	})
}

// Tests for [Crypt.EntombFromFile] function.
func TestCryptEntombFromFile(t *testing.T) {
	cryptInstance := initCrypt(t)
	testMsg := []byte("testdata")

	t.Run("valid entomb from file without cleanup", func(t *testing.T) {
		testFilePath := path.Join(t.TempDir(), "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		assert.NoError(t, err)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, false)
		assert.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		assert.NoError(t, err)
		assert.Equal(t, testMsg, result)
	})

	t.Run("valid entomb from file with cleanup", func(t *testing.T) {
		testFilePath := path.Join(t.TempDir(), "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		assert.NoError(t, err)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, true)
		assert.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		assert.NoError(t, err)
		assert.Equal(t, testMsg, result)

		_, err = os.Stat(testFilePath)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("empty tomb name", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("", "/does/not/matter", false)
		assert.Error(t, err)
	})

	t.Run("invalid tomb name", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("\x00not-valid", "/does/not/matter", false)
		assert.Error(t, err)
	})

	t.Run("empty file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "", false)
		assert.Error(t, err)
	})

	t.Run("invalid file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "\x00/invalid/path", false)
		assert.Error(t, err)
	})

	t.Run("invalid file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "\x00/invalid/path", false)
		assert.Error(t, err)
	})

	t.Run("non-existent file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "/file/does/not/exist", false)
		assert.Error(t, err)
	})

	t.Run("error from Entomb func", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.key = nil
		testFilePath := path.Join(t.TempDir(), "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		assert.NoError(t, err)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, false)
		assert.Error(t, err)
	})

	t.Run("os.Remove error from cleanup", func(t *testing.T) {
		tempDir := t.TempDir()
		testFilePath := path.Join(tempDir, "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		assert.NoError(t, err)

		// Set temp directory to read only so os.Remove fails
		err = os.Chmod(tempDir, 0500)
		assert.NoError(t, err)
		defer os.Chmod(tempDir, 0700)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, true)
		assert.Error(t, err)
	})
}

// initCrypt is a helper function for creating a valid instance
// of [Crypt] for testing purposes.
func initCrypt(t *testing.T) *Crypt {
	tempDir := t.TempDir()
	keyPath := path.Join(tempDir, testCryptKeyPath)
	tombsPath := path.Join(tempDir, testCryptTombsPath)

	c, err := NewCrypt(keyPath, tombsPath, true, true)
	assert.NoError(t, err)
	assert.NotNil(t, c)

	return c
}
