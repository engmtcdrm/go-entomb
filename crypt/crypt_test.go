package crypt

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/engmtcdrm/go-entomb/internal/testutils"
	"github.com/stretchr/testify/require"
)

const (
	testCryptKeyPath   = "crypt.key"
	testCryptTombsPath = "tombs"
)

// Tests for [NewCrypt] function.
func Test_NewCrypt(t *testing.T) {
	t.Run("valid create crypt instance", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		require.NotNil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with empty keyPath", func(t *testing.T) {
		tempDir := t.TempDir()
		tombsPath := filepath.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt("", tombsPath, true, true)
		require.Error(t, err)
		require.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with invalid key path", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "\x00"+testCryptKeyPath)
		tombsPath := filepath.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		require.Error(t, err)
		require.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with empty tombsPath", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, testCryptKeyPath)

		cryptInstance, err := NewCrypt(keyPath, "", true, true)
		require.Error(t, err)
		require.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with invalid tombsPath", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, testCryptKeyPath)
		tombsPath := filepath.Join(tempDir, "\x00"+testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		require.Error(t, err)
		require.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with key path that does not exist", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := filepath.Join("/does/not/exist", testCryptKeyPath)

		if runtime.GOOS == "windows" {
			keyPath = filepath.Join("TEST:\\does\\not\\exist", testCryptKeyPath)
		}

		tombsPath := filepath.Join(tempDir, testCryptTombsPath)

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		require.Error(t, err)
		require.Nil(t, cryptInstance)
	})

	t.Run("invalid create crypt instance with tombs path that does not exist", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, testCryptKeyPath)
		tombsPath := filepath.Join("/does/not/exist", testCryptTombsPath)

		if runtime.GOOS == "windows" {
			tombsPath = filepath.Join("TEST:\\does\\not\\exist", testCryptTombsPath)
		}

		cryptInstance, err := NewCrypt(keyPath, tombsPath, true, true)
		require.Error(t, err)
		require.Nil(t, cryptInstance)
	})
}

// Tests for [Crypt.ValidateTombNameFunc] function.
func Test_Crypt_ValidateTombNameFunc(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("nil func", func(t *testing.T) {
		c, err := cryptInstance.ValidateTombNameFunc(nil)
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("error from getTombs", func(t *testing.T) {
		cryptInstance.tombsPath = "\x00" + cryptInstance.tombsPath
		c, err := cryptInstance.ValidateTombNameFunc(nil)
		require.Error(t, err)
		require.Nil(t, c)
	})
}

// Tests for [Crypt.TombFileExt] function.
func Test_Crypt_TombFileExt(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("valid extension", func(t *testing.T) {
		c, err := cryptInstance.TombFileExt(".newext")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, ".newext", c.tombFileExt)
	})

	t.Run("error from getTombs", func(t *testing.T) {
		cryptInstance.tombsPath = "\x00" + cryptInstance.tombsPath
		c, err := cryptInstance.TombFileExt(".newext2")
		require.Error(t, err)
		require.Nil(t, c)
	})
}

// Tests for [Crypt.Desecrate] function.
func Test_Crypt_Desecrate(t *testing.T) {
	cryptInstance := initCrypt(t)
	_ = cryptInstance

	t.Run("delete existing tomb", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb", []byte("testdata"))
		require.NoError(t, err)
		err = cryptInstance.Desecrate("testtomb")
		require.NoError(t, err)
	})

	t.Run("delete non-existing tomb", func(t *testing.T) {
		err := cryptInstance.Desecrate("nonexistent")
		require.Error(t, err)
	})

	t.Run("os.Remove error", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb2", []byte("testdata"))
		require.NoError(t, err)

		// Delete the tomb file to simulate an error when trying to delete it again
		cryptInstance.tombsMu.RLock()
		tomb, exists := cryptInstance.tombs["testtomb2"]
		cryptInstance.tombsMu.RUnlock()
		require.True(t, exists)
		err = os.Remove(tomb.Path())
		require.NoError(t, err)

		err = cryptInstance.Desecrate("testtomb2")
		require.Error(t, err)
	})
}

// Tests for [Crypt.DesecrateAll] function.
func Test_Crypt_DesecrateAll(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("delete all tombs", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb1", []byte("testdata"))
		require.NoError(t, err)
		err = cryptInstance.Entomb("testtomb2", []byte("testdata"))
		require.NoError(t, err)

		err = cryptInstance.DesecrateAll()
		require.NoError(t, err)

		cryptInstance.tombsMu.RLock()
		defer cryptInstance.tombsMu.RUnlock()
		require.Empty(t, cryptInstance.tombs)
	})

	t.Run("os.RemoveAll error", func(t *testing.T) {
		// Comment from RemoveAll:
		// The rmdir system call does not permit removing ".",
		// so we don't permit it either.
		cryptInstance.tombsPath = "."
		err := cryptInstance.DesecrateAll()
		require.Error(t, err)
	})
}

// Tests for [Crypt.Entomb] function.
func Test_Crypt_Entomb(t *testing.T) {
	cryptInstance := initCrypt(t)
	testMsg := []byte("testdata")

	t.Run("valid entomb", func(t *testing.T) {
		expected := testMsg

		err := cryptInstance.Entomb("testtomb", expected)
		require.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("empty tomb name", func(t *testing.T) {
		err := cryptInstance.Entomb("", testMsg)
		require.Error(t, err)
	})

	t.Run("invalid tomb name", func(t *testing.T) {
		err := cryptInstance.Entomb("\x00not-valid", testMsg)
		require.Error(t, err)
	})

	t.Run("invalid full tomb path", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = "\x00" + cryptInstance.tombsPath
		err := cryptInstance.Entomb("testtomb", testMsg)
		require.Error(t, err)
	})

	t.Run("error from entomb.Encrypt", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.key = nil

		err := cryptInstance.Entomb("testtomb", testMsg)
		require.Error(t, err)
	})

	t.Run("invalid tombs path", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = "/does/not/exist"

		if runtime.GOOS == "windows" {
			cryptInstance.tombsPath = "Z:\\does\\not\\exist"
		}

		err := cryptInstance.Entomb("testtomb", testMsg)
		require.Error(t, err)
	})

	t.Run("bad tombs path permissions", func(t *testing.T) {
		cryptInstance := initCrypt(t)

		err := testutils.PermissionTest(
			cryptInstance.tombsPath,
			cryptInstance.Entomb,
			"testtomb", testMsg,
		)
		require.Error(t, err)
	})
}

// Tests for [Crypt.EntombFromFile] function.
func Test_Crypt_EntombFromFile(t *testing.T) {
	cryptInstance := initCrypt(t)
	testMsg := []byte("testdata")

	t.Run("valid entomb from file without cleanup", func(t *testing.T) {
		testFilePath := filepath.Join(t.TempDir(), "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		require.NoError(t, err)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, false)
		require.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		require.NoError(t, err)
		require.Equal(t, testMsg, result)
	})

	t.Run("valid entomb from file with cleanup", func(t *testing.T) {
		testFilePath := filepath.Join(t.TempDir(), "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		require.NoError(t, err)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, true)
		require.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		require.NoError(t, err)
		require.Equal(t, testMsg, result)

		_, err = os.Stat(testFilePath)
		require.True(t, os.IsNotExist(err))
	})

	t.Run("empty tomb name", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("", "/does/not/matter", false)
		require.Error(t, err)
	})

	t.Run("invalid tomb name", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("\x00not-valid", "/does/not/matter", false)
		require.Error(t, err)
	})

	t.Run("empty file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "", false)
		require.Error(t, err)
	})

	t.Run("invalid file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "\x00/invalid/path", false)
		require.Error(t, err)
	})

	t.Run("invalid file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "\x00/invalid/path", false)
		require.Error(t, err)
	})

	t.Run("non-existent file path", func(t *testing.T) {
		err := cryptInstance.EntombFromFile("testtomb", "/file/does/not/exist", false)
		require.Error(t, err)
	})

	t.Run("error from Entomb func", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.key = nil
		testFilePath := filepath.Join(t.TempDir(), "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		require.NoError(t, err)

		err = cryptInstance.EntombFromFile("testtomb", testFilePath, false)
		require.Error(t, err)
	})

	t.Run("os.Remove error from cleanup", func(t *testing.T) {
		tempDir := t.TempDir()
		testFilePath := filepath.Join(tempDir, "testfile.txt")

		err := os.WriteFile(testFilePath, testMsg, 0644)
		require.NoError(t, err)

		// Set temp directory to read only so os.Remove fails
		err = testutils.PermissionTestReadOnly(
			testFilePath,
			cryptInstance.EntombFromFile,
			"testtomb", testFilePath, true,
		)

		// err = cryptInstance.EntombFromFile("testtomb", testFilePath, true)
		require.Error(t, err)
	})
}

// Tests for [Crypt.Epitaph] function.
func Test_Crypt_Epitaph(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("empty crypt", func(t *testing.T) {
		tombs := cryptInstance.Epitaph()
		require.Empty(t, tombs)
	})

	t.Run("non-empty crypt", func(t *testing.T) {
		testMsg := []byte("testdata")

		err := cryptInstance.Entomb("testtomb", testMsg)
		require.NoError(t, err)

		tombs := cryptInstance.Epitaph()
		require.NotEmpty(t, tombs)
		require.Len(t, tombs, 1)
	})
}

// Tests for [Crypt.Exhume] function.
func Test_Crypt_Exhume(t *testing.T) {
	cryptInstance := initCrypt(t)
	testMsg := []byte("testdata")

	t.Run("valid exhume", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb", testMsg)
		require.NoError(t, err)

		result, err := cryptInstance.Exhume("testtomb")
		require.NoError(t, err)
		require.Equal(t, testMsg, result)
	})

	t.Run("non-existent tomb", func(t *testing.T) {
		_, err := cryptInstance.Exhume("nonexistent")
		require.Error(t, err)
	})

	t.Run("empty tomb name", func(t *testing.T) {
		_, err := cryptInstance.Exhume("")
		require.Error(t, err)
	})

	t.Run("invalid tomb name", func(t *testing.T) {
		_, err := cryptInstance.Exhume("\x00not-valid")
		require.Error(t, err)
	})

	t.Run("non-existent tomb file", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb", testMsg)
		require.NoError(t, err)

		err = os.Remove(filepath.Join(cryptInstance.tombsPath, "testtomb"+cryptInstance.tombFileExt))
		require.NoError(t, err)

		_, err = cryptInstance.Exhume("testtomb")
		require.Error(t, err)
	})

	t.Run("error from entomb.Decrypt", func(t *testing.T) {
		err := cryptInstance.Entomb("testtomb", testMsg)
		require.NoError(t, err)

		cryptInstance.key = nil

		result, err := cryptInstance.Exhume("testtomb")
		require.Error(t, err)
		require.Nil(t, result)
	})
}

// Tests for [Crypt.initializeTombsPath] function.
func Test_Crypt_initializeTombsPath(t *testing.T) {
	t.Run("valid initialization", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = t.TempDir()
		err := cryptInstance.initializeTombsPath()
		require.NoError(t, err)
		require.DirExists(t, cryptInstance.tombsPath)
	})

	t.Run("empty tombsPath", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = ""
		err := cryptInstance.initializeTombsPath()
		require.Error(t, err)
		require.NoDirExists(t, cryptInstance.tombsPath)
	})

	t.Run("unwritable tombsPath", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		tombsPath := filepath.Join(t.TempDir(), "tombs")
		cryptInstance.tombsPath = filepath.Join(tombsPath, "subdir")

		err := testutils.PermissionTest(tombsPath, cryptInstance.initializeTombsPath)
		require.Error(t, err)
		require.NoDirExists(t, cryptInstance.tombsPath)
	})

	t.Run("tombsPath is a file", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		tombsPath := filepath.Join(t.TempDir(), "tombs")
		err := os.WriteFile(tombsPath, []byte("thisisafile"), 0644)
		require.NoError(t, err)
		defer os.Remove(tombsPath)

		cryptInstance.tombsPath = tombsPath
		err = cryptInstance.initializeTombsPath()
		require.Error(t, err)
		require.NoDirExists(t, cryptInstance.tombsPath)
	})
}

// Tests for [Crypt.getTombs] function.
func Test_Crypt_getTombs(t *testing.T) {
	// Need to implement tests
}

// Tests for [Crypt.walkTombsDirFunc] function.
func Test_Crypt_walkTombsDirFunc(t *testing.T) {
	cryptInstance := initCrypt(t)
	t.Run("valid walkTombsDirFunc", func(t *testing.T) {
		walkFunc := cryptInstance.walkTombsDirFunc(cryptInstance.tombs)
		require.NotNil(t, walkFunc)

		dirEntry := &mockDirEntry{}

		validTomb := filepath.Join(cryptInstance.tombsPath, "valid.tomb")

		err := walkFunc(validTomb, dirEntry, nil)
		require.NoError(t, err)
	})

	t.Run("nil tombs map", func(t *testing.T) {
		walkFunc := cryptInstance.walkTombsDirFunc(nil)
		err := walkFunc("", nil, nil)
		require.Error(t, err)
	})

	t.Run("error from filepath.Rel", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		walkFunc := cryptInstance.walkTombsDirFunc(cryptInstance.tombs)

		dirEntry := &mockDirEntry{}

		err := walkFunc("\x00fake.tomb", dirEntry, nil)
		require.Error(t, err)
	})

	t.Run("error from cleanAndValidatePath", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.tombsPath = "\x00not-valid-path"
		walkFunc := cryptInstance.walkTombsDirFunc(cryptInstance.tombs)

		dirEntry := &mockDirEntry{}

		err := walkFunc("\x00fake.tomb", dirEntry, nil)
		require.Error(t, err)
	})

	t.Run("error from cleanAndValidatePath2", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		walkFunc := cryptInstance.walkTombsDirFunc(cryptInstance.tombs)

		dirEntry := &mockDirEntry{}

		err := walkFunc("/not!a!valid.tomb", dirEntry, nil)
		require.Error(t, err)
	})
}

// Tests for [Crypt.newTomb] function.
func Test_Crypt_newTomb(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("valid new tomb", func(t *testing.T) {
		tomb, err := cryptInstance.newTomb("testtomb")
		require.NoError(t, err)
		require.NotNil(t, tomb)
		require.Equal(t, "testtomb", tomb.Name())
		expectedPath := filepath.Join(cryptInstance.tombsPath, "testtomb"+cryptInstance.tombFileExt)
		require.Equal(t, expectedPath, tomb.Path())
	})

	t.Run("empty name", func(t *testing.T) {
		tomb, err := cryptInstance.newTomb("")
		require.Error(t, err)
		require.Nil(t, tomb)
	})
}

// Tests for [Crypt.validateName] function.
func Test_Crypt_validateName(t *testing.T) {
	cryptInstance := initCrypt(t)

	t.Run("valid name", func(t *testing.T) {
		err := cryptInstance.validateName("validname")
		require.NoError(t, err)
	})

	t.Run("empty name", func(t *testing.T) {
		err := cryptInstance.validateName("")
		require.Error(t, err)
	})

	t.Run("invalid name from isInvalidPath", func(t *testing.T) {
		err := cryptInstance.validateName("\x00invalid")
		require.Error(t, err)
	})

	t.Run("invalid name from validateTombNameFn", func(t *testing.T) {
		err := cryptInstance.validateName("?][invalid")
		require.Error(t, err)
	})

	t.Run("nil validateTombNameFn", func(t *testing.T) {
		cryptInstance := initCrypt(t)
		cryptInstance.validateTombNameFn = nil
		err := cryptInstance.validateName("validname")
		require.NoError(t, err)
	})
}

// mockDirEntry is a mock implementation of the fs.DirEntry interface for testing purposes.
type mockDirEntry struct{}

func (f *mockDirEntry) Name() string               { return "fake.tomb" }
func (f *mockDirEntry) IsDir() bool                { return false }
func (f *mockDirEntry) Type() fs.FileMode          { return 0 }
func (f *mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// initCrypt is a helper function for creating a valid instance
// of [Crypt] for testing purposes.
func initCrypt(t *testing.T) *Crypt {
	t.Helper()

	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, testCryptKeyPath)
	tombsPath := filepath.Join(tempDir, testCryptTombsPath)

	c, err := NewCrypt(keyPath, tombsPath, true, true)
	require.NoError(t, err)
	require.NotNil(t, c)

	return c
}
