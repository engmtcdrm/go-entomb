package entomb

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for [readKey] functions.
func TestReadKey(t *testing.T) {
	t.Run("empty key path", func(t *testing.T) {
		key, err := readKey("", []byte("hashedPassphrase"))
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("nil hashed passphrase", func(t *testing.T) {
		key, err := readKey("some/path", nil)
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("invalid path", func(t *testing.T) {
		key, err := readKey("nonexistent/path", []byte("hashedPassphrase"))
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("bad key", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		badFakeKey, err := getRandEncrypt(1000)
		require.NoError(t, err)

		err = os.WriteFile(keyPath, badFakeKey, 0600)
		require.NoError(t, err)

		origHashSize := hashSize
		hashSize = 0
		defer func() { hashSize = origHashSize }()

		key, err := readKey(keyPath, []byte("hashedPassphrase"))
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("valid key, mismatched passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := GetKey(keyPath, []byte("test_passphrase"))
		require.NoError(t, err)
		require.NotNil(t, key)

		key, err = readKey(keyPath, []byte("wrong_passphrase"))
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("valid key and passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		originalKey, err := GetKey(keyPath, []byte("test_passphrase"))
		require.NoError(t, err)
		require.NotNil(t, originalKey)

		hashedPassphrase, err := hashValue([]byte("test_passphrase"))
		require.NoError(t, err)

		key, err := readKey(keyPath, hashedPassphrase)
		require.NoError(t, err)
		require.NotNil(t, key)
	})
}

// Tests for [genKey] function.
func TestGenKey(t *testing.T) {
	t.Run("empty key path", func(t *testing.T) {
		key, err := genKey("", []byte("hashedPassphrase"))
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("nil hashed passphrase", func(t *testing.T) {
		key, err := genKey("some/path", nil)
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("invalid path", func(t *testing.T) {
		key, err := genKey("nonexistent/path", []byte("hashedPassphrase"))
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("valid key generation", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := genKey(keyPath, []byte("hashedPassphrase"))
		require.NoError(t, err)
		require.NotNil(t, key)

		// Ensure the key file was created
		_, err = os.Stat(keyPath)
		require.NoError(t, err)
	})
}
