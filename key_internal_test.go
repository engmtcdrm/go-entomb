package entomb

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

// SHA512 is 64 bytes
func TestReadKey(t *testing.T) {
	t.Run("empty key path", func(t *testing.T) {
		key, err := readKey("", []byte("hashedPassphrase"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("nil hashed passphrase", func(t *testing.T) {
		key, err := readKey("some/path", nil)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("invalid path", func(t *testing.T) {
		key, err := readKey("nonexistent/path", []byte("hashedPassphrase"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("bad key", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		badFakeKey, err := getRandEncrypt(1000)
		assert.NoError(t, err)

		err = os.WriteFile(keyPath, badFakeKey, 0600)
		assert.NoError(t, err)

		origHashSize := hashSize
		hashSize = 0
		defer func() { hashSize = origHashSize }()

		key, err := readKey(keyPath, []byte("hashedPassphrase"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("valid key, mismatched passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := GetKey(keyPath, []byte("test_passphrase"))
		assert.NoError(t, err)
		assert.NotNil(t, key)

		key, err = readKey(keyPath, []byte("wrong_passphrase"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("valid key and passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		originalKey, err := GetKey(keyPath, []byte("test_passphrase"))
		assert.NoError(t, err)
		assert.NotNil(t, originalKey)

		hashedPassphrase, err := hashValue([]byte("test_passphrase"))
		assert.NoError(t, err)

		key, err := readKey(keyPath, hashedPassphrase)
		assert.NoError(t, err)
		assert.NotNil(t, key)
		// assert.Equal(t, originalKey.FernetKey.Encode(), key.FernetKey.Encode())
	})
}

func TestGenKey(t *testing.T) {
	t.Run("empty key path", func(t *testing.T) {
		key, err := genKey("", []byte("hashedPassphrase"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("nil hashed passphrase", func(t *testing.T) {
		key, err := genKey("some/path", nil)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("invalid path", func(t *testing.T) {
		key, err := genKey("nonexistent/path", []byte("hashedPassphrase"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("valid key generation", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := genKey(keyPath, []byte("hashedPassphrase"))
		assert.NoError(t, err)
		assert.NotNil(t, key)

		// Ensure the key file was created
		_, err = os.Stat(keyPath)
		assert.NoError(t, err)
	})
}
