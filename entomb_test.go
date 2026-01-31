package entomb

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTomb(t *testing.T) {
	t.Run("Create Tomb with host and user", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		k, err := GetKeyHostUser(keyPath, true, true)
		assert.NoError(t, err)

		tomb, err := NewTomb(k, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, tomb)
	})

	t.Run("Create Tomb without host and user", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		k, err := GetKeyHostUser(keyPath, true, true)
		assert.NoError(t, err)

		tomb, err := NewTomb(k, false, false)
		assert.NoError(t, err)
		assert.NotNil(t, tomb)
	})

	t.Run("Create Tomb with nil key value", func(t *testing.T) {
		tomb, err := NewTomb(nil, true, true)
		assert.Error(t, err)
		assert.Nil(t, tomb)

		os.RemoveAll("tomb.key")
	})
}

func TestTombEncryptDecrypt(t *testing.T) {
	keyPath := path.Join(t.TempDir(), "test_key")
	k, err := GetKeyHostUser(keyPath, true, true)
	assert.NoError(t, err)

	tomb, err := NewTomb(k, true, true)
	assert.NoError(t, err)

	msg := []byte("test message")
	encrypted, err := tomb.Encrypt(msg)
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)

	decrypted, err := tomb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.True(t, bytes.Equal(msg, decrypted))
}
