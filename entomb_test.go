package entomb

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEntomb(t *testing.T) {
	keyPath := path.Join(t.TempDir(), "test_key")
	k, err := GetKeyHostUser(keyPath, true, true)
	assert.NoError(t, err)

	t.Run("Create Entomb with host and user", func(t *testing.T) {
		entomb, err := NewEntombHostUser(k, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, entomb)
	})

	t.Run("Create Tomb without host and user", func(t *testing.T) {
		tomb, err := NewEntombHostUser(k, false, false)
		assert.NoError(t, err)
		assert.NotNil(t, tomb)
	})

	t.Run("Create Entomb with nil key value", func(t *testing.T) {
		entomb, err := NewEntombHostUser(nil, true, true)
		assert.Error(t, err)
		assert.Nil(t, entomb)

		os.RemoveAll("tomb.key")
	})
}

func TestEntombEncryptDecrypt(t *testing.T) {
	keyPath := path.Join(t.TempDir(), "test_key")
	k, err := GetKeyHostUser(keyPath, true, true)
	assert.NoError(t, err)

	entomb, err := NewEntombHostUser(k, true, true)
	assert.NoError(t, err)

	msg := []byte("test message")
	encrypted, err := entomb.Encrypt(msg)
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)

	decrypted, err := entomb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.True(t, bytes.Equal(msg, decrypted))
}
