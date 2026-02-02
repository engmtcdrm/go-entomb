package entomb_test

import (
	"bytes"
	"path"
	"testing"

	"github.com/engmtcdrm/go-entomb"
	"github.com/stretchr/testify/assert"
)

const (
	testPassphrase = "test_passphrase"
	testMsg        = "test message"
)

func TestGetKeyHostUser(t *testing.T) {
	t.Run("test with host and user", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, decrypted)
		assert.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with host only", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, false)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, decrypted)
		assert.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with user only", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, false, true)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, decrypted)
		assert.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with empty keyPath", func(t *testing.T) {
		key, err := entomb.GetKeyHostUser("", true, true)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestGetKey(t *testing.T) {
	t.Run("test with valid passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKey(keyPath, []byte(testPassphrase))
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, decrypted)
		assert.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with empty passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKey(keyPath, []byte(""))
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, decrypted)
		assert.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with nil passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKey(keyPath, nil)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.NotNil(t, decrypted)
		assert.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with empty keyPath", func(t *testing.T) {
		key, err := entomb.GetKey("", []byte(testPassphrase))
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}
