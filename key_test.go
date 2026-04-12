package entomb_test

import (
	"bytes"
	"path"
	"testing"

	"github.com/engmtcdrm/go-entomb"
	"github.com/stretchr/testify/require"
)

const (
	testPassphrase = "test_passphrase"
	testMsg        = "test message"
)

// Tests for [GetKeyHostUser] function.
func Test_GetKeyHostUser(t *testing.T) {
	t.Run("test with host and user", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		require.NoError(t, err)
		require.NotNil(t, decrypted)
		require.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with host only", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, false)
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		require.NoError(t, err)
		require.NotNil(t, decrypted)
		require.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with user only", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, false, true)
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		require.NoError(t, err)
		require.NotNil(t, decrypted)
		require.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with empty keyPath", func(t *testing.T) {
		key, err := entomb.GetKeyHostUser("", true, true)
		require.Error(t, err)
		require.Nil(t, key)
	})
}

// Tests for [GetKey] function.
func Test_GetKey(t *testing.T) {
	t.Run("test with valid passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKey(keyPath, []byte(testPassphrase))
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		require.NoError(t, err)
		require.NotNil(t, decrypted)
		require.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with empty passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKey(keyPath, []byte(""))
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		require.NoError(t, err)
		require.NotNil(t, decrypted)
		require.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with nil passphrase", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKey(keyPath, nil)
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		decrypted, err := entomb.Decrypt(key, encrypted)
		require.NoError(t, err)
		require.NotNil(t, decrypted)
		require.True(t, bytes.Equal(msg, decrypted))
	})

	t.Run("test with empty keyPath", func(t *testing.T) {
		key, err := entomb.GetKey("", []byte(testPassphrase))
		require.Error(t, err)
		require.Nil(t, key)
	})
}
