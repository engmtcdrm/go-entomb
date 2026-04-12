package entomb_test

import (
	"bytes"
	"path"
	"testing"

	"github.com/engmtcdrm/go-entomb"
	"github.com/fernet/fernet-go"
	"github.com/stretchr/testify/require"
)

func Test_Encrypt(t *testing.T) {
	t.Run("test valid key and message", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		require.NoError(t, err)
		require.NotNil(t, key)

		encrypted, err := entomb.Encrypt(key, []byte(testMsg))
		require.NoError(t, err)
		require.NotNil(t, encrypted)
	})

	t.Run("test nil key", func(t *testing.T) {
		encrypted, err := entomb.Encrypt(nil, []byte(testMsg))
		require.Error(t, err)
		require.Nil(t, encrypted)
	})

	t.Run("test uninitialized key (empty Key struct)", func(t *testing.T) {
		key := &entomb.Key{}
		encrypted, err := entomb.Encrypt(key, []byte(testMsg))
		require.Error(t, err)
		require.Nil(t, encrypted)
	})

	t.Run("test initialized key, nil EncryptedPassphrase", func(t *testing.T) {
		fernetKey := fernet.Key{}
		key := &entomb.Key{FernetKey: &fernetKey}
		encrypted, err := entomb.Encrypt(key, []byte(testMsg))
		require.Error(t, err)
		require.Nil(t, encrypted)
	})

	t.Run("test valid key and nil message", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		require.NoError(t, err)
		require.NotNil(t, key)

		encrypted, err := entomb.Encrypt(key, nil)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
	})
}

func Test_Decrypt(t *testing.T) {
	t.Run("test valid key and message", func(t *testing.T) {
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

	t.Run("test nil key", func(t *testing.T) {
		decrypted, err := entomb.Decrypt(nil, []byte(testMsg))
		require.Error(t, err)
		require.Nil(t, decrypted)
	})

	t.Run("test valid key and message", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		require.NoError(t, err)
		require.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		require.NoError(t, err)
		require.NotNil(t, encrypted)

		key2 := &entomb.Key{
			FernetKey:           key.FernetKey,
			EncryptedPassphrase: append(key.EncryptedPassphrase, []byte("different")...),
		}

		decrypted, err := entomb.Decrypt(key2, encrypted)
		require.Error(t, err)
		require.Nil(t, decrypted)
	})
}
