package entomb_test

import (
	"bytes"
	"path"
	"testing"

	"github.com/engmtcdrm/go-entomb"
	"github.com/fernet/fernet-go"
	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	t.Run("test valid key and message", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		encrypted, err := entomb.Encrypt(key, []byte(testMsg))
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
	})

	t.Run("test nil key", func(t *testing.T) {
		encrypted, err := entomb.Encrypt(nil, []byte(testMsg))
		assert.Error(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("test uninitialized key (empty Key struct)", func(t *testing.T) {
		key := &entomb.Key{}
		encrypted, err := entomb.Encrypt(key, []byte(testMsg))
		assert.Error(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("test initialized key, nil EncryptedPassphrase", func(t *testing.T) {
		fernetKey := fernet.Key{}
		key := &entomb.Key{FernetKey: &fernetKey}
		encrypted, err := entomb.Encrypt(key, []byte(testMsg))
		assert.Error(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("test valid key and nil message", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		encrypted, err := entomb.Encrypt(key, nil)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("test valid key and message", func(t *testing.T) {
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

	t.Run("test nil key", func(t *testing.T) {
		decrypted, err := entomb.Decrypt(nil, []byte(testMsg))
		assert.Error(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("test valid key and message", func(t *testing.T) {
		keyPath := path.Join(t.TempDir(), "test_key")
		key, err := entomb.GetKeyHostUser(keyPath, true, true)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		msg := []byte(testMsg)
		encrypted, err := entomb.Encrypt(key, msg)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		key2 := &entomb.Key{
			FernetKey:           key.FernetKey,
			EncryptedPassphrase: append(key.EncryptedPassphrase, []byte("different")...),
		}

		decrypted, err := entomb.Decrypt(key2, encrypted)
		assert.Error(t, err)
		assert.Nil(t, decrypted)
	})
}
