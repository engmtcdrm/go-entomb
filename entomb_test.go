package entomb

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTomb(t *testing.T) {
	keyPath := "test_key"
	tomb, err := NewTomb(keyPath, true, true)
	assert.NoError(t, err)
	assert.NotNil(t, tomb)

	// Clean up
	os.Remove(keyPath)
}

func TestTomb_EncryptDecrypt(t *testing.T) {
	keyPath := "test_key"
	tomb, err := NewTomb(keyPath, true, true)
	assert.NoError(t, err)

	msg := []byte("test message")
	encrypted, err := tomb.Encrypt(msg)
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)

	decrypted, err := tomb.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.True(t, bytes.Equal(msg, decrypted))

	// Clean up
	os.Remove(keyPath)
}
