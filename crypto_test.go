package entomb

import (
	"bytes"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntombEncryptDecryptHostUser(t *testing.T) {
	keyPath := path.Join(t.TempDir(), "test_key")
	k, err := GetKeyHostUser(keyPath, true, true)
	assert.NoError(t, err)

	msg := []byte("test message")
	encrypted, err := Encrypt(k, msg)
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)

	decrypted, err := Decrypt(k, encrypted)
	assert.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.True(t, bytes.Equal(msg, decrypted))
}
