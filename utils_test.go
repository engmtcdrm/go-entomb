package entomb

import (
	"os"
	"testing"

	"github.com/fernet/fernet-go"
	"github.com/stretchr/testify/assert"
)

func TestHashSHA(t *testing.T) {
	data := []byte("test data")
	hashed, err := hashSHA(data)
	assert.NoError(t, err)
	assert.NotNil(t, hashed)
	assert.Equal(t, 64, len(hashed))
}

func TestGetRandEncrypt(t *testing.T) {
	size := 32
	encrypted, err := getRandEncrypt(size)
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)
}

func TestSaltValue(t *testing.T) {
	var k fernet.Key
	err := k.Generate()
	assert.NoError(t, err)

	data := []byte("test data")
	hu := []byte("test hu")
	salted, err := saltValue(k, data, hu)
	assert.NoError(t, err)
	assert.NotNil(t, salted)
}

func TestCreateReadKey(t *testing.T) {
	keyPath := "test_key"
	hu := "test hu"

	// Ensure the key file does not exist before the test
	os.Remove(keyPath)

	// Test key creation
	key, err := createReadKey(keyPath, hu)
	assert.NoError(t, err)
	assert.NotNil(t, key)

	// Test key reading
	readKey, err := createReadKey(keyPath, hu)
	assert.NoError(t, err)
	assert.Equal(t, key, readKey)

	// Clean up
	os.Remove(keyPath)
}
