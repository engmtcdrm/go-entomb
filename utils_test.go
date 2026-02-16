package entomb

import (
	"os"
	"testing"

	"github.com/fernet/fernet-go"
	"github.com/stretchr/testify/assert"
)

func TestHashSHA(t *testing.T) {
	data := []byte("test data")
	hashed, err := hashValue(data)
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
	var key fernet.Key
	err := key.Generate()
	assert.NoError(t, err)

	data := []byte("test data")
	hostUser := []byte("test hu")
	salted, _, err := saltKey(key, data, hostUser)
	assert.NoError(t, err)
	assert.NotNil(t, salted)
}

func TestCreateReadKey(t *testing.T) {
	keyPath := "test_key"
	hostUser := "test hu"
	hostUserHash, err := hashValue([]byte(hostUser))
	assert.NoError(t, err)

	// Ensure the key file does not exist before the test
	os.Remove(keyPath)

	// Test key creation
	key, err := GetKey(keyPath, hostUserHash)
	assert.NoError(t, err)
	assert.NotNil(t, key)

	// Test key reading
	readKey, err := GetKey(keyPath, hostUserHash)
	assert.NoError(t, err)
	assert.Equal(t, key, readKey)

	// Clean up
	os.Remove(keyPath)
}
