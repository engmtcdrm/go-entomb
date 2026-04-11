package entomb

import (
	"os"
	"testing"

	"github.com/fernet/fernet-go"
	"github.com/stretchr/testify/require"
)

// Test for [hashValue] function.
func TestHashSHA(t *testing.T) {
	data := []byte("test data")
	hashed, err := hashValue(data)
	require.NoError(t, err)
	require.NotNil(t, hashed)
	require.Equal(t, 64, len(hashed))
}

// Test for [getRandEncrypt] function.
func TestGetRandEncrypt(t *testing.T) {
	t.Run("valid getRandEncrypt", func(t *testing.T) {
		size := 32
		encrypted, err := getRandEncrypt(size)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
	})

	t.Run("invalid getRandEncrypt with negative size", func(t *testing.T) {
		size := -1
		encrypted, err := getRandEncrypt(size)
		require.Error(t, err)
		require.Nil(t, encrypted)
	})
}

// Test for [saltKey] function.
func TestSaltValue(t *testing.T) {
	var key fernet.Key
	err := key.Generate()
	require.NoError(t, err)

	data := []byte("test data")
	hostUser := []byte("test hu")
	salted, _, err := saltKey(key, data, hostUser)
	require.NoError(t, err)
	require.NotNil(t, salted)
}

// Test for [GetKey] function.
func TestCreateReadKey(t *testing.T) {
	keyPath := "test_key"
	hostUser := "test hu"
	hostUserHash, err := hashValue([]byte(hostUser))
	require.NoError(t, err)

	// Ensure the key file does not exist before the test
	os.Remove(keyPath)

	// Test key creation
	key, err := GetKey(keyPath, hostUserHash)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Test key reading
	readKey, err := GetKey(keyPath, hostUserHash)
	require.NoError(t, err)
	require.Equal(t, key, readKey)

	// Clean up
	os.Remove(keyPath)
}
