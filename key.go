package entomb

import (
	"bytes"
	"errors"
	"os"
	"sync"

	"github.com/fernet/fernet-go"
)

var keyMutex sync.RWMutex

// GetKeyHostUser generates a new encryption key or reads an existing one from the specified path.
// If useHost or useUser is true, the host/user hash will be included in the key to bind it to the host/user.
func GetKeyHostUser(keyPath string, useHost, useUser bool) (*fernet.Key, error) {
	hostUserHash, err := hashHostUser(useHost, useUser)
	if err != nil {
		return nil, err
	}

	return GetKey(keyPath, hostUserHash)
}

// GetKey generates a new encryption key or reads an existing one from the specified path.
// The passphrase is used for verfication when reading the key and tomb decryption.
func GetKey(keyPath string, passphrase []byte) (*fernet.Key, error) {
	if _, err := os.Stat(keyPath); err == nil {
		return readKey(keyPath, passphrase)
	}

	return genKey(keyPath, passphrase)
}

// readKey reads an existing encryption key from the specified path.
func readKey(keyPath string, passphrase []byte) (*fernet.Key, error) {
	// Read the key from the file with shared lock
	keyMutex.RLock()
	defer keyMutex.RUnlock()

	fileBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	encryptedRandHashHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedRandHashTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	var key fernet.Key

	if err := key.Generate(); err != nil {
		return nil, err
	}

	ld := (len(fileBytes) - (len(encryptedRandHashHead) + len(key.Encode()) + len(encryptedRandHashTail))) / 2
	fileBytes = fileBytes[ld : len(fileBytes)-ld]
	decryptedKey := fileBytes[len(encryptedRandHashHead) : len(encryptedRandHashHead)+len(key.Encode())]
	encryptedPassphrase := fileBytes[len(encryptedRandHashHead)+len(key.Encode()):]

	keys, err := fernet.DecodeKeys(string(decryptedKey))
	if err != nil {
		return nil, err
	}

	decryptedPassphrase := fernet.VerifyAndDecrypt(encryptedPassphrase, 0, keys)

	if !bytes.Equal(decryptedPassphrase, passphrase) {
		return nil, errors.New("an error occurred during key verification")
	}

	return keys[0], nil
}

// genKey generates a new encryption key and saves it to the specified path.
func genKey(keyPath string, passphrase []byte) (*fernet.Key, error) {
	var key fernet.Key

	if err := key.Generate(); err != nil {
		return nil, err
	}

	saltKey, err := saltValue(key, []byte(key.Encode()), passphrase)
	if err != nil {
		return nil, err
	}

	// Write the key to the file with exclusive lock
	keyMutex.Lock()
	defer keyMutex.Unlock()

	if err = os.WriteFile(keyPath, saltKey, 0600); err != nil {
		return nil, err
	}

	return &key, nil
}
