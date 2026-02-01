package entomb

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/fernet/fernet-go"
)

var keyMutex sync.RWMutex

// GetKeyHostUser generates a new encryption key or reads an existing one from the specified path.
// If useHost or useUser is true, the host/user hash will be included in the key to bind it to the host/user.
func GetKeyHostUser(keyPath string, useHost, useUser bool) (*Key, error) {
	hashedHostUser, err := hashHostUser(useHost, useUser)
	if err != nil {
		return nil, err
	}

	return GetKey(keyPath, hashedHostUser)
}

// GetKey generates a new encryption key or reads an existing one from the specified path.
// The passphrase is used for verfication when reading the key and tomb decryption.
func GetKey(keyPath string, passphrase []byte) (*Key, error) {
	if passphrase == nil {
		passphrase = []byte{}
	}

	hashedPassphrase, err := hashValue(passphrase)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(keyPath); err == nil {
		return readKey(keyPath, hashedPassphrase)
	}

	return genKey(keyPath, hashedPassphrase)
}

// readKey reads an existing encryption key from the specified path.
func readKey(keyPath string, passphrase []byte) (*Key, error) {
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

	// Retrieve the Fernet Key and the encrypted hashed passphrase
	ld := (len(fileBytes) - (len(encryptedRandHashHead) + len(key.Encode()) + len(encryptedRandHashTail))) / 2
	fileBytes = fileBytes[ld : len(fileBytes)-ld]
	fernetKey := fileBytes[len(encryptedRandHashHead) : len(encryptedRandHashHead)+len(key.Encode())]
	encryptedPassphrase := fileBytes[len(encryptedRandHashHead)+len(key.Encode()):]

	keys, err := fernet.DecodeKeys(string(fernetKey))
	if err != nil {
		return nil, err
	}

	decryptedPassphrase := fernet.VerifyAndDecrypt(encryptedPassphrase, 0, keys)

	if !bytes.Equal(decryptedPassphrase, passphrase) {
		return nil, errors.New("an error occurred during key verification")
	}

	return &Key{
		FernetKey:           keys[0],
		EncryptedPassphrase: encryptedPassphrase,
	}, nil
}

// genKey generates a new encryption key and saves it to the specified path.
func genKey(keyPath string, passphrase []byte) (*Key, error) {
	var key fernet.Key

	if err := key.Generate(); err != nil {
		return nil, err
	}

	saltedKey, encryptedPassphrase, err := saltKey(key, []byte(key.Encode()), passphrase)
	if err != nil {
		return nil, err
	}

	// Write the key to the file with exclusive lock
	keyMutex.Lock()
	defer keyMutex.Unlock()

	if err = os.WriteFile(keyPath, saltedKey, 0600); err != nil {
		return nil, err
	}

	return &Key{
		FernetKey:           &key,
		EncryptedPassphrase: encryptedPassphrase,
	}, nil
}

func saltKey(key fernet.Key, data []byte, passphrase []byte) ([]byte, []byte, error) {
	encryptedRandHead, err := getRandomEncrypt(maxRandomHashDataSize)
	if err != nil {
		return nil, nil, err
	}

	encryptedRandHash, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, nil, err
	}

	encryptedPassphrase, err := fernet.EncryptAndSign(passphrase, &key)
	if err != nil {
		return nil, nil, err
	}

	encryptedRandTail, err := getRandomEncrypt(maxRandomHashDataSize)
	if err != nil {
		return nil, nil, err
	}

	saltData := slices.Concat(
		encryptedRandHead,
		encryptedRandHash,
		data,
		encryptedPassphrase,
		encryptedRandTail,
	)

	return saltData, encryptedPassphrase, nil
}
