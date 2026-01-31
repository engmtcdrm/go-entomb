package entomb

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"sync"

	"github.com/fernet/fernet-go"
)

var keyMutex sync.RWMutex

func createReadKey(keyPath string, hostUserHash []byte) (fernet.Key, error) {
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return createKey(keyPath, hostUserHash)
	}

	return readKey(keyPath, hostUserHash)
}

func createKey(keyPath string, hostUserHash []byte) (fernet.Key, error) {
	var key fernet.Key

	slog.Debug("Key file does not exist. Creating a new key.")

	if err := key.Generate(); err != nil {
		return fernet.Key{}, err
	}

	sk, err := saltValue(key, []byte(key.Encode()), hostUserHash)
	if err != nil {
		return fernet.Key{}, err
	}

	// Write the key to the file with exclusive lock
	keyMutex.Lock()
	defer keyMutex.Unlock()

	if err = os.WriteFile(keyPath, sk, 0600); err != nil {
		return fernet.Key{}, err
	}

	return key, nil
}

func readKey(keyPath string, hostUserHash []byte) (fernet.Key, error) {
	var key fernet.Key

	slog.Debug("Key file exists. Reading key from file.")

	// Read the key from the file with shared lock
	keyMutex.RLock()
	defer keyMutex.RUnlock()

	fileBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fernet.Key{}, err
	}

	encRandomHashHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return fernet.Key{}, err
	}

	encRandomHashTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return fernet.Key{}, err
	}

	if err := key.Generate(); err != nil {
		return fernet.Key{}, err
	}

	ld := (len(fileBytes) - (len(encRandomHashHead) + len(key.Encode()) + len(encRandomHashTail))) / 2
	fileBytes = fileBytes[ld : len(fileBytes)-ld]
	kd := fileBytes[len(encRandomHashHead) : len(encRandomHashHead)+len(key.Encode())]
	hue := fileBytes[len(encRandomHashHead)+len(key.Encode()):]

	k3, err := fernet.DecodeKeys(string(kd))
	if err != nil {
		return fernet.Key{}, err
	}

	hostUserDecoded := fernet.VerifyAndDecrypt(hue, 0, k3)

	if !bytes.Equal(hostUserDecoded, hostUserHash) {
		return fernet.Key{}, errors.New("an error occurred during key verification")
	}

	return *k3[0], nil
}
