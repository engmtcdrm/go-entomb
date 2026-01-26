package entomb

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"

	"github.com/fernet/fernet-go"
)

// Encryptor/Decryptor
//
// Into the depths we dive, where the secrets lie...
type Tomb struct {
	key         *fernet.Key
	secretsPath string
	hostUserEnc []byte
}

// Creates a new Tomb
//
// The keyPath is the path to the key file. If the key file does not exist, a new
// key will be generated and saved to the key file. If the key file exists, the key
// will be read from the file.
// The useHost and useUser parameters determine whether the hostname and username
// should be included when encrypting/decrypting secrets.
func NewTomb(keyPath string, useHost bool, useUser bool) (*Tomb, error) {
	var err error

	if keyPath == "" {
		keyPath = "tomb.key"
	}

	keyPath = filepath.Clean(keyPath)

	hostUserHash, err := encryptHostUser(useHost, useUser)
	if err != nil {
		return nil, err
	}

	key, err := createReadKey(keyPath, hostUserHash)
	if err != nil {
		return nil, err
	}

	encHostUserHash, err := fernet.EncryptAndSign(hostUserHash, &key)
	if err != nil {
		return nil, err
	}

	return &Tomb{
		key:         &key,
		hostUserEnc: encHostUserHash,
	}, nil
}

func (tomb *Tomb) SecretsPath(path string) {
	path = filepath.Clean(path)
	tomb.secretsPath = path
}

// Encrypts the message and returns the encrypted data
func (tomb *Tomb) Encrypt(msg []byte) ([]byte, error) {
	encRandomHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encMsg, err := fernet.EncryptAndSign(msg, tomb.key)
	if err != nil {
		return nil, err
	}
	msg = nil

	encRandomTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	finalData := slices.Concat(encRandomHead, encMsg, tomb.hostUserEnc, encRandomTail)

	return finalData, nil
}

// Decrypts the data and returns the decrypted message
func (tomb *Tomb) Decrypt(data []byte) ([]byte, error) {
	encRandomHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encRandomTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	key, err := fernet.DecodeKeys(tomb.key.Encode())
	if err != nil {
		return nil, err
	}

	// Retrieve the encrypted message and the encrypted host/user hash
	encMsg := data[len(encRandomHead) : len(data)-(len(tomb.hostUserEnc)+len(encRandomTail))]
	encHostUserHash := data[len(encRandomHead)+len(encMsg) : len(data)-len(encRandomTail)]
	decHostUserHash := fernet.VerifyAndDecrypt(encHostUserHash, 0, key)
	decHostUserHash2 := fernet.VerifyAndDecrypt(tomb.hostUserEnc, 0, key)

	if bytes.Equal(decHostUserHash, decHostUserHash2) {
		msg := fernet.VerifyAndDecrypt(encMsg, 0, key)

		if msg != nil {
			return msg, nil
		}
	}

	return nil, errors.New("an error occurred during decryption")
}
