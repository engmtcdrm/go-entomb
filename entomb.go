package entomb

import (
	"bytes"
	"errors"
	"slices"

	"github.com/fernet/fernet-go"
)

// Encryptor/Decryptor
//
// Into the depths we dive, where the secrets lie...
type Tomb struct {
	key                 *fernet.Key
	encryptedPassphrase []byte
}

// Creates a new Tomb
//
// The keyPath is the path to the key file. If the key file does not exist, a new
// key will be generated and saved to the key file. If the key file exists, the key
// will be read from the file.
// The useHost and useUser parameters determine whether the hostname and username
// should be included when encrypting/decrypting secrets.
func NewTombHostUser(key *fernet.Key, useHost bool, useUser bool) (*Tomb, error) {
	hostUser, err := concatHostUser(useHost, useUser)
	if err != nil {
		return nil, err
	}

	return NewTomb(key, hostUser)
}

func NewTomb(key *fernet.Key, passphrase []byte) (*Tomb, error) {
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}

	hashedPassphrase, err := hashValue(passphrase)
	if err != nil {
		return nil, err
	}

	encryptedPassphrase, err := fernet.EncryptAndSign(hashedPassphrase, key)
	if err != nil {
		return nil, err
	}

	return &Tomb{
		key:                 key,
		encryptedPassphrase: encryptedPassphrase,
	}, nil
}

// Encrypts the message and returns the encrypted data
func (tomb *Tomb) Encrypt(msg []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedMsg, err := fernet.EncryptAndSign(msg, tomb.key)
	if err != nil {
		return nil, err
	}
	msg = nil

	encryptedRandTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	finalData := slices.Concat(
		encryptedRandHead,
		encryptedMsg,
		tomb.encryptedPassphrase,
		encryptedRandTail,
	)

	return finalData, nil
}

// Decrypts the data and returns the decrypted message
func (tomb *Tomb) Decrypt(data []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedRandTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	key, err := fernet.DecodeKeys(tomb.key.Encode())
	if err != nil {
		return nil, err
	}

	// Retrieve the encrypted message and the encrypted hashed host/user
	encryptedMsg := data[len(encryptedRandHead) : len(data)-(len(tomb.encryptedPassphrase)+len(encryptedRandTail))]
	encryptedHashedHostUser := data[len(encryptedRandHead)+len(encryptedMsg) : len(data)-len(encryptedRandTail)]
	decryptedHashedHostUser := fernet.VerifyAndDecrypt(encryptedHashedHostUser, 0, key)
	decryptedHashedHostUser2 := fernet.VerifyAndDecrypt(tomb.encryptedPassphrase, 0, key)

	if bytes.Equal(decryptedHashedHostUser, decryptedHashedHostUser2) {
		msg := fernet.VerifyAndDecrypt(encryptedMsg, 0, key)

		if msg != nil {
			return msg, nil
		}
	}

	return nil, errors.New("an error occurred during decryption")
}
