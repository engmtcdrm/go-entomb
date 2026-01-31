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
type Entomb struct {
	key                 *fernet.Key
	encryptedPassphrase []byte
}

// Creates a new Entomb instance with host/user binding if true.
func NewEntombHostUser(key *fernet.Key, useHost bool, useUser bool) (*Entomb, error) {
	hostUser, err := concatHostUser(useHost, useUser)
	if err != nil {
		return nil, err
	}

	return NewEntomb(key, hostUser)
}

func NewEntomb(key *fernet.Key, passphrase []byte) (*Entomb, error) {
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

	return &Entomb{
		key:                 key,
		encryptedPassphrase: encryptedPassphrase,
	}, nil
}

// Encrypts the message and returns the encrypted data
func (entomb *Entomb) Encrypt(msg []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedMsg, err := fernet.EncryptAndSign(msg, entomb.key)
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
		entomb.encryptedPassphrase,
		encryptedRandTail,
	)

	return finalData, nil
}

// Decrypts the data and returns the decrypted message
func (entomb *Entomb) Decrypt(data []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedRandTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	key, err := fernet.DecodeKeys(entomb.key.Encode())
	if err != nil {
		return nil, err
	}

	// Retrieve the encrypted message and the encrypted hashed host/user
	encryptedMsg := data[len(encryptedRandHead) : len(data)-(len(entomb.encryptedPassphrase)+len(encryptedRandTail))]
	encryptedHashedHostUser := data[len(encryptedRandHead)+len(encryptedMsg) : len(data)-len(encryptedRandTail)]
	decryptedHashedHostUser := fernet.VerifyAndDecrypt(encryptedHashedHostUser, 0, key)
	decryptedHashedHostUser2 := fernet.VerifyAndDecrypt(entomb.encryptedPassphrase, 0, key)

	if bytes.Equal(decryptedHashedHostUser, decryptedHashedHostUser2) {
		msg := fernet.VerifyAndDecrypt(encryptedMsg, 0, key)

		if msg != nil {
			return msg, nil
		}
	}

	return nil, errors.New("an error occurred during decryption")
}
