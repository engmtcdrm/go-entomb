package entomb

import (
	"bytes"
	"errors"
	"slices"

	"github.com/fernet/fernet-go"
)

// Encrypts the message and returns the encrypted data.
func Encrypt(key *Key, msg []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedMsg, err := fernet.EncryptAndSign(msg, key.FernetKey)
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
		key.EncryptedPassphrase,
		encryptedRandTail,
	)

	return finalData, nil
}

// Decrypts the data and returns the decrypted message.
func Decrypt(key *Key, data []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedRandTail, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	keys, err := fernet.DecodeKeys(key.FernetKey.Encode())
	if err != nil {
		return nil, err
	}

	// Retrieve the encrypted message and the encrypted hashed passphrase
	encryptedMsg := data[len(encryptedRandHead) : len(data)-(len(key.EncryptedPassphrase)+len(encryptedRandTail))]
	encryptedHashedPassphrase := data[len(encryptedRandHead)+len(encryptedMsg) : len(data)-len(encryptedRandTail)]
	decryptedHashedPassphrase := fernet.VerifyAndDecrypt(encryptedHashedPassphrase, 0, keys)
	decryptedKeyPhassphrase := fernet.VerifyAndDecrypt(key.EncryptedPassphrase, 0, keys)

	if bytes.Equal(decryptedHashedPassphrase, decryptedKeyPhassphrase) {
		msg := fernet.VerifyAndDecrypt(encryptedMsg, 0, keys)
		if msg != nil {
			return msg, nil
		}
	}

	return nil, errors.New("an error occurred during decryption")
}
