package entomb

import (
	"crypto/rand"
	"crypto/sha512"
	"log"
	"math/big"
	"slices"

	"github.com/fernet/fernet-go"
)

const maxRandomHashDataSize = 9901 // Magic number for maximum random hash data size

var hashSize int

func init() {
	hash, err := hashValue(nil)
	if err != nil {
		log.Fatalf("Failed to generate hash: %v", err)
	}
	hashSize = len(hash)
}

// getRandomEncrypt generates random data of size s, encrypts it with a random
// Fernet key, and returns the encrypted data.
func getRandomEncrypt(s int) ([]byte, error) {
	d := make([]byte, s)
	_, err := rand.Read(d)
	if err != nil {
		return nil, err
	}

	var key fernet.Key
	if err := key.Generate(); err != nil {
		return nil, err
	}

	t, err := fernet.EncryptAndSign(d, &key)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func saltValue(key fernet.Key, data []byte, passphrase []byte) ([]byte, error) {
	encryptedRandHead, err := getRandomEncrypt(maxRandomHashDataSize)
	if err != nil {
		return nil, err
	}

	encryptedRandHash, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encryptedPassphrase, err := fernet.EncryptAndSign(passphrase, &key)
	if err != nil {
		return nil, err
	}

	encryptedRandTail, err := getRandomEncrypt(maxRandomHashDataSize)
	if err != nil {
		return nil, err
	}

	saltData := slices.Concat(
		encryptedRandHead,
		encryptedRandHash,
		data,
		encryptedPassphrase,
		encryptedRandTail,
	)

	return saltData, nil
}

// hashValue returns a hash of the given data. If data is nil or empty, it
// generates random data with a length between 1000 and [maxRandomHashDataSize]
// bytes to hash.
func hashValue(data []byte) ([]byte, error) {
	if data == nil {
		data = []byte{}
	}

	if len(data) == 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(maxRandomHashDataSize))
		if err != nil {
			return nil, err
		}
		n = n.Add(n, big.NewInt(1000)) // Ensure at least 1000 bytes

		data = make([]byte, n.Int64())
		_, err = rand.Read(data)
		if err != nil {
			return nil, err
		}
	}

	h := sha512.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
