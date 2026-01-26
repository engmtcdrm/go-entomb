package entomb

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"log"
	"log/slog"
	"math/big"
	"os"
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

func saltValue(key fernet.Key, data []byte, hostUserHash []byte) ([]byte, error) {
	encRandomHead, err := getRandomEncrypt(maxRandomHashDataSize)
	if err != nil {
		return nil, err
	}

	encRandomHash, err := getRandomEncrypt(hashSize)
	if err != nil {
		return nil, err
	}

	encHostUser, err := fernet.EncryptAndSign(hostUserHash, &key)
	if err != nil {
		return nil, err
	}

	encRandomTail, err := getRandomEncrypt(maxRandomHashDataSize)
	if err != nil {
		return nil, err
	}

	finalData := slices.Concat(encRandomHead, encRandomHash, data, encHostUser, encRandomTail)

	return finalData, nil
}

func createReadKey(keyPath string, hostUserHash []byte) (fernet.Key, error) {
	var key fernet.Key

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		slog.Debug("Key file does not exist. Creating a new key.")

		if err := key.Generate(); err != nil {
			return fernet.Key{}, err
		}

		sk, err := saltValue(key, []byte(key.Encode()), hostUserHash)
		if err != nil {
			return fernet.Key{}, err
		}

		if err = os.WriteFile(keyPath, sk, 0600); err != nil {
			return fernet.Key{}, err
		}

		return key, nil
	} else {
		slog.Debug("Key file exists. Reading key from file.")

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
