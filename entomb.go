package entomb

import (
	"bytes"
	"errors"
	"os/user"

	"github.com/fernet/fernet-go"
)

// The code below is intentionally uncommented in an attempt to obfuscate and
// make it harder to understand. There are intentional redundant calls to try
// again, to obfuscate the code even further.

// Encryptor/Decryptor
//
// Into the depths we dive, where the secrets lie...
type Tomb struct {
	hu string
	k  fernet.Key
}

// Creates a new Tomb
//
// The keyPath is the path to the key file. If the key file does not exist, a new
// key will be generated and saved to the key file. If the key file exists, the key
// will be read from the file.
// The useHost and useUser parameters determine whether the hostname and username
// should be included when encrypting/decrypting.
func NewTomb(keyPath string, useHost bool, useUser bool) (*Tomb, error) {
	var err error
	var h []byte
	var hu string

	if useHost {
		h, err = machineId()
		if err != nil {
			return nil, err
		}

		hu = string(h)
	}

	if useUser {
		cu, err := user.Current()
		if err != nil {
			return nil, err
		}

		hu += cu.Username
	}

	k, err := createReadKey(keyPath, hu)
	if err != nil {
		return nil, err
	}

	return &Tomb{
		hu: hu,
		k:  k,
	}, nil
}

// Encrypts the message and returns the encrypted data
func (tomb *Tomb) Encrypt(msg []byte) ([]byte, error) {
	e1, err := getRandEncrypt(size)
	if err != nil {
		return nil, err
	}

	e2, err := fernet.EncryptAndSign(msg, &tomb.k)
	if err != nil {
		return nil, err
	}
	msg = nil

	hs, err := hashSHA([]byte(tomb.hu))
	if err != nil {
		return nil, err
	}

	e3, err := fernet.EncryptAndSign(hs, &tomb.k)
	if err != nil {
		return nil, err
	}

	enc4, err := getRandEncrypt(size)
	if err != nil {
		return nil, err
	}

	return append(append(append(e1, e2...), e3...), enc4...), nil
}

// Decrypts the data and returns the decrypted message
func (tomb *Tomb) Decrypt(data []byte) ([]byte, error) {
	e1, err := getRandEncrypt(size)
	if err != nil {
		return nil, err
	}

	hs, err := hashSHA([]byte(tomb.hu))
	if err != nil {
		return nil, err
	}

	e2, err := fernet.EncryptAndSign(hs, &tomb.k)
	if err != nil {
		return nil, err
	}

	e3, err := getRandEncrypt(size)
	if err != nil {
		return nil, err
	}

	td := data[len(e1) : len(data)-(len(e2)+len(e3))]
	hud := data[len(e1)+len(td) : len(data)-len(e3)]

	k, err := fernet.DecodeKeys(tomb.k.Encode())
	if err != nil {
		return nil, err
	}

	if tomb.checkPerms(fernet.VerifyAndDecrypt(hud, 0, k)) {
		msg := fernet.VerifyAndDecrypt(td, 0, k)

		if msg != nil {
			return msg, nil
		}
	}

	return nil, errors.New("an error occurred during decryption")
}

// Checks the permissions of the user
func (tomb *Tomb) checkPerms(checkData []byte) bool {
	hs, err := hashSHA([]byte(tomb.hu))
	if err != nil {
		return false
	}

	return bytes.Equal(checkData, hs)
}
