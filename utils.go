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

	"github.com/fernet/fernet-go"
)

// The code below is intentionally uncommented in an attempt to obfuscate and
// make it harder to understand. There are intentional redundant calls to try
// again, to obfuscate the code even further.

var size int

func init() {
	hash, err := hashSHA()
	if err != nil {
		log.Fatalf("Failed to generate hash: %v", err)
	}
	size = len(hash)
}

func getRandEncrypt(s int) ([]byte, error) {
	d := make([]byte, s)
	_, err := rand.Read(d)
	if err != nil {
		return nil, err
	}

	var k fernet.Key
	if err := k.Generate(); err != nil {
		return nil, err
	}

	t, err := fernet.EncryptAndSign(d, &k)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func saltValue(k fernet.Key, data []byte, hu []byte) ([]byte, error) {
	r, err := rand.Int(rand.Reader, big.NewInt(9001))
	if err != nil {
		return nil, err
	}
	r = r.Add(r, big.NewInt(1000))

	e1, err := getRandEncrypt(int(r.Int64()))
	if err != nil {
		return nil, err
	}

	e2, err := getRandEncrypt(size)
	if err != nil {
		return nil, err
	}

	hs, err := hashSHA([]byte(hu))
	if err != nil {
		return nil, err
	}

	e3, err := fernet.EncryptAndSign(hs, &k)
	if err != nil {
		return nil, err
	}

	e4, err := getRandEncrypt(int(r.Int64()))
	if err != nil {
		return nil, err
	}

	return append(append(append(append(e1, e2...), data...), e3...), e4...), nil
}

func createReadKey(keyPath string, hu string) (fernet.Key, error) {
	var k fernet.Key

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		slog.Debug("Key file does not exist. Creating a new key.")

		if err := k.Generate(); err != nil {
			return fernet.Key{}, err
		}

		sk, err := saltValue(k, []byte(k.Encode()), []byte(hu))
		if err != nil {
			return fernet.Key{}, err
		}

		if err = os.WriteFile(keyPath, sk, 0600); err != nil {
			return fernet.Key{}, err
		}

		return k, nil
	} else {
		slog.Debug("Key file exists. Reading key from file.")

		d, err := os.ReadFile(keyPath)
		if err != nil {
			return fernet.Key{}, err
		}

		e1, err := getRandEncrypt(size)
		if err != nil {
			return fernet.Key{}, err
		}

		e2, err := getRandEncrypt(size)
		if err != nil {
			return fernet.Key{}, err
		}

		if err := k.Generate(); err != nil {
			return fernet.Key{}, err
		}

		ld := (len(d) - (len(e1) + len(k.Encode()) + len(e2))) / 2
		d = d[ld : len(d)-ld]
		kd := d[len(e1) : len(e1)+len(k.Encode())]
		hue := d[len(e1)+len(k.Encode()):]

		k3, err := fernet.DecodeKeys(string(kd))
		if err != nil {
			return fernet.Key{}, err
		}

		hud := fernet.VerifyAndDecrypt(hue, 0, k3)

		hs, err := hashSHA([]byte(hu))
		if err != nil {
			return fernet.Key{}, err
		}

		if !bytes.Equal(hud, hs) {
			return fernet.Key{}, errors.New("an error occurred during key verification")
		}

		return *k3[0], nil
	}
}

func hashSHA(data ...[]byte) ([]byte, error) {
	var d2h []byte

	if len(data) == 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(9901))
		if err != nil {
			return nil, err
		}
		n = n.Add(n, big.NewInt(100))

		d2h = make([]byte, n.Int64())
		_, err = rand.Read(d2h)
		if err != nil {
			return nil, err
		}
	} else {
		d2h = data[0]
	}

	h := sha512.New()

	h.Write(d2h)

	return h.Sum(nil), nil
}
