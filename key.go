package entomb

import (
	"github.com/fernet/fernet-go"
)

// Key represents an encryption key with its associated Fernet key and encrypted passphrase.
type Key struct {
	FernetKey           *fernet.Key
	EncryptedPassphrase []byte
}
