package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/engmtcdrm/go-entomb"
)

func main() {
	tempDir, err := os.MkdirTemp("", "test-")
	if err != nil {
		panic(err)
	}
	defer func() {
		if removeError := os.RemoveAll(tempDir); removeError != nil {
			err = fmt.Errorf("failed to remove temp dir: %w", removeError)
		}
	}()

	t, err := entomb.NewTomb(filepath.Join(tempDir, ".key"))
	if err != nil {
		panic(err)
	}

	msg := "Hello, World!"

	fmt.Printf("Message to encrypt: %s\n", msg)

	// Encrypt a string
	encrypted, err := t.Encrypt([]byte(msg))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted: %s\n", encrypted)

	// Decrypt the string
	decrypted, err := t.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}
