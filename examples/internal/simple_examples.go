package internal

import (
	"fmt"
	"os"
	"path"

	pp "github.com/engmtcdrm/go-prettyprint"

	"github.com/engmtcdrm/go-entomb"
)

func NewKeyEncDecExample() {
	tempDir, err := os.MkdirTemp("", "test-")
	if err != nil {
		panic(err)
	}
	defer func() {
		if removeError := os.RemoveAll(tempDir); removeError != nil {
			err = fmt.Errorf("failed to remove temp dir: %w", removeError)
		}
	}()

	keyPath := path.Join(tempDir, "___key.key")

	fmt.Print("Creating new key...\n\n")

	t, err := entomb.NewTomb(keyPath, true, false)
	if err != nil {
		panic(err)
	}

	msg := "Hello, World!"

	fmt.Printf("Message to encrypt: %s\n\n", pp.Green(msg))

	// Encrypt a string
	encrypted, err := t.Encrypt([]byte(msg))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted message: %s\n\n", pp.Green(string(encrypted)))

	// Decrypt the string
	decrypted, err := t.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted message: %s\n", pp.Green(string(decrypted)))
}

func ExistingKeyEncDecExample() {
	tempDir, err := os.MkdirTemp("", "test-")
	if err != nil {
		panic(err)
	}
	defer func() {
		if removeError := os.RemoveAll(tempDir); removeError != nil {
			err = fmt.Errorf("failed to remove temp dir: %w", removeError)
		}
	}()

	keyPath := path.Join(tempDir, "___key.key")

	fmt.Println("Creating new key...")

	// Create a new tomb to generate and save the key
	t, err := entomb.NewTomb(keyPath, true, false)
	if err != nil {
		panic(err)
	}

	fmt.Print("Now using the new key from previous step...\n\n")

	// Now create a new tomb instance using the existing key
	t, err = entomb.NewTomb(keyPath, true, false)
	if err != nil {
		panic(err)
	}

	msg := "Hello, World!"

	fmt.Printf("Message to encrypt: %s\n\n", pp.Green(msg))

	// Encrypt a string
	encrypted, err := t.Encrypt([]byte(msg))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted message: %s\n\n", pp.Green(string(encrypted)))

	// Decrypt the string
	decrypted, err := t.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted message: %s\n", pp.Green(string(decrypted)))
}
