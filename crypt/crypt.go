package crypt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/engmtcdrm/go-entomb"
)

const (
	DirFilePerms = 0700
	FilePerms    = 0600
)

type Crypt struct {
	key *entomb.Key

	tombsPath        string
	tombs            map[string]*Tomb
	tombsMu          sync.RWMutex
	tombsLastModTime time.Time

	tombMu             sync.RWMutex
	tombFileExt        string
	validateTombNameFn func(name string) error
}

func NewCrypt(keyPath string, tombsPath string, useHost, useUser bool) (*Crypt, error) {
	if keyPath == "" {
		return nil, ErrEmptyKeyPath
	}

	if tombsPath == "" {
		return nil, ErrEmptyTombsPath
	}

	cleanKeyPath, err := cleanAndValidatePath(keyPath)
	if err != nil {
		return nil, fmt.Errorf(errMsgFormat, ErrInvalidKeyPath, err)
	}

	key, err := entomb.GetKeyHostUser(cleanKeyPath, useHost, useUser)
	if err != nil {
		return nil, err
	}

	c := &Crypt{
		key:                key,
		tombs:              make(map[string]*Tomb, 0),
		tombFileExt:        ".tomb",
		validateTombNameFn: DefaultValidateTombName,
	}

	c.tombsPath, err = cleanAndValidatePath(tombsPath)
	if err != nil {
		return nil, fmt.Errorf(errMsgFormat, ErrInvalidTombsPath, err)
	}

	if err := c.initializeTombsPath(); err != nil {
		return nil, err
	}

	if err := c.getTombs(); err != nil {
		return nil, err
	}

	return c, nil
}

// ValidateTombNameFunc sets a custom function to validate tomb names.
func (c *Crypt) ValidateTombNameFunc(f func(name string) error) (*Crypt, error) {
	c.validateTombNameFn = f

	if err := c.getTombs(); err != nil {
		return nil, err
	}

	return c, nil
}

// TombFileExt sets the file extension for tomb files. It returns an error if there is an
// issue retrieving the tombs after changing the extension.
func (c *Crypt) TombFileExt(ext string) (*Crypt, error) {
	c.tombFileExt = ext

	if err := c.getTombs(); err != nil {
		return nil, err
	}

	return c, nil
}

// Desecrate deletes the tomb with the given name. It returns an error if the tomb does
// not exist or if there is an issue deleting the tomb file.
func (c *Crypt) Desecrate(name string) error {
	c.tombsMu.RLock()
	tomb, exists := c.tombs[name]
	c.tombsMu.RUnlock()

	if !exists {
		return ErrTombNotFound
	}

	err := os.Remove(tomb.Path())
	if err != nil {
		return err
	}

	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()
	delete(c.tombs, name)

	c.tombsLastModTime = time.Now()

	return nil
}

// DesecrateAll deletes all tombs. It returns an error if there is an issue deleting
// the tomb files.
func (c *Crypt) DesecrateAll() error {
	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()
	if err := os.RemoveAll(c.tombsPath); err != nil {
		return err
	}

	c.tombs = make(map[string]*Tomb, 0)
	c.tombsLastModTime = time.Now()

	return nil
}

// Entomb encrypts the given message and saves it as a tomb with the given name. It returns
// an error if the tomb name is invalid, if there is an issue encrypting the message, or if
// there is an issue saving the tomb file.
func (c *Crypt) Entomb(name string, msg []byte) error {
	if name == "" {
		return ErrEmptyTombName
	}

	if err := c.validateName(name); err != nil {
		return err
	}

	fullPath := filepath.Join(c.tombsPath, name+c.tombFileExt)
	absFullPath, err := cleanAndValidatePath(fullPath)
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrInvalidTombPath, err)
	}

	encMsg, err := entomb.Encrypt(c.key, msg)
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrEncryptTomb, err)
	}

	c.tombMu.Lock()
	defer c.tombMu.Unlock()

	err = os.MkdirAll(filepath.Dir(absFullPath), DirFilePerms)
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrMakeTombPath, err)
	}

	err = os.WriteFile(absFullPath, encMsg, FilePerms)
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrWriteTomb, err)
	}

	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()

	c.tombs[name], err = c.newTomb(name)
	if err != nil {
		return err
	}

	c.tombsLastModTime = time.Now()

	return nil
}

// EntombFromFile reads the content of the file at filePath, encrypts it, and saves it as a
// tomb with the given name. If cleanup is true, it deletes the original file after
// successfully creating the tomb. It returns an error if the tomb name is invalid, if
// there is an issue reading the file, encrypting the message, saving the tomb file, or
// deleting the original file.
func (c *Crypt) EntombFromFile(name string, filePath string, cleanup bool) error {
	if name == "" {
		return ErrEmptyTombName
	}

	if err := c.validateName(name); err != nil {
		return err
	}

	if filePath == "" {
		return ErrEmptyTombPath
	}

	rawFile, err := cleanAndValidatePath(filePath)
	if err != nil {
		return err
	}

	msgBytes, err := os.ReadFile(rawFile)
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrReadTomb, err)
	}

	msgBytes = trimSpaceBytes(&msgBytes)
	encMsg, err := entomb.Encrypt(c.key, msgBytes)
	clearMsg(&msgBytes)
	if err != nil {
		return err
	}

	tomb, err := c.newTomb(name)
	if err != nil {
		return err
	}

	newTombPath := filepath.Dir(tomb.Path())

	err = os.MkdirAll(newTombPath, DirFilePerms)
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrMakeTombPath, err)
	}

	if err = os.WriteFile(tomb.Path(), encMsg, FilePerms); err != nil {
		return fmt.Errorf(errMsgFormat, ErrWriteTomb, err)
	}

	if cleanup {
		if err = os.Remove(rawFile); err != nil {
			return fmt.Errorf(errMsgFormat, ErrRemoveFile, err)
		}
	}

	return nil
}

// Epitaph returns a slice of all tombs. It returns an empty slice if there are no tombs.
func (c *Crypt) Epitaph() []*Tomb {
	c.tombsMu.RLock()
	defer c.tombsMu.RUnlock()

	var tombs []*Tomb
	for _, tomb := range c.tombs {
		tombs = append(tombs, tomb)
	}

	return tombs
}

// Exhume retrieves and decrypts the message from the tomb with the given name. It returns an
// error if the tomb does not exist, if there is an issue reading the tomb file, or if there
// is an issue decrypting the message.
func (c *Crypt) Exhume(name string) ([]byte, error) {
	if name == "" {
		return nil, ErrEmptyTombName
	}

	if err := c.validateName(name); err != nil {
		return nil, err
	}

	c.tombsMu.RLock()
	tomb, exists := c.tombs[name]
	c.tombsMu.RUnlock()

	if !exists {
		return nil, ErrTombNotFound
	}

	encMsg, err := os.ReadFile(tomb.Path())
	if err != nil {
		return nil, fmt.Errorf(errMsgFormat, ErrReadTomb, err)
	}

	msg, err := entomb.Decrypt(c.key, encMsg)
	if err != nil {
		return nil, fmt.Errorf(errMsgFormat, ErrDecryptTomb, err)
	}

	return msg, nil
}

// initializeTombsPath validates the tombs path, creates it if it doesn't exist,
// and sets the absolute path to the struct.
func (c *Crypt) initializeTombsPath() error {
	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()

	statPath, err := os.Stat(c.tombsPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(c.tombsPath, DirFilePerms)
			if err != nil {
				return fmt.Errorf(errMsgFormat, ErrInitTombsPath, err)
			}

			return nil
		}

		return fmt.Errorf(errMsgFormat, ErrInitTombsPath, err)
	}

	if !statPath.IsDir() {
		return ErrTombsPathNotDirectory
	}

	return nil
}

// getTombs scans the tombs path for tomb files and updates the tombs map. It returns an error
// if there is an issue accessing the tombs path or reading the tomb files.
func (c *Crypt) getTombs() error {
	tombs := make(map[string]*Tomb, 0)

	err := filepath.WalkDir(c.tombsPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(path) == c.tombFileExt && !d.IsDir() {
			relPath, err := filepath.Rel(c.tombsPath, path)
			if err != nil {
				return err
			}

			name := strings.TrimSuffix(relPath, c.tombFileExt)
			absPath, err := cleanAndValidatePath(path)
			if err != nil {
				return err
			}

			if err := c.validateName(name); err != nil {
				return err
			}

			tombs[name], err = NewTomb(name, absPath)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf(errMsgFormat, ErrGetTombs, err)
	}

	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()

	c.tombs = tombs
	c.tombsLastModTime = time.Now()

	return nil
}

// newTomb creates a new Tomb instance with the given name and path.
func (c *Crypt) newTomb(name string) (*Tomb, error) {
	return NewTomb(
		name,
		filepath.Join(c.tombsPath, name+c.tombFileExt),
	)
}

// validateName checks if the tomb name is valid using both path validation and
// the custom validation function if it is set.
func (c *Crypt) validateName(name string) error {
	if isInvalidPath(name) {
		return ErrInvalidTombName
	}

	if err := c.validateTombNameFn(name); err != nil {
		return err
	}

	return nil
}
