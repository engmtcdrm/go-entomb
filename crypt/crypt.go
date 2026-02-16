package crypt

import (
	"errors"
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
	validateTombNameFn func(name string) bool
}

func NewCrypt(keyPath string, tombsPath string, useHost, useUser bool) (*Crypt, error) {
	if keyPath == "" {
		return nil, errors.New("key path is empty")
	}

	if tombsPath == "" {
		return nil, errors.New("tombs path is empty")
	}

	key, err := entomb.GetKeyHostUser(keyPath, useHost, useUser)
	if err != nil {
		return nil, err
	}

	c := &Crypt{
		key:                key,
		tombs:              make(map[string]*Tomb, 0),
		tombFileExt:        ".tomb",
		validateTombNameFn: nil,
	}

	if err := c.initializeTombsPath(tombsPath); err != nil {
		return nil, err
	}

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
		return errors.New("tomb not found")
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

// Entomb encrypts the given message and saves it as a tomb with the given name. It returns
// an error if the tomb name is invalid, if there is an issue encrypting the message, or if
// there is an issue saving the tomb file.
func (c *Crypt) Entomb(name string, msg []byte) error {
	fullPath := filepath.Join(c.tombsPath, name+c.tombFileExt)
	absFullPath, err := cleanAbsPath(fullPath)
	if err != nil {
		return err
	}

	if isInvalidPath(absFullPath) {
		return errors.New("invalid tomb name")
	}

	// TODO: Run validateTombNameFn if set, ignore for now since it is not currently used

	encMsg, err := entomb.Encrypt(c.key, msg)
	if err != nil {
		return err
	}

	c.tombMu.Lock()
	defer c.tombMu.Unlock()

	err = os.MkdirAll(filepath.Dir(absFullPath), DirFilePerms)
	if err != nil {
		return err
	}

	err = os.WriteFile(absFullPath, encMsg, FilePerms)
	if err != nil {
		return err
	}

	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()

	c.tombs[name] = NewTomb(name, absFullPath)
	c.tombsLastModTime = time.Now()

	return nil
}

// Exhume retrieves and decrypts the message from the tomb with the given name. It returns an
// error if the tomb does not exist, if there is an issue reading the tomb file, or if there
// is an issue decrypting the message.
func (c *Crypt) Exhume(name string) ([]byte, error) {
	c.tombsMu.RLock()
	tomb, exists := c.tombs[name]
	c.tombsMu.RUnlock()

	if !exists {
		return nil, errors.New("tomb not found")
	}

	encMsg, err := os.ReadFile(tomb.Path())
	if err != nil {
		return nil, err
	}

	msg, err := entomb.Decrypt(c.key, encMsg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// initializeTombsPath validates the tombs path, creates it if it doesn't exist,
// and sets the absolute path to the struct.
func (c *Crypt) initializeTombsPath(tombsPath string) error {
	if isInvalidPath(tombsPath) {
		return errors.New("invalid tombs path")
	}

	absPath, err := cleanAbsPath(tombsPath)
	if err != nil {
		return err
	}

	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()

	statPath, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(absPath, DirFilePerms)
			if err != nil {
				return err
			}

			c.tombsPath = absPath

			return nil
		}

		return err
	}

	if !statPath.IsDir() {
		return errors.New("tombs path exists but is not a directory")
	}

	c.tombsPath = absPath

	return nil
}

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
			absPath, err := cleanAbsPath(path)
			if err != nil {
				return err
			}

			tombs[name] = NewTomb(name, absPath)
		}

		return nil
	})
	if err != nil {
		return err
	}

	c.tombsMu.Lock()
	defer c.tombsMu.Unlock()

	c.tombs = tombs
	c.tombsLastModTime = time.Now()

	return nil
}
