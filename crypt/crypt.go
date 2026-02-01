package crypt

import (
	"sync"
	"time"

	"github.com/engmtcdrm/go-entomb"
)

type Crypt struct {
	key *entomb.Key

	tombsPath        string
	tombs            map[string]string
	tombsMutex       sync.RWMutex
	tombsLastModTime time.Time

	tombMutex   sync.RWMutex
	tombFileExt string
}

func NewCrypt(keyPath string, tombsPath string, useHost, useUser bool) (*Crypt, error) {
	key, err := entomb.GetKeyHostUser(keyPath, useHost, useUser)
	if err != nil {
		return nil, err
	}

	return &Crypt{
		key:         key,
		tombs:       make(map[string]string, 0),
		tombsPath:   tombsPath,
		tombFileExt: ".tomb",
	}, nil
}
