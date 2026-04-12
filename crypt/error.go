package crypt

import "errors"

const (
	errMsgFormat = "%w: %w"
)

var (
	ErrEmptyKeyPath           = errors.New("key path is empty")
	ErrEmptyTombName          = errors.New("tomb name is empty")
	ErrEmptyTombPath          = errors.New("tomb path is empty")
	ErrEmptyTombsPath         = errors.New("tombs path is empty")
	ErrInitTombsPath          = errors.New("initializing tombs path failed")
	ErrInvalidDefaultTombName = errors.New("name can only contain alphanumeric, hyphens, underscores, and slashes")
	ErrInvalidPath            = errors.New("path contains invalid characters")
	ErrInvalidKeyPath         = errors.New("invalid key path")
	ErrInvalidTombName        = errors.New("invalid tomb name")
	ErrInvalidTombPath        = errors.New("invalid tomb path")
	ErrInvalidTombsPath       = errors.New("invalid tombs path")
	ErrMakeTombPath           = errors.New("making tomb path failed")
	ErrReadTomb               = errors.New("reading tomb failed")
	ErrWriteTomb              = errors.New("writing tomb failed")
	ErrRemoveFile             = errors.New("removing file failed")
	ErrRemoveTomb             = errors.New("removing tomb failed")
	ErrEncryptTomb            = errors.New("encrypting tomb failed")
	ErrDecryptTomb            = errors.New("decrypting tomb failed")
	ErrTombsPathNotDirectory  = errors.New("tombs path exists but is not a directory")
	ErrTombNotFound           = errors.New("tomb not found")
	ErrGetTombs               = errors.New("getting tombs from tombs path failed")
)
