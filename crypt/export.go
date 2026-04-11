package crypt

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
)

func (c *Crypt) export(exportFilePrefix, passphrase string) error {
	if len(c.tombs) == 0 {
		return nil
	}

	exportDate := time.Now().Format("20060102_150405")
	exportTombsFilename := joinFileName("-", exportDate, exportFilePrefix, "export.crypt")
	exportKeyFilename := joinFileName("-", exportDate, exportFilePrefix, "export.key")
	exportPassphraseFilename := joinFileName("-", exportDate, exportFilePrefix, "export.passphrase")

	exportBasePath := filepath.Base(c.tombsPath)
	exportTombsPath := filepath.Join(exportBasePath, exportTombsFilename)
	exportKeyPath := filepath.Join(exportBasePath, exportKeyFilename)
	exportPassphrasePath := filepath.Join(exportBasePath, exportPassphraseFilename)
	_, _, _ = exportTombsPath, exportKeyPath, exportPassphrasePath

	var exportKey fernet.Key

	if err := exportKey.Generate(); err != nil {
		return err
	}

	for _, tomb := range c.tombs {
		_ = tomb
	}

	return nil
}

func exportTomb(exportKey fernet.Key, tomb *Tomb) error {
	return nil
}

func joinFileName(sep string, parts ...string) string {
	return strings.Join(parts, sep)
}
