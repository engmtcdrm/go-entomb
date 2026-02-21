package crypt_test

import (
	"testing"

	"github.com/engmtcdrm/go-entomb/crypt"
	"github.com/stretchr/testify/assert"
)

func TestNewTomb(t *testing.T) {
	t.Run("create tomb", func(t *testing.T) {
		name := "mytomb"
		path := "/path/to/mytomb"
		tomb, err := crypt.NewTomb(name, path)
		assert.NoError(t, err)
		assert.Equal(t, name, tomb.Name())
		assert.Equal(t, path, tomb.Path())
	})

	t.Run("create tomb with empty name", func(t *testing.T) {
		name := ""
		path := "/path/to/mytomb"
		tomb, err := crypt.NewTomb(name, path)
		assert.Error(t, err)
		assert.Nil(t, tomb)
	})

	t.Run("create tomb with empty path", func(t *testing.T) {
		name := "mytomb"
		path := ""
		tomb, err := crypt.NewTomb(name, path)
		assert.Error(t, err)
		assert.Nil(t, tomb)
	})
}
