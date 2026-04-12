package crypt_test

import (
	"testing"

	"github.com/engmtcdrm/go-entomb/crypt"
	"github.com/stretchr/testify/require"
)

// Tests for [crypt.NewTomb] function.
func Test_NewTomb(t *testing.T) {
	t.Run("create tomb", func(t *testing.T) {
		name := "mytomb"
		path := "/path/to/mytomb"
		tomb, err := crypt.NewTomb(name, path)
		require.NoError(t, err)
		require.Equal(t, name, tomb.Name())
		require.Equal(t, path, tomb.Path())
	})

	t.Run("create tomb with empty name", func(t *testing.T) {
		name := ""
		path := "/path/to/mytomb"
		tomb, err := crypt.NewTomb(name, path)
		require.Error(t, err)
		require.Nil(t, tomb)
	})

	t.Run("create tomb with empty path", func(t *testing.T) {
		name := "mytomb"
		path := ""
		tomb, err := crypt.NewTomb(name, path)
		require.Error(t, err)
		require.Nil(t, tomb)
	})
}
