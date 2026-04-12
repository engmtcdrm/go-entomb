package crypt_test

import (
	"testing"

	"github.com/engmtcdrm/go-entomb/crypt"
	"github.com/stretchr/testify/require"
)

// Tests for [crypt.DefaultValidateTombName] function.
func Test_DefaultValidateTombName(t *testing.T) {
	t.Run("valid name", func(t *testing.T) {
		err := crypt.DefaultValidateTombName("valid_name-123")
		require.NoError(t, err)
	})

	t.Run("invalid name", func(t *testing.T) {
		err := crypt.DefaultValidateTombName("invalid.name")
		require.Error(t, err)
	})
}
