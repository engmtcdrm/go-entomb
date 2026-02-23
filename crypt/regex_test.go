package crypt_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/engmtcdrm/go-entomb/crypt"
)

// Tests for [crypt.DefaultValidateTombName] function.
func TestDefaultValidateTombName(t *testing.T) {
	t.Run("valid name", func(t *testing.T) {
		err := crypt.DefaultValidateTombName("valid_name-123")
		assert.NoError(t, err)
	})

	t.Run("invalid name", func(t *testing.T) {
		err := crypt.DefaultValidateTombName("invalid.name")
		assert.Error(t, err)
	})
}
