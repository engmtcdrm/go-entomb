package crypt

import (
	"errors"
	"regexp"
)

const (
	regexValidName = `^[\w\/\\\-]+$`
)

func DefaultValidateSecretName(s string) error {
	var re = regexp.MustCompile(regexValidName)

	if re.MatchString(s) {
		return nil
	}

	return errors.New("invalid secret name: Secret name can only contain alphanumeric, hyphens, underscores, and slashes")
}
