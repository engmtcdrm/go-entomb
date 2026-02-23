package crypt

import (
	"fmt"
	"regexp"
)

const (
	regexValidName = `^[\w\/\\\-]+$`
)

// DefaultValidateTombName checks if the tomb name contains only valid characters. Valid
// characters are alphanumeric, hyphens, underscores, and slashes.
func DefaultValidateTombName(s string) error {
	var re = regexp.MustCompile(regexValidName)

	if re.MatchString(s) {
		return nil
	}

	return fmt.Errorf(errMsgFormat, ErrInvalidTombName, ErrInvalidDefaultTombName)
}
