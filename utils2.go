package entomb

import (
	"os/user"
	"strings"
)

func concatHostUser(useHost bool, useUser bool) ([]byte, error) {
	var hostUser string
	var err error

	if useHost {
		hostUser, err = getHost()
		if err != nil {
			return nil, err
		}
	}

	if useUser {
		cu, err := user.Current()
		if err != nil {
			return nil, err
		}

		hostUser += cu.Username
	}

	return []byte(hostUser), nil
}

// getHost retrieves the machine ID of the host system.
func getHost() (string, error) {
	host, err := machineId()
	if err != nil {
		return "", err
	}

	// Remove newlines and tabs from machine ID
	replacer := strings.NewReplacer(
		"\n", "",
		"\t", "",
		"\r", "",
	)
	hostStr := replacer.Replace(string(host))
	return hostStr, nil
}
