package entomb

import (
	"crypto/rand"
	"math/big"
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

// hashHostUser generates a SHA hash based on the host machine ID and/or the current user's username.
func hashHostUser(useHost bool, useUser bool) ([]byte, error) {
	hostUser, err := concatHostUser(useHost, useUser)
	if err != nil {
		return nil, err
	}

	hostUserHash, err := hashValue(hostUser)
	if err != nil {
		return nil, err
	}

	return hostUserHash, nil
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

func getRandomBytes() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(maxRandomHashDataSize))
	if err != nil {
		return nil, err
	}
	n = n.Add(n, big.NewInt(1000)) // Ensure at least 1000 bytes

	return n, nil
}
