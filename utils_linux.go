//go:build linux
// +build linux

package entomb

import (
	"os"
)

func machineId() ([]byte, error) {
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		mid, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil {
			return nil, err
		}
	}

	return mid, nil
}
