//go:build linux

package entomb

import (
	"os"
)

func machineID() ([]byte, error) {
	mid, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		return mid, nil
	}

	mid, err = os.ReadFile("/var/lib/dbus/machine-id")
	if err == nil {
		return mid, nil
	}

	midStr, err := os.Hostname()
	if err == nil {
		return []byte(midStr), nil
	}

	return []byte("localhost"), nil
}
