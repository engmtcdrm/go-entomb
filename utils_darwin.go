//go:build darwin
// +build darwin

package entomb

import (
	"bytes"
	"net"
	"os/exec"
)

func machineId() ([]byte, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err == nil {
		for _, line := range bytes.Split(out, []byte("\n")) {
			if bytes.Contains(line, []byte("IOPlatformUUID")) {
				parts := bytes.Split(line, []byte{byte('"')})
				if len(parts) > 3 {
					return parts[3], nil
				}
			}
		}
	}

	// Fallback: use MAC address of first active interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr, nil
		}
	}

	return nil, nil // No UUID or MAC found
}
