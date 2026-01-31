//go:build windows
// +build windows

package entomb

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func machineId() ([]byte, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	mid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return nil, err
	}

	return []byte(mid), nil
}

// isValidPath checks for characters that are not allowed in Windows file paths.
func isValidPath(path string) bool {
	return !isInvalidPath(path)
}

// isInvalidPath checks for characters that are not allowed in Windows file paths.
func isInvalidPath(path string) bool {
	return strings.ContainsAny(path, `<>:"/\|?*`)
}
