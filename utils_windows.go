//go:build windows
// +build windows

package entomb

import (
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
