package internal

import "github.com/engmtcdrm/go-eggy"

var AllExamples = []eggy.Example{
	{Name: "New Key; Encrypt/Decrypt Example", Fn: NewKeyEncDecExample},
	{Name: "Existing Key; Encrypt/Decrypt Example", Fn: ExistingKeyEncDecExample},
	{Name: "Crypt Example", Fn: CryptExample},
}
