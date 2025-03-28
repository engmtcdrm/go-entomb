<!-- Code generated by gomarkdoc. DO NOT EDIT -->

[![Go](https://github.com/engmtcdrm/go-entomb/actions/workflows/test.yml/badge.svg)](https://github.com/engmtcdrm/go-entomb/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/engmtcdrm/go-entomb.svg?label=Latest%20Release)](https://github.com/engmtcdrm/go-entomb/releases/latest)

# entomb

```go
import "github.com/engmtcdrm/go-entomb"
```

Package entomb allows for the encryption and decryption of data using the Fernet symmetric encryption algorithm. It includes additional salting, hashing, and code obfuscation to make it harder for attackers to reverse\-engineer the code.

Anything encrypted with this package can only be decrypted by the original user and machine that encrypted it.

## Index

- [type Tomb](<#Tomb>)
  - [func NewTomb\(keyPath string\) \(\*Tomb, error\)](<#NewTomb>)
  - [func \(tomb \*Tomb\) Decrypt\(data \[\]byte\) \(\[\]byte, error\)](<#Tomb.Decrypt>)
  - [func \(tomb \*Tomb\) Encrypt\(msg \[\]byte\) \(\[\]byte, error\)](<#Tomb.Encrypt>)


<a name="Tomb"></a>
## type [Tomb](<https://github.com/engmtcdrm/go-entomb/blob/master/entomb.go#L183-L186>)

Encryptor/Decryptor

Into the depths we dive, where the secrets lie...

```go
type Tomb struct {
    // contains filtered or unexported fields
}
```

<a name="NewTomb"></a>
### func [NewTomb](<https://github.com/engmtcdrm/go-entomb/blob/master/entomb.go#L193>)

```go
func NewTomb(keyPath string) (*Tomb, error)
```

Creates a new Tomb

The keyPath is the path to the key file. If the key file does not exist, a new key will be generated and saved to the key file. If the key file exists, the key will be read from the file.

<a name="Tomb.Decrypt"></a>
### func \(\*Tomb\) [Decrypt](<https://github.com/engmtcdrm/go-entomb/blob/master/entomb.go#L259>)

```go
func (tomb *Tomb) Decrypt(data []byte) ([]byte, error)
```

Decrypts the data and returns the decrypted message

<a name="Tomb.Encrypt"></a>
### func \(\*Tomb\) [Encrypt](<https://github.com/engmtcdrm/go-entomb/blob/master/entomb.go#L228>)

```go
func (tomb *Tomb) Encrypt(msg []byte) ([]byte, error)
```

Encrypts the message and returns the encrypted data

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)
