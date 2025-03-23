// Package entomb allows for the encryption and decryption of data
// using the Fernet symmetric encryption algorithm. It includes
// additional salting, hashing, and code obfuscation to make it
// harder for attackers to reverse-engineer the code.
//
// Anything encrypted with this package can only be decrypted by
// the original user and machine that encrypted it.
package entomb
