// Package entomb allows for the encryption and decryption of data
// using the Fernet symmetric encryption algorithm. It includes
// additional salting, and hashing  to make it
// harder for attackers to brute-force the key.
//
// Anything encrypted with this package can only be decrypted by
// the original user and machine that encrypted it.
package entomb
