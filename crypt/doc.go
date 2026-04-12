// Package crypt provides a vault for managing encrypted messages
// known as tombs. It builds on the entomb package to offer a
// higher-level interface for storing, retrieving, and organizing
// encrypted data on disk.
//
// A [Crypt] manages a collection of [Tomb] entries, each representing
// a named, encrypted message persisted as a file. Messages can be
// created (entombed), read (exhumed), and deleted (desecrated)
// through the Crypt API.
//
// Key features:
//   - Encrypt and store messages as tomb files with [Crypt.Entomb]
//   - Decrypt and retrieve messages with [Crypt.Exhume]
//   - Import messages directly from files with [Crypt.EntombFromFile]
//   - List all stored tombs with [Crypt.Epitaph]
//   - Delete individual or all tombs with [Crypt.Desecrate] and [Crypt.DesecrateAll]
//   - Configurable tomb file extensions and name validation
//   - Thread-safe access to the underlying tomb store
package crypt
