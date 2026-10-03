// Package secretbox encrypts the secrets conductor-sync keeps in its state
// database (the Google service account key set through the management
// API): AES-256-GCM with a random nonce per value and the secret's name as
// additional data, so a ciphertext cannot be moved to another name. The
// key comes from systemd credentials (LoadCredential=) or a 0600 file and
// never reaches the database.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// KeySize is the key length (AES-256).
const KeySize = 32

// Box seals and opens values.
type Box struct{ aead cipher.AEAD }

// ParseKey accepts a key file's content: 32 raw bytes, or 64 hex digits,
// or standard base64 of 32 bytes (surrounding whitespace ignored), so
// `head -c 32 /dev/urandom` and `openssl rand -hex 32` both work.
func ParseKey(b []byte) ([]byte, error) {
	if len(b) == KeySize {
		return b, nil
	}
	s := strings.TrimSpace(string(b))
	if k, err := hex.DecodeString(s); err == nil && len(k) == KeySize {
		return k, nil
	}
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == KeySize {
		return k, nil
	}
	return nil, errors.New("secretbox: the state key must be 32 bytes (raw, 64 hex digits or base64)")
}

// New builds a box from a key file's content.
func New(keyFile []byte) (*Box, error) {
	k, err := ParseKey(keyFile)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext for name.
func (b *Box) Seal(name string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, b.aead.Seal(nil, nonce, plaintext, []byte(name)), nil
}

// ErrDecrypt is a value that does not open with this key (wrong key,
// tampered value, or a value stored under another name).
var ErrDecrypt = errors.New("secretbox: cannot decrypt (wrong state key or tampered value)")

// Open decrypts a value sealed for name.
func (b *Box) Open(name string, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != b.aead.NonceSize() {
		return nil, ErrDecrypt
	}
	out, err := b.aead.Open(nil, nonce, ciphertext, []byte(name))
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}
