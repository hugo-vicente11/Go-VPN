// Package identity handles the X25519 key pairs that identify a peer. Each
// peer keeps its private key secret and gives its public key to the other
// peer.
package identity

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// PrivateKey is a peer's X25519 private key. It must never leave the peer.
//
// The zero value is not a valid key: create one with GeneratePrivateKey or
// ParsePrivateKey.
type PrivateKey struct {
	key *ecdh.PrivateKey
}

// PublicKey is a peer's X25519 public key. It is not secret, and is given to
// the other peer so it can identify this one.
//
// The zero value is not a valid key: get one from PrivateKey.PublicKey or
// ParsePublicKey.
type PublicKey struct {
	key *ecdh.PublicKey
}

// GeneratePrivateKey generates a new random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	c := ecdh.X25519()
	privKey, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generating private key: %w", err)
	}

	privStruct := PrivateKey{key: privKey}

	return &privStruct, nil
}

// PublicKey returns the public key that belongs to k.
func (k *PrivateKey) PublicKey() *PublicKey {
	pubKey := PublicKey{key: k.key.PublicKey()}
	return &pubKey
}

// ParsePrivateKey decodes a private key in standard base64 with padding, the
// format Encode and wg genkey produce. Surrounding whitespace, such as a
// trailing newline from a key file, is ignored.
func ParsePrivateKey(s string) (*PrivateKey, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("identity: private key is not valid base64: %w", err)
	}

	privKey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("identity: private key is not valid: %w", err)
	}

	return &PrivateKey{key: privKey}, nil
}

// ParsePublicKey decodes a public key in standard base64 with padding, the
// format String and wg pubkey produce. Surrounding whitespace is ignored.
//
// It checks only the format and length. Some public keys that pass, such as
// all zeros, are unsafe to use; the Diffie-Hellman step rejects them.
func ParsePublicKey(s string) (*PublicKey, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("identity: public key is not valid base64: %w", err)
	}

	pubKey, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("identity: public key is not valid: %w", err)
	}

	return &PublicKey{key: pubKey}, nil
}

// String returns k in standard base64 with padding.
func (k *PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k.key.Bytes())
}

// Encode returns k in standard base64 with padding.
//
// PrivateKey has no String method on purpose, so that printing or logging a
// private key by mistake does not reveal it.
func (k *PrivateKey) Encode() string {
	return base64.StdEncoding.EncodeToString(k.key.Bytes())
}

// SharedSecret computes the X25519 Diffie-Hellman shared secret between k and
// peer, as specified in RFC 7748, section 6.1. Both peers get the same secret:
// a.SharedSecret(b.PublicKey()) equals b.SharedSecret(a.PublicKey()).
//
// It returns an error if peer is a low-order point, such as all zeros, which
// would make the secret all zeros whatever the private key is.
//
// The secret is not uniformly random, so it must not be used directly as an
// encryption key: pass it through a key derivation function such as HKDF.
func (k *PrivateKey) SharedSecret(peer *PublicKey) ([32]byte, error) {
	secretBytes, err := k.key.ECDH(peer.key)
	if err != nil {
		return [32]byte{}, fmt.Errorf("identity: computing shared secret: %w", err)
	}

	return [32]byte(secretBytes), nil
}
