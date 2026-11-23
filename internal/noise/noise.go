// Package noise implements the WireGuard handshake, as defined in section 5.4
// of the WireGuard whitepaper: two peers that know each other's static public
// keys exchange two messages and get a session.Session with fresh keys. See
// Handshake.
package noise

import (
	gohmac "crypto/hmac"
	"errors"
	gohash "hash"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol names from section 5.4 of the whitepaper. Every WireGuard peer
// uses the same values, so a typo here breaks every handshake.
const (
	construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	identifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1    = "mac1----"
)

// initialChainKey and initialHash are Ci and Hi from the whitepaper, the
// state every handshake starts from.
var (
	initialChainKey = hash([]byte(construction))
	initialHash     = hash(initialChainKey[:], []byte(identifier))
)

// errDecrypt means an encrypted handshake field failed authentication: the
// key, the associated data or the ciphertext is not what the sender used. It
// does not say which, because the AEAD cannot tell them apart.
var errDecrypt = errors.New("noise: decryption failed")

// newBLAKE2s returns an unkeyed BLAKE2s-256 hash, for gohmac.New. It never
// panics in practice: New256 fails only with a key longer than 32 bytes, and
// the key here is nil.
func newBLAKE2s() gohash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// sum writes each piece of data to h in order and returns the result, which
// is the same as hashing all the pieces joined together. It ignores the
// errors from Write, because hash.Hash documents that Write never returns one.
func sum(h gohash.Hash, data [][]byte) []byte {
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// hash returns HASH(data) from the whitepaper: BLAKE2s with a 32-byte output.
// The handshake uses it to compute the initial chaining key and hash, and in
// MixHash to keep a running hash of every message sent.
func hash(data ...[]byte) [32]byte {
	return [32]byte(sum(newBLAKE2s(), data))
}

// mac returns MAC(key, data) from the whitepaper: keyed BLAKE2s with a 16-byte
// output. It is not hmac: keyed BLAKE2s is a mode of BLAKE2s itself, and gives
// a different result. The handshake uses it for the mac1 field.
//
// The key is always 32 bytes for mac1. The mac2 field of cookie replies would
// need a 16-byte key instead.
func mac(key [32]byte, data ...[]byte) [16]byte {
	h, err := blake2s.New128(key[:])
	if err != nil {
		// New128 fails only with an empty key or one longer than 32 bytes.
		panic(err)
	}
	return [16]byte(sum(h, data))
}

// mac1Key returns the key for the mac1 field of a handshake message:
// HASH(labelMAC1 || Spub), where Spub is the static public key of the peer
// that receives the message. The sender uses the peer's key, and the receiver
// its own.
//
// The result depends only on the public key, so each peer can compute it once
// per key and reuse it for every message.
func mac1Key(k *identity.PublicKey) [32]byte {
	return hash([]byte(labelMAC1), k.Bytes())
}

// hmac returns HMAC(key, data) from the whitepaper: HMAC with BLAKE2s and a
// 32-byte output. The handshake uses it only inside the key derivation
// functions.
func hmac(key [32]byte, data ...[]byte) [32]byte {
	return [32]byte(sum(gohmac.New(newBLAKE2s, key[:]), data))
}

// kdf1 returns KDF1(key, input) from the whitepaper: one 32-byte output.
// The handshake uses it to mix a value into the chaining key when nothing is
// encrypted right after.
//
// The KDF functions are HKDF (RFC 5869) with BLAKE2s: extract with key as the
// salt, then expand with an empty info.
func kdf1(key [32]byte, input []byte) [32]byte {
	t0 := hmac(key, input)
	t1 := hmac(t0, []byte{0x1})
	return t1
}

// kdf2 returns KDF2(key, input) from the whitepaper: two 32-byte outputs.
// The handshake uses it to update the chaining key and get a key for the next
// encrypted field, and at the end to derive the two transport keys.
func kdf2(key [32]byte, input []byte) ([32]byte, [32]byte) {
	t0 := hmac(key, input)
	t1 := hmac(t0, []byte{0x1})
	t2 := hmac(t0, t1[:], []byte{0x2})

	return t1, t2
}

// kdf3 returns KDF3(key, input) from the whitepaper: three 32-byte outputs.
// The handshake uses it once, to mix in the preshared key.
func kdf3(key [32]byte, input []byte) ([32]byte, [32]byte, [32]byte) {
	t0 := hmac(key, input)
	t1 := hmac(t0, []byte{0x1})
	t2 := hmac(t0, t1[:], []byte{0x2})
	t3 := hmac(t0, t2[:], []byte{0x3})

	return t1, t2, t3
}

// aeadEncrypt returns AEAD(key, 0, plaintext, associatedData) from the
// whitepaper: ChaCha20-Poly1305 with a counter of 0, so the nonce is 12 zero
// bytes. The result is the ciphertext followed by a 16-byte tag, so it is 16
// bytes longer than plaintext; an empty plaintext gives just the tag.
//
// The handshake uses it to encrypt the initiator's static key, the timestamp
// and the empty field of the response, with the hash H as associatedData.
//
// A fixed nonce is safe only because each key encrypts a single field: the
// handshake derives a new key with a KDF before every call. Never call it
// twice with the same key.
func aeadEncrypt(key [32]byte, plaintext, associatedData []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		// New fails only with a key that is not 32 bytes long.
		panic(err)
	}

	var nonce [chacha20poly1305.NonceSize]byte
	return aead.Seal(nil, nonce[:], plaintext, associatedData)
}

// aeadDecrypt reverses aeadEncrypt: it checks the tag and returns the
// plaintext. It returns errDecrypt if key or associatedData is not the one the
// sender used, or if ciphertext was changed or is shorter than a tag.
func aeadDecrypt(key [32]byte, ciphertext, associatedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		// New fails only with a key that is not 32 bytes long.
		panic(err)
	}

	var nonce [chacha20poly1305.NonceSize]byte

	msg, err := aead.Open(nil, nonce[:], ciphertext, associatedData)
	if err != nil {
		return nil, errDecrypt
	}

	return msg, nil
}
