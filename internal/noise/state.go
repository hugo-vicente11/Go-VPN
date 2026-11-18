package noise

import "github.com/hugo-vicente11/go-vpn/internal/identity"

// handshakeState is the state each peer keeps during a handshake: the
// chaining key C and the hash H from the whitepaper.
//
// C accumulates the secrets: every Diffie-Hellman result is mixed into it, so
// only the two peers can compute it. H accumulates the transcript: everything
// sent is mixed into it, and it is the associated data of every encrypted
// field, so a change to any earlier byte makes decryption fail.
//
// Both fields are arrays, so copying a handshakeState gives an independent
// copy.
type handshakeState struct {
	chainKey [32]byte
	hash     [32]byte
}

// newHandshakeState returns the state a handshake starts from:
//
//	C = Ci
//	H = HASH(Hi || Spub_r)
//
// responderStatic is the responder's static public key on both sides: the
// initiator passes its peer's key, and the responder its own. The initiator
// knows this key before the handshake starts, the "K" in IK, so both peers
// begin with the same state before any message is sent.
func newHandshakeState(responderStatic *identity.PublicKey) *handshakeState {
	return &handshakeState{chainKey: initialChainKey, hash: hash(initialHash[:], responderStatic.Bytes())}
}

// mixHash mixes data into the hash: H = HASH(H || data). It does not change
// the chaining key. The handshake uses it for each ephemeral public key, each
// encrypted field (the ciphertext, not the plaintext) and the value the
// preshared key step derives.
func (s *handshakeState) mixHash(data []byte) {
	s.hash = hash(s.hash[:], data)
}

// mixKey mixes input into the chaining key: C = KDF1(C, input). It does not
// change the hash. The handshake uses it when nothing is encrypted right
// after: for each ephemeral public key and the responder's two DH results.
func (s *handshakeState) mixKey(input []byte) {
	s.chainKey = kdf1(s.chainKey, input)
}

// mixKeyAndGetKey mixes input into the chaining key and returns a key for the
// next encrypted field: C, k = KDF2(C, input). It does not change the hash.
// The initiator uses it for its two DH results, before it encrypts its static
// key and the timestamp.
func (s *handshakeState) mixKeyAndGetKey(input []byte) [32]byte {
	c, k := kdf2(s.chainKey, input)
	s.chainKey = c
	return k
}

// mixKeyAndHash mixes input into both the chaining key and the hash, and
// returns a key for the next encrypted field: C, t, k = KDF3(C, input), then
// H = HASH(H || t). The responder uses it once, for the preshared key.
func (s *handshakeState) mixKeyAndHash(input []byte) [32]byte {
	c, t, k := kdf3(s.chainKey, input)
	s.chainKey = c
	s.mixHash(t[:])

	return k
}
