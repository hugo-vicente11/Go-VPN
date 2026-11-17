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
