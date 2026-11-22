package noise

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
)

// handshake runs the WireGuard handshake with one peer, from this side.
//
// localStatic and remoteStatic come from the configuration and last for every
// handshake. The other fields belong to the handshake in progress: creating a
// message sets them, and the next message continues from them.
type handshake struct {
	localStatic  *identity.PrivateKey // this peer's identity
	remoteStatic *identity.PublicKey  // the peer's identity, known in advance

	state          *handshakeState      // C and H so far
	localEphemeral *identity.PrivateKey // this side's ephemeral key
	localIndex     uint32               // this side's index, which the peer echoes
}

// newHandshake returns a handshake between localStatic, this peer's private
// key, and remoteStatic, the peer's public key. No message is created yet.
func newHandshake(localStatic *identity.PrivateKey, remoteStatic *identity.PublicKey) *handshake {
	return &handshake{localStatic: localStatic, remoteStatic: remoteStatic}
}

// createInitiationWith creates the initiation message, the first message of
// the handshake, as the initiator, following section 5.4.2 of the whitepaper.
// It takes the ephemeral key, the time and the index as arguments, so that
// tests can fix them; createInitiation picks them.
//
// The message gives the responder this side's ephemeral key in the clear, the
// static key encrypted after the es Diffie-Hellman, so that only the
// responder learns who is calling, and the timestamp encrypted after the ss
// Diffie-Hellman, which proves the sender holds localStatic and stops
// replays. mac1 is set with the responder's public key.
//
// On success it keeps the state, the ephemeral key and the index, which the
// response needs. On error, h is unchanged.
func (h *handshake) createInitiationWith(ephemeral *identity.PrivateKey, now time.Time, index uint32) ([initiationSize]byte, error) {
	state := newHandshakeState(h.remoteStatic)
	var msg initiationMessage
	pubEphemeral := ephemeral.PublicKey().Bytes()
	copy(msg.ephemeral[:], pubEphemeral)
	state.mixHash(msg.ephemeral[:])
	state.mixKey(msg.ephemeral[:])

	dhES, err := ephemeral.SharedSecret(h.remoteStatic)
	if err != nil {
		return [initiationSize]byte{}, err
	}

	k := state.mixKeyAndGetKey(dhES[:])
	encryptedStatic := state.encryptAndHash(k, h.localStatic.PublicKey().Bytes())
	copy(msg.encryptedStatic[:], encryptedStatic)

	dhSS, err := h.localStatic.SharedSecret(h.remoteStatic)
	if err != nil {
		return [initiationSize]byte{}, err
	}

	k = state.mixKeyAndGetKey(dhSS[:])
	timestamp := tai64n(now)
	encryptedTimestamp := state.encryptAndHash(k, timestamp[:])
	copy(msg.encryptedTimestamp[:], encryptedTimestamp)

	msg.initiatorIndex = index

	b := msg.marshal()
	setMAC1(b[:], initiationMAC1Offset, mac1Key(h.remoteStatic))

	h.state = state
	h.localEphemeral = ephemeral
	h.localIndex = index

	return b, nil
}

// createInitiation creates the initiation message with a new random ephemeral
// key, a random index and the current time. See createInitiationWith.
func (h *handshake) createInitiation() ([initiationSize]byte, error) {
	localEphemeral, err := identity.GeneratePrivateKey()
	if err != nil {
		return [initiationSize]byte{}, err
	}

	var randIndex [4]byte
	// rand.Read never returns an error: it crashes the program if the
	// operating system cannot provide random bytes.
	rand.Read(randIndex[:])
	index := binary.LittleEndian.Uint32(randIndex[:])
	now := time.Now()

	return h.createInitiationWith(localEphemeral, now, index)
}
