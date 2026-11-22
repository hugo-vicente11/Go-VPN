package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
)

// handshake runs the WireGuard handshake with one peer, from this side.
//
// The first group of fields lasts across handshakes: the two static keys from
// the configuration, and the last timestamp accepted from the peer, which
// must outlive each handshake to stop replays. The second group belongs to
// the handshake in progress: each message sets it, and the next message
// continues from it.
type handshake struct {
	localStatic   *identity.PrivateKey // this peer's identity
	remoteStatic  *identity.PublicKey  // the peer's identity, known in advance
	lastTimestamp [12]byte             // newest TAI64N accepted from the peer

	state           *handshakeState      // C and H so far
	localEphemeral  *identity.PrivateKey // this side's ephemeral key
	localIndex      uint32               // this side's index, which the peer echoes
	remoteIndex     uint32               // the peer's index, to echo back
	remoteEphemeral *identity.PublicKey  // the peer's ephemeral key
}

// Errors returned when consuming a handshake message, besides the ones from
// unmarshal, verifyMAC1 and decryption. Callers should drop the message
// without replying.
var (
	// errUnknownPeer means the message decrypted, so the sender knows this
	// peer's public key, but its static key is not the configured peer's.
	errUnknownPeer = errors.New("noise: static key is not the configured peer's")
	// errReplayedTimestamp means the timestamp is not newer than the last one
	// accepted, so the message may be an old one sent again.
	errReplayedTimestamp = errors.New("noise: timestamp is not more recent than the last one")
)

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

// consumeInitiation reads an initiation message as the responder, the
// reverse of createInitiationWith. It runs the cheap checks first, so that
// junk costs no Diffie-Hellman: the format, then mac1 with this peer's own
// public key. It then repeats the initiator's steps from the other side: the
// es Diffie-Hellman decrypts the initiator's static key, which must be the
// configured peer's, and the ss Diffie-Hellman decrypts the timestamp, which
// must be newer than the last one accepted.
//
// On success both sides hold the same state, and it keeps the peer's
// ephemeral key and index for the response. On error, h is unchanged, so a
// forged message cannot disturb a real handshake or move lastTimestamp.
func (h *handshake) consumeInitiation(b []byte) error {
	var msg initiationMessage
	err := msg.unmarshal(b)
	if err != nil {
		return err
	}

	err = verifyMAC1(b, initiationMAC1Offset, mac1Key(h.localStatic.PublicKey()))
	if err != nil {
		return err
	}

	state := newHandshakeState(h.localStatic.PublicKey())
	state.mixHash(msg.ephemeral[:])
	state.mixKey(msg.ephemeral[:])
	remoteEphemeral, err := identity.NewPublicKey(msg.ephemeral[:])
	if err != nil {
		return err
	}

	dhES, err := h.localStatic.SharedSecret(remoteEphemeral)
	if err != nil {
		return err
	}

	k := state.mixKeyAndGetKey(dhES[:])
	static, err := state.decryptAndHash(k, msg.encryptedStatic[:])
	if err != nil {
		return err
	}

	if !bytes.Equal(static, h.remoteStatic.Bytes()) {
		return errUnknownPeer
	}

	dhSS, err := h.localStatic.SharedSecret(h.remoteStatic)
	if err != nil {
		return err
	}

	k = state.mixKeyAndGetKey(dhSS[:])

	timestamp, err := state.decryptAndHash(k, msg.encryptedTimestamp[:])
	if err != nil {
		return err
	}

	if bytes.Compare(timestamp, h.lastTimestamp[:]) <= 0 {
		return errReplayedTimestamp
	}

	h.state = state
	h.remoteEphemeral = remoteEphemeral
	h.remoteIndex = msg.initiatorIndex
	copy(h.lastTimestamp[:], timestamp)

	return nil
}
