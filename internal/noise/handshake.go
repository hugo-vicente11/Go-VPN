package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
	"github.com/hugo-vicente11/go-vpn/internal/session"
)

// Handshake runs the WireGuard handshake with one peer, from this side.
//
// The initiator calls CreateInitiation, sends the message, and passes the
// reply to ConsumeResponse. The responder passes the initiation it receives
// to ConsumeInitiation, then calls CreateResponse and sends the result. Each
// side then calls NewSession for the session that carries the tunnel's
// packets. Methods called out of this order return an error. The same
// Handshake can then run the handshake again, for new keys.
//
// A Handshake is not safe for concurrent use.
//
// The first group of fields lasts across handshakes: the two static keys from
// the configuration, and the last timestamp accepted from the peer, which
// must outlive each handshake to stop replays. The second group belongs to
// the handshake in progress: each message sets it, and the next message
// continues from it.
type Handshake struct {
	localStatic   *identity.PrivateKey // this peer's identity
	localPublic   *identity.PublicKey  // localStatic's public key, computed once
	remoteStatic  *identity.PublicKey  // the peer's identity, known in advance
	lastTimestamp [12]byte             // newest TAI64N accepted from the peer
	presharedKey  [32]byte             // Q in the whitepaper, zero without a PSK

	state           *handshakeState      // C and H so far
	localEphemeral  *identity.PrivateKey // this side's ephemeral key
	localIndex      uint32               // this side's index, which the peer echoes
	remoteIndex     uint32               // the peer's index, to echo back
	remoteEphemeral *identity.PublicKey  // the peer's ephemeral key
	stage           handshakeStage       // the last step this side completed
}

// handshakeStage is the last step of the handshake that this side completed.
// Each step checks it, so that the messages can only come in order, and
// NewSession reads the role from it: only the initiator ends in
// responseConsumedStage, and only the responder in responseCreatedStage.
type handshakeStage uint8

// The stages, in the order of the handshake. The initiator goes through
// initiationCreatedStage and responseConsumedStage, and the responder through
// initiationConsumedStage and responseCreatedStage.
const (
	nothingStage            handshakeStage = iota // no handshake in progress
	initiationCreatedStage                        // CreateInitiation succeeded
	initiationConsumedStage                       // ConsumeInitiation succeeded
	responseCreatedStage                          // CreateResponse succeeded
	responseConsumedStage                         // ConsumeResponse succeeded
)

// Errors returned by the handshake, besides the ones from unmarshal,
// verifyMAC1 and decryption. Callers should drop the message without
// replying.
var (
	// errUnknownPeer means the message decrypted, so the sender knows this
	// peer's public key, but its static key is not the configured peer's.
	errUnknownPeer = errors.New("noise: static key is not the configured peer's")
	// errReplayedTimestamp means the timestamp is not newer than the last one
	// accepted, so the message may be an old one sent again.
	errReplayedTimestamp = errors.New("noise: timestamp is not more recent than the last one")
	// errNoInitiation means a response was asked for when the last step was
	// not accepting an initiation message: none was accepted, or it was
	// already answered.
	errNoInitiation = errors.New("noise: no initiation message was consumed")
	// errNoInitiationCreated means a response arrived when this side is not
	// waiting for one: it created no initiation message, or it already
	// consumed the response to it.
	errNoInitiationCreated = errors.New("noise: no initiation message was created")
	// errUnknownIndex means the response echoes an index other than the one
	// this side sent, so it answers some other initiation.
	errUnknownIndex = errors.New("noise: the response is not for the index of this handshake")
	// errUnfinishedHandshake means a session was asked for before the
	// handshake finished, so there are no transport keys yet.
	errUnfinishedHandshake = errors.New("noise: handshake has not finished yet")
)

// NewHandshake returns a handshake between localStatic, this peer's private
// key, and remoteStatic, the peer's public key. No message is created yet.
func NewHandshake(localStatic *identity.PrivateKey, remoteStatic *identity.PublicKey) *Handshake {
	return &Handshake{localStatic: localStatic, remoteStatic: remoteStatic, localPublic: localStatic.PublicKey()}
}

// createInitiationWith creates the initiation message, the first message of
// the handshake, as the initiator, following section 5.4.2 of the whitepaper.
// It takes the ephemeral key, the time and the index as arguments, so that
// tests can fix them; CreateInitiation picks them.
//
// The message gives the responder this side's ephemeral key in the clear, the
// static key encrypted after the es Diffie-Hellman, so that only the
// responder learns who is calling, and the timestamp encrypted after the ss
// Diffie-Hellman, which proves the sender holds localStatic and stops
// replays. mac1 is set with the responder's public key.
//
// On success it keeps the state, the ephemeral key and the index, which the
// response needs. On error, h is unchanged.
func (h *Handshake) createInitiationWith(ephemeral *identity.PrivateKey, now time.Time, index uint32) ([initiationSize]byte, error) {
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
	h.stage = initiationCreatedStage

	return b, nil
}

// LocalPublicKey returns this peer's static public key.
func (h *Handshake) LocalPublicKey() *identity.PublicKey {
	return h.localPublic
}

// PeerPublicKey returns the peer's static public key, the one this handshake
// was created with.
func (h *Handshake) PeerPublicKey() *identity.PublicKey {
	return h.remoteStatic
}

// Initiating reports whether this side sent an initiation and is waiting
// for its response.
func (h *Handshake) Initiating() bool {
	return h.stage == initiationCreatedStage
}

// CreateInitiation creates the initiation message with a new random ephemeral
// key, a random index and the current time. See createInitiationWith.
func (h *Handshake) CreateInitiation() ([]byte, error) {
	localEphemeral, err := identity.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	var randIndex [4]byte
	// rand.Read never returns an error: it crashes the program if the
	// operating system cannot provide random bytes.
	rand.Read(randIndex[:])
	index := binary.LittleEndian.Uint32(randIndex[:])
	now := time.Now()

	b, err := h.createInitiationWith(localEphemeral, now, index)
	if err != nil {
		return nil, err
	}

	return b[:], nil
}

// ConsumeInitiation reads an initiation message as the responder, the
// reverse of CreateInitiation. It runs the cheap checks first, so that
// junk costs no Diffie-Hellman: the format, then mac1 with this peer's own
// public key. It then repeats the initiator's steps from the other side: the
// es Diffie-Hellman decrypts the initiator's static key, which must be the
// configured peer's, and the ss Diffie-Hellman decrypts the timestamp, which
// must be newer than the last one accepted.
//
// On success both sides hold the same state, and it keeps the peer's
// ephemeral key and index for the response. On error, h is unchanged, so a
// forged message cannot disturb a real handshake or move lastTimestamp.
func (h *Handshake) ConsumeInitiation(b []byte) error {
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
	h.stage = initiationConsumedStage
	copy(h.lastTimestamp[:], timestamp)

	return nil
}

// createResponseWith creates the response message, the second message of the
// handshake, as the responder, following section 5.4.3 of the whitepaper. It
// continues from the state ConsumeInitiation left, and returns
// errNoInitiation if that was not the last step. It takes the ephemeral key
// and the index as arguments, so that tests can fix them; CreateResponse
// picks them.
//
// The message gives the initiator this side's ephemeral key in the clear. Two
// Diffie-Hellman results are mixed into the chaining key: ee, ephemeral with
// ephemeral, for forward secrecy, and se, this side's ephemeral with the
// initiator's static key, so that only the real initiator can follow. Then
// the preshared key gives the only encryption key of the message, which
// encrypts an empty field: its tag proves that this side reached the same
// state. mac1 is set with the initiator's public key.
//
// On success it keeps the state, the ephemeral key and the index, which
// transport data messages will carry. On error, h is unchanged.
func (h *Handshake) createResponseWith(ephemeral *identity.PrivateKey, index uint32) ([responseSize]byte, error) {
	var msg responseMessage

	if h.stage != initiationConsumedStage {
		return [responseSize]byte{}, errNoInitiation
	}

	state := *h.state
	pubEphemeral := ephemeral.PublicKey().Bytes()
	copy(msg.ephemeral[:], pubEphemeral)
	state.mixHash(pubEphemeral)
	state.mixKey(pubEphemeral)

	dhEE, err := ephemeral.SharedSecret(h.remoteEphemeral)
	if err != nil {
		return [responseSize]byte{}, err
	}
	state.mixKey(dhEE[:])

	dhSE, err := ephemeral.SharedSecret(h.remoteStatic)
	if err != nil {
		return [responseSize]byte{}, err
	}
	state.mixKey(dhSE[:])

	k := state.mixKeyAndHash(h.presharedKey[:])
	encryptedNothing := state.encryptAndHash(k, nil)
	copy(msg.encryptedNothing[:], encryptedNothing)

	msg.responderIndex = index
	msg.initiatorIndex = h.remoteIndex

	b := msg.marshal()
	setMAC1(b[:], responseMAC1Offset, mac1Key(h.remoteStatic))

	h.state = &state
	h.localIndex = index
	h.localEphemeral = ephemeral
	h.stage = responseCreatedStage

	return b, nil
}

// CreateResponse creates the response message with a new random ephemeral
// key and a random index. See createResponseWith.
func (h *Handshake) CreateResponse() ([]byte, error) {
	localEphemeral, err := identity.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	var randIndex [4]byte
	// rand.Read never returns an error: it crashes the program if the
	// operating system cannot provide random bytes.
	rand.Read(randIndex[:])
	index := binary.LittleEndian.Uint32(randIndex[:])

	b, err := h.createResponseWith(localEphemeral, index)
	if err != nil {
		return nil, err
	}

	return b[:], nil
}

// ConsumeResponse reads a response message as the initiator, the reverse of
// CreateResponse. It runs the cheap checks first: the format, mac1 with
// this peer's own public key, then that an initiation was created and that
// the response echoes its index. It then repeats the responder's steps from
// the other side: the ee and se Diffie-Hellman results and the preshared key
// go into the chaining key, and the tag of the empty field must check out.
// That tag proves the responder reached the same state, which needs the
// responder's private key from the es step of the initiation, so it also
// proves who answered.
//
// On success both sides hold the same state, ready for
// deriveTransportKeys, and it keeps the responder's ephemeral key and index,
// which transport data messages will carry. On error, h is unchanged. The
// same response consumed twice fails with errNoInitiationCreated, before any
// Diffie-Hellman, because this side is no longer waiting for one.
func (h *Handshake) ConsumeResponse(b []byte) error {
	var msg responseMessage
	err := msg.unmarshal(b)
	if err != nil {
		return err
	}

	err = verifyMAC1(b, responseMAC1Offset, mac1Key(h.localStatic.PublicKey()))
	if err != nil {
		return err
	}

	if h.stage != initiationCreatedStage {
		return errNoInitiationCreated
	}

	if msg.initiatorIndex != h.localIndex {
		return errUnknownIndex
	}

	state := *h.state

	state.mixHash(msg.ephemeral[:])
	state.mixKey(msg.ephemeral[:])

	remoteEphemeral, err := identity.NewPublicKey(msg.ephemeral[:])
	if err != nil {
		return err
	}

	dhEE, err := h.localEphemeral.SharedSecret(remoteEphemeral)
	if err != nil {
		return err
	}
	state.mixKey(dhEE[:])

	dhSE, err := h.localStatic.SharedSecret(remoteEphemeral)
	if err != nil {
		return err
	}
	state.mixKey(dhSE[:])

	k := state.mixKeyAndHash(h.presharedKey[:])

	_, err = state.decryptAndHash(k, msg.encryptedNothing[:])
	if err != nil {
		return err
	}

	h.state = &state
	h.remoteIndex = msg.responderIndex
	h.remoteEphemeral = remoteEphemeral
	h.stage = responseConsumedStage

	return nil
}

// NewSession returns the session for transport data messages once the
// handshake has finished: after ConsumeResponse on the initiator, or after
// CreateResponse on the responder. Before that, it returns
// errUnfinishedHandshake.
//
// Both sides derive the same two keys, and the stage tells which one this
// side seals with: the initiator seals with the first and the responder with
// the second. The session writes the peer's index and expects this side's.
//
// It then clears the handshake in progress, so that the ephemeral private key
// does not stay in memory, which forward secrecy depends on, and so that a
// second call fails instead of returning another session with the same keys,
// whose counter would start again at 0 and reuse nonces.
func (h *Handshake) NewSession() (*session.Session, error) {
	var sendKey, recvKey session.Key
	switch h.stage {
	case responseConsumedStage:
		sendKey, recvKey = h.state.deriveTransportKeys()
	case responseCreatedStage:
		recvKey, sendKey = h.state.deriveTransportKeys()
	default:
		return nil, errUnfinishedHandshake
	}

	h.state = nil
	h.localEphemeral = nil
	h.remoteEphemeral = nil
	h.stage = nothingStage

	return session.New(sendKey, recvKey, h.remoteIndex, h.localIndex)
}
