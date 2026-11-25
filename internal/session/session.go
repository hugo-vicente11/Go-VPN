package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session seals messages with one key and opens them with another, one for
// each direction of a tunnel. Open accepts each message at most once. It is
// safe for concurrent use.
type Session struct {
	sendAEAD     cipher.AEAD
	recvAEAD     cipher.AEAD
	sendCounter  atomic.Uint64
	replayWindow replayWindow
	localIndex   uint32 // this side's index, which Open expects
	remoteIndex  uint32 // the peer's index, which Seal writes
}

// Key is a symmetric key for sealing and opening transport data messages.
type Key [chacha20poly1305.KeySize]byte

const (
	// DataMessageType is the type of a transport data message, in its first 4
	// bytes as a little-endian uint32, like the handshake message types.
	DataMessageType = 4
	// HeaderSize is the size of a transport data message header.
	HeaderSize     = 16
	receiverOffset = 4
	counterOffset  = 8
	// Overhead is the number of bytes Seal adds to a packet: the header and the tag.
	Overhead     = HeaderSize + chacha20poly1305.Overhead
	counterLimit = math.MaxUint64 - (1 << 13)
)

// Errors returned by Open and Seal.
var (
	// ErrShort means the message is shorter than a header and tag.
	ErrShort = errors.New("session: message too short")
	// ErrType means the message is not a transport data message.
	ErrType = errors.New("session: invalid message type")
	// ErrAuth means the message failed authentication: it was modified,
	// corrupted, or sealed with a different key.
	ErrAuth = errors.New("session: message authentication failed")
	// ErrCounterExhausted means the session has sealed too many messages
	// and must not be used to send again.
	ErrCounterExhausted = errors.New("session: reached counter limit")
	// ErrReplay means the message was already opened, or is too old for the
	// replay window to tell whether it was.
	ErrReplay = errors.New("session: replayed or too old message")
	// ErrWrongIndex means the message is for another receiver index, so it
	// belongs to another session.
	ErrWrongIndex = errors.New("session: message is for another receiver index")
)

// New returns a Session that seals messages with send and opens them with
// recv. The peer's Session must use the same keys the other way around.
//
// remoteIndex is the index the peer chose in the handshake: Seal writes it in
// the receiver field of every message, so the peer can tell which of its
// sessions the message is for. localIndex is the index this side chose: Open
// rejects messages that do not carry it. Each index sits in the same position
// as the key it goes with, and the peer's Session takes the same two indices
// the other way around.
//
// Nonces are unique only within one Session: a new Session with the same
// send key starts its counter at 0 again and reuses nonces.
func New(send, recv Key, remoteIndex, localIndex uint32) (*Session, error) {
	sendAEAD, err := chacha20poly1305.New(send[:])
	if err != nil {
		return nil, err
	}

	recvAEAD, err := chacha20poly1305.New(recv[:])
	if err != nil {
		return nil, err
	}

	session := Session{sendAEAD: sendAEAD, recvAEAD: recvAEAD, localIndex: localIndex, remoteIndex: remoteIndex}
	return &session, nil
}

// makeNonce returns the nonce for counter: 4 zero bytes followed by the
// counter in little-endian order.
func makeNonce(counter uint64) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// Seal encrypts packet into a transport data message and appends it to dst,
// returning the updated slice. dst may be nil.
//
// Each call uses the next counter value as the nonce. Once Seal returns
// ErrCounterExhausted, the caller must stop sending with this Session.
func (s *Session) Seal(dst, packet []byte) ([]byte, error) {
	count := s.sendCounter.Add(1) - 1
	if count >= counterLimit {
		return nil, ErrCounterExhausted
	}

	nonce := makeNonce(count)
	dst = binary.LittleEndian.AppendUint32(dst, DataMessageType)
	dst = binary.LittleEndian.AppendUint32(dst, s.remoteIndex)
	dst = binary.LittleEndian.AppendUint64(dst, count)
	return s.sendAEAD.Seal(dst, nonce[:], packet, nil), nil
}

// Open authenticates and decrypts a transport data message, appends the
// packet to dst, and returns the updated slice. dst may be nil.
//
// It returns ErrShort, ErrType, ErrWrongIndex, or ErrAuth if msg is invalid,
// and ErrReplay if msg was already opened or is too old to tell. The index is
// checked before decrypting, so a message for another session costs no
// decryption. Callers should drop
// invalid messages without replying.
func (s *Session) Open(dst, msg []byte) ([]byte, error) {
	if len(msg) < Overhead {
		return nil, ErrShort
	}

	if binary.LittleEndian.Uint32(msg[:receiverOffset]) != DataMessageType {
		return nil, ErrType
	}

	if binary.LittleEndian.Uint32(msg[receiverOffset:counterOffset]) != s.localIndex {
		return nil, ErrWrongIndex
	}

	counter := binary.LittleEndian.Uint64(msg[counterOffset:HeaderSize])
	nonce := makeNonce(counter)

	res, err := s.recvAEAD.Open(dst, nonce[:], msg[HeaderSize:], nil)
	if err != nil {
		return nil, ErrAuth
	}

	if s.replayWindow.accept(counter) != nil {
		return nil, ErrReplay
	}

	return res, nil
}
