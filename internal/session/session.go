package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session encrypts and decrypts transport data messages with a single key.
// It is safe for concurrent use.
type Session struct {
	aead    cipher.AEAD
	counter atomic.Uint64
}

const (
	messageType        = 4
	headerSize         = 16
	receiverOffset     = 4
	counterOffset      = 8
	receiverIndex      = 0
	minimumMessageSize = headerSize + chacha20poly1305.Overhead
	counterLimit       = math.MaxUint64 - (1 << 13)
)

// Errors returned by Open and Seal.
var (
	// ErrShort means the message is shorter than a header and tag.
	ErrShort = errors.New("session: message too short")
	// ErrType means the message is not a transport data message for this session.
	ErrType = errors.New("session: invalid message type")
	// ErrAuth means the message failed authentication: it was modified,
	// corrupted, or sealed with a different key.
	ErrAuth = errors.New("session: message authentication failed")
	// ErrCounterExhausted means the session has sealed too many messages
	// and must not be used to send again.
	ErrCounterExhausted = errors.New("session: reached counter limit")
)

// New returns a Session that seals and opens messages with key.
func New(key [32]byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}

	session := Session{aead: aead}
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
	count := s.counter.Add(1) - 1
	if count >= counterLimit {
		return nil, ErrCounterExhausted
	}

	nonce := makeNonce(count)
	dst = binary.LittleEndian.AppendUint32(dst, messageType)
	dst = binary.LittleEndian.AppendUint32(dst, receiverIndex)
	dst = binary.LittleEndian.AppendUint64(dst, count)
	return s.aead.Seal(dst, nonce[:], packet, nil), nil
}

// Open authenticates and decrypts a transport data message, appends the
// packet to dst, and returns the updated slice. dst may be nil.
//
// It returns ErrShort, ErrType, or ErrAuth if msg is invalid. Callers
// should drop invalid messages without replying.
func (s *Session) Open(dst, msg []byte) ([]byte, error) {
	if len(msg) < minimumMessageSize {
		return nil, ErrShort
	}

	if binary.LittleEndian.Uint32(msg[:receiverOffset]) != messageType {
		return nil, ErrType
	}

	if binary.LittleEndian.Uint32(msg[receiverOffset:counterOffset]) != receiverIndex {
		return nil, ErrType
	}

	nonce := makeNonce(binary.LittleEndian.Uint64(msg[counterOffset:headerSize]))

	res, err := s.aead.Open(dst, nonce[:], msg[headerSize:], nil)
	if err != nil {
		return nil, ErrAuth
	}

	return res, nil
}
