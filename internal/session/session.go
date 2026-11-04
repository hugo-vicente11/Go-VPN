package session

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session seals messages with one key and opens them with another, one for
// each direction of a tunnel. It is safe for concurrent use.
type Session struct {
	sendAEAD    cipher.AEAD
	recvAEAD    cipher.AEAD
	sendCounter atomic.Uint64
}

// Key is a symmetric key for sealing and opening transport data messages.
type Key [chacha20poly1305.KeySize]byte

const (
	messageType = 4
	// HeaderSize is the size of a transport data message header.
	HeaderSize     = 16
	receiverOffset = 4
	counterOffset  = 8
	receiverIndex  = 0
	// Overhead is the number of bytes Seal adds to a packet: the header and the tag.
	Overhead     = HeaderSize + chacha20poly1305.Overhead
	counterLimit = math.MaxUint64 - (1 << 13)
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

// New returns a Session that seals messages with send and opens them with
// recv. The peer's Session must use the same keys the other way around.
//
// Nonces are unique only within one Session: a new Session with the same
// send key starts its counter at 0 again and reuses nonces.
func New(send, recv Key) (*Session, error) {
	sendAEAD, err := chacha20poly1305.New(send[:])
	if err != nil {
		return nil, err
	}

	recvAEAD, err := chacha20poly1305.New(recv[:])
	if err != nil {
		return nil, err
	}

	session := Session{sendAEAD: sendAEAD, recvAEAD: recvAEAD}
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
	dst = binary.LittleEndian.AppendUint32(dst, messageType)
	dst = binary.LittleEndian.AppendUint32(dst, receiverIndex)
	dst = binary.LittleEndian.AppendUint64(dst, count)
	return s.sendAEAD.Seal(dst, nonce[:], packet, nil), nil
}

// Open authenticates and decrypts a transport data message, appends the
// packet to dst, and returns the updated slice. dst may be nil.
//
// It returns ErrShort, ErrType, or ErrAuth if msg is invalid. Callers
// should drop invalid messages without replying.
func (s *Session) Open(dst, msg []byte) ([]byte, error) {
	if len(msg) < Overhead {
		return nil, ErrShort
	}

	if binary.LittleEndian.Uint32(msg[:receiverOffset]) != messageType {
		return nil, ErrType
	}

	if binary.LittleEndian.Uint32(msg[receiverOffset:counterOffset]) != receiverIndex {
		return nil, ErrType
	}

	nonce := makeNonce(binary.LittleEndian.Uint64(msg[counterOffset:HeaderSize]))

	res, err := s.recvAEAD.Open(dst, nonce[:], msg[HeaderSize:], nil)
	if err != nil {
		return nil, ErrAuth
	}

	return res, nil
}

// ParseKey decodes a key in standard base64 with padding, the format
// produced by wg genkey. Surrounding whitespace, such as a trailing newline
// from a key file, is ignored. It returns an error if s is not valid base64
// or does not decode to exactly chacha20poly1305.KeySize bytes.
func ParseKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("session: key is not valid base64: %w", err)
	}

	if len(key) != chacha20poly1305.KeySize {
		return Key{}, fmt.Errorf("session: invalid key length: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}

	var res Key
	copy(res[:], key)

	return res, nil
}
