package noise

import (
	gohmac "crypto/hmac"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// Message types, the first byte of each handshake message. The 3 bytes after
// it are reserved and always zero, so the first 4 bytes read as a
// little-endian uint32 equal the type.
const (
	initiationType = 1
	responseType   = 2
)

// Sizes of the handshake messages, from section 5.4 of the whitepaper.
const (
	initiationSize = 148
	responseSize   = 92
)

// Offsets of the mac1 field. mac1 is computed over every byte before it.
const (
	initiationMAC1Offset = 116
	responseMAC1Offset   = 60
)

// Errors returned by unmarshal. Callers should drop the message without
// replying.
var (
	// errMessageSize means the message is not exactly the size of its type.
	errMessageSize = errors.New("noise: invalid message size")
	// errMessageType means the first 4 bytes are not the expected type
	// followed by 3 zero bytes.
	errMessageType = errors.New("noise: invalid message type")
	// errInvalidMAC1 means the mac1 field is not the one computed with the
	// receiver's public key: the sender does not know that key, or the
	// message was changed.
	errInvalidMAC1 = errors.New("noise: invalid mac1")
)

// initiationMessage is the first handshake message, from the initiator to
// the responder. The comments give each field's name in the whitepaper. The
// encrypted fields are as long as their plaintext plus a 16-byte tag.
type initiationMessage struct {
	initiatorIndex     uint32                               // sender
	ephemeral          [32]byte                             // unencrypted_ephemeral
	encryptedStatic    [32 + chacha20poly1305.Overhead]byte // encrypted_static
	encryptedTimestamp [12 + chacha20poly1305.Overhead]byte // encrypted_timestamp
	mac1               [16]byte                             // mac1
	mac2               [16]byte                             // mac2, zero without a cookie
}

// marshal returns m in the wire format: the type and reserved bytes, then
// each field in order, with the index in little-endian.
func (m *initiationMessage) marshal() [initiationSize]byte {
	res := make([]byte, 0, initiationSize)
	// The type as a little-endian uint32 also writes the 3 reserved zero bytes.
	res = binary.LittleEndian.AppendUint32(res, initiationType)
	res = binary.LittleEndian.AppendUint32(res, m.initiatorIndex)
	res = append(res, m.ephemeral[:]...)
	res = append(res, m.encryptedStatic[:]...)
	res = append(res, m.encryptedTimestamp[:]...)
	res = append(res, m.mac1[:]...)
	res = append(res, m.mac2[:]...)

	// Panics if a field is missing, which a test catches.
	return [initiationSize]byte(res)
}

// unmarshal fills m from b, the reverse of marshal. It returns errMessageSize
// if b is not exactly initiationSize bytes, and errMessageType if it is not
// an initiation message. On error, m is unchanged.
//
// It checks only the format: whether the fields are valid is up to mac1 and
// decryption.
func (m *initiationMessage) unmarshal(b []byte) error {
	if len(b) != initiationSize {
		return errMessageSize
	}

	if binary.LittleEndian.Uint32(b) != initiationType {
		return errMessageType
	}
	b = b[4:]

	// Each copy fills one field, as long as the field, and the slice then
	// moves past it. The order is the same as in marshal.
	m.initiatorIndex = binary.LittleEndian.Uint32(b)
	b = b[4:]
	b = b[copy(m.ephemeral[:], b):]
	b = b[copy(m.encryptedStatic[:], b):]
	b = b[copy(m.encryptedTimestamp[:], b):]
	b = b[copy(m.mac1[:], b):]
	copy(m.mac2[:], b)

	return nil
}

// responseMessage is the second handshake message, from the responder to the
// initiator. initiatorIndex is copied from the initiation message, so that
// the initiator can tell which handshake it answers.
type responseMessage struct {
	responderIndex   uint32                          // sender
	initiatorIndex   uint32                          // receiver
	ephemeral        [32]byte                        // unencrypted_ephemeral
	encryptedNothing [chacha20poly1305.Overhead]byte // encrypted_nothing: only the tag
	mac1             [16]byte                        // mac1
	mac2             [16]byte                        // mac2, zero without a cookie
}

// marshal returns m in the wire format: the type and reserved bytes, then
// each field in order, with the indices in little-endian.
func (m *responseMessage) marshal() [responseSize]byte {
	res := make([]byte, 0, responseSize)
	// The type as a little-endian uint32 also writes the 3 reserved zero bytes.
	res = binary.LittleEndian.AppendUint32(res, responseType)
	res = binary.LittleEndian.AppendUint32(res, m.responderIndex)
	res = binary.LittleEndian.AppendUint32(res, m.initiatorIndex)
	res = append(res, m.ephemeral[:]...)
	res = append(res, m.encryptedNothing[:]...)
	res = append(res, m.mac1[:]...)
	res = append(res, m.mac2[:]...)

	// Panics if a field is missing, which a test catches.
	return [responseSize]byte(res)
}

// unmarshal fills m from b, the reverse of marshal. It returns errMessageSize
// if b is not exactly responseSize bytes, and errMessageType if it is not a
// response message. On error, m is unchanged.
//
// It checks only the format: whether the fields are valid is up to mac1 and
// decryption.
func (m *responseMessage) unmarshal(b []byte) error {
	if len(b) != responseSize {
		return errMessageSize
	}

	if binary.LittleEndian.Uint32(b) != responseType {
		return errMessageType
	}
	b = b[4:]

	// Each copy fills one field, as long as the field, and the slice then
	// moves past it. The order is the same as in marshal.
	m.responderIndex = binary.LittleEndian.Uint32(b)
	b = b[4:]
	m.initiatorIndex = binary.LittleEndian.Uint32(b)
	b = b[4:]
	b = b[copy(m.ephemeral[:], b):]
	b = b[copy(m.encryptedNothing[:], b):]
	b = b[copy(m.mac1[:], b):]
	copy(m.mac2[:], b)

	return nil
}

// setMAC1 computes mac1 = MAC(key, b[:offset]) and writes it at offset in b,
// a marshaled message. key is mac1Key of the receiver's public key, and
// offset is initiationMAC1Offset or responseMAC1Offset.
//
// b must be at least offset+16 bytes long, as marshal returns. setMAC1 does
// not check it, because b always comes from marshal and never from the
// network.
func setMAC1(b []byte, offset int, key [32]byte) {
	mac1 := mac(key, b[:offset])
	copy(b[offset:], mac1[:])
}

// verifyMAC1 checks the mac1 field at offset in b, a message received from
// the network. key is mac1Key of the receiver's own public key. It returns
// errMessageSize if b is too short to hold mac1, and errInvalidMAC1 if mac1
// is wrong.
//
// It is cheap, so the receiver calls it before any Diffie-Hellman, to drop
// messages from anyone who does not know its public key. The comparison takes
// the same time wherever the bytes differ, so that timing does not reveal
// how much of a forged mac1 is right.
func verifyMAC1(b []byte, offset int, key [32]byte) error {
	if len(b) < offset+blake2s.Size128 {
		return errMessageSize
	}

	want := mac(key, b[:offset])

	if !gohmac.Equal(want[:], b[offset:offset+blake2s.Size128]) {
		return errInvalidMAC1
	}

	return nil
}
