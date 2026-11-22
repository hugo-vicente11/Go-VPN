package noise

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
)

// fill sets every byte of b to v, so that each field of a test message holds
// a different value and swapped fields show up.
func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

// testInitiation returns an initiation message with a different value in
// every field.
func testInitiation() initiationMessage {
	m := initiationMessage{initiatorIndex: 0x04030201}
	fill(m.ephemeral[:], 0xa1)
	fill(m.encryptedStatic[:], 0xa2)
	fill(m.encryptedTimestamp[:], 0xa3)
	fill(m.mac1[:], 0xa4)
	fill(m.mac2[:], 0xa5)
	return m
}

// testResponse returns a response message with a different value in every
// field.
func testResponse() responseMessage {
	m := responseMessage{responderIndex: 0x04030201, initiatorIndex: 0x08070605}
	fill(m.ephemeral[:], 0xb1)
	fill(m.encryptedNothing[:], 0xb2)
	fill(m.mac1[:], 0xb3)
	fill(m.mac2[:], 0xb4)
	return m
}

func TestInitiationRoundTrip(t *testing.T) {
	m := testInitiation()
	b := m.marshal()

	var got initiationMessage
	if err := got.unmarshal(b[:]); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != m {
		t.Errorf("unmarshal(marshal()) = %+v, want %+v", got, m)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	m := testResponse()
	b := m.marshal()

	var got responseMessage
	if err := got.unmarshal(b[:]); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != m {
		t.Errorf("unmarshal(marshal()) = %+v, want %+v", got, m)
	}
}

// field is a piece of a marshaled message that a layout test expects at a
// given offset.
type field struct {
	name   string
	offset int
	want   []byte
}

// checkLayout fails the test if any field is not at its offset in b.
func checkLayout(t *testing.T, b []byte, fields []field) {
	t.Helper()
	for _, f := range fields {
		got := b[f.offset : f.offset+len(f.want)]
		if !bytes.Equal(got, f.want) {
			t.Errorf("%s at offset %d = %x, want %x", f.name, f.offset, got, f.want)
		}
	}
}

// TestInitiationLayout checks that each field is at the offset section 5.4.2
// of the whitepaper gives, and that the index is little-endian.
func TestInitiationLayout(t *testing.T) {
	m := testInitiation()
	b := m.marshal()

	checkLayout(t, b[:], []field{
		{"type and reserved", 0, []byte{1, 0, 0, 0}},
		{"initiatorIndex", 4, []byte{0x01, 0x02, 0x03, 0x04}},
		{"ephemeral", 8, m.ephemeral[:]},
		{"encryptedStatic", 40, m.encryptedStatic[:]},
		{"encryptedTimestamp", 88, m.encryptedTimestamp[:]},
		{"mac1", initiationMAC1Offset, m.mac1[:]},
		{"mac2", 132, m.mac2[:]},
	})
}

// TestResponseLayout checks that each field is at the offset section 5.4.3
// of the whitepaper gives, and that the indices are little-endian.
func TestResponseLayout(t *testing.T) {
	m := testResponse()
	b := m.marshal()

	checkLayout(t, b[:], []field{
		{"type and reserved", 0, []byte{2, 0, 0, 0}},
		{"responderIndex", 4, []byte{0x01, 0x02, 0x03, 0x04}},
		{"initiatorIndex", 8, []byte{0x05, 0x06, 0x07, 0x08}},
		{"ephemeral", 12, m.ephemeral[:]},
		{"encryptedNothing", 44, m.encryptedNothing[:]},
		{"mac1", responseMAC1Offset, m.mac1[:]},
		{"mac2", 76, m.mac2[:]},
	})
}

// TestMessageConstants checks that the size and mac1 offset constants match
// the fields, so that changing a field without its constant fails here.
func TestMessageConstants(t *testing.T) {
	var i initiationMessage
	initiationFields := 4 + 4 + len(i.ephemeral) + len(i.encryptedStatic) + len(i.encryptedTimestamp)
	if initiationMAC1Offset != initiationFields {
		t.Errorf("initiationMAC1Offset = %d, want %d", initiationMAC1Offset, initiationFields)
	}
	if want := initiationFields + len(i.mac1) + len(i.mac2); initiationSize != want {
		t.Errorf("initiationSize = %d, want %d", initiationSize, want)
	}

	var r responseMessage
	responseFields := 4 + 4 + 4 + len(r.ephemeral) + len(r.encryptedNothing)
	if responseMAC1Offset != responseFields {
		t.Errorf("responseMAC1Offset = %d, want %d", responseMAC1Offset, responseFields)
	}
	if want := responseFields + len(r.mac1) + len(r.mac2); responseSize != want {
		t.Errorf("responseSize = %d, want %d", responseSize, want)
	}
}

// unmarshaler is implemented by both message types, so that the rejection
// tests can run against each.
type unmarshaler interface {
	unmarshal(b []byte) error
}

// TestUnmarshalRejects checks that unmarshal rejects anything that is not
// exactly a message of its type, and leaves the message unchanged when it
// does.
func TestUnmarshalRejects(t *testing.T) {
	initiation, response := testInitiation(), testResponse()
	validInitiation, validResponse := initiation.marshal(), response.marshal()

	// changed returns a copy of b with byte i set to v.
	changed := func(b []byte, i int, v byte) []byte {
		c := bytes.Clone(b)
		c[i] = v
		return c
	}
	// withType returns a copy of b with its first 4 bytes set to typ.
	withType := func(b []byte, typ uint32) []byte {
		c := bytes.Clone(b)
		binary.LittleEndian.PutUint32(c, typ)
		return c
	}

	messages := []struct {
		name   string
		valid  []byte
		other  []byte // a valid message of the other type
		target func() unmarshaler
	}{
		{"initiation", validInitiation[:], validResponse[:], func() unmarshaler { m := testInitiation(); return &m }},
		{"response", validResponse[:], validInitiation[:], func() unmarshaler { m := testResponse(); return &m }},
	}

	for _, msg := range messages {
		tests := []struct {
			name    string
			b       []byte
			wantErr error
		}{
			{"empty", nil, errMessageSize},
			{"one byte short", msg.valid[:len(msg.valid)-1], errMessageSize},
			{"one byte long", append(bytes.Clone(msg.valid), 0), errMessageSize},
			{"other message type", msg.other, errMessageSize},
			{"transport data type", withType(msg.valid, 4), errMessageType},
			{"type of the other message", withType(msg.valid, uint32(3-msg.valid[0])), errMessageType},
			{"reserved byte 1 set", changed(msg.valid, 1, 1), errMessageType},
			{"reserved byte 3 set", changed(msg.valid, 3, 1), errMessageType},
		}

		for _, tc := range tests {
			t.Run(msg.name+"/"+tc.name, func(t *testing.T) {
				m := msg.target()
				before := msg.target()

				if err := m.unmarshal(tc.b); !errors.Is(err, tc.wantErr) {
					t.Fatalf("unmarshal error = %v, want %v", err, tc.wantErr)
				}
				if !sameMessage(m, before) {
					t.Error("a failed unmarshal changed the message")
				}
			})
		}
	}
}

// sameMessage reports whether a and b hold the same message.
func sameMessage(a, b unmarshaler) bool {
	switch a := a.(type) {
	case *initiationMessage:
		return *a == *b.(*initiationMessage)
	case *responseMessage:
		return *a == *b.(*responseMessage)
	}
	return false
}

// TestSetMAC1 checks setMAC1 against a value computed with Python's hashlib:
// keyed BLAKE2s-128 with mac1Key of Alice's public key, over the first 116
// bytes of testInitiation.
func TestSetMAC1(t *testing.T) {
	m := testInitiation()
	b := m.marshal()

	setMAC1(b[:], initiationMAC1Offset, mac1Key(alicePublicKey(t)))

	checkHex(t, "mac1", b[initiationMAC1Offset:initiationMAC1Offset+16], "1b870cc322a03b6a2184d30e45c0efa0")
}

// TestSetMAC1ChangesOnlyMAC1 checks that setMAC1 leaves every byte outside the
// mac1 field as it was.
func TestSetMAC1ChangesOnlyMAC1(t *testing.T) {
	m := testInitiation()
	b := m.marshal()
	before := b

	setMAC1(b[:], initiationMAC1Offset, mac1Key(alicePublicKey(t)))

	if !bytes.Equal(b[:initiationMAC1Offset], before[:initiationMAC1Offset]) {
		t.Error("setMAC1 changed the bytes before mac1")
	}
	if !bytes.Equal(b[initiationMAC1Offset+16:], before[initiationMAC1Offset+16:]) {
		t.Error("setMAC1 changed mac2")
	}
}

// signedMessages returns a marshaled message of each type with mac1 set for
// Alice's public key.
func signedMessages(t *testing.T) []struct {
	name   string
	b      []byte
	offset int
} {
	t.Helper()
	key := mac1Key(alicePublicKey(t))

	i, r := testInitiation(), testResponse()
	ib, rb := i.marshal(), r.marshal()
	setMAC1(ib[:], initiationMAC1Offset, key)
	setMAC1(rb[:], responseMAC1Offset, key)

	return []struct {
		name   string
		b      []byte
		offset int
	}{
		{"initiation", ib[:], initiationMAC1Offset},
		{"response", rb[:], responseMAC1Offset},
	}
}

func TestVerifyMAC1Accepts(t *testing.T) {
	key := mac1Key(alicePublicKey(t))

	for _, msg := range signedMessages(t) {
		t.Run(msg.name, func(t *testing.T) {
			if err := verifyMAC1(msg.b, msg.offset, key); err != nil {
				t.Errorf("verifyMAC1: %v", err)
			}
		})
	}
}

// TestVerifyMAC1IgnoresMAC2 checks that mac2 is not covered by mac1, which
// would fail if the offset were past the mac1 field.
func TestVerifyMAC1IgnoresMAC2(t *testing.T) {
	key := mac1Key(alicePublicKey(t))

	for _, msg := range signedMessages(t) {
		t.Run(msg.name, func(t *testing.T) {
			msg.b[len(msg.b)-1] ^= 0x01
			if err := verifyMAC1(msg.b, msg.offset, key); err != nil {
				t.Errorf("verifyMAC1 after changing mac2: %v", err)
			}
		})
	}
}

func TestVerifyMAC1Rejects(t *testing.T) {
	key := mac1Key(alicePublicKey(t))

	// Bob's public key from RFC 7748, section 6.1, as another receiver.
	bob, err := identity.ParsePublicKey("3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=")
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	otherKey := mac1Key(bob)

	for _, msg := range signedMessages(t) {
		// flipped returns a copy of the message with one bit of byte i flipped.
		flipped := func(i int) []byte {
			c := bytes.Clone(msg.b)
			c[i] ^= 0x01
			return c
		}

		tests := []struct {
			name    string
			b       []byte
			key     [32]byte
			wantErr error
		}{
			{"changed type", flipped(0), key, errInvalidMAC1},
			{"changed byte before mac1", flipped(msg.offset - 1), key, errInvalidMAC1},
			{"changed first mac1 byte", flipped(msg.offset), key, errInvalidMAC1},
			{"changed last mac1 byte", flipped(msg.offset + 15), key, errInvalidMAC1},
			{"other receiver's key", msg.b, otherKey, errInvalidMAC1},
			{"cut inside mac1", msg.b[:msg.offset+15], key, errMessageSize},
			{"empty", nil, key, errMessageSize},
		}

		for _, tc := range tests {
			t.Run(msg.name+"/"+tc.name, func(t *testing.T) {
				if err := verifyMAC1(tc.b, msg.offset, tc.key); !errors.Is(err, tc.wantErr) {
					t.Errorf("verifyMAC1 error = %v, want %v", err, tc.wantErr)
				}
			})
		}
	}
}
