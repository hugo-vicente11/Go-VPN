package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	testKey  = Key{1, 2, 3}
	otherKey = Key{4, 5, 6}

	// testKeyB64 is a key in the format wg genkey produces, written by hand.
	// It decodes to the bytes 0 to 31 (see testKeyB64Bytes), not to testKey.
	testKeyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

// newTestSession returns a Session for key, failing the test if it cannot be created.
func newTestSession(t *testing.T, key Key) *Session {
	t.Helper()
	s, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// seal seals packet with s, failing the test on error.
func seal(t *testing.T, s *Session, packet []byte) []byte {
	t.Helper()
	msg, err := s.Seal(nil, packet)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return msg
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newTestSession(t, testKey)
	packet := []byte("hello")

	msg := seal(t, s, packet)
	if want := len(packet) + Overhead; len(msg) != want {
		t.Errorf("len(msg) = %d, want %d", len(msg), want)
	}

	got, err := s.Open(nil, msg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, packet) {
		t.Errorf("Open = %q, want %q", got, packet)
	}
}

// TestSealKnownAnswer checks Seal against a message built by hand from the
// WireGuard transport data format, without using Seal's own header or nonce
// code. A round trip cannot catch a wrong nonce layout, because Seal and Open
// would both get it wrong in the same way.
func TestSealKnownAnswer(t *testing.T) {
	s := newTestSession(t, testKey)
	packet := []byte("hi")

	// Every byte of the counter is different, so a byte in the wrong place shows up.
	s.counter.Store(0x0102030405060708)
	got := seal(t, s, packet)

	header := []byte{
		4, 0, 0, 0, // type 4, then 3 reserved zero bytes
		0, 0, 0, 0, // receiver index
		8, 7, 6, 5, 4, 3, 2, 1, // counter, little-endian
	}
	nonce := []byte{
		0, 0, 0, 0, // 4 zero bytes
		8, 7, 6, 5, 4, 3, 2, 1, // counter, little-endian
	}
	aead, err := chacha20poly1305.New(testKey[:])
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	want := aead.Seal(header, nonce, packet, nil)

	if !bytes.Equal(got, want) {
		t.Errorf("Seal =\n%x\nwant\n%x", got, want)
	}
}

// TestOpenAcceptsKeepalive checks that an empty packet, which WireGuard uses
// as a keepalive, survives a round trip.
func TestOpenAcceptsKeepalive(t *testing.T) {
	s := newTestSession(t, testKey)

	msg := seal(t, s, nil)
	if len(msg) != Overhead {
		t.Errorf("len(msg) = %d, want %d", len(msg), Overhead)
	}

	got, err := s.Open(nil, msg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Open = %q, want empty packet", got)
	}
}

func TestSealIncrementsCounter(t *testing.T) {
	s := newTestSession(t, testKey)
	packet := []byte("hello")

	first := seal(t, s, packet)
	second := seal(t, s, packet)

	for i, msg := range [][]byte{first, second} {
		got := binary.LittleEndian.Uint64(msg[counterOffset:HeaderSize])
		if want := uint64(i); got != want {
			t.Errorf("message %d: counter = %d, want %d", i, got, want)
		}
	}

	// The same packet sealed with a different nonce must not produce the same ciphertext.
	if bytes.Equal(first[HeaderSize:], second[HeaderSize:]) {
		t.Error("sealing the same packet twice produced identical ciphertexts")
	}
}

func TestSealCounterExhausted(t *testing.T) {
	s := newTestSession(t, testKey)

	// The last counter value below the limit is still usable.
	s.counter.Store(counterLimit - 1)
	if _, err := s.Seal(nil, []byte("hello")); err != nil {
		t.Fatalf("Seal at counter %d: %v", uint64(counterLimit-1), err)
	}

	// The counter is now at the limit.
	if _, err := s.Seal(nil, []byte("hello")); !errors.Is(err, ErrCounterExhausted) {
		t.Errorf("Seal at counter limit: error = %v, want %v", err, ErrCounterExhausted)
	}
}

func TestOpenRejectsShortMessage(t *testing.T) {
	s := newTestSession(t, testKey)

	for _, n := range []int{0, 1, HeaderSize - 1, Overhead - 1} {
		if _, err := s.Open(nil, make([]byte, n)); !errors.Is(err, ErrShort) {
			t.Errorf("Open(%d bytes): error = %v, want %v", n, err, ErrShort)
		}
	}
}

// TestOpenRejectsTampered flips one bit in each part of a sealed message and
// checks that Open rejects it with the right error.
func TestOpenRejectsTampered(t *testing.T) {
	s := newTestSession(t, testKey)
	msg := seal(t, s, []byte("hello"))

	tests := []struct {
		name    string
		offset  int
		wantErr error
	}{
		{"type", 0, ErrType},
		{"reserved", 1, ErrType},
		{"receiver index", receiverOffset, ErrType},
		{"counter", counterOffset, ErrAuth},
		{"ciphertext", HeaderSize, ErrAuth},
		{"tag", len(msg) - 1, ErrAuth},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := bytes.Clone(msg)
			tampered[tc.offset] ^= 1

			if _, err := s.Open(nil, tampered); !errors.Is(err, tc.wantErr) {
				t.Errorf("Open: error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	msg := seal(t, newTestSession(t, testKey), []byte("hello"))

	if _, err := newTestSession(t, otherKey).Open(nil, msg); !errors.Is(err, ErrAuth) {
		t.Errorf("Open: error = %v, want %v", err, ErrAuth)
	}
}

// testKeyB64Bytes returns the key that testKeyB64 encodes: the bytes 0 to 31.
func testKeyB64Bytes() Key {
	var key Key
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestParseKey(t *testing.T) {
	want := testKeyB64Bytes()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", testKeyB64, false},
		{"trailing newline", testKeyB64 + "\n", false},
		{"surrounding whitespace", "  " + testKeyB64 + "\t", false},
		{"invalid base64", "not base64!", true},
		{"missing padding", strings.TrimSuffix(testKeyB64, "="), true},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16)), true},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 33)), true},
		{"empty", "", true},
		{"only whitespace", "\n", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKey(tc.input)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("ParseKey(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && got != want {
				t.Errorf("ParseKey(%q) = %x, want %x", tc.input, got, want)
			}
		})
	}
}

// TestParseKeyErrorContext checks that ParseKey's errors say they come from
// this package, so a user can tell a bad key file from other failures.
func TestParseKeyErrorContext(t *testing.T) {
	for _, input := range []string{"not base64!", ""} {
		_, err := ParseKey(input)
		if err == nil {
			t.Fatalf("ParseKey(%q) returned nil error, want an error", input)
		}
		if msg := err.Error(); !strings.HasPrefix(msg, "session: ") {
			t.Errorf("ParseKey(%q) error = %q, want it to start with %q", input, msg, "session: ")
		}
	}
}
