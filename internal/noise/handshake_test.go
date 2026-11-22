package noise

import (
	"bytes"
	"testing"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
)

// Fixed keys for the handshake tests: Alice and Bob from RFC 7748, section
// 6.1, as the initiator and the responder, and a fixed ephemeral key.
const (
	alicePrivate     = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	bobPrivate       = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os="
	ephemeralPrivate = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

// testIndex and testTime are the fixed index and time the tests pass to
// createInitiationWith.
const testIndex = 0x01020304

var testTime = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// privateKey returns the private key that s encodes, failing the test on
// error.
func privateKey(t *testing.T, s string) *identity.PrivateKey {
	t.Helper()
	k, err := identity.ParsePrivateKey(s)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	return k
}

// initiatorHandshake returns Alice's side of a handshake with Bob.
func initiatorHandshake(t *testing.T) *handshake {
	t.Helper()
	bob := privateKey(t, bobPrivate).PublicKey()
	return newHandshake(privateKey(t, alicePrivate), bob)
}

// createTestInitiation creates an initiation message with the fixed ephemeral
// key, index and time.
func createTestInitiation(t *testing.T, h *handshake) [initiationSize]byte {
	t.Helper()
	b, err := h.createInitiationWith(privateKey(t, ephemeralPrivate), testTime, testIndex)
	if err != nil {
		t.Fatalf("createInitiationWith: %v", err)
	}
	return b
}

// TestCreateInitiationFormat checks that the message parses, that mac1 is set
// for the responder, and that the plaintext fields are the ones passed in.
func TestCreateInitiationFormat(t *testing.T) {
	h := initiatorHandshake(t)
	b := createTestInitiation(t, h)

	var msg initiationMessage
	if err := msg.unmarshal(b[:]); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := verifyMAC1(b[:], initiationMAC1Offset, mac1Key(h.remoteStatic)); err != nil {
		t.Errorf("verifyMAC1 with the responder's key: %v", err)
	}
	if msg.initiatorIndex != testIndex {
		t.Errorf("initiatorIndex = %#x, want %#x", msg.initiatorIndex, testIndex)
	}
	if want := privateKey(t, ephemeralPrivate).PublicKey().Bytes(); !bytes.Equal(msg.ephemeral[:], want) {
		t.Errorf("ephemeral = %x, want %x", msg.ephemeral, want)
	}
	if msg.mac2 != [16]byte{} {
		t.Errorf("mac2 = %x, want zero", msg.mac2)
	}
}

// TestCreateInitiationHidesStatic checks that the initiator's static key and
// the timestamp do not appear in the clear in the message.
func TestCreateInitiationHidesStatic(t *testing.T) {
	h := initiatorHandshake(t)
	b := createTestInitiation(t, h)

	if bytes.Contains(b[:], h.localStatic.PublicKey().Bytes()) {
		t.Error("the message contains the initiator's static public key in the clear")
	}
	ts := tai64n(testTime)
	if bytes.Contains(b[:], ts[:]) {
		t.Error("the message contains the timestamp in the clear")
	}
}

// TestCreateInitiationKeepsState checks that the handshake keeps what the
// response needs.
func TestCreateInitiationKeepsState(t *testing.T) {
	h := initiatorHandshake(t)
	createTestInitiation(t, h)

	if h.localIndex != testIndex {
		t.Errorf("localIndex = %#x, want %#x", h.localIndex, testIndex)
	}
	if h.localEphemeral == nil || !bytes.Equal(h.localEphemeral.PublicKey().Bytes(), privateKey(t, ephemeralPrivate).PublicKey().Bytes()) {
		t.Error("localEphemeral is not the ephemeral key passed in")
	}
	if h.state == nil {
		t.Fatal("state is nil")
	}
	start := newHandshakeState(h.remoteStatic)
	if h.state.chainKey == start.chainKey || h.state.hash == start.hash {
		t.Error("state is still the initial state")
	}
}

// TestCreateInitiationIsDeterministic checks that the same inputs give the
// same message, and that changing any input changes it.
func TestCreateInitiationIsDeterministic(t *testing.T) {
	base := createTestInitiation(t, initiatorHandshake(t))

	if again := createTestInitiation(t, initiatorHandshake(t)); again != base {
		t.Error("the same inputs gave different messages")
	}

	otherEphemeral, err := identity.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		ephemeral *identity.PrivateKey
		now       time.Time
		index     uint32
	}{
		{"other ephemeral key", otherEphemeral, testTime, testIndex},
		{"other time", privateKey(t, ephemeralPrivate), testTime.Add(time.Nanosecond), testIndex},
		{"other index", privateKey(t, ephemeralPrivate), testTime, testIndex + 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := initiatorHandshake(t).createInitiationWith(tc.ephemeral, tc.now, tc.index)
			if err != nil {
				t.Fatalf("createInitiationWith: %v", err)
			}
			if b == base {
				t.Error("the message did not change")
			}
		})
	}
}

// TestCreateInitiationRejectsLowOrderKey checks that a low-order responder key
// makes creation fail and leaves the handshake unchanged.
func TestCreateInitiationRejectsLowOrderKey(t *testing.T) {
	zero, err := identity.NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	h := newHandshake(privateKey(t, alicePrivate), zero)

	if _, err := h.createInitiationWith(privateKey(t, ephemeralPrivate), testTime, testIndex); err == nil {
		t.Fatal("createInitiationWith accepted an all-zero responder key")
	}
	if h.state != nil || h.localEphemeral != nil || h.localIndex != 0 {
		t.Error("a failed createInitiationWith changed the handshake")
	}
}

// TestCreateInitiation checks the version with random inputs: the message is
// valid, and two calls give different ephemeral keys and messages.
func TestCreateInitiation(t *testing.T) {
	h := initiatorHandshake(t)

	first, err := h.createInitiation()
	if err != nil {
		t.Fatalf("createInitiation: %v", err)
	}
	if err := verifyMAC1(first[:], initiationMAC1Offset, mac1Key(h.remoteStatic)); err != nil {
		t.Errorf("verifyMAC1: %v", err)
	}
	firstEphemeral := h.localEphemeral.PublicKey().Bytes()

	second, err := h.createInitiation()
	if err != nil {
		t.Fatalf("createInitiation: %v", err)
	}
	if second == first {
		t.Error("two calls gave the same message")
	}
	if bytes.Equal(h.localEphemeral.PublicKey().Bytes(), firstEphemeral) {
		t.Error("two calls used the same ephemeral key")
	}
}
