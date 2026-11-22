package noise

import (
	"bytes"
	"errors"
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

// responderHandshake returns Bob's side of a handshake with Alice.
func responderHandshake(t *testing.T) *handshake {
	t.Helper()
	alice := privateKey(t, alicePrivate).PublicKey()
	return newHandshake(privateKey(t, bobPrivate), alice)
}

// TestConsumeInitiation checks that Bob accepts Alice's message and ends in
// the same state, which shows both sides took the same steps.
func TestConsumeInitiation(t *testing.T) {
	alice, bob := initiatorHandshake(t), responderHandshake(t)
	b := createTestInitiation(t, alice)

	if err := bob.consumeInitiation(b[:]); err != nil {
		t.Fatalf("consumeInitiation: %v", err)
	}

	if *bob.state != *alice.state {
		t.Errorf("states differ: initiator %x/%x, responder %x/%x",
			alice.state.chainKey, alice.state.hash, bob.state.chainKey, bob.state.hash)
	}
	if bob.remoteIndex != testIndex {
		t.Errorf("remoteIndex = %#x, want %#x", bob.remoteIndex, testIndex)
	}
	if want := alice.localEphemeral.PublicKey().Bytes(); !bytes.Equal(bob.remoteEphemeral.Bytes(), want) {
		t.Errorf("remoteEphemeral = %x, want %x", bob.remoteEphemeral.Bytes(), want)
	}
	if want := tai64n(testTime); bob.lastTimestamp != want {
		t.Errorf("lastTimestamp = %x, want %x", bob.lastTimestamp, want)
	}
}

// TestConsumeInitiationNewerTimestamp checks that a later message from the
// same peer is accepted after an earlier one.
func TestConsumeInitiationNewerTimestamp(t *testing.T) {
	bob := responderHandshake(t)

	for i, now := range []time.Time{testTime, testTime.Add(time.Nanosecond), testTime.Add(time.Minute)} {
		b, err := initiatorHandshake(t).createInitiationWith(privateKey(t, ephemeralPrivate), now, testIndex)
		if err != nil {
			t.Fatalf("createInitiationWith: %v", err)
		}
		if err := bob.consumeInitiation(b[:]); err != nil {
			t.Fatalf("message %d: consumeInitiation: %v", i, err)
		}
	}
}

// resign returns a copy of b with byte i flipped and mac1 computed again for
// Bob, so that the change reaches the checks after mac1.
func resign(t *testing.T, b [initiationSize]byte, i int) []byte {
	t.Helper()
	c := b
	c[i] ^= 0x01
	setMAC1(c[:], initiationMAC1Offset, mac1Key(privateKey(t, bobPrivate).PublicKey()))
	return c[:]
}

func TestConsumeInitiationRejects(t *testing.T) {
	bobPublic := privateKey(t, bobPrivate).PublicKey()

	charlie, err := identity.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	valid := createTestInitiation(t, initiatorHandshake(t))

	// forAnotherResponder is Alice's message to Charlie instead of Bob.
	forAnotherResponder := createTestInitiation(t, newHandshake(privateKey(t, alicePrivate), charlie.PublicKey()))
	// fromUnknownPeer is Charlie's message to Bob: Charlie knows Bob's key,
	// but Bob expects Alice.
	fromUnknownPeer := createTestInitiation(t, newHandshake(charlie, bobPublic))

	// older is Alice's message from a second before testTime.
	older, err := initiatorHandshake(t).createInitiationWith(privateKey(t, ephemeralPrivate), testTime.Add(-time.Second), testIndex)
	if err != nil {
		t.Fatalf("createInitiationWith: %v", err)
	}

	tests := []struct {
		name string
		// first, if set, is consumed successfully before b.
		first   []byte
		b       []byte
		wantErr error
	}{
		{"too short", nil, valid[:initiationSize-1], errMessageSize},
		{"wrong type", nil, resign(t, valid, 0), errMessageType},
		{"for another responder", nil, forAnotherResponder[:], errInvalidMAC1},
		{"changed byte without new mac1", nil, func() []byte { c := valid; c[50] ^= 1; return c[:] }(), errInvalidMAC1},
		{"from an unknown peer", nil, fromUnknownPeer[:], errUnknownPeer},
		{"changed ephemeral", nil, resign(t, valid, 8+31), errDecrypt},
		{"changed encrypted static", nil, resign(t, valid, 40), errDecrypt},
		{"changed encrypted timestamp", nil, resign(t, valid, 88), errDecrypt},
		{"replayed", valid[:], valid[:], errReplayedTimestamp},
		{"older timestamp", valid[:], older[:], errReplayedTimestamp},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bob := responderHandshake(t)
			if tc.first != nil {
				if err := bob.consumeInitiation(tc.first); err != nil {
					t.Fatalf("consuming the first message: %v", err)
				}
			}
			before := *bob

			if err := bob.consumeInitiation(tc.b); !errors.Is(err, tc.wantErr) {
				t.Fatalf("consumeInitiation error = %v, want %v", err, tc.wantErr)
			}
			if *bob != before {
				t.Error("a rejected message changed the handshake")
			}
		})
	}
}

// TestConsumeInitiationAfterRejection checks that a forged message does not
// stop the real one from being accepted afterwards.
func TestConsumeInitiationAfterRejection(t *testing.T) {
	bob := responderHandshake(t)
	valid := createTestInitiation(t, initiatorHandshake(t))

	if err := bob.consumeInitiation(resign(t, valid, 88)); err == nil {
		t.Fatal("consumeInitiation accepted a changed timestamp")
	}
	if err := bob.consumeInitiation(valid[:]); err != nil {
		t.Errorf("consumeInitiation of the real message after a forged one: %v", err)
	}
}

// TestConsumeInitiationIndexIsNotEncrypted shows that the index is protected
// only by mac1: it is not mixed into the hash, as in the whitepaper, so
// someone who knows Bob's public key can change it and compute mac1 again.
// That only lets them break the handshake, which they could do anyway.
func TestConsumeInitiationIndexIsNotEncrypted(t *testing.T) {
	bob := responderHandshake(t)
	valid := createTestInitiation(t, initiatorHandshake(t))

	if err := bob.consumeInitiation(resign(t, valid, 4)); err != nil {
		t.Fatalf("consumeInitiation: %v", err)
	}
	if bob.remoteIndex == testIndex {
		t.Error("remoteIndex is the original index, want the changed one")
	}
}
