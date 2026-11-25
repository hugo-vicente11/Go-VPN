package noise

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
	"github.com/hugo-vicente11/go-vpn/internal/session"
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
func initiatorHandshake(t *testing.T) *Handshake {
	t.Helper()
	bob := privateKey(t, bobPrivate).PublicKey()
	return NewHandshake(privateKey(t, alicePrivate), bob)
}

// createTestInitiation creates an initiation message with the fixed ephemeral
// key, index and time.
func createTestInitiation(t *testing.T, h *Handshake) [initiationSize]byte {
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
	h := NewHandshake(privateKey(t, alicePrivate), zero)

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

	first, err := h.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	if err := verifyMAC1(first[:], initiationMAC1Offset, mac1Key(h.remoteStatic)); err != nil {
		t.Errorf("verifyMAC1: %v", err)
	}
	firstEphemeral := h.localEphemeral.PublicKey().Bytes()

	second, err := h.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	if len(first) != initiationSize {
		t.Errorf("len = %d, want %d", len(first), initiationSize)
	}
	if bytes.Equal(second, first) {
		t.Error("two calls gave the same message")
	}
	if bytes.Equal(h.localEphemeral.PublicKey().Bytes(), firstEphemeral) {
		t.Error("two calls used the same ephemeral key")
	}
}

// responderHandshake returns Bob's side of a handshake with Alice.
func responderHandshake(t *testing.T) *Handshake {
	t.Helper()
	alice := privateKey(t, alicePrivate).PublicKey()
	return NewHandshake(privateKey(t, bobPrivate), alice)
}

// TestConsumeInitiation checks that Bob accepts Alice's message and ends in
// the same state, which shows both sides took the same steps.
func TestConsumeInitiation(t *testing.T) {
	alice, bob := initiatorHandshake(t), responderHandshake(t)
	b := createTestInitiation(t, alice)

	if err := bob.ConsumeInitiation(b[:]); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
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
		if err := bob.ConsumeInitiation(b[:]); err != nil {
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
	forAnotherResponder := createTestInitiation(t, NewHandshake(privateKey(t, alicePrivate), charlie.PublicKey()))
	// fromUnknownPeer is Charlie's message to Bob: Charlie knows Bob's key,
	// but Bob expects Alice.
	fromUnknownPeer := createTestInitiation(t, NewHandshake(charlie, bobPublic))

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
				if err := bob.ConsumeInitiation(tc.first); err != nil {
					t.Fatalf("consuming the first message: %v", err)
				}
			}
			before := *bob

			if err := bob.ConsumeInitiation(tc.b); !errors.Is(err, tc.wantErr) {
				t.Fatalf("ConsumeInitiation error = %v, want %v", err, tc.wantErr)
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

	if err := bob.ConsumeInitiation(resign(t, valid, 88)); err == nil {
		t.Fatal("ConsumeInitiation accepted a changed timestamp")
	}
	if err := bob.ConsumeInitiation(valid[:]); err != nil {
		t.Errorf("ConsumeInitiation of the real message after a forged one: %v", err)
	}
}

// TestConsumeInitiationIndexIsNotEncrypted shows that the index is protected
// only by mac1: it is not mixed into the hash, as in the whitepaper, so
// someone who knows Bob's public key can change it and compute mac1 again.
// That only lets them break the handshake, which they could do anyway.
func TestConsumeInitiationIndexIsNotEncrypted(t *testing.T) {
	bob := responderHandshake(t)
	valid := createTestInitiation(t, initiatorHandshake(t))

	if err := bob.ConsumeInitiation(resign(t, valid, 4)); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	if bob.remoteIndex == testIndex {
		t.Error("remoteIndex is the original index, want the changed one")
	}
}

// responderIndex is the fixed index Bob passes to createResponseWith, and
// responderEphemeral his fixed ephemeral key (the bytes 32 to 63).
const (
	responderIndex     = 0x05060708
	responderEphemeral = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
)

// bobAfterInitiation returns Alice's and Bob's handshakes after Bob accepted
// Alice's initiation message, ready for Bob to respond.
func bobAfterInitiation(t *testing.T) (alice, bob *Handshake) {
	t.Helper()
	alice, bob = initiatorHandshake(t), responderHandshake(t)
	b := createTestInitiation(t, alice)
	if err := bob.ConsumeInitiation(b[:]); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	return alice, bob
}

// createTestResponse creates a response with Bob's fixed ephemeral key and
// index.
func createTestResponse(t *testing.T, bob *Handshake) [responseSize]byte {
	t.Helper()
	b, err := bob.createResponseWith(privateKey(t, responderEphemeral), responderIndex)
	if err != nil {
		t.Fatalf("createResponseWith: %v", err)
	}
	return b
}

// TestCreateResponseFormat checks that the response parses, that mac1 is set
// for the initiator, and that it carries both indices and Bob's ephemeral key.
func TestCreateResponseFormat(t *testing.T) {
	alice, bob := bobAfterInitiation(t)
	b := createTestResponse(t, bob)

	var msg responseMessage
	if err := msg.unmarshal(b[:]); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := verifyMAC1(b[:], responseMAC1Offset, mac1Key(alice.localStatic.PublicKey())); err != nil {
		t.Errorf("verifyMAC1 with the initiator's key: %v", err)
	}
	if msg.responderIndex != responderIndex {
		t.Errorf("responderIndex = %#x, want %#x", msg.responderIndex, responderIndex)
	}
	if msg.initiatorIndex != testIndex {
		t.Errorf("initiatorIndex = %#x, want the initiator's %#x", msg.initiatorIndex, testIndex)
	}
	if want := privateKey(t, responderEphemeral).PublicKey().Bytes(); !bytes.Equal(msg.ephemeral[:], want) {
		t.Errorf("ephemeral = %x, want %x", msg.ephemeral, want)
	}
	if msg.mac2 != [16]byte{} {
		t.Errorf("mac2 = %x, want zero", msg.mac2)
	}
}

// TestCreateResponseKeepsState checks that Bob keeps his index and ephemeral
// key, and that his state moved on from the one the initiation left.
func TestCreateResponseKeepsState(t *testing.T) {
	_, bob := bobAfterInitiation(t)
	afterInitiation := *bob.state

	createTestResponse(t, bob)

	if bob.localIndex != responderIndex {
		t.Errorf("localIndex = %#x, want %#x", bob.localIndex, responderIndex)
	}
	if bob.localEphemeral == nil || !bytes.Equal(bob.localEphemeral.PublicKey().Bytes(), privateKey(t, responderEphemeral).PublicKey().Bytes()) {
		t.Error("localEphemeral is not the ephemeral key passed in")
	}
	if bob.state.chainKey == afterInitiation.chainKey || bob.state.hash == afterInitiation.hash {
		t.Error("state did not change")
	}
}

// TestCreateResponseIsDeterministic checks that the same inputs give the same
// response, and that changing the ephemeral key or the index changes it.
func TestCreateResponseIsDeterministic(t *testing.T) {
	_, bob := bobAfterInitiation(t)
	base := createTestResponse(t, bob)

	_, bob = bobAfterInitiation(t)
	if again := createTestResponse(t, bob); again != base {
		t.Error("the same inputs gave different responses")
	}

	otherEphemeral, err := identity.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		ephemeral *identity.PrivateKey
		index     uint32
	}{
		{"other ephemeral key", otherEphemeral, responderIndex},
		{"other index", privateKey(t, responderEphemeral), responderIndex + 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, bob := bobAfterInitiation(t)
			b, err := bob.createResponseWith(tc.ephemeral, tc.index)
			if err != nil {
				t.Fatalf("createResponseWith: %v", err)
			}
			if b == base {
				t.Error("the response did not change")
			}
		})
	}
}

// TestCreateResponseWithoutInitiation checks that a response needs an
// initiation accepted as the last step, and that the handshake is left
// unchanged otherwise: not on a handshake that only created one, nor one
// that already answered it, nor an initiator that finished.
func TestCreateResponseWithoutInitiation(t *testing.T) {
	onlyCreated := initiatorHandshake(t)
	createTestInitiation(t, onlyCreated)

	_, answered := bobAfterInitiation(t)
	createTestResponse(t, answered)

	finished, _, response := aliceAfterResponse(t)
	if err := finished.ConsumeResponse(response[:]); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}

	tests := []struct {
		name string
		h    *Handshake
	}{
		{"new handshake", responderHandshake(t)},
		{"after creating an initiation", onlyCreated},
		{"after creating a response", answered},
		{"initiator after consuming the response", finished},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := *tc.h
			_, err := tc.h.createResponseWith(privateKey(t, responderEphemeral), responderIndex)
			if !errors.Is(err, errNoInitiation) {
				t.Fatalf("createResponseWith error = %v, want %v", err, errNoInitiation)
			}
			if *tc.h != before {
				t.Error("a failed createResponseWith changed the handshake")
			}
		})
	}
}

// TestCreateResponse checks the version with random inputs: the response is
// valid, and two calls give different ephemeral keys and indices.
func TestCreateResponse(t *testing.T) {
	alice, bob := bobAfterInitiation(t)
	first, err := bob.CreateResponse()
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if err := verifyMAC1(first[:], responseMAC1Offset, mac1Key(alice.localStatic.PublicKey())); err != nil {
		t.Errorf("verifyMAC1: %v", err)
	}

	_, bob2 := bobAfterInitiation(t)
	second, err := bob2.CreateResponse()
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if len(first) != responseSize {
		t.Errorf("len = %d, want %d", len(first), responseSize)
	}
	if bytes.Equal(second, first) {
		t.Error("two calls gave the same response")
	}
	if bytes.Equal(bob.localEphemeral.PublicKey().Bytes(), bob2.localEphemeral.PublicKey().Bytes()) {
		t.Error("two calls used the same ephemeral key")
	}
}

// aliceAfterResponse returns Alice's and Bob's handshakes after Bob created
// his response, and the response, ready for Alice to consume it.
func aliceAfterResponse(t *testing.T) (alice, bob *Handshake, response [responseSize]byte) {
	t.Helper()
	alice, bob = bobAfterInitiation(t)
	response = createTestResponse(t, bob)
	return alice, bob, response
}

// TestConsumeResponse checks that Alice accepts Bob's response, ends in the
// same state, and that both sides then get the same transport keys.
func TestConsumeResponse(t *testing.T) {
	alice, bob, b := aliceAfterResponse(t)

	if err := alice.ConsumeResponse(b[:]); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}

	if *alice.state != *bob.state {
		t.Errorf("states differ: initiator %x/%x, responder %x/%x",
			alice.state.chainKey, alice.state.hash, bob.state.chainKey, bob.state.hash)
	}
	if alice.remoteIndex != responderIndex {
		t.Errorf("remoteIndex = %#x, want %#x", alice.remoteIndex, responderIndex)
	}
	if want := bob.localEphemeral.PublicKey().Bytes(); !bytes.Equal(alice.remoteEphemeral.Bytes(), want) {
		t.Errorf("remoteEphemeral = %x, want %x", alice.remoteEphemeral.Bytes(), want)
	}

	aliceSend, aliceRecv := alice.state.deriveTransportKeys()
	bobRecv, bobSend := bob.state.deriveTransportKeys()
	if aliceSend != bobRecv {
		t.Error("initiator-to-responder keys differ")
	}
	if aliceRecv != bobSend {
		t.Error("responder-to-initiator keys differ")
	}
}

// resignResponse returns a copy of b with byte i flipped and mac1 computed
// again for Alice, so that the change reaches the checks after mac1.
func resignResponse(t *testing.T, b [responseSize]byte, i int) []byte {
	t.Helper()
	c := b
	c[i] ^= 0x01
	setMAC1(c[:], responseMAC1Offset, mac1Key(privateKey(t, alicePrivate).PublicKey()))
	return c[:]
}

func TestConsumeResponseRejects(t *testing.T) {
	_, _, valid := aliceAfterResponse(t)

	// otherPSK is a response from a Bob with a different preshared key.
	_, bobWithPSK := bobAfterInitiation(t)
	bobWithPSK.presharedKey[0] = 1
	otherPSK := createTestResponse(t, bobWithPSK)

	tests := []struct {
		name string
		// first, if set, is consumed successfully before b.
		first   []byte
		b       []byte
		wantErr error
	}{
		{"too short", nil, valid[:responseSize-1], errMessageSize},
		{"wrong type", nil, resignResponse(t, valid, 0), errMessageType},
		{"changed byte without new mac1", nil, func() []byte { c := valid; c[50] ^= 1; return c[:] }(), errInvalidMAC1},
		{"other initiator index", nil, resignResponse(t, valid, 8), errUnknownIndex},
		{"changed ephemeral", nil, resignResponse(t, valid, 12), errDecrypt},
		{"changed encrypted nothing", nil, resignResponse(t, valid, 44), errDecrypt},
		{"other preshared key", nil, otherPSK[:], errDecrypt},
		{"replayed", valid[:], valid[:], errNoInitiationCreated},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alice, _, _ := aliceAfterResponse(t)
			if tc.first != nil {
				if err := alice.ConsumeResponse(tc.first); err != nil {
					t.Fatalf("consuming the first message: %v", err)
				}
			}
			before := *alice
			stateBefore := *alice.state

			if err := alice.ConsumeResponse(tc.b); !errors.Is(err, tc.wantErr) {
				t.Fatalf("ConsumeResponse error = %v, want %v", err, tc.wantErr)
			}
			if *alice != before || *alice.state != stateBefore {
				t.Error("a rejected message changed the handshake")
			}
		})
	}
}

// TestConsumeResponseWithoutInitiation checks that a valid response is
// rejected by a handshake that created no initiation, which is left
// unchanged.
func TestConsumeResponseWithoutInitiation(t *testing.T) {
	_, _, b := aliceAfterResponse(t)
	h := initiatorHandshake(t)
	before := *h

	if err := h.ConsumeResponse(b[:]); !errors.Is(err, errNoInitiationCreated) {
		t.Fatalf("ConsumeResponse error = %v, want %v", err, errNoInitiationCreated)
	}
	if *h != before {
		t.Error("a rejected message changed the handshake")
	}
}

// TestConsumeResponseAfterRejection checks that a forged response does not
// stop the real one from being accepted afterwards.
func TestConsumeResponseAfterRejection(t *testing.T) {
	alice, _, valid := aliceAfterResponse(t)

	if err := alice.ConsumeResponse(resignResponse(t, valid, 44)); err == nil {
		t.Fatal("ConsumeResponse accepted a changed encrypted nothing")
	}
	if err := alice.ConsumeResponse(valid[:]); err != nil {
		t.Errorf("ConsumeResponse of the real message after a forged one: %v", err)
	}
}

// TestHandshake runs the whole handshake with random ephemeral keys, indices
// and the current time, as the real program will, and checks that both sides
// end with the same transport keys.
func TestHandshake(t *testing.T) {
	alice, bob := initiatorHandshake(t), responderHandshake(t)

	initiation, err := alice.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	if err := bob.ConsumeInitiation(initiation[:]); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	response, err := bob.CreateResponse()
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if err := alice.ConsumeResponse(response[:]); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}

	if alice.remoteIndex != bob.localIndex || bob.remoteIndex != alice.localIndex {
		t.Errorf("indices do not match: alice %#x/%#x, bob %#x/%#x",
			alice.localIndex, alice.remoteIndex, bob.localIndex, bob.remoteIndex)
	}
	aliceSend, aliceRecv := alice.state.deriveTransportKeys()
	bobRecv, bobSend := bob.state.deriveTransportKeys()
	if aliceSend != bobRecv || aliceRecv != bobSend {
		t.Error("the two sides got different transport keys")
	}
}

// TestHandshakeKnownAnswer checks the whole handshake against the values that
// testdata/handshake_vectors.py computes: an independent implementation,
// written from the whitepaper, with the same fixed keys, indices and time and
// no preshared key. The other tests only show that both sides agree; this one
// catches a mistake they share, such as a wrong constant or a step out of
// order, which would break the handshake with any other WireGuard peer.
func TestHandshakeKnownAnswer(t *testing.T) {
	const (
		wantInitiation = "01000000040302018f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f" +
			"a6766329390656afa10f82819b732869ef96ee45b4fe4fc362db07b74cfc749ae66606f5fbeca63673" +
			"d75505b7d68d8f290d458109520623a5642f7c468a1094b05bf240bd7d3c8052219fdaa70acba19730" +
			"d1ef61cb6db683daa64200000000000000000000000000000000"
		wantResponse = "020000000807060504030201358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2" +
			"cd1662541df3b8c407577031807119a1502e36f75db07c27b709829f137d805c409b069000000000" +
			"000000000000000000000000"
		wantInitiatorToResponder = "35d8fc4c09c91e60f9797fe771cf57b17d88c579b53728664db4b46014116f8c"
		wantResponderToInitiator = "cbf246d70fe49f90537537bbeb24e45c83b4459563e5288ec4d0f927384e7ecc"
	)

	alice, bob := initiatorHandshake(t), responderHandshake(t)

	initiation := createTestInitiation(t, alice)
	if got := hex.EncodeToString(initiation[:]); got != wantInitiation {
		t.Fatalf("initiation:\n got %s\nwant %s", got, wantInitiation)
	}
	if err := bob.ConsumeInitiation(initiation[:]); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}

	response := createTestResponse(t, bob)
	if got := hex.EncodeToString(response[:]); got != wantResponse {
		t.Fatalf("response:\n got %s\nwant %s", got, wantResponse)
	}
	if err := alice.ConsumeResponse(response[:]); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}

	initiatorToResponder, responderToInitiator := alice.state.deriveTransportKeys()
	if got := hex.EncodeToString(initiatorToResponder[:]); got != wantInitiatorToResponder {
		t.Errorf("initiatorToResponder = %s, want %s", got, wantInitiatorToResponder)
	}
	if got := hex.EncodeToString(responderToInitiator[:]); got != wantResponderToInitiator {
		t.Errorf("responderToInitiator = %s, want %s", got, wantResponderToInitiator)
	}
}

// finishedHandshake returns Alice's and Bob's handshakes after the whole
// handshake, with the fixed inputs, ready for NewSession on both sides.
func finishedHandshake(t *testing.T) (alice, bob *Handshake) {
	t.Helper()
	alice, bob, response := aliceAfterResponse(t)
	if err := alice.ConsumeResponse(response[:]); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}
	return alice, bob
}

// newTestSession calls NewSession, failing the test on error.
func newTestSession(t *testing.T, h *Handshake) *session.Session {
	t.Helper()
	s, err := h.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// checkSessions checks that a and b work as the two ends of a tunnel, and
// that each message carries the receiver's index.
func checkSessions(t *testing.T, a, b *session.Session, aIndex, bIndex uint32) {
	t.Helper()
	for _, dir := range []struct {
		name     string
		from, to *session.Session
		toIndex  uint32
	}{
		{"initiator to responder", a, b, bIndex},
		{"responder to initiator", b, a, aIndex},
	} {
		msg, err := dir.from.Seal(nil, []byte("packet"))
		if err != nil {
			t.Fatalf("%s: Seal: %v", dir.name, err)
		}
		if got := binary.LittleEndian.Uint32(msg[4:8]); got != dir.toIndex {
			t.Errorf("%s: receiver index = %#x, want %#x", dir.name, got, dir.toIndex)
		}
		got, err := dir.to.Open(nil, msg)
		if err != nil {
			t.Fatalf("%s: Open: %v", dir.name, err)
		}
		if !bytes.Equal(got, []byte("packet")) {
			t.Errorf("%s: Open = %q, want %q", dir.name, got, "packet")
		}
	}
}

// TestNewSession checks that the sessions of both sides work together, each
// sealing with the key the other opens with and writing the other's index,
// and that the handshake in progress is cleared, keeping only what lasts
// across handshakes.
func TestNewSession(t *testing.T) {
	alice, bob := finishedHandshake(t)

	aliceSession := newTestSession(t, alice)
	bobSession := newTestSession(t, bob)
	checkSessions(t, aliceSession, bobSession, testIndex, responderIndex)

	for _, side := range []struct {
		name string
		h    *Handshake
	}{
		{"initiator", alice},
		{"responder", bob},
	} {
		if side.h.state != nil || side.h.localEphemeral != nil || side.h.remoteEphemeral != nil {
			t.Errorf("%s: the state and ephemeral keys were not cleared", side.name)
		}
		if side.h.stage != nothingStage {
			t.Errorf("%s: stage = %d, want nothingStage", side.name, side.h.stage)
		}
		if side.h.localStatic == nil || side.h.remoteStatic == nil {
			t.Errorf("%s: the static keys were cleared", side.name)
		}
	}
	if want := tai64n(testTime); bob.lastTimestamp != want {
		t.Errorf("lastTimestamp = %x, want %x, so old initiations could be replayed", bob.lastTimestamp, want)
	}
}

// TestNewSessionTwice checks that a second call fails instead of returning
// another session with the same keys, which would reuse nonces.
func TestNewSessionTwice(t *testing.T) {
	alice, bob := finishedHandshake(t)

	for _, h := range []*Handshake{alice, bob} {
		newTestSession(t, h)
		if _, err := h.NewSession(); !errors.Is(err, errUnfinishedHandshake) {
			t.Errorf("second NewSession error = %v, want %v", err, errUnfinishedHandshake)
		}
	}
}

// TestNewSessionUnfinished checks that NewSession fails at every stage
// before the end, and leaves the handshake unchanged.
func TestNewSessionUnfinished(t *testing.T) {
	afterInitiation := initiatorHandshake(t)
	createTestInitiation(t, afterInitiation)
	_, afterConsuming := bobAfterInitiation(t)

	tests := []struct {
		name string
		h    *Handshake
	}{
		{"new handshake", initiatorHandshake(t)},
		{"after creating an initiation", afterInitiation},
		{"after consuming an initiation", afterConsuming},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := *tc.h
			if _, err := tc.h.NewSession(); !errors.Is(err, errUnfinishedHandshake) {
				t.Fatalf("NewSession error = %v, want %v", err, errUnfinishedHandshake)
			}
			if *tc.h != before {
				t.Error("a failed NewSession changed the handshake")
			}
		})
	}
}

// TestHandshakeAgain checks that the same two handshakes can run a second
// handshake after the first one gave its sessions, as a peer that starts
// again must, and that the new sessions use new keys: a message from the
// first sessions does not open with the second ones.
func TestHandshakeAgain(t *testing.T) {
	alice, bob := finishedHandshake(t)
	oldAlice := newTestSession(t, alice)
	newTestSession(t, bob)

	// The second initiation needs a newer timestamp, or Bob rejects it as a
	// replay.
	initiation, err := alice.createInitiationWith(privateKey(t, ephemeralPrivate), testTime.Add(time.Second), testIndex+1)
	if err != nil {
		t.Fatalf("createInitiationWith: %v", err)
	}
	if err := bob.ConsumeInitiation(initiation[:]); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	response, err := bob.createResponseWith(privateKey(t, responderEphemeral), responderIndex+1)
	if err != nil {
		t.Fatalf("createResponseWith: %v", err)
	}
	if err := alice.ConsumeResponse(response[:]); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}

	newAlice := newTestSession(t, alice)
	newBob := newTestSession(t, bob)
	checkSessions(t, newAlice, newBob, testIndex+1, responderIndex+1)

	old, err := oldAlice.Seal(nil, []byte("packet"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := newBob.Open(nil, old); err == nil {
		t.Error("the new session opened a message from the old one")
	}
}

// TestCreateReturnsNilOnError checks that CreateInitiation and CreateResponse
// return no bytes with an error, so a caller that forgets the error has
// nothing to send.
func TestCreateReturnsNilOnError(t *testing.T) {
	b, err := responderHandshake(t).CreateResponse()
	if !errors.Is(err, errNoInitiation) {
		t.Fatalf("CreateResponse error = %v, want %v", err, errNoInitiation)
	}
	if b != nil {
		t.Errorf("CreateResponse returned %d bytes with an error, want nil", len(b))
	}
}

// TestInitiating checks that Initiating is true only while this side waits
// for the response to its initiation.
func TestInitiating(t *testing.T) {
	alice, bob := initiatorHandshake(t), responderHandshake(t)
	if alice.Initiating() {
		t.Error("Initiating = true before any initiation")
	}

	initiation, err := alice.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	if !alice.Initiating() {
		t.Error("Initiating = false after CreateInitiation")
	}

	if err := bob.ConsumeInitiation(initiation); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	if bob.Initiating() {
		t.Error("the responder's Initiating = true")
	}
	response, err := bob.CreateResponse()
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if err := alice.ConsumeResponse(response); err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}
	if alice.Initiating() {
		t.Error("Initiating = true after ConsumeResponse")
	}
}

func TestHandshakePublicKeys(t *testing.T) {
	alice := initiatorHandshake(t)
	wantLocal := privateKey(t, alicePrivate).PublicKey().String()
	wantPeer := privateKey(t, bobPrivate).PublicKey().String()

	if got := alice.LocalPublicKey().String(); got != wantLocal {
		t.Errorf("LocalPublicKey = %s, want %s", got, wantLocal)
	}
	if got := alice.PeerPublicKey().String(); got != wantPeer {
		t.Errorf("PeerPublicKey = %s, want %s", got, wantPeer)
	}
}
