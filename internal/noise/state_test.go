package noise

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hugo-vicente11/go-vpn/internal/session"
)

// The expected values in these tests were computed with Python's hashlib,
// starting from Hi in TestInitialState and Alice's public key.

func TestNewHandshakeState(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))

	if s.chainKey != initialChainKey {
		t.Errorf("chainKey = %x, want initialChainKey %x", s.chainKey, initialChainKey)
	}
	checkHex(t, "hash", s.hash[:], "e7a5e4b40a7a5675887ad11042ccfc1112ed3507384bca39896693cfab32bdc6")
}

func TestMixHash(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))
	s.mixHash([]byte("abc"))

	checkHex(t, "hash", s.hash[:], "aa01ab5ad64be2ef211d073a9eddace7b778c029ded05c45df351372345427d1")
	if s.chainKey != initialChainKey {
		t.Errorf("mixHash changed chainKey to %x", s.chainKey)
	}
}

// TestMixHashSeparatesCalls checks that mixing "a" then "b" differs from
// mixing "ab" once: each call hashes the previous H, so the transcript keeps
// the boundary between messages, unlike hash, which joins its pieces.
func TestMixHashSeparatesCalls(t *testing.T) {
	twice := newHandshakeState(alicePublicKey(t))
	twice.mixHash([]byte("a"))
	twice.mixHash([]byte("b"))

	once := newHandshakeState(alicePublicKey(t))
	once.mixHash([]byte("ab"))

	if twice.hash == once.hash {
		t.Error(`mixHash("a") then mixHash("b") equals mixHash("ab")`)
	}
}

// TestHandshakeStateCopyIsIndependent checks that changing a copy of the state
// does not change the original, nor the global initial values.
func TestHandshakeStateCopyIsIndependent(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))
	before := *s

	c := *s
	c.mixHash([]byte("abc"))

	if *s != before {
		t.Error("mixHash on a copy changed the original")
	}
	checkHex(t, "initialHash", initialHash[:], "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3")
}

// The mixKey tests compare each method with the KDF it should call, which
// TestKDF3 already checks against Python. They also check that each method
// changes only the fields it should.

func TestMixKey(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))
	before := *s
	input := []byte("abc")

	s.mixKey(input)

	if want := kdf1(before.chainKey, input); s.chainKey != want {
		t.Errorf("chainKey = %x, want %x", s.chainKey, want)
	}
	if s.hash != before.hash {
		t.Errorf("mixKey changed hash to %x", s.hash)
	}
}

func TestMixKeyAndGetKey(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))
	before := *s
	input := []byte("abc")

	key := s.mixKeyAndGetKey(input)

	wantChainKey, wantKey := kdf2(before.chainKey, input)
	if s.chainKey != wantChainKey {
		t.Errorf("chainKey = %x, want %x", s.chainKey, wantChainKey)
	}
	if key != wantKey {
		t.Errorf("returned key = %x, want %x", key, wantKey)
	}
	if s.hash != before.hash {
		t.Errorf("mixKeyAndGetKey changed hash to %x", s.hash)
	}
}

func TestMixKeyAndHash(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))
	before := *s
	input := []byte("abc")

	key := s.mixKeyAndHash(input)

	wantChainKey, tau, wantKey := kdf3(before.chainKey, input)
	if s.chainKey != wantChainKey {
		t.Errorf("chainKey = %x, want %x", s.chainKey, wantChainKey)
	}
	if key != wantKey {
		t.Errorf("returned key = %x, want %x", key, wantKey)
	}
	if want := hash(before.hash[:], tau[:]); s.hash != want {
		t.Errorf("hash = %x, want HASH(H || t) %x", s.hash, want)
	}
}

// TestHandshakeStatesAgree checks that two peers making the same calls end in
// the same state, as the initiator and responder must.
func TestHandshakeStatesAgree(t *testing.T) {
	steps := func(s *handshakeState) [32]byte {
		s.mixHash([]byte("ephemeral"))
		s.mixKey([]byte("ephemeral"))
		k1 := s.mixKeyAndGetKey([]byte("dh"))
		k2 := s.mixKeyAndHash([]byte("psk"))
		return hash(k1[:], k2[:])
	}

	a, b := newHandshakeState(alicePublicKey(t)), newHandshakeState(alicePublicKey(t))
	keysA, keysB := steps(a), steps(b)

	if *a != *b {
		t.Errorf("states differ: %x/%x and %x/%x", a.chainKey, a.hash, b.chainKey, b.hash)
	}
	if keysA != keysB {
		t.Error("the two states returned different keys")
	}
}

// handshakeStatePair returns two equal states, one for each side of a
// handshake, and a key for the next encrypted field.
func handshakeStatePair(t *testing.T) (sender, receiver *handshakeState, key [32]byte) {
	t.Helper()
	sender = newHandshakeState(alicePublicKey(t))
	receiver = newHandshakeState(alicePublicKey(t))
	return sender, receiver, testKey()
}

func TestEncryptAndHashRoundTrip(t *testing.T) {
	for _, plaintext := range [][]byte{[]byte("static key"), nil} {
		sender, receiver, key := handshakeStatePair(t)

		ciphertext := sender.encryptAndHash(key, plaintext)
		if want := len(plaintext) + 16; len(ciphertext) != want {
			t.Errorf("len(ciphertext) = %d, want %d", len(ciphertext), want)
		}

		got, err := receiver.decryptAndHash(key, ciphertext)
		if err != nil {
			t.Fatalf("decryptAndHash(%q): %v", plaintext, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("decryptAndHash = %q, want %q", got, plaintext)
		}
		if *sender != *receiver {
			t.Errorf("states differ after %q: hash %x and %x", plaintext, sender.hash, receiver.hash)
		}
	}
}

// TestEncryptAndHashMixesCiphertext checks that the hash takes in the
// ciphertext, as the whitepaper defines, and that the chaining key is
// unchanged.
func TestEncryptAndHashMixesCiphertext(t *testing.T) {
	s, _, key := handshakeStatePair(t)
	before := *s
	plaintext := []byte("static key")

	ciphertext := s.encryptAndHash(key, plaintext)

	if want := aeadEncrypt(key, plaintext, before.hash[:]); !bytes.Equal(ciphertext, want) {
		t.Errorf("ciphertext = %x, want AEAD with the old hash %x", ciphertext, want)
	}
	if want := hash(before.hash[:], ciphertext); s.hash != want {
		t.Errorf("hash = %x, want HASH(H || ciphertext) %x", s.hash, want)
	}
	if s.chainKey != before.chainKey {
		t.Errorf("encryptAndHash changed chainKey to %x", s.chainKey)
	}
}

// TestDecryptAndHashRejects checks that decryption fails when the receiver's
// state or key differs from the sender's, or the ciphertext was changed, and
// that a failure leaves the state unchanged.
func TestDecryptAndHashRejects(t *testing.T) {
	tests := []struct {
		name  string
		setup func(receiver *handshakeState, key *[32]byte, ciphertext []byte)
	}{
		{"different hash", func(r *handshakeState, _ *[32]byte, _ []byte) { r.mixHash([]byte("x")) }},
		{"different key", func(_ *handshakeState, k *[32]byte, _ []byte) { k[0] ^= 1 }},
		{"tampered ciphertext", func(_ *handshakeState, _ *[32]byte, c []byte) { c[0] ^= 1 }},
		{"tampered tag", func(_ *handshakeState, _ *[32]byte, c []byte) { c[len(c)-1] ^= 1 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver, key := handshakeStatePair(t)
			ciphertext := sender.encryptAndHash(key, []byte("static key"))
			tc.setup(receiver, &key, ciphertext)
			before := *receiver

			if _, err := receiver.decryptAndHash(key, ciphertext); !errors.Is(err, errDecrypt) {
				t.Fatalf("decryptAndHash error = %v, want %v", err, errDecrypt)
			}
			if *receiver != before {
				t.Error("a failed decryptAndHash changed the state")
			}
		})
	}
}

// TestDeriveTransportKeys checks the keys against KDF2(C, empty), which
// TestKDFIsHKDF already checks, and that the state is zeroed afterwards.
func TestDeriveTransportKeys(t *testing.T) {
	s := newHandshakeState(alicePublicKey(t))
	s.mixKey([]byte("dh"))
	before := *s

	i2r, r2i := s.deriveTransportKeys()

	wantI2R, wantR2I := kdf2(before.chainKey, nil)
	if i2r != wantI2R {
		t.Errorf("initiatorToResponder = %x, want T1 %x", i2r, wantI2R)
	}
	if r2i != wantR2I {
		t.Errorf("responderToInitiator = %x, want T2 %x", r2i, wantR2I)
	}
	if i2r == r2i {
		t.Error("the two transport keys are equal")
	}
	if *s != (handshakeState{}) {
		t.Errorf("state after deriveTransportKeys = %x/%x, want zero", s.chainKey, s.hash)
	}
}

// TestDeriveTransportKeysMakeSessions checks that two peers in the same state
// get keys that work together: what one session seals, the other opens.
func TestDeriveTransportKeysMakeSessions(t *testing.T) {
	initiator, responder := newHandshakeState(alicePublicKey(t)), newHandshakeState(alicePublicKey(t))

	iSend, iRecv := initiator.deriveTransportKeys()
	rRecv, rSend := responder.deriveTransportKeys()

	const initiatorIndex, responderIndex = 1, 2
	iSession, err := session.New(iSend, iRecv, responderIndex, initiatorIndex)
	if err != nil {
		t.Fatalf("session.New for the initiator: %v", err)
	}
	rSession, err := session.New(rSend, rRecv, initiatorIndex, responderIndex)
	if err != nil {
		t.Fatalf("session.New for the responder: %v", err)
	}

	for _, dir := range []struct {
		name     string
		from, to *session.Session
	}{
		{"initiator to responder", iSession, rSession},
		{"responder to initiator", rSession, iSession},
	} {
		msg, err := dir.from.Seal(nil, []byte("packet"))
		if err != nil {
			t.Fatalf("%s: Seal: %v", dir.name, err)
		}
		got, err := dir.to.Open(nil, msg)
		if err != nil {
			t.Fatalf("%s: Open: %v", dir.name, err)
		}
		if string(got) != "packet" {
			t.Errorf("%s: Open = %q, want %q", dir.name, got, "packet")
		}
	}
}
