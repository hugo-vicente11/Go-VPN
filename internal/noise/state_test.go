package noise

import "testing"

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
