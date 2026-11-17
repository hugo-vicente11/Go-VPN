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
