package noise

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/blake2s"
)

// The expected values in these tests were computed with Python's hashlib and
// hmac modules, an implementation independent of the Go code under test.

// testKey returns the key used in the known-answer tests: the bytes 0 to 31.
func testKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// splits holds the same input as one piece and in several pieces, to check
// that the functions hash the pieces as if they were joined together.
var splits = []struct {
	name string
	data [][]byte
}{
	{"one piece", [][]byte{[]byte("abc")}},
	{"two pieces", [][]byte{[]byte("a"), []byte("bc")}},
	{"three pieces", [][]byte{[]byte("a"), []byte("b"), []byte("c")}},
	{"with empty pieces", [][]byte{{}, []byte("ab"), {}, []byte("c")}},
}

// checkHex fails the test if got, in hex, is not want.
func checkHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if g := hex.EncodeToString(got); g != want {
		t.Errorf("%s = %s, want %s", name, g, want)
	}
}

func TestHash(t *testing.T) {
	// "abc" is the example in RFC 7693, appendix B.
	const want = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"

	for _, s := range splits {
		t.Run(s.name, func(t *testing.T) {
			got := hash(s.data...)
			checkHex(t, "hash", got[:], want)
		})
	}

	t.Run("no input", func(t *testing.T) {
		got := hash()
		checkHex(t, "hash()", got[:], "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
	})
}

func TestMAC(t *testing.T) {
	const want = "61ba5f165c194692e09d12520cc4c74a"

	for _, s := range splits {
		t.Run(s.name, func(t *testing.T) {
			got := mac(testKey(), s.data...)
			checkHex(t, "mac", got[:], want)
		})
	}
}

func TestHMAC(t *testing.T) {
	const want = "82623be5bc0a391b24dce53e67d028eff92d586de0485ac37822e597d049c74f"

	for _, s := range splits {
		t.Run(s.name, func(t *testing.T) {
			got := hmac(testKey(), s.data...)
			checkHex(t, "hmac", got[:], want)
		})
	}
}

// TestMACIsNotTruncatedOrHMAC checks the two easiest mistakes in mac: using
// HMAC instead of keyed BLAKE2s, and cutting a 32-byte keyed BLAKE2s output in
// half. BLAKE2s mixes the output length into its initial state, so a 16-byte
// output is not the first half of a 32-byte one.
func TestMACIsNotTruncatedOrHMAC(t *testing.T) {
	key, data := testKey(), []byte("abc")
	got := mac(key, data)

	h, err := blake2s.New256(key[:])
	if err != nil {
		t.Fatalf("blake2s.New256: %v", err)
	}
	h.Write(data)
	if truncated := h.Sum(nil)[:16]; bytes.Equal(got[:], truncated) {
		t.Error("mac equals keyed BLAKE2s-256 cut to 16 bytes")
	}

	if hm := hmac(key, data); bytes.Equal(got[:], hm[:16]) {
		t.Error("mac equals hmac cut to 16 bytes")
	}
}

// TestKeyChangesOutput checks that mac and hmac use their key.
func TestKeyChangesOutput(t *testing.T) {
	data := []byte("abc")
	var otherKey [32]byte

	if mac(testKey(), data) == mac(otherKey, data) {
		t.Error("mac gives the same output with two different keys")
	}
	if hmac(testKey(), data) == hmac(otherKey, data) {
		t.Error("hmac gives the same output with two different keys")
	}
}
