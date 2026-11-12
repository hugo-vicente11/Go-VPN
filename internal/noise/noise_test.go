package noise

import (
	"bytes"
	"crypto/hkdf"
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

// kdfInputs holds the inputs for the KDF tests, with the outputs Python gives
// for each one with testKey.
var kdfInputs = []struct {
	name       string
	input      []byte
	t1, t2, t3 string
}{
	{
		name:  "input",
		input: []byte("input"),
		t1:    "87b7f70b24183c6db5dc4f6d9f4c47cdb203321aa2a0bef714896adb3107a040",
		t2:    "538a02e1eb2e31b7e4d4b82476d1fe2acf50085d3fb584537279195f5d1f5824",
		t3:    "9ad858025593be88de0f9442a589cfe84a88dc19e4753d93684d1c5efc4837f9",
	},
	{
		// The handshake derives the transport keys from an empty input.
		name:  "empty",
		input: nil,
		t1:    "7a38c34bf2b8738d7374ca77c44ecb309a11d2b2528304fa86052c365e722624",
		t2:    "1a17621f346abdc520746a9fb64d8eb03231d674fc15687537b0780fd9c060fd",
		t3:    "4eaf02809ac4b930ef63479de62275f1c55656e61f78a3cc653c18a2223d6c5f",
	},
}

func TestKDF3(t *testing.T) {
	for _, tc := range kdfInputs {
		t.Run(tc.name, func(t *testing.T) {
			t1, t2, t3 := kdf3(testKey(), tc.input)
			checkHex(t, "t1", t1[:], tc.t1)
			checkHex(t, "t2", t2[:], tc.t2)
			checkHex(t, "t3", t3[:], tc.t3)
		})
	}
}

// TestKDFOutputsMatch checks that kdf1 and kdf2 return the first outputs of
// kdf3, as the whitepaper defines them.
func TestKDFOutputsMatch(t *testing.T) {
	for _, tc := range kdfInputs {
		t.Run(tc.name, func(t *testing.T) {
			t1, t2, _ := kdf3(testKey(), tc.input)

			if got := kdf1(testKey(), tc.input); got != t1 {
				t.Errorf("kdf1 = %x, want %x", got, t1)
			}
			got1, got2 := kdf2(testKey(), tc.input)
			if got1 != t1 || got2 != t2 {
				t.Errorf("kdf2 = %x, %x, want %x, %x", got1, got2, t1, t2)
			}
		})
	}
}

// TestKDFOutputsDiffer checks that the outputs of one call are all different.
// Equal outputs would mean a missing counter byte or a missing previous output.
func TestKDFOutputsDiffer(t *testing.T) {
	for _, tc := range kdfInputs {
		t.Run(tc.name, func(t *testing.T) {
			t1, t2, t3 := kdf3(testKey(), tc.input)
			if t1 == t2 || t2 == t3 || t1 == t3 {
				t.Errorf("kdf3 outputs are not all different: %x, %x, %x", t1, t2, t3)
			}
		})
	}
}

// TestKDFIsHKDF checks that kdf3 is HKDF with BLAKE2s, using the standard
// library's implementation: extract with the key as the salt, then expand to
// 96 bytes with an empty info.
func TestKDFIsHKDF(t *testing.T) {
	for _, tc := range kdfInputs {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey()
			prk, err := hkdf.Extract(newBLAKE2s, tc.input, key[:])
			if err != nil {
				t.Fatalf("hkdf.Extract: %v", err)
			}
			want, err := hkdf.Expand(newBLAKE2s, prk, "", 96)
			if err != nil {
				t.Fatalf("hkdf.Expand: %v", err)
			}

			t1, t2, t3 := kdf3(key, tc.input)
			got := bytes.Join([][]byte{t1[:], t2[:], t3[:]}, nil)
			if !bytes.Equal(got, want) {
				t.Errorf("kdf3 =\n%x\nwant HKDF\n%x", got, want)
			}
		})
	}
}

// TestInitialState checks Ci and Hi against the values wireguard-go hardcodes,
// also computed with Python.
func TestInitialState(t *testing.T) {
	checkHex(t, "initialChainKey", initialChainKey[:], "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")
	checkHex(t, "initialHash", initialHash[:], "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3")
}

// TestLabelMAC1Length checks that labelMAC1 is 8 bytes, as the whitepaper
// defines it. A missing dash is easy to miss by eye.
func TestLabelMAC1Length(t *testing.T) {
	if len(labelMAC1) != 8 {
		t.Errorf("len(labelMAC1) = %d, want 8", len(labelMAC1))
	}
}
