package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// rfc7748 holds the X25519 test vectors from RFC 7748, section 6.1, in hex.
var rfc7748 = struct {
	alicePrivate, alicePublic string
	bobPrivate, bobPublic     string
	shared                    string
}{
	alicePrivate: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
	alicePublic:  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
	bobPrivate:   "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
	bobPublic:    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
	shared:       "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
}

// hexToBase64 converts a key written in hex, as RFC 7748 does, to the base64
// format the Parse functions read.
func hexToBase64(t *testing.T, s string) string {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// privateKeyFromHex returns the private key that s encodes in hex, failing
// the test if ParsePrivateKey rejects it.
func privateKeyFromHex(t *testing.T, s string) *PrivateKey {
	t.Helper()
	k, err := ParsePrivateKey(hexToBase64(t, s))
	if err != nil {
		t.Fatalf("ParsePrivateKey(%s): %v", s, err)
	}
	return k
}

// publicKeyFromHex returns the public key that s encodes in hex, failing the
// test if ParsePublicKey rejects it.
func publicKeyFromHex(t *testing.T, s string) *PublicKey {
	t.Helper()
	k, err := ParsePublicKey(hexToBase64(t, s))
	if err != nil {
		t.Fatalf("ParsePublicKey(%s): %v", s, err)
	}
	return k
}

// generate returns a new private key, failing the test on error.
func generate(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return k
}

// TestPublicKeyKnownAnswer checks PrivateKey.PublicKey against the public keys
// that RFC 7748 gives for Alice's and Bob's private keys.
func TestPublicKeyKnownAnswer(t *testing.T) {
	tests := []struct {
		name          string
		private, want string
	}{
		{"Alice", rfc7748.alicePrivate, rfc7748.alicePublic},
		{"Bob", rfc7748.bobPrivate, rfc7748.bobPublic},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub := privateKeyFromHex(t, tc.private).PublicKey()
			if got := hex.EncodeToString(pub.key.Bytes()); got != tc.want {
				t.Errorf("PublicKey = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestGeneratePrivateKeyIsRandom(t *testing.T) {
	a, b := generate(t), generate(t)
	if bytes.Equal(a.key.Bytes(), b.key.Bytes()) {
		t.Error("two generated private keys are equal")
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	k := generate(t)

	got, err := ParsePrivateKey(k.Encode())
	if err != nil {
		t.Fatalf("ParsePrivateKey(Encode()): %v", err)
	}
	if !bytes.Equal(got.key.Bytes(), k.key.Bytes()) {
		t.Error("ParsePrivateKey(Encode()) returned a different key")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	k := generate(t).PublicKey()

	got, err := ParsePublicKey(k.String())
	if err != nil {
		t.Fatalf("ParsePublicKey(String()): %v", err)
	}
	if !bytes.Equal(got.key.Bytes(), k.key.Bytes()) {
		t.Error("ParsePublicKey(String()) returned a different key")
	}
}

// parsers runs a test against both Parse functions, which accept the same
// format.
var parsers = []struct {
	name  string
	parse func(string) error
}{
	{"ParsePrivateKey", func(s string) error { _, err := ParsePrivateKey(s); return err }},
	{"ParsePublicKey", func(s string) error { _, err := ParsePublicKey(s); return err }},
}

func TestParseIgnoresWhitespace(t *testing.T) {
	key := hexToBase64(t, rfc7748.alicePrivate)

	for _, p := range parsers {
		for _, s := range []string{key + "\n", "  " + key + "\t\n"} {
			if err := p.parse(s); err != nil {
				t.Errorf("%s(%q): %v", p.name, s, err)
			}
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	valid := make([]byte, 32)
	valid[0] = 1

	tests := []struct {
		name, input string
	}{
		{"empty", ""},
		{"not base64", "not base64!"},
		{"no padding", base64.RawStdEncoding.EncodeToString(valid)},
		{"31 bytes", b64(valid[:31])},
		{"33 bytes", b64(append(valid, 0))},
	}

	for _, p := range parsers {
		for _, tc := range tests {
			if err := p.parse(tc.input); err == nil {
				t.Errorf("%s(%s): no error", p.name, tc.name)
			}
		}
	}
}

// TestParsePrivateKeyErrorHidesKey checks that when a private key is almost
// valid, the error does not repeat it, so it cannot end up in a log.
func TestParsePrivateKeyErrorHidesKey(t *testing.T) {
	key := hexToBase64(t, rfc7748.alicePrivate)

	for _, s := range []string{key + "!", key + "AAAA"} {
		_, err := ParsePrivateKey(s)
		if err == nil {
			t.Fatalf("ParsePrivateKey(%q): no error", s)
		}
		if strings.Contains(err.Error(), key[:8]) {
			t.Errorf("ParsePrivateKey error %q contains the key", err)
		}
	}
}

// sharedSecret calls k.SharedSecret, failing the test on error.
func sharedSecret(t *testing.T, k *PrivateKey, peer *PublicKey) [32]byte {
	t.Helper()
	secret, err := k.SharedSecret(peer)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	return secret
}

// TestSharedSecretKnownAnswer checks SharedSecret against the shared secret
// that RFC 7748 gives for Alice's and Bob's keys, computed from both sides.
func TestSharedSecretKnownAnswer(t *testing.T) {
	tests := []struct {
		name          string
		private, peer string
	}{
		{"Alice with Bob's public key", rfc7748.alicePrivate, rfc7748.bobPublic},
		{"Bob with Alice's public key", rfc7748.bobPrivate, rfc7748.alicePublic},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret := sharedSecret(t, privateKeyFromHex(t, tc.private), publicKeyFromHex(t, tc.peer))
			if got := hex.EncodeToString(secret[:]); got != rfc7748.shared {
				t.Errorf("SharedSecret = %s, want %s", got, rfc7748.shared)
			}
		})
	}
}

// TestSharedSecretSymmetric checks that two generated key pairs agree on the
// same secret, and that a third key pair gets a different one.
func TestSharedSecretSymmetric(t *testing.T) {
	a, b, c := generate(t), generate(t), generate(t)

	ab := sharedSecret(t, a, b.PublicKey())
	ba := sharedSecret(t, b, a.PublicKey())
	if ab != ba {
		t.Errorf("a with b = %x, b with a = %x, want them equal", ab, ba)
	}

	if ac := sharedSecret(t, a, c.PublicKey()); ac == ab {
		t.Error("a got the same secret with b and with c")
	}
}

// TestSharedSecretRejectsLowOrder checks that SharedSecret refuses public keys
// that are low-order points. Each one would give an all-zero secret, so a
// peer sending one could force a secret it knows. ParsePublicKey accepts
// them, because they are 32 valid bytes.
func TestSharedSecretRejectsLowOrder(t *testing.T) {
	k := privateKeyFromHex(t, rfc7748.alicePrivate)

	tests := []struct {
		name, peer string
	}{
		{"zero", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"one", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"order 8", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret, err := k.SharedSecret(publicKeyFromHex(t, tc.peer))
			if err == nil {
				t.Fatalf("SharedSecret = %x, want an error", secret)
			}
			if !strings.HasPrefix(err.Error(), "identity: ") {
				t.Errorf("error = %q, want it to start with %q", err, "identity: ")
			}
			if errors.Unwrap(err) == nil {
				t.Errorf("error = %q, want it to wrap the cause", err)
			}
		})
	}
}
