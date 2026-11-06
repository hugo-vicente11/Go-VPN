package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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

// newTestSession returns a Session that uses key in both directions, so it can
// open its own messages. It fails the test if the Session cannot be created.
func newTestSession(t *testing.T, key Key) *Session {
	t.Helper()
	return newSession(t, key, key)
}

// newSession returns a Session that seals with send and opens with recv. It
// fails the test if the Session cannot be created.
func newSession(t *testing.T, send, recv Key) *Session {
	t.Helper()
	s, err := New(send, recv)
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
	s.sendCounter.Store(0x0102030405060708)
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
	s.sendCounter.Store(counterLimit - 1)
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

func TestOpenRejectsReplay(t *testing.T) {
	s := newTestSession(t, testKey)
	msg := seal(t, s, []byte("hello"))

	if _, err := s.Open(nil, msg); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := s.Open(nil, msg); !errors.Is(err, ErrReplay) {
		t.Errorf("second Open: error = %v, want %v", err, ErrReplay)
	}
}

// TestOpenAcceptsReordered checks that messages arriving out of order, as UDP
// allows, are all opened.
func TestOpenAcceptsReordered(t *testing.T) {
	s := newTestSession(t, testKey)
	packets := [][]byte{[]byte("zero"), []byte("one"), []byte("two")}

	var msgs [][]byte
	for _, p := range packets {
		msgs = append(msgs, seal(t, s, p))
	}

	for _, i := range []int{0, 2, 1} {
		got, err := s.Open(nil, msgs[i])
		if err != nil {
			t.Fatalf("Open message %d: %v", i, err)
		}
		if !bytes.Equal(got, packets[i]) {
			t.Errorf("Open message %d = %q, want %q", i, got, packets[i])
		}
	}
}

// TestOpenForgedCounterKeepsWindow checks that a message that fails
// authentication does not move the replay window. Anyone can send a message
// with a high counter. If Open moved the window before authenticating it,
// every real message after it would be rejected as too old.
func TestOpenForgedCounterKeepsWindow(t *testing.T) {
	s := newTestSession(t, testKey)
	real := seal(t, s, []byte("real"))

	forged := seal(t, s, []byte("forged"))
	binary.LittleEndian.PutUint64(forged[counterOffset:HeaderSize], 1<<40)

	if _, err := s.Open(nil, forged); !errors.Is(err, ErrAuth) {
		t.Fatalf("Open forged message: error = %v, want %v", err, ErrAuth)
	}
	if _, err := s.Open(nil, real); err != nil {
		t.Errorf("Open real message after a forged one: %v", err)
	}
}

// TestOpenConcurrentReplay checks that when many goroutines open the same
// message at once, exactly one succeeds. Run it with -race.
func TestOpenConcurrentReplay(t *testing.T) {
	const goroutines = 100

	s := newTestSession(t, testKey)
	msg := seal(t, s, []byte("hello"))

	var accepted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Open(nil, msg)
			switch {
			case err == nil:
				accepted.Add(1)
			case !errors.Is(err, ErrReplay):
				t.Errorf("Open: error = %v, want nil or %v", err, ErrReplay)
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Errorf("Open succeeded %d times, want 1", got)
	}
}

// TestSessionPair checks two Sessions set up as the two ends of a tunnel,
// each sealing with the key the other opens with.
func TestSessionPair(t *testing.T) {
	a := newSession(t, testKey, otherKey)
	b := newSession(t, otherKey, testKey)
	checkSessionPair(t, a, b)
}

// checkSessionPair checks that a and b work as the two ends of a tunnel. Both
// must be new, so their first messages use the same counter.
func checkSessionPair(t *testing.T, a, b *Session) {
	t.Helper()
	packet := []byte("hello")

	fromA := seal(t, a, packet)
	fromB := seal(t, b, packet)

	t.Run("each side opens the other's message", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			s    *Session
			msg  []byte
		}{
			{"b opens a", b, fromA},
			{"a opens b", a, fromB},
		} {
			got, err := tc.s.Open(nil, tc.msg)
			if err != nil {
				t.Fatalf("%s: Open: %v", tc.name, err)
			}
			if !bytes.Equal(got, packet) {
				t.Errorf("%s: Open = %q, want %q", tc.name, got, packet)
			}
		}
	})

	t.Run("a side cannot open its own message", func(t *testing.T) {
		if _, err := a.Open(nil, fromA); !errors.Is(err, ErrAuth) {
			t.Errorf("Open: error = %v, want %v", err, ErrAuth)
		}
	})

	// Both messages use counter 0. With one shared key they would be sealed
	// with the same key and nonce, and the ciphertexts would be identical.
	t.Run("same counter gives different ciphertexts", func(t *testing.T) {
		if bytes.Equal(fromA[HeaderSize:], fromB[HeaderSize:]) {
			t.Error("both directions produced the same ciphertext for the same counter and packet")
		}
	})
}

// deriveKeys calls DeriveKeys, failing the test on error.
func deriveKeys(t *testing.T, shared Key, initiator bool) (send, recv Key) {
	t.Helper()
	send, recv, err := DeriveKeys(shared, initiator)
	if err != nil {
		t.Fatalf("DeriveKeys(initiator=%v): %v", initiator, err)
	}
	return send, recv
}

func TestDeriveKeys(t *testing.T) {
	iSend, iRecv := deriveKeys(t, testKey, true)
	rSend, rRecv := deriveKeys(t, testKey, false)

	if iSend != rRecv {
		t.Errorf("initiator send key %x != responder receive key %x", iSend, rRecv)
	}
	if iRecv != rSend {
		t.Errorf("initiator receive key %x != responder send key %x", iRecv, rSend)
	}
	if iSend == iRecv {
		t.Errorf("send and receive keys are both %x, want one key for each direction", iSend)
	}
	for _, k := range []Key{iSend, iRecv} {
		if k == testKey {
			t.Errorf("derived key %x is the shared key", k)
		}
	}

	otherSend, otherRecv := deriveKeys(t, otherKey, true)
	if otherSend == iSend || otherRecv == iRecv {
		t.Error("different shared keys derived the same keys")
	}
}

// TestDeriveKeysKnownAnswer checks DeriveKeys against keys computed outside
// Go, with HKDF-SHA256 written by hand from RFC 5869. The other tests only
// compare derived keys with each other, so they cannot catch a change that
// alters both directions, such as a new hash, salt, or label. Peers running
// different versions would then derive different keys.
func TestDeriveKeysKnownAnswer(t *testing.T) {
	want := map[bool]struct{ send, recv string }{
		true: {
			send: "3b38df6ff2f8a6119c1d913318e8ad091da1097d89814a42f279ff2e45f4cba0",
			recv: "febd29c9d4f4ffb13f6b1d2bff5b1ef67c27e298a07d0511add117eb7fc05b22",
		},
		false: {
			send: "febd29c9d4f4ffb13f6b1d2bff5b1ef67c27e298a07d0511add117eb7fc05b22",
			recv: "3b38df6ff2f8a6119c1d913318e8ad091da1097d89814a42f279ff2e45f4cba0",
		},
	}

	for _, initiator := range []bool{true, false} {
		send, recv := deriveKeys(t, testKeyB64Bytes(), initiator)
		if got := hex.EncodeToString(send[:]); got != want[initiator].send {
			t.Errorf("DeriveKeys(initiator=%v) send = %s, want %s", initiator, got, want[initiator].send)
		}
		if got := hex.EncodeToString(recv[:]); got != want[initiator].recv {
			t.Errorf("DeriveKeys(initiator=%v) recv = %s, want %s", initiator, got, want[initiator].recv)
		}
	}
}

// TestDerivedSessionPair checks that Sessions built from DeriveKeys work as
// the two ends of a tunnel.
func TestDerivedSessionPair(t *testing.T) {
	iSend, iRecv := deriveKeys(t, testKey, true)
	rSend, rRecv := deriveKeys(t, testKey, false)

	checkSessionPair(t, newSession(t, iSend, iRecv), newSession(t, rSend, rRecv))
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
