package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
	"github.com/hugo-vicente11/go-vpn/internal/noise"
	"github.com/hugo-vicente11/go-vpn/internal/session"
)

func TestValidateTunnelAddr(t *testing.T) {
	tests := []struct {
		name    string
		input   netip.Prefix
		wantErr bool
	}{
		{"host address", netip.MustParsePrefix("10.0.0.1/24"), false},
		{"length 30 host address", netip.MustParsePrefix("10.0.0.1/30"), false},
		{"length 31 point-to-point", netip.MustParsePrefix("10.0.0.0/31"), false},
		{"empty", netip.Prefix{}, true},
		{"IPv6", netip.MustParsePrefix("fd00::1/64"), true},
		{"length 32", netip.MustParsePrefix("10.0.0.1/32"), true},
		{"network address", netip.MustParsePrefix("10.0.0.0/24"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTunnelAddr(tc.input)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("validateTunnelAddr(%v) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestValidateTunnelAddrSuggestsHost checks that rejecting a network address
// suggests the first host address with the same prefix length, ready to copy.
func TestValidateTunnelAddrSuggestsHost(t *testing.T) {
	err := validateTunnelAddr(netip.MustParsePrefix("10.0.0.0/24"))
	if err == nil {
		t.Fatal("validateTunnelAddr(10.0.0.0/24) returned nil, want error")
	}

	const want = "such as 10.0.0.1/24"
	if msg := err.Error(); !strings.HasSuffix(msg, want) {
		t.Errorf("error = %q, want it to end with %q", msg, want)
	}
}

// testKeyFileContent is a private key file as wg genkey writes it, with a
// trailing newline. It decodes to the bytes 0 to 31.
const testKeyFileContent = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"

func TestLoadPrivateKey(t *testing.T) {
	want := strings.TrimSpace(testKeyFileContent)

	tests := []struct {
		name    string
		content string // file content; empty means the file is not created
		mode    os.FileMode
		wantErr string // substring the error must contain; empty means success
	}{
		{"valid", testKeyFileContent, 0o600, ""},
		{"group readable", testKeyFileContent, 0o640, "chmod 600"},
		{"world readable", testKeyFileContent, 0o644, "chmod 600"},
		{"missing", "", 0, "no such file"},
		{"garbage", "not a key", 0o600, "not valid base64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.key")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
				// WriteFile's mode is reduced by the umask, so set it explicitly.
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}

			got, err := loadPrivateKey(path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("loadPrivateKey: %v", err)
				}
				if enc := got.Encode(); enc != want {
					t.Errorf("loadPrivateKey = %s, want %s", enc, want)
				}
				return
			}

			if err == nil {
				t.Fatalf("loadPrivateKey returned nil error, want one containing %q", tc.wantErr)
			}
			if msg := err.Error(); !strings.Contains(msg, tc.wantErr) {
				t.Errorf("loadPrivateKey error = %q, want it to contain %q", msg, tc.wantErr)
			}
			// Every error must name the file, so the user knows which one to fix.
			if msg := err.Error(); !strings.Contains(msg, path) {
				t.Errorf("loadPrivateKey error = %q, want it to name %s", msg, path)
			}
		})
	}
}

// TestLoadPrivateKeyMissingIsNotExist checks that a missing file can still be
// recognized with errors.Is after loadPrivateKey wraps the error.
func TestLoadPrivateKeyMissingIsNotExist(t *testing.T) {
	_, err := loadPrivateKey(filepath.Join(t.TempDir(), "missing.key"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("loadPrivateKey error = %v, want it to wrap %v", err, fs.ErrNotExist)
	}
}

// Alice's key pair from RFC 7748, section 6.1, in base64.
const (
	alicePrivate = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	alicePublic  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
)

// errWrite is the error failingWriter returns.
var errWrite = errors.New("write failed")

// failingWriter is an io.Writer whose writes always fail, like stdout
// redirected to a full disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

// runGenkey calls genkey and returns what it wrote, failing the test on error.
func runGenkey(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	if err := genkey(&out); err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return out.String()
}

func TestGenkey(t *testing.T) {
	out := runGenkey(t)

	key, ok := strings.CutSuffix(out, "\n")
	if !ok {
		t.Fatalf("genkey wrote %q, want it to end with a newline", out)
	}
	if strings.ContainsAny(key, " \t\n") {
		t.Errorf("genkey wrote %q, want only the key and one newline", out)
	}
	if _, err := identity.ParsePrivateKey(key); err != nil {
		t.Errorf("ParsePrivateKey(genkey output): %v", err)
	}
}

func TestGenkeyIsRandom(t *testing.T) {
	if a, b := runGenkey(t), runGenkey(t); a == b {
		t.Errorf("genkey wrote %q twice", a)
	}
}

func TestPubkey(t *testing.T) {
	for _, input := range []string{alicePrivate, alicePrivate + "\n"} {
		var out bytes.Buffer
		if err := pubkey(strings.NewReader(input), &out); err != nil {
			t.Fatalf("pubkey(%q): %v", input, err)
		}
		if got, want := out.String(), alicePublic+"\n"; got != want {
			t.Errorf("pubkey(%q) wrote %q, want %q", input, got, want)
		}
	}
}

// TestPubkeyGenkey checks that pubkey reads what genkey writes, as in
// govpn genkey | govpn pubkey, and gets the same key as identity.
func TestPubkeyGenkey(t *testing.T) {
	private := runGenkey(t)

	var out bytes.Buffer
	if err := pubkey(strings.NewReader(private), &out); err != nil {
		t.Fatalf("pubkey(genkey output): %v", err)
	}

	key, err := identity.ParsePrivateKey(private)
	if err != nil {
		t.Fatalf("ParsePrivateKey(genkey output): %v", err)
	}
	if got, want := out.String(), key.PublicKey().String()+"\n"; got != want {
		t.Errorf("pubkey wrote %q, want %q", got, want)
	}
}

func TestPubkeyRejectsEmptyInput(t *testing.T) {
	for _, input := range []string{"", "\n", "  \t\n"} {
		var out bytes.Buffer
		if err := pubkey(strings.NewReader(input), &out); !errors.Is(err, errNoPrivateKey) {
			t.Errorf("pubkey(%q) error = %v, want %v", input, err, errNoPrivateKey)
		}
		if out.Len() != 0 {
			t.Errorf("pubkey(%q) wrote %q, want nothing", input, out.String())
		}
	}
}

func TestPubkeyRejectsInvalidKey(t *testing.T) {
	for _, input := range []string{"not base64!", "AAAA", alicePublic + "AAAA"} {
		var out bytes.Buffer
		err := pubkey(strings.NewReader(input), &out)
		if err == nil {
			t.Errorf("pubkey(%q) returned nil error, want one", input)
			continue
		}
		if errors.Is(err, errNoPrivateKey) {
			t.Errorf("pubkey(%q) error = %v, want an invalid key error, not %v", input, err, errNoPrivateKey)
		}
		if out.Len() != 0 {
			t.Errorf("pubkey(%q) wrote %q, want nothing", input, out.String())
		}
	}
}

// TestWriteErrors checks that genkey and pubkey report a failed write, so a
// user does not end up with an empty key file and no error.
func TestWriteErrors(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{"genkey", func() error { return genkey(failingWriter{}) }},
		{"pubkey", func() error { return pubkey(strings.NewReader(alicePrivate), failingWriter{}) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, errWrite) {
				t.Errorf("error = %v, want it to wrap %v", err, errWrite)
			}
		})
	}
}

// testTimeout bounds every wait in the forward tests, so a bug makes a test
// fail instead of hang.
const testTimeout = 2 * time.Second

// errClosed is what fakePipe returns once it is closed.
var errClosed = errors.New("fake pipe closed")

// fakePipe stands in for both the TUN device and the UDP transport in the
// forward tests. The test puts packets on in, which Read and Recv return, and
// takes what forward writes or sends from out.
//
// Like the real device and socket, Close makes a waiting Read or Recv return
// an error. Without that, forward could never stop.
type fakePipe struct {
	in        chan []byte
	out       chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func newFakePipe() *fakePipe {
	return &fakePipe{
		in:   make(chan []byte),
		out:  make(chan []byte, 16),
		done: make(chan struct{}),
	}
}

func (p *fakePipe) Read(b []byte) (int, error) {
	select {
	case packet := <-p.in:
		return copy(b, packet), nil
	case <-p.done:
		return 0, errClosed
	}
}

// Write stores a copy, because forward reuses its buffers.
func (p *fakePipe) Write(b []byte) (int, error) {
	select {
	case p.out <- bytes.Clone(b):
		return len(b), nil
	case <-p.done:
		return 0, errClosed
	}
}

func (p *fakePipe) Recv(b []byte) (int, error) { return p.Read(b) }

func (p *fakePipe) Send(b []byte) error {
	_, err := p.Write(b)
	return err
}

func (p *fakePipe) Name() string { return "fake0" }

func (p *fakePipe) Close() error {
	p.closeOnce.Do(func() { close(p.done) })
	return nil
}

func (p *fakePipe) closed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// put gives packet to forward through p, failing the test if forward does not
// take it in time.
func (p *fakePipe) put(t *testing.T, packet []byte) {
	t.Helper()
	select {
	case p.in <- packet:
	case <-time.After(testTimeout):
		t.Fatalf("forward did not read %q in time", packet)
	}
}

// take returns the next packet forward wrote or sent through p, failing the
// test if none arrives in time.
func (p *fakePipe) take(t *testing.T) []byte {
	t.Helper()
	select {
	case packet := <-p.out:
		return packet
	case <-time.After(testTimeout):
		t.Fatal("forward did not write anything in time")
		return nil
	}
}

// forwardTest runs forward with fakes. It holds the peerState forward uses,
// whose session a test can replace, and the peer's Session, which uses the
// same keys the other way around.
type forwardTest struct {
	dev, conn *fakePipe
	state     *peerState
	peer      *session.Session
	cancel    context.CancelFunc
	result    chan error
}

// newSessionPair returns two Sessions that work as the two ends of a tunnel.
// Each seed gives different keys, so pairs from different seeds cannot open
// each other's messages.
func newSessionPair(t *testing.T, seed byte) (local, peer *session.Session) {
	t.Helper()
	a, b := session.Key{seed, 1}, session.Key{seed, 2}
	const localIndex, peerIndex = 1, 2
	local, err := session.New(a, b, peerIndex, localIndex)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	peer, err = session.New(b, a, localIndex, peerIndex)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	return local, peer
}

// startForward starts forward in the background with a session already in
// place and no handshake. When the test ends, it stops forward and fails the
// test if forward does not return.
func startForward(t *testing.T) *forwardTest {
	t.Helper()
	return startForwardWith(t, nil)
}

// startForwardWith is startForward with h as the handshake, so forward
// answers handshake messages with it. A session is already in place, so
// forward sends no initiations.
func startForwardWith(t *testing.T, h *noise.Handshake) *forwardTest {
	t.Helper()
	s, peer := newSessionPair(t, 0)
	state := &peerState{handshake: h, retryInterval: time.Hour}
	state.sessionPointer.Store(s)
	return launchForward(t, state, peer)
}

// startHandshakingForward starts forward with h and no session, as govpn
// starts, so forward sends an initiation at once and again every interval.
func startHandshakingForward(t *testing.T, h *noise.Handshake, interval time.Duration) *forwardTest {
	t.Helper()
	return launchForward(t, &peerState{handshake: h, retryInterval: interval}, nil)
}

// launchForward runs forward with state in the background. When the test
// ends, it stops forward and fails the test if forward does not return.
func launchForward(t *testing.T, state *peerState, peer *session.Session) *forwardTest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ft := &forwardTest{
		dev:    newFakePipe(),
		conn:   newFakePipe(),
		state:  state,
		peer:   peer,
		cancel: cancel,
		result: make(chan error, 1),
	}
	go func() { ft.result <- forward(ctx, ft.dev, ft.conn, ft.state) }()

	t.Cleanup(func() {
		cancel()
		select {
		case <-ft.result:
		case <-time.After(testTimeout):
			t.Error("forward did not return after its context was cancelled")
		}
	})
	return ft
}

// sealFromPeer returns packet sealed by the peer, ready to put on ft.conn.
func (ft *forwardTest) sealFromPeer(t *testing.T, packet []byte) []byte {
	t.Helper()
	msg, err := ft.peer.Seal(nil, packet)
	if err != nil {
		t.Fatalf("peer Seal: %v", err)
	}
	return msg
}

// checkPacket fails the test if got is not want.
func checkPacket(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("device got %q, want %q", got, want)
	}
}

func TestForwardSendsPackets(t *testing.T) {
	ft := startForward(t)
	packet := []byte("packet from the tun device")

	ft.dev.put(t, packet)
	msg := ft.conn.take(t)

	got, err := ft.peer.Open(nil, msg)
	if err != nil {
		t.Fatalf("peer cannot open the sent message: %v", err)
	}
	checkPacket(t, got, packet)
}

func TestForwardReceivesPackets(t *testing.T) {
	ft := startForward(t)
	packet := []byte("packet from the peer")

	ft.conn.put(t, ft.sealFromPeer(t, packet))
	checkPacket(t, ft.dev.take(t), packet)
}

// The next tests send a valid message after the one that must be dropped.
// forward handles messages in order, so if the first thing written to the
// device is the valid packet, the earlier message was dropped.

func TestForwardDropsInvalidMessages(t *testing.T) {
	ft := startForward(t)
	valid := ft.sealFromPeer(t, []byte("valid"))
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1] ^= 1

	for _, msg := range [][]byte{[]byte("garbage"), {}, tampered} {
		ft.conn.put(t, msg)
	}
	ft.conn.put(t, valid)

	checkPacket(t, ft.dev.take(t), []byte("valid"))
}

func TestForwardDropsReplayedMessages(t *testing.T) {
	ft := startForward(t)
	first := ft.sealFromPeer(t, []byte("first"))
	second := ft.sealFromPeer(t, []byte("second"))

	ft.conn.put(t, first)
	ft.conn.put(t, first)
	ft.conn.put(t, second)

	checkPacket(t, ft.dev.take(t), []byte("first"))
	checkPacket(t, ft.dev.take(t), []byte("second"))
}

func TestForwardSkipsKeepalives(t *testing.T) {
	ft := startForward(t)

	ft.conn.put(t, ft.sealFromPeer(t, nil))
	ft.conn.put(t, ft.sealFromPeer(t, []byte("after keepalive")))

	checkPacket(t, ft.dev.take(t), []byte("after keepalive"))
}

func TestForwardStopsOnCancel(t *testing.T) {
	ft := startForward(t)
	ft.cancel()

	select {
	case err := <-ft.result:
		if err != nil {
			t.Errorf("forward = %v, want nil", err)
		}
		// Put the result back for the cleanup in startForward.
		ft.result <- err
	case <-time.After(testTimeout):
		t.Fatal("forward did not return after its context was cancelled")
	}

	if !ft.dev.closed() {
		t.Error("forward did not close the device")
	}
	if !ft.conn.closed() {
		t.Error("forward did not close the conn")
	}
}

// message returns a message of size bytes whose first 4 bytes hold typ, as a
// little-endian uint32.
func message(typ uint32, size int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, typ)
	return b
}

// TestForwardRoutesByType checks that only data messages reach the session
// when there is no handshake: handshake messages, unknown types and messages
// too short to hold a type are dropped, without stopping forward.
func TestForwardRoutesByType(t *testing.T) {
	ft := startForward(t)

	for _, msg := range [][]byte{
		message(noise.InitiationType, 148),
		message(noise.ResponseType, 92),
		message(3, 64),
		{byte(session.DataMessageType), 0, 0},
	} {
		ft.conn.put(t, msg)
	}
	ft.conn.put(t, ft.sealFromPeer(t, []byte("data")))

	checkPacket(t, ft.dev.take(t), []byte("data"))
}

// openAll opens each message with s and returns the packets, failing the test
// if one does not open.
func openAll(t *testing.T, s *session.Session, msgs ...[]byte) []string {
	t.Helper()
	var packets []string
	for _, msg := range msgs {
		packet, err := s.Open(nil, msg)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		packets = append(packets, string(packet))
	}
	return packets
}

// The next two tests start with no session, then give forward one. forward
// takes a packet only after it finished the one before, so once "dropped too"
// is taken, "dropped" was handled with no session. "dropped too" itself may
// be handled before or after the session arrives, so the tests allow both.

// TestForwardWithoutSessionDropsPackets checks that packets from the device
// are dropped while there is no session, and sent once there is one.
func TestForwardWithoutSessionDropsPackets(t *testing.T) {
	ft := startForward(t)
	ft.state.sessionPointer.Store(nil)

	ft.dev.put(t, []byte("dropped"))
	ft.dev.put(t, []byte("dropped too"))
	s, peer := newSessionPair(t, 1)
	ft.state.sessionPointer.Store(s)
	ft.dev.put(t, []byte("sent"))

	got := openAll(t, peer, ft.conn.take(t))
	if got[0] == "dropped too" {
		got = openAll(t, peer, ft.conn.take(t))
	}
	if got[0] != "sent" {
		t.Errorf("first packet sent = %q, want %q", got[0], "sent")
	}
}

// TestForwardWithoutSessionDropsMessages checks that data messages are
// dropped while there is no session, and opened once there is one.
func TestForwardWithoutSessionDropsMessages(t *testing.T) {
	ft := startForward(t)
	ft.state.sessionPointer.Store(nil)
	s, peer := newSessionPair(t, 1)
	seal := func(packet string) []byte {
		msg, err := peer.Seal(nil, []byte(packet))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return msg
	}

	ft.conn.put(t, seal("dropped"))
	ft.conn.put(t, seal("dropped too"))
	ft.state.sessionPointer.Store(s)
	ft.conn.put(t, seal("written"))

	got := ft.dev.take(t)
	if string(got) == "dropped too" {
		got = ft.dev.take(t)
	}
	checkPacket(t, got, []byte("written"))
}

// TestForwardUsesReplacedSession checks that forward picks up a new session
// for the next packet and message: packets are sealed for the new peer, and
// messages from the old one no longer open.
func TestForwardUsesReplacedSession(t *testing.T) {
	ft := startForward(t)

	// A round trip in each direction, so forward is waiting for the next
	// packet and message when the session changes.
	ft.dev.put(t, []byte("old"))
	openAll(t, ft.peer, ft.conn.take(t))
	ft.conn.put(t, ft.sealFromPeer(t, []byte("old")))
	checkPacket(t, ft.dev.take(t), []byte("old"))

	s, peer := newSessionPair(t, 1)
	ft.state.sessionPointer.Store(s)

	ft.dev.put(t, []byte("new"))
	if got := openAll(t, peer, ft.conn.take(t)); got[0] != "new" {
		t.Errorf("packet = %q, want %q", got[0], "new")
	}

	msg, err := peer.Seal(nil, []byte("new"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ft.conn.put(t, ft.sealFromPeer(t, []byte("from the old peer")))
	ft.conn.put(t, msg)
	checkPacket(t, ft.dev.take(t), []byte("new"))
}

// newKey returns a new random private key, failing the test on error.
func newKey(t *testing.T) *identity.PrivateKey {
	t.Helper()
	key, err := identity.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return key
}

// newHandshakePair returns two Handshakes between two new key pairs: local
// for forward, and peer for the test to play the other side.
func newHandshakePair(t *testing.T) (local, peer *noise.Handshake) {
	t.Helper()
	localKey, peerKey := newKey(t), newKey(t)
	return noise.NewHandshake(localKey, peerKey.PublicKey()), noise.NewHandshake(peerKey, localKey.PublicKey())
}

// checkTunnel fails the test unless forward and s work as the two ends of a
// tunnel: a packet sealed with s reaches the device, and a packet from the
// device opens with s.
func checkTunnel(t *testing.T, ft *forwardTest, s *session.Session) {
	t.Helper()
	msg, err := s.Seal(nil, []byte("to the device"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ft.conn.put(t, msg)
	checkPacket(t, ft.dev.take(t), []byte("to the device"))

	ft.dev.put(t, []byte("from the device"))
	if got := openAll(t, s, ft.conn.take(t)); got[0] != "from the device" {
		t.Errorf("packet = %q, want %q", got[0], "from the device")
	}
}

// checkNothingSent fails the test if forward sent anything on ft.conn. Call
// it after taking a packet that forward handled last, so anything sent before
// is already there.
func checkNothingSent(t *testing.T, ft *forwardTest) {
	t.Helper()
	select {
	case msg := <-ft.conn.out:
		t.Errorf("forward sent %x, want nothing", msg)
	default:
	}
}

// TestForwardAnswersInitiation checks that forward, as the responder, answers
// an initiation with a response that finishes the peer's handshake, and then
// uses the new session.
func TestForwardAnswersInitiation(t *testing.T) {
	local, peer := newHandshakePair(t)
	ft := startForwardWith(t, local)

	initiation, err := peer.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	ft.conn.put(t, initiation)

	if err := peer.ConsumeResponse(ft.conn.take(t)); err != nil {
		t.Fatalf("ConsumeResponse(forward's response): %v", err)
	}
	s, err := peer.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	checkTunnel(t, ft, s)
}

// TestForwardFinishesHandshake checks that forward, as the initiator, finishes
// the handshake when the response arrives, sends a keepalive with the new
// session, and then uses that session.
func TestForwardFinishesHandshake(t *testing.T) {
	local, peer := newHandshakePair(t)
	ft := startHandshakingForward(t, local, 50*time.Millisecond)

	s := completeHandshake(t, ft, peer)
	checkTunnel(t, ft, s)
}

// TestForwardDropsInvalidHandshakeMessages checks that handshake messages
// that do not check out are dropped: forward sends nothing back, keeps its
// session, and goes on.
func TestForwardDropsInvalidHandshakeMessages(t *testing.T) {
	localKey, peerKey := newKey(t), newKey(t)
	ft := startForwardWith(t, noise.NewHandshake(localKey, peerKey.PublicKey()))

	initiation, err := noise.NewHandshake(peerKey, localKey.PublicKey()).CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	tampered := bytes.Clone(initiation)
	tampered[20] ^= 1

	// A stranger knows forward's public key, so its initiation passes mac1,
	// but its static key is not the configured peer's.
	stranger := noise.NewHandshake(newKey(t), localKey.PublicKey())
	strangerInitiation, err := stranger.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}

	for _, msg := range [][]byte{
		message(noise.InitiationType, 148),
		initiation[:len(initiation)-1],
		tampered,
		strangerInitiation,
		// forward sent no initiation, so no response can finish a handshake.
		message(noise.ResponseType, 92),
	} {
		ft.conn.put(t, msg)
	}
	ft.conn.put(t, ft.sealFromPeer(t, []byte("data")))

	checkPacket(t, ft.dev.take(t), []byte("data"))
	checkNothingSent(t, ft)
}

// TestForwardDropsReplayedInitiation checks that an initiation is answered
// only once. Answering a replay would replace the session with one the real
// peer does not have, so anyone who saw the initiation could cut the tunnel.
func TestForwardDropsReplayedInitiation(t *testing.T) {
	local, peer := newHandshakePair(t)
	ft := startForwardWith(t, local)

	initiation, err := peer.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	ft.conn.put(t, initiation)
	if err := peer.ConsumeResponse(ft.conn.take(t)); err != nil {
		t.Fatalf("ConsumeResponse(forward's response): %v", err)
	}
	s, err := peer.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	ft.conn.put(t, initiation)
	checkTunnel(t, ft, s)
	checkNothingSent(t, ft)
}

func TestCheckPeerPublicKey(t *testing.T) {
	private, err := identity.ParsePrivateKey(alicePrivate)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	other, err := identity.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	if err := checkPeerPublicKey(private, private.PublicKey()); !errors.Is(err, errOwnPublicKey) {
		t.Errorf("own public key: error = %v, want %v", err, errOwnPublicKey)
	}
	if err := checkPeerPublicKey(private, other.PublicKey()); err != nil {
		t.Errorf("other peer's public key: error = %v, want nil", err)
	}
}

func TestRetryDelay(t *testing.T) {
	for _, interval := range []time.Duration{0, 1, 2, 3, 30 * time.Millisecond, 5 * time.Second} {
		for range 100 {
			got := retryDelay(interval)
			if got < interval || got > interval+interval/3 {
				t.Fatalf("retryDelay(%v) = %v, want between %v and %v", interval, got, interval, interval+interval/3)
			}
		}
	}
}

// checkInitiation fails the test if msg is not a handshake initiation.
func checkInitiation(t *testing.T, msg []byte) {
	t.Helper()
	if len(msg) != 148 || binary.LittleEndian.Uint32(msg) != noise.InitiationType {
		t.Fatalf("message = %d bytes of type %d, want a 148-byte initiation", len(msg), binary.LittleEndian.Uint32(msg))
	}
}

// completeHandshake answers forward's initiations as the peer until forward
// sends the keepalive that ends the handshake, and returns the peer's session
// that opens it. forward may send a new initiation before a response
// arrives, which makes that response stale, so the loop answers every one.
func completeHandshake(t *testing.T, ft *forwardTest, peer *noise.Handshake) *session.Session {
	t.Helper()
	var sessions []*session.Session
	deadline := time.After(testTimeout)
	for {
		var msg []byte
		select {
		case msg = <-ft.conn.out:
		case <-deadline:
			t.Fatal("the handshake did not finish in time")
		}

		if binary.LittleEndian.Uint32(msg) == noise.InitiationType {
			if err := peer.ConsumeInitiation(msg); err != nil {
				t.Fatalf("ConsumeInitiation: %v", err)
			}
			response, err := peer.CreateResponse()
			if err != nil {
				t.Fatalf("CreateResponse: %v", err)
			}
			s, err := peer.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			sessions = append(sessions, s)
			ft.conn.put(t, response)
			continue
		}

		for _, s := range sessions {
			if packet, err := s.Open(nil, msg); err == nil {
				if len(packet) != 0 {
					t.Fatalf("first data message = %q, want a keepalive", packet)
				}
				return s
			}
		}
		t.Fatal("forward sent a data message no response's session can open")
	}
}

func TestForwardSendsInitiationAtStart(t *testing.T) {
	local, peer := newHandshakePair(t)
	// A long interval, so only the first initiation can arrive in time.
	ft := startHandshakingForward(t, local, time.Hour)

	msg := ft.conn.take(t)
	checkInitiation(t, msg)
	if err := peer.ConsumeInitiation(msg); err != nil {
		t.Errorf("ConsumeInitiation: %v", err)
	}
}

func TestForwardRetriesInitiation(t *testing.T) {
	local, _ := newHandshakePair(t)
	ft := startHandshakingForward(t, local, 20*time.Millisecond)

	first, second := ft.conn.take(t), ft.conn.take(t)
	checkInitiation(t, first)
	checkInitiation(t, second)
	if bytes.Equal(first, second) {
		t.Error("forward sent the same initiation twice, want a new one each time")
	}
}

// TestForwardStopsInitiatingWithSession checks that forward sends no more
// initiations once a handshake has finished.
func TestForwardStopsInitiatingWithSession(t *testing.T) {
	const interval = 10 * time.Millisecond
	local, peer := newHandshakePair(t)
	ft := startHandshakingForward(t, local, interval)

	completeHandshake(t, ft, peer)

	// An initiation already being created when the session arrived can still
	// be sent, so let it arrive and drop it before checking.
	time.Sleep(5 * interval)
	for len(ft.conn.out) > 0 {
		<-ft.conn.out
	}

	select {
	case msg := <-ft.conn.out:
		t.Errorf("forward sent a %d-byte message of type %d after the handshake finished", len(msg), binary.LittleEndian.Uint32(msg))
	case <-time.After(10 * interval):
	}
}

// newOrderedHandshakePair is newHandshakePair with the keys in a known order:
// local's public key is the greater one if localWins, so local wins a crossed
// handshake.
func newOrderedHandshakePair(t *testing.T, localWins bool) (local, peer *noise.Handshake) {
	t.Helper()
	a, b := newKey(t), newKey(t)
	if (bytes.Compare(a.PublicKey().Bytes(), b.PublicKey().Bytes()) > 0) != localWins {
		a, b = b, a
	}
	return noise.NewHandshake(a, b.PublicKey()), noise.NewHandshake(b, a.PublicKey())
}

// TestForwardCrossedHandshakeWinner checks that a peer waiting for the
// response to its own initiation, with the greater public key, ignores the
// peer's initiation and finishes its own handshake.
func TestForwardCrossedHandshakeWinner(t *testing.T) {
	local, peer := newOrderedHandshakePair(t, true)
	ft := startHandshakingForward(t, local, time.Hour)
	ownInitiation := ft.conn.take(t)

	// The peer starts its own handshake at the same time.
	peerInitiation, err := peer.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	ft.conn.put(t, peerInitiation)

	// The peer loses, so it gives up its own and answers forward's.
	if err := peer.ConsumeInitiation(ownInitiation); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	response, err := peer.CreateResponse()
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	s, err := peer.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	ft.conn.put(t, response)

	// forward handles messages in order, so if it had answered the peer's
	// initiation, that response would come before the keepalive.
	msg := ft.conn.take(t)
	if typ := binary.LittleEndian.Uint32(msg); typ != session.DataMessageType {
		t.Fatalf("first message after the crossed initiation has type %d, want a keepalive", typ)
	}
	if got := openAll(t, s, msg); got[0] != "" {
		t.Errorf("first data message = %q, want a keepalive", got[0])
	}
	checkTunnel(t, ft, s)
}

// TestForwardCrossedHandshakeLoser checks that a peer waiting for the response
// to its own initiation, with the smaller public key, gives it up and answers
// the peer's initiation.
func TestForwardCrossedHandshakeLoser(t *testing.T) {
	local, peer := newOrderedHandshakePair(t, false)
	ft := startHandshakingForward(t, local, time.Hour)
	checkInitiation(t, ft.conn.take(t))

	peerInitiation, err := peer.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	ft.conn.put(t, peerInitiation)

	if err := peer.ConsumeResponse(ft.conn.take(t)); err != nil {
		t.Fatalf("ConsumeResponse(forward's response): %v", err)
	}
	s, err := peer.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	checkTunnel(t, ft, s)
}

// link delivers everything forward sends on a to b's conn, until the test
// ends, as a network between two peers would.
func link(t *testing.T, a, b *forwardTest) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case msg := <-a.conn.out:
				select {
				case b.conn.in <- msg:
				case <-b.conn.done:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()
}

// deliver puts packet on from's device until it comes out of to's device,
// because packets are dropped until the handshake finishes.
func deliver(t *testing.T, from, to *forwardTest, packet string) {
	t.Helper()
	deadline := time.After(testTimeout)
	for {
		from.dev.put(t, []byte(packet))
		select {
		case got := <-to.dev.out:
			if string(got) != packet {
				t.Fatalf("device got %q, want %q", got, packet)
			}
			return
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("%q was not delivered in time", packet)
		}
	}
}

// TestForwardTwoPeers runs two forwards linked to each other, as two govpn
// started at the same time. Both send an initiation at once, so their
// handshakes usually cross, and packets must still get through both ways.
func TestForwardTwoPeers(t *testing.T) {
	ha, hb := newHandshakePair(t)
	// A long interval, so the first initiations are the only ones: a retry
	// cannot hide a crossed handshake that went wrong.
	a := launchForward(t, &peerState{handshake: ha, retryInterval: time.Hour}, nil)
	b := launchForward(t, &peerState{handshake: hb, retryInterval: time.Hour}, nil)
	link(t, a, b)
	link(t, b, a)

	deliver(t, a, b, "from a")
	deliver(t, b, a, "from b")
}

// TestForwardWinnerAnswersWhenNotInitiating checks that the tie rule applies
// only to crossed handshakes: a peer with the greater public key that is not
// waiting for its own response still answers the peer's initiation.
func TestForwardWinnerAnswersWhenNotInitiating(t *testing.T) {
	local, peer := newOrderedHandshakePair(t, true)
	// A session is already in place, so forward sends no initiation of its own.
	ft := startForwardWith(t, local)

	initiation, err := peer.CreateInitiation()
	if err != nil {
		t.Fatalf("CreateInitiation: %v", err)
	}
	ft.conn.put(t, initiation)

	if err := peer.ConsumeResponse(ft.conn.take(t)); err != nil {
		t.Fatalf("ConsumeResponse(forward's response): %v", err)
	}
}
