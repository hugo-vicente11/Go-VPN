package main

import (
	"bytes"
	"context"
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

// testKeyFileContent is a key file as wg genkey writes it, with a trailing
// newline. It decodes to the bytes 0 to 31.
const testKeyFileContent = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"

func TestLoadKey(t *testing.T) {
	var want session.Key
	for i := range want {
		want[i] = byte(i)
	}

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
			path := filepath.Join(t.TempDir(), "govpn.key")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
				// WriteFile's mode is reduced by the umask, so set it explicitly.
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}

			got, err := loadKey(path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("loadKey: %v", err)
				}
				if got != want {
					t.Errorf("loadKey = %x, want %x", got, want)
				}
				return
			}

			if err == nil {
				t.Fatalf("loadKey returned nil error, want one containing %q", tc.wantErr)
			}
			if msg := err.Error(); !strings.Contains(msg, tc.wantErr) {
				t.Errorf("loadKey error = %q, want it to contain %q", msg, tc.wantErr)
			}
			// Every error must name the file, so the user knows which one to fix.
			if msg := err.Error(); !strings.Contains(msg, path) {
				t.Errorf("loadKey error = %q, want it to name %s", msg, path)
			}
		})
	}
}

// TestLoadKeyMissingIsNotExist checks that a missing file can still be
// recognized with errors.Is after loadKey wraps the error.
func TestLoadKeyMissingIsNotExist(t *testing.T) {
	_, err := loadKey(filepath.Join(t.TempDir(), "missing.key"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("loadKey error = %v, want it to wrap %v", err, fs.ErrNotExist)
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

// forwardTest runs forward with fakes, and holds the peer's Session, which
// uses the same keys the other way around.
type forwardTest struct {
	dev, conn *fakePipe
	peer      *session.Session
	cancel    context.CancelFunc
	result    chan error
}

// startForward starts forward in the background. When the test ends, it
// stops forward and fails the test if forward does not return.
func startForward(t *testing.T) *forwardTest {
	t.Helper()
	a, b := session.Key{1}, session.Key{2}
	s, err := session.New(a, b)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	peer, err := session.New(b, a)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ft := &forwardTest{
		dev:    newFakePipe(),
		conn:   newFakePipe(),
		peer:   peer,
		cancel: cancel,
		result: make(chan error, 1),
	}
	go func() { ft.result <- forward(ctx, ft.dev, ft.conn, s) }()

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
