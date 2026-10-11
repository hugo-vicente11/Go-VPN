package transport

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// listenLoopback opens a UDP socket on 127.0.0.1 with a kernel-chosen port.
func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("creating UDP socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// udpAddr asserts that a is a *net.UDPAddr.
func udpAddr(t *testing.T, a net.Addr) *net.UDPAddr {
	t.Helper()
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		t.Fatalf("address is %T, want *net.UDPAddr", a)
	}
	return ua
}

// rig is a Transport pointed at a peer socket controlled by the test.
type rig struct {
	peer *net.UDPConn   // plays the legitimate other end
	trpt *Transport     // the code under test
	dest netip.AddrPort // where a socket must send to reach trpt
}

func newRig(t *testing.T) rig {
	t.Helper()
	peer := listenLoopback(t)

	trpt, err := New(0, udpAddr(t, peer.LocalAddr()).AddrPort())
	if err != nil {
		t.Fatalf("creating transport: %v", err)
	}
	t.Cleanup(func() { trpt.Close() })

	port := udpAddr(t, trpt.conn.LocalAddr()).Port
	dest := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	return rig{peer: peer, trpt: trpt, dest: dest}
}

func send(t *testing.T, from *net.UDPConn, payload []byte, to netip.AddrPort) {
	t.Helper()
	if _, err := from.WriteToUDPAddrPort(payload, to); err != nil {
		t.Fatalf("sending: %v", err)
	}
}

// recv calls Recv with a deadline so a missing datagram fails instead of hanging.
func recv(t *testing.T, trpt *Transport) []byte {
	t.Helper()
	if err := trpt.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("setting read deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := trpt.Recv(buf)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return buf[:n]
}

// readFrom reads one datagram on conn with a deadline and returns its payload
// and sender, normalized the same way Transport normalizes addresses.
func readFrom(t *testing.T, conn *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("setting read deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	return buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}

func TestNewAndClose(t *testing.T) {
	addr := netip.MustParseAddrPort("127.0.0.1:8989")
	trpt, err := New(0, addr)
	if err != nil {
		t.Fatalf("error while creating transport layer: %v", err)
	}
	if err := trpt.Close(); err != nil {
		t.Fatalf("error while closing transport layer: %v", err)
	}
}

func TestRecvFromPeer(t *testing.T) {
	r := newRig(t)
	want := []byte("hello")

	send(t, r.peer, want, r.dest)

	if got := recv(t, r.trpt); !bytes.Equal(got, want) {
		t.Errorf("Recv() = %q, want %q", got, want)
	}
}

func TestRecvDropsStranger(t *testing.T) {
	r := newRig(t)
	stranger := listenLoopback(t)
	want := []byte("hello")

	send(t, stranger, []byte("stranger"), r.dest)
	send(t, r.peer, want, r.dest)

	if got := recv(t, r.trpt); !bytes.Equal(got, want) {
		t.Errorf("Recv() = %q, want %q", got, want)
	}
}

func TestSendReachesPeer(t *testing.T) {
	r := newRig(t)
	want := []byte("hello")

	if err := r.trpt.Send(want); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got, from := readFrom(t, r.peer)
	if !bytes.Equal(got, want) {
		t.Errorf("peer received %q, want %q", got, want)
	}
	if from != r.dest {
		t.Errorf("datagram came from %v, want %v", from, r.dest)
	}
}

// Shutdown relies on this: closing the socket must wake up a Recv that is
// blocked waiting for a datagram, with an error.
func TestRecvReturnsErrorAfterClose(t *testing.T) {
	r := newRig(t)

	errc := make(chan error, 1)
	go func() {
		_, err := r.trpt.Recv(make([]byte, 1500))
		errc <- err
	}()

	// Nothing was sent and nothing was closed, so Recv must still be blocked.
	select {
	case err := <-errc:
		t.Fatalf("Recv returned before Close: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := r.trpt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Recv error = %v, want one wrapping net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv still blocked 2s after Close")
	}
}

func TestNewFailsWhenPortInUse(t *testing.T) {
	r := newRig(t)
	port := udpAddr(t, r.trpt.conn.LocalAddr()).Port

	second, err := New(port, r.dest)
	if err == nil {
		second.Close()
		t.Fatalf("New succeeded on port %d, which is already in use", port)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("New error = %v, want one wrapping EADDRINUSE", err)
	}
}
