package transport

import (
	"bytes"
	"net"
	"net/netip"
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
