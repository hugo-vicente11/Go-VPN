package transport

import (
	"fmt"
	"net"
	"net/netip"
)

type Transport struct {
	conn *net.UDPConn
	peer netip.AddrPort
}

func New(port int, peer netip.AddrPort) (*Transport, error) {
	laddr := &net.UDPAddr{Port: port}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("creating the udp socket: %w", err)
	}

	return &Transport{conn: conn, peer: netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())}, nil
}

func (t *Transport) Send(payload []byte) error {
	_, err := t.conn.WriteToUDPAddrPort(payload, t.peer)
	return err
}

func (t *Transport) Recv(buf []byte) (int, error) {
	for {
		n, sender, err := t.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, fmt.Errorf("reading from UDP socket: %w", err)
		}
		if t.peer != netip.AddrPortFrom(sender.Addr().Unmap(), sender.Port()) {
			continue
		}
		return n, nil
	}
}

func (t *Transport) Close() error {
	return t.conn.Close()
}
