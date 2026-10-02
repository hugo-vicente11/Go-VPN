package transport

import (
	"fmt"
	"net"
	"net/netip"
)

type Transport struct {
	conn *net.UDPConn
	peer *net.UDPAddr
}

func New(port int, peer netip.AddrPort) (*Transport, error) {
	laddr := &net.UDPAddr{Port: port}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("creating the udp socket: %w", err)
	}

	return &Transport{conn: conn, peer: net.UDPAddrFromAddrPort(peer)}, nil
}

func (t *Transport) Send(payload []byte) error {
	_, err := t.conn.WriteToUDP(payload, t.peer)
	return err
}

func (t *Transport) Recv(buf []byte) (int, error) {
	// TODO: validate sender == peer
	return t.conn.Read(buf)
}

func (t *Transport) Close() error {
	return t.conn.Close()
}
