package transport

import (
	"fmt"
	"net"
)

type Transport struct {
	conn *net.UDPConn
	peer *net.UDPAddr
}

func New(port int, peerAddr string) (*Transport, error) {
	laddr := &net.UDPAddr{Port: port}

	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolving peer address: %w", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("creating the udp socket: %w", err)
	}

	return &Transport{conn: conn, peer: peer}, nil
}

func (t *Transport) Send(payload []byte) error {
	_, err := t.conn.WriteToUDP(payload, t.peer)
	if err != nil {
		return fmt.Errorf("writing into UDP socket: %w", err)
	}
	return nil
}

func (t *Transport) Recv(buf []byte) (int, error) {
	// TODO: validate sender == peer
	n, err := t.conn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("receiving payload from UDP socket: %w", err)
	}
	return n, nil
}

func (t *Transport) Close() error {
	return t.conn.Close()
}
