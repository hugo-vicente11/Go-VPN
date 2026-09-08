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
