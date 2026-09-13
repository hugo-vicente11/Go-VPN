package main

import (
	"fmt"
	"log"

	"github.com/hugo-vicente11/go-vpn/internal/tun"
)

func main() {
	dev, err := tun.New()
	if err != nil {
		log.Fatalf("failed to create a tun device: %v", err)
	}

	fmt.Printf("TUN device created: %s\n", dev.Name())

	buf := make([]byte, 1500)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			log.Fatalf("read error: %v", err)
		}
		IHL := buf[0] & 0x0F
		ipHeaderLen := 4 * IHL // IHL is 32 bit words (multiplied by 4 gives us bytes)
		if buf[9] != 1 || buf[ipHeaderLen] != 8 {
			continue // Ignores packet
		}

		// Swap source and destination addresses
		var temp [4]byte
		copy(temp[:], buf[12:16])
		copy(buf[12:16], buf[16:20])
		copy(buf[16:20], temp[:])

		// Turn the Echo Request into an Echo Reply and recompute the IP checksum
		buf[ipHeaderLen] = 0
		buf[10] = 0
		buf[11] = 0
		ipChecksum := checksum(buf[:ipHeaderLen])
		buf[10] = byte(ipChecksum >> 8)
		buf[11] = byte(ipChecksum & 0xFF)

		// Recompute the ICMP checksum
		buf[ipHeaderLen+2] = 0
		buf[ipHeaderLen+3] = 0
		icmpChecksum := checksum(buf[ipHeaderLen:n])
		buf[ipHeaderLen+2] = byte(icmpChecksum >> 8)
		buf[ipHeaderLen+3] = byte(icmpChecksum & 0xFF)

		// Send the reply back through the tun device
		if _, err := dev.Write(buf[:n]); err != nil {
			log.Fatalf("write error: %v", err)
		}

		fmt.Printf("read %d bytes: % x\n", n, buf[:n])
	}
}

func checksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}
