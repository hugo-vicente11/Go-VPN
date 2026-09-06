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
		fmt.Printf("read %d bytes: % x\n", n, buf[:n])
	}
}
