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
	defer dev.Close()
	fmt.Printf("TUN device created: %s\n", dev.Name())
	buf := make([]byte, 1500)

	for {
		n, err := dev.Read(buf)
		if err != nil {
			log.Fatalf("failed to read from tun device: %v", err)
		}
		fmt.Printf("Read %d bytes from tun\n", n)
		fmt.Printf("Content read: \"% x\"\n", buf[:n])
	}

}
