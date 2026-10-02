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

}
