package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/transport"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Aborted, wrong number of arguments passed (port and addr)")
	}
	portStr, peerAddr := os.Args[1], os.Args[2]
	buf := make([]byte, 2048)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Port must be an integer.")
	}

	t, err := transport.New(port, peerAddr)
	if err != nil {
		log.Fatalf("creating transport: %v", err)
	}
	defer t.Close()

	go func() {
		for {
			err := t.Send([]byte("Ping"))
			if err != nil {
				log.Fatalf("Error while sending UDP traffic: %v", err)
			}
			time.Sleep(time.Second * 3)
		}
	}()

	for {
		n, err := t.Recv(buf)
		if err != nil {
			log.Fatalf("Error while reading UDP traffic: %v", err)
		}
		fmt.Printf("Read %d bytes\nPayload: %s\n", n, buf[:n])
	}
}
