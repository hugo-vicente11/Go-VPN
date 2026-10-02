package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/transport"
)

func main() {
	log.SetPrefix("udptest: ")
	var peer netip.AddrPort
	flag.TextVar(&peer, "peer", netip.AddrPort{}, "peer to exchange messages with, as `ip:port`")
	port := flag.Int("port", 9000, "local UDP `port` to listen on")
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprint(w, `udptest sends "Ping" to a peer every 3 seconds and prints what it receives.

Usage:
  udptest -peer ip:port [-port port]

Example (two-namespace lab):
  sudo ip netns exec A ./bin/udptest -peer 192.168.50.2:9000
  sudo ip netns exec B ./bin/udptest -peer 192.168.50.1:9000

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() > 0 {
		flagErrorf("unexpected arguments: %q", flag.Args())
	}
	if !peer.IsValid() {
		flagErrorf("-peer is required")
	}
	if *port < 1 || *port > 65535 {
		flagErrorf("-port must be between 1 and 65535, got %d", *port)
	}

	buf := make([]byte, 2048)

	t, err := transport.New(*port, peer)
	if err != nil {
		log.Fatalf("creating transport: %v", err)
	}
	defer t.Close()

	go func() {
		for {
			err := t.Send([]byte("Ping"))
			if err != nil {
				log.Fatalf("send: %v", err)
			}
			time.Sleep(time.Second * 3)
		}
	}()

	for {
		n, err := t.Recv(buf)
		if err != nil {
			log.Fatalf("receive: %v", err)
		}
		fmt.Printf("Read %d bytes\nPayload: %s\n", n, buf[:n])
	}
}

// flagErrorf reports a command-line usage error, prints usage, and exits with
// status 2, matching how the flag package handles its own parse errors.
func flagErrorf(format string, args ...any) {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "udptest: "+format+"\n\n", args...)
	flag.Usage()
	os.Exit(2)
}
