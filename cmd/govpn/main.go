package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"

	"github.com/hugo-vicente11/go-vpn/internal/tun"
)

func main() {
	// Parsing command line arguments
	var peer netip.AddrPort
	flag.TextVar(&peer, "peer", netip.AddrPort{}, "peer to exchange messages with, as `ip:port`")
	port := flag.Int("port", 9000, "local UDP `port` to listen on, must be between 1 and 65535")
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprint(w, `govpn creates a Virtual Private Network so you can safely communicate with
other peers.

Usage:
  govpn -peer ip:port [-port port]

Example:
  ./bin/govpn -peer 192.168.50.2:9000

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	// Validate command line arguments
	if flag.NArg() > 0 {
		flagErrorf("unexpected arguments: %q", flag.Args())
	}

	if !peer.IsValid() {
		flagErrorf("-peer is required")
	}

	if *port < 1 || *port > 65535 {
		flagErrorf("-port must be between 1 and 65535, got %d", *port)
	}

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

// flagErrorf reports a command-line usage error, prints usage, and exits with
// status 2, matching how the flag package handles its own parse errors.
func flagErrorf(format string, args ...any) {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "govpn: "+format+"\n\n", args...)
	flag.Usage()
	os.Exit(2)
}
