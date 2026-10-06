package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/hugo-vicente11/go-vpn/internal/transport"
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

	if err := run(*port, peer); err != nil {
		log.Fatal(err)
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

func run(port int, peer netip.AddrPort) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var wg sync.WaitGroup
	// Create TUN interface
	dev, err := tun.New()
	if err != nil {
		return fmt.Errorf("creating tun device: %w", err)
	}
	defer dev.Close()
	fmt.Printf("TUN device created: %s\n", dev.Name())

	t, err := transport.New(port, peer)
	if err != nil {
		return fmt.Errorf("creating UDP transport layer: %w", err)
	}
	defer t.Close()

	go func() {
		<-ctx.Done()
		dev.Close()
		t.Close()
	}()

	recvBuf := make([]byte, 1500)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nRecv, err := t.Recv(recvBuf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				fmt.Fprintf(os.Stderr, "Error while reading UDP payload\n")
				continue
			}
			nWrite, err := dev.Write(recvBuf[:nRecv])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error while writing into: %s\n", dev.Name())
			}
			if nRecv != nWrite {
				fmt.Fprintf(os.Stderr, "Did not write everything!\n")
			}
		}
	}()

	readBuf := make([]byte, 1500)
	for {
		nRead, err := dev.Read(readBuf)
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			fmt.Fprintf(os.Stderr, "Error while reading from %s\n", dev.Name())
			continue
		}
		err = t.Send(readBuf[:nRead])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while sending UDP payload\n")
		}
	}
}
