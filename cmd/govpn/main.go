package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
	"github.com/hugo-vicente11/go-vpn/internal/session"
	"github.com/hugo-vicente11/go-vpn/internal/transport"
	"github.com/hugo-vicente11/go-vpn/internal/tun"
)

const (
	ethernetMTU    = 1500
	ipv6Size       = 40
	udpOverhead    = 8
	cryptoOverhead = session.Overhead
	tunnelMTU      = ethernetMTU - ipv6Size - udpOverhead - cryptoOverhead
	udpPayloadSize = ethernetMTU - ipv6Size - udpOverhead
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "genkey":
			checkNoArgs("genkey", "genkey")
			if err := genkey(os.Stdout); err != nil {
				log.Fatal(err)
			}
			return

		case "pubkey":
			checkNoArgs("pubkey", "pubkey < private.key")
			if err := pubkey(os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	// Parsing command line arguments
	var peer netip.AddrPort
	var address netip.Prefix
	flag.TextVar(&peer, "peer", netip.AddrPort{}, "peer to exchange messages with, as `ip:port`")
	port := flag.Int("port", 9000, "local UDP `port` to listen on, must be between 1 and 65535")
	flag.TextVar(&address, "address", netip.Prefix{}, "tunnel address of this peer, as `ip/len` (e.g. 10.0.0.1/24)")
	keyFile := flag.String("key-file", "", "`path` to the base64 key file, readable only by its owner")
	isInitiator := flag.Bool("initiator", false, "set on exactly one of the two peers: this peer encrypts with the initiator-to-responder key")

	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprint(w, `govpn creates a Virtual Private Network so you can safely communicate with
other peers.

Usage:
  govpn -peer ip:port -address ip/len -key-file path [-port port] [-initiator]
  (umask 077; govpn genkey > private.key)
  govpn pubkey < private.key > public.key

genkey writes a new private key; pubkey reads one and writes its public key.

Example (two-namespace lab, see scripts/lab-up.sh):
  sudo ip netns exec A ./bin/govpn -peer 192.168.50.2:9000 -address 10.0.0.1/24 -key-file govpn.key -initiator
  sudo ip netns exec B ./bin/govpn -peer 192.168.50.1:9000 -address 10.0.0.2/24 -key-file govpn.key
  sudo ip netns exec A ping 10.0.0.2

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

	if *keyFile == "" {
		flagErrorf("-key-file is required")
	}

	if err := validateTunnelAddr(address); err != nil {
		flagErrorf("-address %v", err)
	}

	if *port < 1 || *port > 65535 {
		flagErrorf("-port must be between 1 and 65535, got %d", *port)
	}

	if err := run(*port, peer, address, *keyFile, *isInitiator); err != nil {
		log.Fatal(err)
	}

}

// checkNoArgs exits with status 2 if the command cmd was given any arguments.
// It prints a short usage line instead of the tunnel's flags, which cmd does
// not use. Everything goes to stderr, because stdout carries the command's
// output, such as a key redirected into a file.
func checkNoArgs(cmd, usage string) {
	if len(os.Args) <= 2 {
		return
	}
	fmt.Fprintf(os.Stderr, "govpn %s: unexpected arguments: %q\n", cmd, os.Args[2:])
	fmt.Fprintf(os.Stderr, "Usage: govpn %s\n", usage)
	os.Exit(2)
}

// flagErrorf reports a command-line usage error, prints usage, and exits with
// status 2, matching how the flag package handles its own parse errors.
func flagErrorf(format string, args ...any) {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "govpn: "+format+"\n\n", args...)
	flag.Usage()
	os.Exit(2)
}

func run(port int, peer netip.AddrPort, addr netip.Prefix, keyFile string, isInitiator bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var wg sync.WaitGroup

	key, err := loadKey(keyFile)
	if err != nil {
		return err
	}

	sendKey, recvKey, err := session.DeriveKeys(key, isInitiator)
	if err != nil {
		return fmt.Errorf("deriving keys from shared secret: %w", err)
	}

	s, err := session.New(sendKey, recvKey)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}

	// Create TUN interface
	dev, err := tun.New()
	if err != nil {
		return fmt.Errorf("creating tun device: %w", err)
	}
	defer dev.Close()

	if err = dev.Configure(addr, tunnelMTU); err != nil {
		return fmt.Errorf("configuring tun device: %w", err)
	}

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

	recvBuf := make([]byte, udpPayloadSize)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nRecv, err := t.Recv(recvBuf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				fmt.Fprintf(os.Stderr, "Error while reading UDP payload: %v\n", err)
				continue
			}
			packet, err := s.Open(recvBuf[session.HeaderSize:session.HeaderSize], recvBuf[:nRecv])
			if err != nil {
				// Drop invalid messages silently. Anyone can send datagrams to
				// this port, so logging each one would let them flood the logs.
				continue
			}

			if len(packet) == 0 {
				// An empty packet is a keepalive: it only shows the peer is alive,
				// so there is nothing to write to the TUN device.
				continue
			}
			nWrite, err := dev.Write(packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error while writing into %s: %v\n", dev.Name(), err)
				continue
			}
			if len(packet) != nWrite {
				fmt.Fprintf(os.Stderr, "Did not write everything! wrote: %d expected %d\n", nWrite, len(packet))
			}
		}
	}()

	readBuf := make([]byte, udpPayloadSize)
	for {
		nRead, err := dev.Read(readBuf[session.HeaderSize:])
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			fmt.Fprintf(os.Stderr, "Error while reading from %s: %v\n", dev.Name(), err)
			continue
		}
		msg, err := s.Seal(readBuf[:0], readBuf[session.HeaderSize:session.HeaderSize+nRead])
		if err != nil {
			stop()
			wg.Wait()
			return fmt.Errorf("sealing packet: %w", err)
		}
		err = t.Send(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while sending UDP payload: %v\n", err)
		}
	}
}

// validateTunnelAddr reports an error if p cannot be used as this peer's tunnel address.
func validateTunnelAddr(p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("is required")
	}

	if !p.Addr().Is4() {
		return fmt.Errorf("must be IPv4, got %s", p.Addr())
	}

	if p.Bits() == 32 {
		return fmt.Errorf("/32 leaves no room for the peer")
	}

	if p.Bits() <= 30 && p.Masked() == p {
		return fmt.Errorf("%s is a network address, use a host address such as %s", p, netip.PrefixFrom(p.Addr().Next(), p.Bits()))
	}

	return nil
}

// loadKey reads the key from the file at path. It refuses files that group
// or others can access, because anyone who can read the key can decrypt
// the tunnel.
func loadKey(path string) (session.Key, error) {
	// Check and read the same open file, so it cannot be swapped in between.
	f, err := os.Open(path)
	if err != nil {
		return session.Key{}, fmt.Errorf("opening key file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return session.Key{}, fmt.Errorf("checking key file: %w", err)
	}

	perms := info.Mode().Perm()
	if perms&0o077 != 0 {
		return session.Key{}, fmt.Errorf("key file %s is accessible by other users (mode %#o); run: chmod 600 %s", path, perms, path)
	}

	fileContents, err := io.ReadAll(f)
	if err != nil {
		return session.Key{}, fmt.Errorf("reading key file: %w", err)
	}

	key, err := session.ParseKey(string(fileContents))
	if err != nil {
		return session.Key{}, fmt.Errorf("key file %s: %w", path, err)
	}

	return key, nil
}

// genkey writes a new private key to w, in base64 followed by a newline,
// the same format as wg genkey.
func genkey(w io.Writer) error {
	key, err := identity.GeneratePrivateKey()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, key.Encode())
	if err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	return nil
}

// errNoPrivateKey means pubkey's input was empty or only whitespace.
var errNoPrivateKey = errors.New("no private key in input")

// pubkey reads a private key from r and writes its public key to w, in base64
// followed by a newline, the same format as wg pubkey. It returns
// errNoPrivateKey if r is empty or holds only whitespace.
func pubkey(r io.Reader, w io.Writer) error {
	privKeyBytes, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading private key: %w", err)
	}

	privKeyString := strings.TrimSpace(string(privKeyBytes))
	if privKeyString == "" {
		return errNoPrivateKey
	}

	privKey, err := identity.ParsePrivateKey(privKeyString)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, privKey.PublicKey())
	if err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	return nil
}
