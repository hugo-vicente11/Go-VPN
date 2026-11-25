package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
	"github.com/hugo-vicente11/go-vpn/internal/noise"
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

// handshakeRetryInterval is how long to wait for a handshake response before
// sending a new initiation. It is REKEY_TIMEOUT in the whitepaper.
const handshakeRetryInterval = 5 * time.Second

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
	peerPublicKey := flag.String("peer-public-key", "", "the peer's public `key`, in base64, as govpn pubkey writes it")
	privateKeyPath := flag.String("private-key-file", "", "`path` to the base64 private key file, readable only by its owner")

	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprint(w, `govpn creates a Virtual Private Network so you can safely communicate with
other peers.

Usage:
  govpn -peer ip:port -address ip/len -private-key-file path -peer-public-key key [-port port]
  (umask 077; govpn genkey > private.key)
  govpn pubkey < private.key > public.key

genkey writes a new private key; pubkey reads one and writes its public key.

Example (two-namespace lab, see scripts/lab-up.sh):
  (umask 077; ./bin/govpn genkey > a.key; ./bin/govpn genkey > b.key)
  ./bin/govpn pubkey < a.key > a.pub; ./bin/govpn pubkey < b.key > b.pub
  sudo ip netns exec A ./bin/govpn -peer 192.168.50.2:9000 -address 10.0.0.1/24 -private-key-file a.key -peer-public-key "$(cat b.pub)"
  sudo ip netns exec B ./bin/govpn -peer 192.168.50.1:9000 -address 10.0.0.2/24 -private-key-file b.key -peer-public-key "$(cat a.pub)"
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

	if *peerPublicKey == "" {
		flagErrorf("-peer-public-key is required")
	}
	peerPublic, err := identity.ParsePublicKey(*peerPublicKey)
	if err != nil {
		flagErrorf("-peer-public-key %v", err)
	}

	if *privateKeyPath == "" {
		flagErrorf("-private-key-file is required")
	}

	if err := validateTunnelAddr(address); err != nil {
		flagErrorf("-address %v", err)
	}

	if *port < 1 || *port > 65535 {
		flagErrorf("-port must be between 1 and 65535, got %d", *port)
	}

	if err := run(*port, peer, address, *privateKeyPath, peerPublic); err != nil {
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

func run(port int, peer netip.AddrPort, addr netip.Prefix, privateKeyFile string, peerPublic *identity.PublicKey) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	key, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}

	if err := checkPeerPublicKey(key, peerPublic); err != nil {
		return err
	}

	handshake := noise.NewHandshake(key, peerPublic)

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

	var pState peerState
	pState.handshake = handshake
	pState.retryInterval = handshakeRetryInterval
	return forward(ctx, dev, t, &pState)
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

// errOwnPublicKey means -peer-public-key is this peer's own public key, so the
// peer would try to handshake with itself.
var errOwnPublicKey = errors.New("-peer-public-key is this peer's own public key; pass the other peer's key")

// checkPeerPublicKey returns errOwnPublicKey if peer is the public key of
// private, a likely mix-up of the two peers' keys.
func checkPeerPublicKey(private *identity.PrivateKey, peer *identity.PublicKey) error {
	if private.PublicKey().String() == peer.String() {
		return errOwnPublicKey
	}
	return nil
}

// loadPrivateKey reads this peer's private key from the file at path. It
// refuses files that group or others can access, because anyone who can read
// the key can pretend to be this peer.
func loadPrivateKey(path string) (*identity.PrivateKey, error) {
	// Check and read the same open file, so it cannot be swapped in between.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening key file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("checking key file: %w", err)
	}

	perms := info.Mode().Perm()
	if perms&0o077 != 0 {
		return nil, fmt.Errorf("key file %s is accessible by other users (mode %#o); run: chmod 600 %s", path, perms, path)
	}

	fileContents, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	key, err := identity.ParsePrivateKey(string(fileContents))
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
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

// device is what forward needs from the TUN device. *tun.Device satisfies
// it, and the tests use a fake.
type device interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Name() string
	Close() error
}

// conn is what forward needs from the UDP transport. *transport.Transport
// satisfies it, and the tests use a fake.
type conn interface {
	Send(payload []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

// peerState is what forward keeps about the peer: the handshake with it and
// the session that handshake gave.
//
// mu guards handshake, which is not safe for concurrent use. It is held only
// while handshake runs, never while sending, so a slow send cannot hold up
// another goroutine that needs the handshake. sessionPointer needs no lock:
// forward loads it for every packet and message, and a finished handshake
// replaces it. A peerState must not be copied, because it holds a mutex and
// an atomic pointer.
type peerState struct {
	mu             sync.Mutex
	handshake      *noise.Handshake // nil means this peer does not handshake
	sessionPointer atomic.Pointer[session.Session]
	retryInterval  time.Duration // wait between initiations while there is no session
}

// answerInitiation consumes an initiation message as the responder and
// returns the response to send and the new session. It returns an error if
// msg is not a valid initiation, and then the handshake is left as it was.
func (p *peerState) answerInitiation(msg []byte) ([]byte, *session.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.handshake.ConsumeInitiation(msg)
	if err != nil {
		return nil, nil, err
	}

	resp, err := p.handshake.CreateResponse()
	if err != nil {
		return nil, nil, err
	}

	s, err := p.handshake.NewSession()
	if err != nil {
		return nil, nil, err
	}

	return resp, s, nil
}

// startHandshake creates a new initiation message, as the initiator. It
// holds mu because the receive loop uses the same handshake.
func (p *peerState) startHandshake() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.handshake.CreateInitiation()
}

// finishHandshake consumes a response message as the initiator and returns
// the new session. It returns an error if msg is not a valid response to the
// initiation this side sent, or if this side sent none.
func (p *peerState) finishHandshake(msg []byte) (*session.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.handshake.ConsumeResponse(msg)
	if err != nil {
		return nil, err
	}

	s, err := p.handshake.NewSession()
	if err != nil {
		return nil, err
	}

	return s, nil
}

// retryDelay returns interval plus up to a third of it at random, so two
// peers that start together do not keep sending initiations at the same time.
func retryDelay(interval time.Duration) time.Duration {
	if interval/3 <= 0 {
		return interval
	}

	return interval + rand.N(interval/3)
}

// forward moves packets in both directions until ctx is cancelled: it reads
// packets from dev, seals them with the current session and sends them on c,
// and it receives messages from c, opens them with the current session and
// writes the packets to dev. It closes dev and c before it returns.
//
// The current session is the one pState.sessionPointer holds when each
// packet or message is handled, so another goroutine can replace it at any
// time. While it is nil, because no handshake has finished, packets and data
// messages are dropped.
//
// Received messages are routed by their type. Data messages go to the
// current session. An initiation is answered with a response, and a response
// is answered with a keepalive; each one makes a new session that replaces
// the current one. Handshake messages are dropped if pState has no handshake
// or if they are invalid, and any other type is dropped.
//
// If pState has a handshake, forward sends an initiation when it starts, and
// again every pState.retryInterval, plus some jitter, while there is no
// session.
//
// It returns nil when ctx is cancelled, and an error if the current session
// can no longer seal, because its send counter is exhausted.
func forward(ctx context.Context, dev device, c conn, pState *peerState) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		dev.Close()
		c.Close()
	}()

	if pState.handshake != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if pState.sessionPointer.Load() == nil {
					msg, err := pState.startHandshake()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error while creating handshake initiation: %v\n", err)
					} else {
						err = c.Send(msg)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Error while sending handshake initiation: %v\n", err)
						}
					}
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(retryDelay(pState.retryInterval)):
				}
			}
		}()
	}

	recvBuf := make([]byte, udpPayloadSize)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nRecv, err := c.Recv(recvBuf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				fmt.Fprintf(os.Stderr, "Error while reading UDP payload: %v\n", err)
				continue
			}

			// Too short to hold a message type, so it is not a message.
			if nRecv < 4 {
				continue
			}

			messageType := binary.LittleEndian.Uint32(recvBuf)

			switch messageType {
			case noise.InitiationType:
				if pState.handshake == nil {
					// This peer does not handshake, so the message
					// cannot be answered.
					continue
				}

				resp, s, err := pState.answerInitiation(recvBuf[:nRecv])
				if err != nil {
					// Drop invalid initiations silently, like invalid
					// data messages: anyone can send them.
					continue
				}
				// Store the session before sending, so it is in place
				// when the initiator's first data message arrives.
				pState.sessionPointer.Store(s)
				err = c.Send(resp)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error while sending handshake response: %v\n", err)
				}
			case noise.ResponseType:
				if pState.handshake == nil {
					// This peer does not handshake, so it sent no
					// initiation for this to answer.
					continue
				}

				s, err := pState.finishHandshake(recvBuf[:nRecv])
				if err != nil {
					// Drop invalid responses silently: anyone can send
					// them.
					continue
				}

				pState.sessionPointer.Store(s)
				// The keepalive is the first data message with the new
				// session. It shows the responder that this side has the
				// session too, even when there is no packet to send.
				keepalive, err := s.Seal(nil, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error while creating handshake keepalive: %v\n", err)
					continue
				}
				err = c.Send(keepalive)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error while sending handshake keepalive: %v\n", err)
				}
			case session.DataMessageType:
				s := pState.sessionPointer.Load()
				if s == nil {
					// No handshake has finished, so there is no key to open
					// the message with.
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
		s := pState.sessionPointer.Load()
		if s == nil {
			// No handshake has finished, so there is no key to seal the
			// packet with. Drop it, as a network with no route would.
			continue
		}
		msg, err := s.Seal(readBuf[:0], readBuf[session.HeaderSize:session.HeaderSize+nRead])
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("sealing packet: %w", err)
		}
		err = c.Send(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while sending UDP payload: %v\n", err)
		}
	}
}
