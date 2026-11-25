# Go-VPN

[![CI](https://github.com/hugo-vicente11/Go-VPN/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hugo-vicente11/Go-VPN/actions/workflows/ci.yml)

A point-to-point VPN written in Go. It tunnels IP packets between two hosts over UDP using a Linux TUN device.

Built as a learning project. Each peer has its own key pair, and the peers run the WireGuard handshake to agree on new keys every time they start. The scheme still has known gaps (see [Security](#security)). **Do not use it to protect real data.**

## How it works

```
app -> tun0 -> govpn -> UDP -> govpn -> tun0 -> app
```

- On startup, each peer sends a handshake initiation to the other, and sends a new one every 5 seconds, plus a small random delay, until a handshake finishes. The other peer answers with a handshake response. Both sides then hold the same two new keys, one for each direction.
- If both peers start a handshake at the same moment, the one with the greater public key keeps its own and the other answers it, so both end with the same keys.
- Reads IP packets from a TUN device, encrypts each one, and sends it as a UDP datagram to the peer. Until a handshake has finished, packets are dropped.
- Receives datagrams from the peer, decrypts them, and writes the packets back to the TUN device.
- Datagrams from any address other than the configured peer are dropped. So are datagrams that fail to decrypt and invalid handshake messages, without a reply or a log line.
- Each message is accepted at most once. Messages may arrive out of order, but one that was already received, or is more than 63 counters older than the newest one, is dropped the same way. A handshake initiation is accepted only if its timestamp is newer than the last one accepted from the peer.
- Shuts down cleanly on `SIGINT` and `SIGTERM`.

Messages use the same formats as WireGuard:

| Type | Message | Bytes |
|---|---|---|
| `1` | Handshake initiation | 148 |
| `2` | Handshake response | 92 |
| `4` | Transport data | 32 plus the packet |

Each packet is encrypted with ChaCha20-Poly1305 in a transport data message:

| Field | Bytes |
|---|---|
| Message type (`4`) and 3 reserved zero bytes | 4 |
| Receiver index, chosen by the peer during the handshake | 4 |
| Counter, little-endian, used to build the nonce | 8 |
| Encrypted packet | variable |
| Poly1305 authentication tag | 16 |

## Requirements

- Linux
- Go 1.27 or newer (to build from source)
- Root, or the `CAP_NET_ADMIN` capability (needed to create the TUN device)
- Docker with Compose v2 (only for the Docker setup)

## Build

```
go build -o bin/govpn ./cmd/govpn
```

## Usage

```
govpn -peer ip:port -address ip/len -private-key-file path -peer-public-key key [-port port]
govpn genkey
govpn pubkey
```

The first form runs the tunnel. `genkey` and `pubkey` create key pairs (see [Key pairs](#key-pairs)).

| Flag | Description | Default |
|---|---|---|
| `-peer` | Address of the other endpoint. Must be an IP, not a hostname. Required. | none |
| `-address` | Tunnel address of this peer, with prefix length (e.g. `10.0.0.1/24`). Must be an IPv4 host address, not the network address, and not a `/32`. Required. | none |
| `-private-key-file` | Path to this peer's private key (see [Key pairs](#key-pairs)). Required. | none |
| `-peer-public-key` | The other peer's public key, in base64, as `govpn pubkey` writes it. Required. | none |
| `-port` | Local UDP port to listen on (1 to 65535). | `9000` |

### Key pairs

Each peer has an X25519 key pair, the kind WireGuard uses. A peer keeps its private key secret and gives its public key to the other peer. During the handshake, each peer proves it holds the private key that matches the public key the other peer was given.

Generate a private key, then compute its public key:

```
(umask 077; govpn genkey > private.key)
govpn pubkey < private.key > public.key
```

`genkey` writes a new random private key. `pubkey` reads a private key and writes the matching public key. Both write the key as standard base64 followed by a newline, the same format as `wg genkey` and `wg pubkey`, so keys from either tool work with the other.

Each peer needs its own private key, passed with `-private-key-file`, and the other peer's public key, passed with `-peer-public-key`.

`umask 077` creates `private.key` readable only by its owner. `govpn` refuses to start if the group or others can access the private key file, and prints the `chmod` command that fixes it. Anyone who can read the private key can pretend to be this peer, so never share or commit it: `*.key` and `*.pub` files are ignored by Git and by Docker builds. The public key is not secret.

### TUN device

`govpn` creates the TUN device, assigns it the `-address`, sets its MTU to 1420, and brings it up before it starts forwarding packets.

The MTU leaves room for the headers added to each tunneled packet, so the outer packet still fits in a standard 1500-byte link:

| Header | Bytes |
|---|---|
| Outer IP (IPv6, the worst case) | 40 |
| UDP | 8 |
| Tunnel header and authentication tag | 32 |
| **TUN MTU** | 1500 − 80 = **1420** |

If both peers' addresses are in the same subnet (for example `10.0.0.1/24` and `10.0.0.2/24`), nothing else is needed. If they are in different subnets, add a route to the remote subnet after `govpn` starts:

```
ip route add 10.0.1.0/24 dev tun0
```

## Try it locally

### With Docker

`docker-compose.yml` runs two peers on a private network (`172.30.0.0/24`). The peers' TUN addresses are in different subnets, so each container also adds a route to the other peer's subnet on startup:

| Container | Network address | TUN address |
|---|---|---|
| `govpn-a` | `172.30.0.2` | `10.0.0.1/24` |
| `govpn-b` | `172.30.0.3` | `10.0.1.1/24` |

Each container needs its own private key and the other container's public key. Generate them in the repository root, with the binary from [Build](#build) or with `wg genkey` and `wg pubkey`:

```
(umask 077; ./bin/govpn genkey > govpn-a.key; ./bin/govpn genkey > govpn-b.key)
./bin/govpn pubkey < govpn-a.key > govpn-a.pub
./bin/govpn pubkey < govpn-b.key > govpn-b.pub
```

The private keys are mounted as Compose secrets at `/run/secrets/private_key`, and the other container's public key as a Compose config at `/peer_public_key`:

| Container | Private key | Peer's public key |
|---|---|---|
| `govpn-a` | `govpn-a.key` | `govpn-b.pub` |
| `govpn-b` | `govpn-b.key` | `govpn-a.pub` |

Start both peers:

```
docker compose up -d --build
```

Each container reports `(healthy)` once its TUN device has the expected address and route (within about 30 seconds):

```
docker compose ps
```

Ping across the tunnel:

```
docker compose exec govpn-a ping -c1 10.0.1.1
```

Restart one peer and ping again. The restarted peer starts a new handshake, and the tunnel works again within a few seconds:

```
docker compose restart govpn-b
docker compose exec govpn-a ping -c1 10.0.1.1
```

Follow the logs with `docker compose logs`, and stop everything with `docker compose down`.

The containers need the `NET_ADMIN` capability and the `/dev/net/tun` device, both already set in the compose file. A peer that exits with an error is restarted automatically.

If the containers keep restarting, check `docker compose logs`:

| Message | Fix |
|---|---|
| The key file `/run/secrets/private_key` is accessible by other users | The path is inside the container, but the file to fix is on the host: `chmod 600 govpn-a.key govpn-b.key` |
| `cat: can't open '/peer_public_key'` | Generate the `.pub` files as shown above |
| `-peer-public-key is this peer's own public key` | Each container must get the other container's `.pub` file |

To use different paths inside the containers, set the `PRIVATE_KEY_FILE` and `PEER_PUBLIC_KEY_FILE` environment variables.

If the containers run but the ping gets no replies, a `.pub` file probably does not match its `.key` file, for example after a new `genkey`. Run `pubkey` again for both keys.

### With network namespaces

`scripts/lab-up.sh` creates two network namespaces, `A` and `B`, connected by a virtual cable (`192.168.50.1` and `192.168.50.2`). Each namespace acts as a separate machine.

Build the binary (see [Build](#build)) and generate a key pair for each peer:

```
(umask 077; ./bin/govpn genkey > a.key; ./bin/govpn genkey > b.key)
./bin/govpn pubkey < a.key > a.pub
./bin/govpn pubkey < b.key > b.pub
```

Then start the lab and one `govpn` per namespace, each in its own terminal. Each one gets its own private key and the other one's public key:

```
sudo ./scripts/lab-up.sh
sudo ip netns exec A ./bin/govpn -peer 192.168.50.2:9000 -address 10.0.0.1/24 -private-key-file a.key -peer-public-key "$(cat b.pub)"
sudo ip netns exec B ./bin/govpn -peer 192.168.50.1:9000 -address 10.0.0.2/24 -private-key-file b.key -peer-public-key "$(cat a.pub)"
```

Both TUN addresses are in the same subnet, so no routes are needed. In a third terminal, ping across the tunnel:

```
sudo ip netns exec A ping -c1 10.0.0.2
```

To check the MTU, send pings with the "don't fragment" bit set. 1392 bytes of ICMP payload plus 8 bytes of ICMP header and 20 bytes of IPv4 header is exactly 1420, so the first ping goes through and the second is rejected locally with `message too long`:

```
sudo ip netns exec A ping -c1 -M do -s 1392 10.0.0.2
sudo ip netns exec A ping -c1 -M do -s 1393 10.0.0.2
```

To see the handshake and check that the traffic is encrypted, start a capture on the virtual cable, then start both `govpn` and ping:

```
sudo ip netns exec A tcpdump -ni vethA -X udp port 9000
```

The first payloads start with `0100 0000` (a handshake initiation) and `0200 0000` (the response). After that, each payload starts with `0400 0000` (transport data), then the 4-byte receiver index the peer chose, then the 8-byte counter, which starts at 0 and goes up by one with each packet. Everything after that looks random. Without encryption, you would see the inner IPv4 header (starting with `45`) and the `10.0.0.x` addresses instead. Restart one `govpn` and the capture shows a new handshake, a new receiver index and a counter back at 0, with new keys.

If a peer was given the wrong public key for the other, the ping gets no replies, and neither `govpn` prints anything: each one drops the other's handshake messages.

Clean up with `sudo ./scripts/lab-down.sh`.

## Project layout

| Path | Purpose |
|---|---|
| `cmd/govpn` | The VPN executable, including the `genkey` and `pubkey` commands |
| `cmd/udptest` | Standalone tool to test the UDP transport |
| `internal/identity` | X25519 key pairs: generation, parsing, and Diffie-Hellman |
| `internal/noise` | The WireGuard handshake: creates and checks the initiation and response messages, and derives the two transport keys |
| `internal/session` | Encryption and decryption of tunnel messages, with replay protection |
| `internal/tun` | TUN device wrapper |
| `internal/transport` | UDP transport |
| `Dockerfile` | Multi-stage build of a minimal `govpn` image |
| `docker-compose.yml` | Two-peer test setup |
| `docker/entrypoint.sh` | Starts `govpn` with the container's TUN address and keys, and adds the route to the other peer's subnet once the TUN device is up |
| `scripts` | Network namespace test lab |

## Security

Each packet is encrypted and authenticated, so a modified or forged packet is dropped, and a captured packet sent again is dropped too. The handshake gives these properties:

- **New keys on every start.** Each handshake uses fresh ephemeral keys, so a restarted peer never reuses a key and nonce it used before.
- **Forward secrecy.** The keys of a session cannot be recomputed from the peers' private keys alone, so stealing a private key later does not decrypt traffic recorded earlier.
- **Peer authentication.** A peer completes the handshake only with the holder of the private key that matches the public key it was given.

These gaps remain:

- **No rekeying.** A session lasts until a peer restarts. WireGuard starts a new handshake every two minutes, so a stolen session key exposes at most a few minutes of traffic. Here it exposes the whole session.
- **No preshared key.** WireGuard can mix an optional preshared key into the handshake, as extra protection against a future quantum computer that could break X25519. `govpn` always uses the default, a key of zeros.
- **No denial-of-service protection.** Anyone who knows a peer's public key can make it process handshake initiations, each one costing a Diffie-Hellman computation. WireGuard answers with cookies when it is under load. `govpn` does not.

## Limitations

- No rekeying, preshared key, or cookies (see [Security](#security))
- Point-to-point only (one peer)
- IPv4 only
- The TUN MTU assumes the underlying link has a 1500-byte MTU
- Outside Docker, routes to a different remote subnet are added manually
