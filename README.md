# Go-VPN

[![CI](https://github.com/hugo-vicente11/Go-VPN/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hugo-vicente11/Go-VPN/actions/workflows/ci.yml)

A point-to-point VPN written in Go. It tunnels IP packets between two hosts over UDP using a Linux TUN device.

Built as a learning project. Traffic is encrypted with a pre-shared key, but the scheme has known weaknesses (see [Security](#security)). **Do not use it to protect real data.**

## How it works

```
app -> tun0 -> govpn -> UDP -> govpn -> tun0 -> app
```

- Reads IP packets from a TUN device, encrypts each one, and sends it as a UDP datagram to the peer.
- Receives datagrams from the peer, decrypts them, and writes the packets back to the TUN device.
- Datagrams from any address other than the configured peer are dropped. So are datagrams that fail to decrypt, without a reply or a log line.
- Each message is accepted at most once. Messages may arrive out of order, but one that was already received, or is more than 63 counters older than the newest one, is dropped the same way.
- Shuts down cleanly on `SIGINT` and `SIGTERM`.

Each packet is encrypted with ChaCha20-Poly1305 and sent in the same format as a WireGuard transport data message:

| Field | Bytes |
|---|---|
| Message type (`4`) and 3 reserved zero bytes | 4 |
| Receiver index (always `0` for now) | 4 |
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
govpn -peer ip:port -address ip/len -key-file path [-port port] [-initiator]
```

| Flag | Description | Default |
|---|---|---|
| `-peer` | Address of the other endpoint. Must be an IP, not a hostname. Required. | none |
| `-address` | Tunnel address of this peer, with prefix length (e.g. `10.0.0.1/24`). Must be an IPv4 host address, not the network address, and not a `/32`. Required. | none |
| `-key-file` | Path to the key file (see [Key file](#key-file)). Required. | none |
| `-port` | Local UDP port to listen on (1 to 65535). | `9000` |
| `-initiator` | Set on exactly one of the two peers (see [Initiator](#initiator)). | off |

### Key file

Both peers use the same 32-byte key, stored as standard base64 (the same format as `wg genkey`). Generate one with:

```
(umask 077; head -c 32 /dev/urandom | base64 > govpn.key)
```

`umask 077` creates the file readable only by its owner. `govpn` refuses to start if the group or others can access the key file, and prints the `chmod` command that fixes it.

Copy the same file to both peers. Never commit it: `*.key` files are ignored by Git and by Docker builds.

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

### Initiator

`govpn` does not encrypt with the key file directly. It derives two keys from it with HKDF-SHA256, one for each direction of the tunnel, so the two peers never encrypt with the same key.

`-initiator` decides which key this peer encrypts with. Pass it to exactly one of the two peers. If both peers have it, or neither does, they encrypt with the same key: the tunnel does not work, nothing is logged, and nonces are reused (see [Security](#security)). `govpn` cannot detect this, because neither peer knows how the other was started.

## Try it locally

### With Docker

`docker-compose.yml` runs two peers on a private network (`172.30.0.0/24`). The peers' TUN addresses are in different subnets, so each container also adds a route to the other peer's subnet on startup:

| Container | Network address | TUN address | Initiator |
|---|---|---|---|
| `govpn-a` | `172.30.0.2` | `10.0.0.1/24` | yes |
| `govpn-b` | `172.30.0.3` | `10.0.1.1/24` | no |

Both containers read the key from `govpn.key` in the repository root, mounted as a Compose secret at `/run/secrets/govpn_key`. Generate it first (see [Key file](#key-file)), then start both peers:

```
(umask 077; head -c 32 /dev/urandom | base64 > govpn.key)
docker compose up -d --build
```

Each container reports `(healthy)` once its TUN device has the expected address and route (about 30 seconds):

```
docker compose ps
```

Ping across the tunnel:

```
docker compose exec govpn-a ping -c1 10.0.1.1
```

Follow the logs with `docker compose logs`, and stop everything with `docker compose down`.

The containers need the `NET_ADMIN` capability and the `/dev/net/tun` device, both already set in the compose file. A peer that exits with an error is restarted automatically.

If the containers keep restarting, check `docker compose logs`. A message saying the key file is accessible by other users names the path inside the container, `/run/secrets/govpn_key`, but the file to fix is `govpn.key` on the host: run `chmod 600 govpn.key`. To use a different path inside the container, set the `KEY_FILE` environment variable.

### With network namespaces

`scripts/lab-up.sh` creates two network namespaces, `A` and `B`, connected by a virtual cable (`192.168.50.1` and `192.168.50.2`). Each namespace acts as a separate machine.

Build the binary (see [Build](#build)) and generate a key (see [Key file](#key-file)). Then start the lab and one `govpn` per namespace, each in its own terminal. `A` is the initiator:

```
sudo ./scripts/lab-up.sh
sudo ip netns exec A ./bin/govpn -peer 192.168.50.2:9000 -address 10.0.0.1/24 -key-file govpn.key -initiator
sudo ip netns exec B ./bin/govpn -peer 192.168.50.1:9000 -address 10.0.0.2/24 -key-file govpn.key
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

To check that the traffic is encrypted, capture it on the virtual cable while you ping:

```
sudo ip netns exec A tcpdump -ni vethA -X udp port 9000
```

Each UDP payload starts with `0400 0000` (the message type), then 4 zero bytes (the receiver index), then the 8-byte counter, which goes up by one with each packet. Everything after that looks random. Without encryption, you would see the inner IPv4 header (starting with `45`) and the `10.0.0.x` addresses instead.

If the two peers use different keys, or both or neither pass `-initiator`, the ping gets no replies, and neither `govpn` prints anything.

Clean up with `sudo ./scripts/lab-down.sh`.

## Project layout

| Path | Purpose |
|---|---|
| `cmd/govpn` | The VPN executable |
| `cmd/udptest` | Standalone tool to test the UDP transport |
| `internal/session` | Encryption and decryption of tunnel messages, and key parsing |
| `internal/tun` | TUN device wrapper |
| `internal/transport` | UDP transport |
| `Dockerfile` | Multi-stage build of a minimal `govpn` image |
| `docker-compose.yml` | Two-peer test setup |
| `docker/entrypoint.sh` | Starts `govpn` with the container's TUN address, and adds the route to the other peer's subnet once the TUN device is up |
| `scripts` | Network namespace test lab |

## Security

Each packet is encrypted and authenticated, so a modified or forged packet is dropped. A captured packet sent again is dropped too. The scheme still has these known weaknesses:

- **Nonces are reused after a restart.** Each direction has its own key, but the keys depend only on the key file. A restarted peer derives the same key, starts its counter at 0 again, and reuses nonces it already sent. The same happens between the two peers if both or neither pass `-initiator`. Reusing a nonce with ChaCha20-Poly1305 lets an observer learn information about the plaintext and forge packets. A key exchange that creates new keys on every start would fix this.
- **Restarting one peer stalls the tunnel.** The other peer still remembers the counters it received, so it drops everything the restarted peer sends until that peer's counter passes the last one received before the restart. After a long session this can take a very long time. Restart both peers to recover.
- **No key exchange.** The key is shared manually and never changes, so there is no forward secrecy: anyone who obtains the key can decrypt all past and future traffic.

## Limitations

- Pre-shared key only: no key exchange or rekeying (see [Security](#security))
- Restarting one peer requires restarting the other (see [Security](#security))
- Point-to-point only (one peer)
- IPv4 only
- The TUN MTU assumes the underlying link has a 1500-byte MTU
- Outside Docker, routes to a different remote subnet are added manually
