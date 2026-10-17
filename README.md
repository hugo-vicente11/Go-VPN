# Go-VPN

[![CI](https://github.com/hugo-vicente11/Go-VPN/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hugo-vicente11/Go-VPN/actions/workflows/ci.yml)

A point-to-point VPN written in Go. It tunnels IP packets between two hosts over UDP using a Linux TUN device.

Built as a learning project. **Traffic is not encrypted yet. Do not use it to protect real data.**

## How it works

```
app -> tun0 -> govpn -> UDP -> govpn -> tun0 -> app
```

- Reads IP packets from a TUN device and sends each one as a UDP datagram to the peer.
- Receives datagrams from the peer and writes them back to the TUN device.
- Datagrams from any address other than the configured peer are dropped.
- Shuts down cleanly on `SIGINT` and `SIGTERM`.

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
govpn -peer ip:port -address ip/len [-port port]
```

| Flag | Description | Default |
|---|---|---|
| `-peer` | Address of the other endpoint. Must be an IP, not a hostname. Required. | none |
| `-address` | Tunnel address of this peer, with prefix length (e.g. `10.0.0.1/24`). Must be an IPv4 host address, not the network address, and not a `/32`. Required. | none |
| `-port` | Local UDP port to listen on (1 to 65535). | `9000` |

`govpn` creates the TUN device, assigns it the `-address`, sets its MTU to 1420, and brings it up before it starts forwarding packets.

The MTU leaves room for the headers added to each tunneled packet, so the outer packet still fits in a standard 1500-byte link:

| Header | Bytes |
|---|---|
| Outer IP (IPv6, the worst case) | 40 |
| UDP | 8 |
| Tunnel header and authentication tag | 32 |
| **TUN MTU** | 1500 − 80 = **1420** |

The 32 bytes for the tunnel header and tag are reserved for encryption, which is not implemented yet.

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

Start both peers:

```
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

### With network namespaces

`scripts/lab-up.sh` creates two network namespaces, `A` and `B`, connected by a virtual cable (`192.168.50.1` and `192.168.50.2`). Each namespace acts as a separate machine.

Build the binary (see [Build](#build)), then start the lab and one `govpn` per namespace, each in its own terminal:

```
sudo ./scripts/lab-up.sh
sudo ip netns exec A ./bin/govpn -peer 192.168.50.2:9000 -address 10.0.0.1/24
sudo ip netns exec B ./bin/govpn -peer 192.168.50.1:9000 -address 10.0.0.2/24
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

Clean up with `sudo ./scripts/lab-down.sh`.

## Project layout

| Path | Purpose |
|---|---|
| `cmd/govpn` | The VPN executable |
| `cmd/udptest` | Standalone tool to test the UDP transport |
| `internal/tun` | TUN device wrapper |
| `internal/transport` | UDP transport |
| `Dockerfile` | Multi-stage build of a minimal `govpn` image |
| `docker-compose.yml` | Two-peer test setup |
| `docker/entrypoint.sh` | Starts `govpn` with the container's TUN address, and adds the route to the other peer's subnet once the TUN device is up |
| `scripts` | Network namespace test lab |

## Limitations

- No encryption, authentication, or key exchange
- Point-to-point only (one peer)
- IPv4 only
- The TUN MTU assumes the underlying link has a 1500-byte MTU
- Outside Docker, routes to a different remote subnet are added manually
