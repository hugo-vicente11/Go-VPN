# Go-VPN

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
govpn -peer ip:port [-port port]
```

| Flag | Description | Default |
|---|---|---|
| `-peer` | Address of the other endpoint. Must be an IP, not a hostname. Required. | none |
| `-port` | Local UDP port to listen on (1 to 65535). | `9000` |

`govpn` creates the TUN device but does not configure it. After it starts, assign an address, bring the interface up, and add a route to the remote network:

```
ip addr add 10.0.0.1/24 dev tun0
ip link set tun0 up
ip route add 10.0.1.0/24 dev tun0
```

## Try it locally

### With Docker

`docker-compose.yml` runs two peers on a private network (`172.30.0.0/24`). Each container creates its TUN device and configures its own address and route on startup:

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
sudo ip netns exec A ./bin/govpn -peer 192.168.50.2:9000
sudo ip netns exec B ./bin/govpn -peer 192.168.50.1:9000
```

Once both are running, configure the TUN devices in a third terminal:

```
sudo ip netns exec A ip addr add 10.0.0.1/24 dev tun0
sudo ip netns exec A ip link set tun0 up
sudo ip netns exec A ip route add 10.0.1.0/24 dev tun0

sudo ip netns exec B ip addr add 10.0.1.1/24 dev tun0
sudo ip netns exec B ip link set tun0 up
sudo ip netns exec B ip route add 10.0.0.0/24 dev tun0
```

Ping across the tunnel:

```
sudo ip netns exec A ping -c1 10.0.1.1
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
| `docker/entrypoint.sh` | Configures the TUN device inside the container, then starts `govpn` |
| `scripts` | Network namespace test lab |

## Limitations

- No encryption, authentication, or key exchange
- Point-to-point only (one peer)
- Outside Docker, TUN addresses and routes are configured manually
