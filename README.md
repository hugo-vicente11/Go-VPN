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
- Go 1.27 or newer
- Root, or the `CAP_NET_ADMIN` capability (needed to create the TUN device)

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

`scripts/lab-up.sh` creates two network namespaces, `A` and `B`, connected by a virtual cable (`192.168.50.1` and `192.168.50.2`). Each namespace acts as a separate machine.

Start the lab and one `govpn` per namespace, each in its own terminal:

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
| `scripts` | Network namespace test lab |

## Limitations

- No encryption, authentication, or key exchange
- Point-to-point only (one peer)
- TUN addresses and routes are configured manually
