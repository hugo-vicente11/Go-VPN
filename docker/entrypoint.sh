#!/bin/sh

set -eu

: "${TUN_IP:?tun IP address not given as environment variable}"
: "${REMOTE_NET:?route not given as environment variable}"
(
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "tun configuration failed (exit $rc)" >&2; fi' EXIT
    attempts=0
    iface=tun0

    echo "Waiting for $iface to appear"
    until ip link show "$iface" >/dev/null 2>&1; do
        attempts=$((attempts+1))
        if [ "$attempts" -ge 50 ]; then
            echo "$iface did not appear" >&2
            exit 1
        fi
        sleep 0.2
    done

    echo "$iface appeared after $attempts retries"
    echo "Adding $TUN_IP to $iface"
    ip addr add "$TUN_IP" dev "$iface"
    echo "Setting $iface UP"
    ip link set "$iface" up
    echo "Adding $REMOTE_NET route"
    ip route add "$REMOTE_NET" dev "$iface"
    echo "$iface successfully configured!"
) &

exec ./bin/govpn "$@"
