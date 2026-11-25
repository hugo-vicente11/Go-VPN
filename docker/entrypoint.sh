#!/bin/sh

set -eu

private_key_file="${PRIVATE_KEY_FILE:-/run/secrets/private_key}"
peer_public_key_file="${PEER_PUBLIC_KEY_FILE:-/peer_public_key}"
peer_public_key=$(cat "$peer_public_key_file")

: "${TUN_IP:?tun IP address not given as environment variable}"
: "${REMOTE_NET:?route not given as environment variable}"
(
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "route setup failed (exit $rc)" >&2; fi' EXIT
    attempts=0
    iface=tun0

    echo "Waiting for $iface to come up"
    until ip link show "$iface" 2>/dev/null | grep -qE '[<,]UP[,>]'; do
        attempts=$((attempts+1))
        if [ "$attempts" -ge 50 ]; then
            echo "$iface did not come up" >&2
            exit 1
        fi
        sleep 0.2
    done

    echo "$iface is up after $attempts retries"
    echo "Adding $REMOTE_NET route"
    ip route add "$REMOTE_NET" dev "$iface"
    echo "Route to $REMOTE_NET via $iface added"
) &

exec ./bin/govpn -address "$TUN_IP" -private-key-file "$private_key_file" -peer-public-key "$peer_public_key" "$@"
