#!/usr/bin/env bash
#
# lab-down.sh — tear down the lab created by lab-up.sh.
#
# Deleting a namespace destroys every interface inside it. Destroying one end
# of a veth pair destroys the other end too, so deleting the namespaces is all
# the cleanup needed.
#
# Usage: sudo ./scripts/lab-down.sh

set -euo pipefail

NS_A=A
NS_B=B

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0)" >&2
    exit 1
fi

for ns in "$NS_A" "$NS_B"; do
    # Only delete namespaces that exist, so this is safe to run any time.
    if ip netns list | grep -qw "$ns"; then
        ip netns del "$ns"
        echo "deleted namespace $ns"
    fi
done
