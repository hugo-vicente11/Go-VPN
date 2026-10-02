#!/usr/bin/env bash
#
# lab-up.sh — build a two-"machine" test lab using network namespaces.
#
#   namespace A                          namespace B
# ┌──────────────────┐                ┌──────────────────┐
# │ vethA            │════ cable ═════│ vethB            │
# │ 192.168.50.1/24  │                │ 192.168.50.2/24  │
# └──────────────────┘                └──────────────────┘
#
# Usage:  sudo ./scripts/lab-up.sh
# Check:  sudo ip netns exec A ping -c 1 192.168.50.2
# Undo:   sudo ./scripts/lab-down.sh

# -e: exit on the first failing command
# -u: treat unset variables as errors
# -o pipefail: a pipeline fails if any command in it fails
set -euo pipefail

NS_A=A
NS_B=B
VETH_A=vethA
VETH_B=vethB
IP_A=192.168.50.1/24
IP_B=192.168.50.2/24

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0)" >&2
    exit 1
fi

# Start from a clean slate so the script can be run repeatedly.
"$(dirname "$0")/lab-down.sh"

# 1. Two isolated network stacks ("machines").
ip netns add "$NS_A"
ip netns add "$NS_B"

# 2. A virtual cable: two interfaces, whatever enters one exits the other.
ip link add "$VETH_A" type veth peer name "$VETH_B"

# 3. Plug one end into each machine.
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

# 4. Addresses. The kernel also adds the 192.168.50.0/24 route for each.
ip -n "$NS_A" addr add "$IP_A" dev "$VETH_A"
ip -n "$NS_B" addr add "$IP_B" dev "$VETH_B"

# 5. Bring interfaces up (they start administratively down).
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up

echo "lab is up:"
echo "  $NS_A: $VETH_A $IP_A"
echo "  $NS_B: $VETH_B $IP_B"
echo "try: sudo ip netns exec $NS_A ping -c 1 ${IP_B%/*}"
