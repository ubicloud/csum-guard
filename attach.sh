#!/bin/bash
# attach.sh DEV [NETNS] - attach csum_guard at tc ingress of DEV on a live host.
# detach.sh / "attach.sh DEV ... --detach" removes it.  Idempotent.
#
# On an Ubicloud host each VM NIC is a tap device inside the VM's own netns
# (see rhizome/host/lib/vm_setup.rb: "ip -n <vm> tuntap add dev <tap> mode tap
# ... vnet_hdr").  The guest controls virtio_net_hdr, so the tap is exactly
# the ingress point the patch defends.  Attach there:
#
#   ./attach.sh <tap> <vm-netns>
#
# Requires: tc (iproute2), bpftool, a kernel with bpf_cast_to_kern_ctx (>=6.3).
set -euo pipefail

OBJ=${OBJ:-$(cd "$(dirname "$0")" && pwd)/csum_guard.bpf.o}
BPFTOOL=${BPFTOOL:-bpftool}
DEV=${1:?usage: attach.sh DEV [NETNS] [--detach]}
NETNS=""; DETACH=0
shift || true
for a in "$@"; do
	case "$a" in
	--detach) DETACH=1 ;;
	*) NETNS=$a ;;
	esac
done

# Run tc/bpftool inside the netns while keeping the host bpffs mount visible.
NS=(); [ -n "$NETNS" ] && NS=(nsenter --net=/run/netns/"$NETNS")
PIN=/sys/fs/bpf/csum_guard_${NETNS:-root}_${DEV}

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

if [ "$DETACH" = 1 ]; then
	"${NS[@]}" tc filter del dev "$DEV" ingress 2>/dev/null || true
	"${NS[@]}" tc qdisc del dev "$DEV" clsact 2>/dev/null || true
	rm -rf "$PIN"
	echo "detached from ${NETNS:+$NETNS/}$DEV"
	exit 0
fi

rm -rf "$PIN"; mkdir -p "$PIN"
$BPFTOOL prog load "$OBJ" "$PIN/prog" type tc pinmaps "$PIN/maps"
"${NS[@]}" tc qdisc add dev "$DEV" clsact 2>/dev/null || true
"${NS[@]}" tc filter replace dev "$DEV" ingress \
	bpf object-pinned "$PIN/prog" direct-action
echo "attached to ${NETNS:+$NETNS/}$DEV  (counters: bpftool map dump pinned $PIN/maps/counters)"
