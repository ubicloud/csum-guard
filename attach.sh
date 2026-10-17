#!/bin/bash
# attach.sh DEV [NETNS] [--detach] - attach csum_guard at tc ingress of DEV on
# a live host, or detach it.  Idempotent.
#
# On an Ubicloud host each VM NIC is a tap device inside the VM's own netns
# (see rhizome/host/lib/vm_setup.rb: "ip -n <vm> tuntap add dev <tap> mode tap
# ... vnet_hdr").  The guest controls virtio_net_hdr, so the tap is exactly
# the ingress point the patch defends.  Attach there:
#
#   ./attach.sh <tap> <vm-netns>
#
# Every attachment shares one counters map, pinned at $CNT; it is kept when
# the filter is detached, so the counts survive VM churn.
#
# Requires: tc (iproute2, built with libbpf), a kernel with
# bpf_cast_to_kern_ctx (>= 6.3).  bpftool only to read the counters.
set -euo pipefail

OBJ=${OBJ:-$(cd "$(dirname "$0")" && pwd)/csum_guard.bpf.o}
CNT=/sys/fs/bpf/tc/globals/csum_guard_cnt
PREF=49152
DEV=${1:?usage: attach.sh DEV [NETNS] [--detach]}
NETNS=""; DETACH=0
shift || true
for a in "$@"; do
	case "$a" in
	--detach) DETACH=1 ;;
	*) NETNS=$a ;;
	esac
done

# nsenter keeps the host bpffs visible; "tc -n" and "ip netns exec" remount
# /sys, which would pin a private counters map per attachment.
NS=(); [ -n "$NETNS" ] && NS=(nsenter --net=/run/netns/"$NETNS")

if [ "$DETACH" = 1 ]; then
	"${NS[@]}" tc filter del dev "$DEV" ingress pref $PREF 2>/dev/null || true
	echo "detached from ${NETNS:+$NETNS/}$DEV"
	exit 0
fi

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
"${NS[@]}" tc qdisc replace dev "$DEV" clsact
"${NS[@]}" tc filter replace dev "$DEV" ingress pref $PREF handle 1 \
	bpf direct-action object-file "$OBJ" section tc
echo "attached to ${NETNS:+$NETNS/}$DEV  (counters: bpftool map dump pinned $CNT)"
