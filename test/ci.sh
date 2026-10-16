#!/bin/bash
# ci.sh - build csum_guard and assert its behaviour, for use in CI.
#
# Runs as root on a VM runner (Ubicloud).  It:
#   1. locates a usable bpftool,
#   2. generates vmlinux.h from the running kernel's BTF and builds the object,
#   3. checks the kernel has bpf_cast_to_kern_ctx (6.3+); if not, builds only
#      and skips the live test with a GitHub warning (exit 0),
#   4. attaches the filter at tc ingress of a tap and asserts, from the drop
#      counters, that a packet with csum_start inside the IP header is dropped
#      and a well-formed CHECKSUM_PARTIAL packet is not.
#
# Exit 0 = pass (including the old-kernel skip), non-zero = a real failure.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$(cd "$HERE/.." && pwd)
PIN=/sys/fs/bpf/csum_guard_ci
NS=(nsenter --net=/run/netns/cgci)
N=20

note() { echo "::notice::$*"; echo "-- $*"; }
warn() { echo "::warning::$*"; echo "!! $*"; }
die()  { echo "::error::$*"; echo "XX $*"; exit 1; }

# GitHub Actions groups, harmless when run outside CI.
group()    { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

find_bpftool() {
	local b
	for b in bpftool /usr/sbin/bpftool /usr/lib/linux-tools/*/bpftool; do
		if command -v "$b" >/dev/null 2>&1 && "$b" version >/dev/null 2>&1; then
			echo "$b"; return 0
		fi
	done
	return 1
}

kernel_ge_63() {
	local r maj min
	r=$(uname -r); maj=${r%%.*}; min=${r#*.}; min=${min%%.*}
	[ "$maj" -gt 6 ] || { [ "$maj" -eq 6 ] && [ "$min" -ge 3 ]; }
}

cleanup() {
	"${NS[@]}" tc qdisc del dev bt clsact 2>/dev/null || true
	ip netns del cgci 2>/dev/null || true
	rm -rf "$PIN"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || die "must run as root"
BPFTOOL=$(find_bpftool) || die "no usable bpftool found"
note "kernel $(uname -m) $(uname -r); bpftool: $BPFTOOL ($($BPFTOOL version | head -1))"

group "Build"
[ -r /sys/kernel/btf/vmlinux ] || die "no /sys/kernel/btf/vmlinux (kernel BTF required)"
$BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > "$DIR/vmlinux.h"
arch=$(uname -m); case "$arch" in x86_64) ta=x86;; aarch64) ta=arm64;; *) ta=$arch;; esac
clang -O2 -g -target bpf -D__TARGET_ARCH_"$ta" -I"$DIR" \
	-c "$DIR/csum_guard.bpf.c" -o "$DIR/csum_guard.bpf.o"
note "built csum_guard.bpf.o"
endgroup

if ! kernel_ge_63; then
	warn "kernel $(uname -r) < 6.3: no bpf_cast_to_kern_ctx, live test skipped (build only)"
	exit 0
fi

group "Attach"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
rm -rf "$PIN"; mkdir -p "$PIN"
ip netns add cgci
ip -n cgci link set lo up
ip -n cgci tuntap add dev bt mode tap vnet_hdr
ip -n cgci link set bt address 02:00:00:00:00:01 up
ip -n cgci addr add 10.0.0.1/24 dev bt
ip -n cgci route add blackhole 10.1.0.0/24
ip netns exec cgci sysctl -qw net.ipv4.ip_forward=1
ip -n cgci neigh replace 10.0.0.2 lladdr 02:00:00:00:00:02 dev bt
# Load inside the netns, keeping the host bpffs mount visible.
"${NS[@]}" env BPFTOOL="$BPFTOOL" PIN="$PIN" OBJ="$DIR/csum_guard.bpf.o" bash -c '
	$BPFTOOL prog load "$OBJ" $PIN/prog type tc pinmaps $PIN/maps
	tc qdisc add dev bt clsact
	tc filter add dev bt ingress bpf object-pinned $PIN/prog direct-action'
note "attached"
endgroup

drops() {  # sum CNT_DROP (index 0) across CPUs
	$BPFTOOL -j map dump pinned "$PIN/maps/counters" | python3 -c '
import json,sys
u=lambda b:int.from_bytes(bytes(int(x,16) for x in b),"little")
d=json.load(sys.stdin)
print(sum(u(v["value"]) for v in d[0]["values"]))'
}

inject() {  # inject N frames of the given mode into the tap, in the netns
	local mode=$1
	coproc INJ { "${NS[@]}" python3 "$HERE/inject.py" bt 02:00:00:00:00:01 "$mode" "$N"; }
	read -r _ <&"${INJ[0]}"   # "ready" (tap exists, created by the injector)
	echo >&"${INJ[1]}"        # go
	read -r _ <&"${INJ[0]}"   # "sent"
	echo >&"${INJ[1]}"        # exit
	wait "$INJ_PID" 2>/dev/null || true
}

group "Assert"
before=$(drops)
inject bad
bad=$(( $(drops) - before ))
note "bad packets (csum_start in IP header): $bad of $N dropped"
[ "$bad" -eq "$N" ] || die "guard dropped $bad/$N bad packets, expected $N"

before=$(drops)
inject good
good_drop=$(( $(drops) - before ))
note "good packets (CHECKSUM_PARTIAL, valid csum_start): $good_drop of $N dropped"
[ "$good_drop" -eq 0 ] || die "guard dropped $good_drop good packets, expected 0"
endgroup

note "PASS: bad dropped, good passed"
