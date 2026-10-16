#!/bin/bash
# Per-packet cost of tap RX with: no tc hook / empty tc prog / csum_guard.
# Build first (from this directory):
#   gcc -O2 -o blast blast.c
#   clang -O2 -g -target bpf -c pass.bpf.c -o pass.bpf.o
#   (cd .. && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c csum_guard.bpf.c -o csum_guard.bpf.o)
# Routed path ending in a blackhole route, so the stack work after tc is small
# and any tc overhead is as visible as it can be (worst case, relative).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BPFTOOL=${BPFTOOL:-bpftool}
N=${N:-2000000}; RUNS=${RUNS:-7}; CPU=${CPU:-1}
PIN=/sys/fs/bpf/cg_bench
NS=(nsenter --net=/run/netns/bn)

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
ip netns del bn 2>/dev/null; rm -rf $PIN; mkdir -p $PIN
ip netns add bn
ip -n bn tuntap add dev bt mode tap vnet_hdr
ip -n bn link set bt address 02:00:00:00:00:01 up
ip -n bn addr add 10.0.0.1/24 dev bt
ip -n bn route add blackhole 10.1.0.0/24
ip netns exec bn sysctl -qw net.ipv4.ip_forward=1
$BPFTOOL prog load "$HERE/pass.bpf.o" $PIN/pass type tc
$BPFTOOL prog load "$HERE/../csum_guard.bpf.o" $PIN/guard type tc pinmaps $PIN/maps

setcfg() {
	"${NS[@]}" tc qdisc del dev bt clsact 2>/dev/null
	case $1 in
	none) ;;
	*) "${NS[@]}" tc qdisc add dev bt clsact
	   "${NS[@]}" tc filter add dev bt ingress bpf object-pinned $PIN/$1 direct-action ;;
	esac
}
one() { printf '\n\n' | taskset -c $CPU ip netns exec bn "$HERE/blast" bt $N $1 | tail -1; }
median() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }

one partial >/dev/null   # warm up
for mode in partial none nonip; do
	declare -A res=()
	for r in $(seq $RUNS); do
		for cfg in none pass guard; do   # interleave configs against drift
			setcfg $cfg
			res[$cfg]+="$(one $mode) "
		done
	done
	for cfg in none pass guard; do
		printf "%-8s %-6s median %6s ns/pkt   runs: %s\n" $mode $cfg \
			"$(echo ${res[$cfg]} | tr ' ' '\n' | median)" "${res[$cfg]}"
	done
	unset res
done

echo "--- in-kernel run time of csum_guard itself (kernel.bpf_stats_enabled) ---"
sysctl -qw kernel.bpf_stats_enabled=1
id=$($BPFTOOL -j prog show pinned $PIN/guard | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
setcfg guard
for mode in partial none nonip; do
	b=$($BPFTOOL -j prog show id $id)
	one $mode >/dev/null
	a=$($BPFTOOL -j prog show id $id)
	python3 - "$mode" "$b" "$a" <<'PY'
import json, sys
m, b, a = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
t = a.get("run_time_ns",0) - b.get("run_time_ns",0); c = a.get("run_cnt",0) - b.get("run_cnt",0)
print(f"{m:8s} prog run_cnt {c}  avg {t/c:.1f} ns/run (includes stats timing overhead)")
PY
done
sysctl -qw kernel.bpf_stats_enabled=0
echo "--- guard counters [drop, drop_short] ---"
$BPFTOOL -j map dump pinned $PIN/maps/counters | python3 -c 'import json,sys
u=lambda b:int.from_bytes(bytes(int(x,16) for x in b),"little")
print([sum(u(v["value"]) for v in e["values"]) for e in json.load(sys.stdin)])'
echo "--- BPF_PROG_TEST_RUN, 10M repeats, median of 5, ns/run (ip_summed is NONE here) ---"
T=$(mktemp -d)
python3 -c 'import sys; sys.stdout.buffer.write(bytes([2,0,0,0,0,1,2,0,0,0,0,2,8,0,0x45,0,0,92,0,0,0,0,64,17,0,0,10,0,0,2,10,1,0,2])+bytes(72))' > $T/v4
python3 -c 'import sys; sys.stdout.buffer.write(bytes([2,0,0,0,0,1,2,0,0,0,0,2,0x88,0xb5])+bytes(92))' > $T/nonip
for prog in pass guard; do for pkt in v4 nonip; do
	for r in 1 2 3 4 5; do
		$BPFTOOL -j prog run pinned $PIN/$prog data_in $T/$pkt repeat 10000000 |
			python3 -c 'import json,sys; print(json.load(sys.stdin)["duration"])'
	done | sort -n | sed -n 3p | xargs printf "%-6s %-6s %s ns/run\n" $prog $pkt
done; done
rm -rf $T
setcfg none; ip netns del bn; rm -rf $PIN
