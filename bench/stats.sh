#!/bin/bash
# In-kernel run time per program run, real tap traffic, kernel.bpf_stats_enabled.
# The empty program gives the stats-timer floor; subtract it.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BPFTOOL=${BPFTOOL:-bpftool}; N=${N:-2000000}; RUNS=${RUNS:-5}; CPU=${CPU:-1}
PIN=/sys/fs/bpf/cg_stats; NS=(nsenter --net=/run/netns/bn)
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
ip netns del bn 2>/dev/null; rm -rf $PIN; mkdir -p $PIN
ip netns add bn
ip -n bn tuntap add dev bt mode tap vnet_hdr
ip -n bn link set bt address 02:00:00:00:00:01 up
ip -n bn addr add 10.0.0.1/24 dev bt
ip -n bn route add blackhole 10.1.0.0/24
ip netns exec bn sysctl -qw net.ipv4.ip_forward=1
$BPFTOOL prog load "$HERE/pass.bpf.o" $PIN/pass type tc
$BPFTOOL prog load "$HERE/${GUARD:-../csum_guard.bpf.o}" $PIN/guard type tc pinmaps $PIN/maps
"${NS[@]}" tc qdisc add dev bt clsact
sysctl -qw kernel.bpf_stats_enabled=1
for mode in partial none nonip; do for prog in pass guard; do
	"${NS[@]}" tc filter replace dev bt ingress pref 1 handle 1 bpf object-pinned $PIN/$prog direct-action
	for r in $(seq $RUNS); do
		b=$($BPFTOOL -j prog show pinned $PIN/$prog)
		printf '\n\n' | taskset -c $CPU ip netns exec bn "$HERE/blast" bt $N $mode >/dev/null
		a=$($BPFTOOL -j prog show pinned $PIN/$prog)
		python3 -c 'import json,sys
b,a=json.loads(sys.argv[1]),json.loads(sys.argv[2])
print((a.get("run_time_ns",0)-b.get("run_time_ns",0))/(a.get("run_cnt",0)-b.get("run_cnt",0)))' "$b" "$a"
	done | sort -n | tr '\n' ' ' | awk -v m=$mode -v p=$prog '{printf "%-8s %-6s median %.1f ns/run   runs: %s\n", m, p, $'"$(( (RUNS+1)/2 ))"', $0}'
done; done
sysctl -qw kernel.bpf_stats_enabled=0
ip netns del bn; rm -rf $PIN
