#!/bin/bash
# Reproduce the header corruption through IPv4 fragmentation on forward,
# then show csum_guard stopping it.
#
#  netns cg1: tap "cgtap" (fed by inject.py) --forward--> veth va (mtu 576)
#  netns cg2: veth vb, sniffer
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
OBJ=$HERE/../csum_guard.bpf.o
BPFTOOL=${BPFTOOL:-bpftool}
PIN=/sys/fs/bpf/csum_guard_test
# bpftool pins the program's counters map by name at the bpffs root.
CNT=/sys/fs/bpf/csum_guard_cnt

cleanup() {
	ip netns del cg1 2>/dev/null
	ip netns del cg2 2>/dev/null
	rm -rf $PIN $CNT
}
cleanup
trap cleanup EXIT

ip netns add cg1
ip netns add cg2
ip -n cg1 link add va mtu 576 type veth peer name vb netns cg2
ip -n cg1 addr add 10.1.0.1/24 dev va
ip -n cg2 addr add 10.1.0.2/24 dev vb
ip -n cg1 link set va up
ip -n cg2 link set vb up
ip -n cg1 link set lo up
ip netns exec cg1 sysctl -qw net.ipv4.ip_forward=1
ip -n cg2 route add 10.0.0.0/24 via 10.1.0.1

run_case() {
	local mode=$1 guard=$2
	coproc INJ { exec ip netns exec cg1 python3 "$HERE/inject.py" cgtap 02:00:00:00:00:01 "$mode"; }
	read -r _ <&"${INJ[0]}"
	ip -n cg1 link set cgtap address 02:00:00:00:00:01
	ip -n cg1 addr add 10.0.0.1/24 dev cgtap
	ip -n cg1 link set cgtap up
	ip -n cg1 neigh replace 10.0.0.2 lladdr 02:00:00:00:00:02 dev cgtap
	if [ "$guard" = on ]; then
		mkdir -p $PIN
		$BPFTOOL prog load "$OBJ" $PIN/prog type tc
		# nsenter keeps /sys/fs/bpf visible; "ip netns exec" remounts /sys.
		nsenter --net=/run/netns/cg1 tc qdisc add dev cgtap clsact
		nsenter --net=/run/netns/cg1 tc filter add dev cgtap ingress bpf object-pinned $PIN/prog direct-action
	fi
	ip netns exec cg2 python3 "$HERE/sniff.py" vb 2 > /tmp/cg_sniff.$$ &
	local sniffer=$!
	sleep 0.7
	echo >&"${INJ[1]}"
	read -r _ <&"${INJ[0]}"
	wait $sniffer
	echo "== mode=$mode guard=$guard: packets seen on far side"
	sed 's/^/   /' /tmp/cg_sniff.$$
	[ -s /tmp/cg_sniff.$$ ] || echo "   (none)"
	if [ "$guard" = on ]; then
		echo "   counters [drop, drop_short] summed over CPUs:"
		$BPFTOOL -j map dump pinned $CNT |
			python3 -c 'import json,sys
def u64(b): return int.from_bytes(bytes(int(x,16) for x in b),"little")
d=json.load(sys.stdin)
print("  ", [sum(u64(v["value"]) for v in e["values"]) for e in d])'
		nsenter --net=/run/netns/cg1 tc qdisc del dev cgtap clsact
		rm -rf $PIN $CNT
	fi
	echo >&"${INJ[1]}"
	wait $INJ_PID 2>/dev/null
	rm -f /tmp/cg_sniff.$$
}

run_case good off
run_case bad off
run_case good on
run_case bad on
