#!/bin/bash
# ci-bench.sh - run the microbenchmark and emit a Markdown table.
#
# Informational only: it never fails the build.  Numbers from a shared CI
# runner are noisy, so read them as a rough sense of cost, not a gate.
# Writes the table to stdout and, in GitHub Actions, to the step summary.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$(cd "$HERE/.." && pwd)
N=${N:-1000000}
RUNS=${RUNS:-5}

find_bpftool() {
	local b
	for b in bpftool /usr/sbin/bpftool /usr/lib/linux-tools/*/bpftool; do
		if command -v "$b" >/dev/null 2>&1 && "$b" version >/dev/null 2>&1; then
			echo "$b"; return 0
		fi
	done
	return 1
}
BPFTOOL=$(find_bpftool) || { echo "no usable bpftool, skipping benchmark"; exit 0; }

arch=$(uname -m); case "$arch" in x86_64) ta=x86;; aarch64) ta=arm64;; *) ta=$arch;; esac
$BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > "$DIR/vmlinux.h" 2>/dev/null
clang -O2 -g -target bpf -D__TARGET_ARCH_"$ta" -I"$DIR" -c "$DIR/csum_guard.bpf.c" -o "$DIR/csum_guard.bpf.o" || {
	echo "build failed, skipping benchmark"; exit 0; }
clang -O2 -g -target bpf -I"$DIR" -c "$HERE/pass.bpf.c" -o "$HERE/pass.bpf.o" || exit 0
gcc -O2 -o "$HERE/blast" "$HERE/blast.c" || exit 0

raw=$(BPFTOOL="$BPFTOOL" N="$N" RUNS="$RUNS" "$HERE/stats.sh" 2>/dev/null)
echo "$raw"

# stats.sh prints: "<mode>  <prog>  median <X> ns/run   runs: ..."
table=$(echo "$raw" | awk '
	/median/ { m[$1 FS $2] = $4 }
	END {
		split("partial none nonip", modes, " ")
		label["partial"]="IPv4 CHECKSUM_PARTIAL"
		label["none"]="IPv4, no offload"
		label["nonip"]="not IPv4"
		print "| packet | empty prog | csum_guard | added |"
		print "|---|---:|---:|---:|"
		for (i in modes) {
			k=modes[i]
			p=m[k FS "pass"]; g=m[k FS "guard"]
			if (p != "" && g != "")
				printf "| %s | %s ns | %s ns | %+.1f ns |\n", label[k], p, g, g-p
		}
	}')

echo
echo "$table"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "### csum_guard microbenchmark — $(uname -m) $(uname -r)"
		echo "_Per-program run time (ns), median of $RUNS x ${N} packets. Shared-runner numbers are noisy; informational only._"
		echo
		echo "$table"
	} >> "$GITHUB_STEP_SUMMARY"
fi
exit 0
