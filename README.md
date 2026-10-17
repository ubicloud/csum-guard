# csum_guard — eBPF mitigation for the ipv4 checksum_start bug

A tc/eBPF filter that reproduces the effect of upstream Linux commit
`6785011f8b16` ("ipv4: validate checksum_start before completing checksum")
on a live system, without a kernel rebuild.

This is the out-of-tree home of the filter. It builds a prebuilt CO-RE BPF
object and publishes it as a GitHub release artifact. A consumer (e.g. the
clover host provisioner) pins a release tag, downloads `csum_guard.bpf.o`,
verifies its SHA-256, and attaches it — no compiler on the host.

## The bug

A sender that controls `virtio_net_hdr` — a tun/tap device opened with
`IFF_VNET_HDR`, a vhost-net guest, or an `AF_PACKET` socket with
`PACKET_VNET_HDR` — can hand the kernel an IPv4 `skb` with
`ip_summed == CHECKSUM_PARTIAL` and `csum_start` pointing *inside* (or
before) the IP header.

`virtio_net_hdr_to_skb()` only requires `csum_start >= 20` measured from the
MAC header (`skb_partial_csum_set` plus the `skb_transport_offset >=
sizeof(iphdr)` test). With a 14-byte Ethernet header that still lets
`csum_start` land 6 bytes into the 20-byte IPv4 header.

Later, when the stack must materialise the checksum — IP fragmentation,
xfrm/IPsec output, nfqueue, `xt_CHECKSUM`, bridge-conntrack fragmentation —
`skb_checksum_help()` folds the sum and writes it back at `csum_start`,
**over the network header**. The patch inserts, at each of those call sites:

```c
if (skb->csum_start < skb->network_header + ip_hdrlen(skb))
    return -EINVAL;   /* or NF_DROP */
```

## What this filter does

`csum_guard.bpf.c` applies the same test one hop earlier, at **tc ingress**
of the device the packet enters on, and drops the packet before it ever
reaches a `skb_checksum_help()` call site:

1. Match only IPv4 (`skb->protocol == ETH_P_IP`).
2. `bpf_cast_to_kern_ctx()` to reach the real `struct sk_buff` and read the
   `ip_summed` bitfield; pass through anything that is not `CHECKSUM_PARTIAL`.
3. Read `network_header`, `csum_start`, and the IHL nibble of the IP header.
4. Drop (`TC_ACT_SHOT`) when `csum_start < network_header + ihl*4`.

A legitimate `CHECKSUM_PARTIAL` packet always has `csum_start` at the
transport header, i.e. at or past the end of the IP header, so the test
never matches good traffic. Per-CPU counters record dropped packets.

Every attachment on a host shares one counters map, which tc pins at
`/sys/fs/bpf/tc/globals/csum_guard_cnt`. The counts outlive the devices,
so drops on short-lived VMs are kept, and the map stays the same size
however many devices are attached. They reset when the host reboots.

This is defence in depth, same as the patch's own framing: the real fix is
input validation, but a drop at the entry device removes the corruption
primitive for the forwarding, IPsec, and netfilter paths on an unpatched or
not-yet-rebooted host.

## Mapping to the patch

| Patch call site                     | Covered by this filter? |
|-------------------------------------|-------------------------|
| `ip_do_fragment` (forward/output)   | yes — dropped at ingress before forwarding |
| `xfrm_output` (IPsec)               | yes |
| `nf_queue_checksum_help` (nfqueue)  | yes |
| `xt_CHECKSUM` target                | yes |
| `nf_br_ip_fragment` (bridge)        | yes, if the device is the bridge ingress |

The one case a tc-ingress filter cannot reach is a locally-generated skb
that never ingresses a device (e.g. crafted inside the host itself); the
in-kernel patch covers that, this does not. For the VM/tap threat model —
the guest is the untrusted sender — ingress of the tap is the right and
complete choke point.

## Files

- `csum_guard.bpf.c` — the filter (CO-RE, needs `bpf_cast_to_kern_ctx`, 6.3+).
- `attach.sh DEV [NETNS] [--detach]` — load + attach on a live host.
- `Makefile` — `make` builds the object; `make dist` adds the SHA-256.
- `test/run.sh` — self-contained netns reproduction and proof.
- `test/ci.sh` — build + assert, used by CI.
- `bench/` — the measurements in **Performance**.
- `.github/workflows/ci.yml` — test + benchmark on Ubicloud.
- `.github/workflows/release.yml` — build + publish the release artifact on tag.

`vmlinux.h` is generated from the running kernel's BTF at build time and is
not checked in.

## Build

```sh
make                 # generates vmlinux.h, builds csum_guard.bpf.o
make dist            # also writes csum_guard.bpf.o.sha256
make test            # build + run the assertion test (needs root)
make bench           # run the microbenchmark (needs root)
```

The object is CO-RE: one build relocates against the target host's BTF at
load, so a single artifact runs on every kernel >= 6.3 and on both x86_64
and aarch64.

## Releases and the consumption contract

Tag a version to publish:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`release.yml` builds `csum_guard.bpf.o`, writes `csum_guard.bpf.o.sha256`,
and attaches both to the GitHub release `v0.1.0`. A consumer pins the tag
and the digest, then downloads and verifies:

```
https://github.com/<owner>/<repo>/releases/download/v0.1.0/csum_guard.bpf.o
https://github.com/<owner>/<repo>/releases/download/v0.1.0/csum_guard.bpf.o.sha256
```

The clover host provisioner mirrors `ndp_proxy_setup.rb`: a `VERSION`
constant and a `SHA256` constant pin the object; the setup class downloads
it, verifies the digest, and attaches with `attach.sh`. Bumping `VERSION`
(and the digest) rolls the new object onto hosts; the artifact is immutable
per tag, so a rollback is a repin of the previous tag.

## Attach (live)

On an Ubicloud host a VM NIC is a tap inside the VM's netns, which is where
the guest-controlled `virtio_net_hdr` enters:

```sh
./attach.sh <tap> <vm-netns>          # attach
./attach.sh <tap> <vm-netns> --detach # remove
```

Load with `nsenter --net`, not `tc -n` or `ip netns exec`: those remount
`/sys`, so each load would pin a private counters map that dies with its
device.

Inspect drops, summed over every device on the host since boot:

```sh
bpftool map dump pinned /sys/fs/bpf/tc/globals/csum_guard_cnt
# index 0 = dropped, 1 = dropped (IP header not readable)
```

The map definition is part of the pinned map's identity: libbpf refuses
to reuse a pinned map whose definition differs, so a release that changes
it must also rename it.

Set `log_drops=1` at load for a `trace_pipe` line per drop.

## Validation

`test/run.sh` builds two netns joined by a veth with MTU 576 (to force
fragmentation on forward), injects frames through a `IFF_VNET_HDR` tap as a
guest would, and sniffs the far side. Observed on kernel 6.18:

```
mode=bad  guard=off : 71.31.0.2 -> 10.1.0.2 ...   # source address corrupted
mode=bad  guard=on  : (none)                       # dropped, counters [3,0]
mode=good guard=off : 10.0.0.2  -> 10.1.0.2 ...    # intact
mode=good guard=on  : 10.0.0.2  -> 10.1.0.2 ...    # intact, counters [0,0]
```

The corrupted source `71.31.0.2` is the folded checksum written over the
first 2 bytes of the saddr (`10.0` -> `71.31`), exactly the corruption the
patch prevents.

## Performance

The upstream check is `static inline` and runs only at the slow-path call
sites, just before a full software checksum, so its cost is lost in the
noise. This filter instead runs on every packet that enters the tap.
Measured with `bench/` on a 4 vCPU Xeon 2.1 GHz VM, kernel 6.18:

Program cost, from `kernel.bpf_stats_enabled` with real tap traffic
(`bench/stats.sh`). An empty tc program gives the floor (the stats timer
itself costs about 29 ns per run in this VM):

| packet                         | empty prog | csum_guard | added  |
|--------------------------------|-----------:|-----------:|-------:|
| IPv4 `CHECKSUM_PARTIAL`        | 31.2 ns    | 33.6 ns    | ~2.4 ns |
| IPv4, no checksum offload      | 29.3 ns    | 30.6 ns    | ~1.3 ns |
| not IPv4                       | 29.1 ns    | 29.0 ns    | ~0 ns   |

`BPF_PROG_TEST_RUN` agrees for the non-partial path: about 1 ns over an
empty program.

`CHECKSUM_PARTIAL` is the common case, not the rare one: a guest with tx
checksum offload sends almost all its packets that way. An earlier version
that counted every inspected packet (a map lookup) and read the IP header
with `bpf_skb_load_bytes()` cost about 9 ns there. Direct packet access and
counting only drops brought it to about 2.4 ns.

The larger cost is the tc hook itself. Per-packet time through the tap
write path (`bench/bench.sh`, 64 byte UDP payload, routed to a blackhole
route so the work after tc is small; 9 interleaved runs of 2M packets,
medians):

| packet                    | no hook  | empty prog | csum_guard |
|---------------------------|---------:|-----------:|-----------:|
| IPv4 `CHECKSUM_PARTIAL`   | 702 ns   | 742 ns     | 741 ns     |
| IPv4, no offload          | 718 ns   | 738 ns     | 745 ns     |
| not IPv4                  | 384 ns   | 412 ns     | 415 ns     |

So attaching any clsact program adds about 20-40 ns per packet here, 3-7%
of this deliberately cheap path. The guard logic cannot be told apart from
an empty program at this noise level. With real forwarding, conntrack, or
IPsec after tc, the relative cost is smaller. If the tap already has a
clsact program, adding this logic to it avoids the second dispatch.

XDP would be cheaper but cannot do this check: it runs before
`virtio_net_hdr_to_skb()` sets `csum_start` and `ip_summed`.

## CI

`.github/workflows/ci.yml` builds the object and runs `test/ci.sh` on
Ubicloud runners across Ubuntu 24.04 and 26.04, then runs the benchmark as
an informational step. The test generates `vmlinux.h` from the runner's
BTF, builds, attaches the filter at a tap ingress, and asserts from the
drop counters that a packet with csum_start inside the IP header is dropped
and a well-formed CHECKSUM_PARTIAL packet is not. On a kernel older than 6.3
(no `bpf_cast_to_kern_ctx`) it builds only and skips the live test, so the
job still passes where the mitigation cannot run.

## Limitations

- Needs `bpf_cast_to_kern_ctx` (Linux 6.3+) to read `sk_buff` fields the
  `__sk_buff` context does not expose, and CO-RE/BTF (`/sys/kernel/btf/vmlinux`).
- Covers packets that ingress a device; not host-locally-generated skbs.
- A pure mitigation — pair it with the kernel update; remove with `--detach`
  once the host runs a patched kernel.
