// SPDX-License-Identifier: GPL-2.0
/*
 * csum_guard: ingress mitigation for the bug fixed by upstream commit
 * 6785011f8b16 ("ipv4: validate checksum_start before completing checksum").
 *
 * A sender that controls virtio_net_hdr (tun/tap IFF_VNET_HDR, vhost-net
 * guests, AF_PACKET PACKET_VNET_HDR) can inject an IPv4 skb with
 * ip_summed == CHECKSUM_PARTIAL and csum_start pointing into (or before)
 * the IP header.  When the stack later calls skb_checksum_help() (IP
 * fragmentation, xfrm/IPsec output, nfqueue, xt_CHECKSUM, bridge conntrack
 * fragmentation) the folded checksum is written over the network header.
 *
 * The patch adds ip_check_csum_start() at those call sites:
 *
 *	if (skb->csum_start < skb->network_header + ip_hdrlen(skb))
 *		return -EINVAL;
 *
 * This program applies the same test at tc ingress of the device the
 * packet enters on and drops the packet there.  A legitimate
 * CHECKSUM_PARTIAL packet always has csum_start at or after the transport
 * header, so the test never matches good traffic.
 *
 * Needs bpf_cast_to_kern_ctx() (Linux 6.3+) to read sk_buff fields that
 * struct __sk_buff does not expose.  Attach with tcx (6.6+) or clsact.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2
#define ETH_P_IP	0x0800
#define CHECKSUM_PARTIAL 3

extern void *bpf_cast_to_kern_ctx(void *) __ksym;

/* Set to 1 from the loader to get one trace_pipe line per drop. */
const volatile __u32 log_drops = 0;

/*
 * Only drops are counted.  A map lookup per inspected packet cost about
 * 6 ns on the CHECKSUM_PARTIAL path, which is the common path for a guest
 * with tx checksum offload; see README.
 */
enum {
	CNT_DROP,	/* dropped: csum_start inside IP header */
	CNT_DROP_SHORT,	/* dropped: IP header not readable */
	CNT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		(*v)++;
}

SEC("tc")
int csum_guard(struct __sk_buff *ctx)
{
	struct sk_buff *skb;
	void *data, *data_end;
	__u32 nh_off;
	__u16 nh, csum_start;
	__u8 vihl;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	skb = bpf_cast_to_kern_ctx(ctx);
	if (BPF_CORE_READ_BITFIELD(skb, ip_summed) != CHECKSUM_PARTIAL)
		return TC_ACT_OK;

	/*
	 * network_header and csum_start are offsets from skb->head.  The
	 * __sk_buff data offsets start at skb->data, which is the MAC header
	 * at tc ingress.
	 */
	nh = skb->network_header;
	csum_start = skb->csum_start;
	nh_off = (__u32)nh - (__u32)(skb->data - skb->head);

	/*
	 * Direct packet access avoids a helper call on the fast path.  Fall
	 * back to bpf_skb_load_bytes() when the IP header is not in the
	 * linear area.  The 256 bound only satisfies the verifier.
	 */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (nh_off <= 256 && data + nh_off + 1 <= data_end) {
		vihl = *(__u8 *)(data + nh_off);
	} else if (bpf_skb_load_bytes(ctx, nh_off, &vihl, 1) < 0) {
		count(CNT_DROP_SHORT);
		return TC_ACT_SHOT;
	}

	if (csum_start < (__u32)nh + (vihl & 0x0f) * 4) {
		count(CNT_DROP);
		if (log_drops)
			bpf_printk("csum_guard: drop ifindex=%u csum_start=%u nh=%u ihl=%u",
				   ctx->ingress_ifindex, csum_start, nh, vihl & 0x0f);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
