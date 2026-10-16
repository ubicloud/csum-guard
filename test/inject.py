#!/usr/bin/env python3
# Inject frames through a tap with IFF_VNET_HDR, as a VM guest does via vhost-net.
#
#   inject.py TAPNAME DST_MAC MODE [COUNT]
#
# MODE "bad":  csum_start = 20 (6 bytes into the IPv4 header), csum_offset = 6,
#              so skb_checksum_help() writes the folded sum over the IPv4 saddr.
#              virtio_net_hdr_to_skb() only demands csum_start >= 20 counted
#              from the MAC header, so with a 14 byte Ethernet header this passes.
# MODE "good": csum_start = 14 + 20 (UDP header), csum_offset = 6.
import warnings; warnings.filterwarnings("ignore")
import fcntl, os, struct, sys, time
from scapy.all import Ether, IP, UDP, Raw, raw

TUNSETIFF = 0x400454CA
IFF_TAP, IFF_NO_PI, IFF_VNET_HDR = 0x0002, 0x1000, 0x4000
VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

tap, dst_mac, mode = sys.argv[1], sys.argv[2], sys.argv[3]
count = int(sys.argv[4]) if len(sys.argv) > 4 else 3
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", tap.encode(), IFF_TAP | IFF_NO_PI | IFF_VNET_HDR))
print("ready", flush=True)
sys.stdin.readline()  # wait until the caller configured the device

pkt = (Ether(src="02:00:00:00:00:02", dst=dst_mac)
       / IP(src="10.0.0.2", dst="10.1.0.2", flags=0)
       / UDP(sport=1111, dport=2222, chksum=0)
       / Raw(b"A" * 1200))
start, off = (20, 6) if mode == "bad" else (34, 6)
# struct virtio_net_hdr: flags, gso_type, hdr_len, gso_size, csum_start, csum_offset
vh = struct.pack("<BBHHHH", VIRTIO_NET_HDR_F_NEEDS_CSUM, 0, 0, 0, start, off)
for _ in range(count):
    os.write(fd, vh + raw(pkt))
    if count <= 3:
        time.sleep(0.1)
print("sent", flush=True)
sys.stdin.readline()
