#!/usr/bin/env python3
# Print src/dst and fragment info of IPv4 packets seen on IFACE for SECONDS.
import sys, warnings; warnings.filterwarnings("ignore")
from scapy.all import sniff, IP

iface, secs = sys.argv[1], float(sys.argv[2])
for p in sniff(iface=iface, timeout=secs, filter="ip"):
    ip = p[IP]
    print(f"{ip.src} -> {ip.dst} id={ip.id} frag={ip.frag} mf={int(ip.flags.MF)} len={ip.len}", flush=True)
