#!/usr/bin/env python3
from scapy.all import sniff, Raw

#Callback executed for every captured packet
def handle(pkt):
	print(pkt.summary())
	#if the packet carries payload bytes (HTTP body / request)
	if pkt.haslayer(Raw):
		try:
			print("RAW: ", pkt[Raw].load.decode(errors="replace"))
		except Exception:
			print("RAW (bytes:)", repr(pkt[Raw].load))
#listen on loopback (lo) for TCP traffic to/from port 8080
# iface ='lo': capture on loopback(where your http.server runs) this avoids noise from other NICs
# filter: BPF filter applied in kernel(move different) , we will only see TCP packets from 8080 port
# prn: callback to handle/display each packet this called handle(pkt)
#store =0: dont keep packets in memory(safer)
# count = 0: capture until you Ctrl+C it (we can change this number)

sniff(iface ="lo",
	filter="tcp and port 8080",
	prn=handle,
	store=0,
	count=0)

