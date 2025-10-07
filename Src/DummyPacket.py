from scapy.all import *
#this a simple packet with a message, we are stacking layers of protocols
packet = Ether() / IP(dst="127.0.0.1") / UDP(dport=12345) / Raw(load = "Satellite Data 1")
"""Ether() adds a basic network learn, it wraps the data,
IP(dst="127.0.0.1") we set a distination for the packet, right now its local host
UDP(dport=12345) uses a test port(like a channel number)
Raw(load= "..."): Puts your "data" in
"""
#this will show the packet
packet.show()

#saves it to check later
wrpcap("my_first_packet.pcap", packet)
# i  can use software like wireshark to see this packet from inside
