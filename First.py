from scapy.all import *
#destination Ip
ip = IP(dst="8.8.8.8")

#destination port
tcp =TCP(dport=80)
# stack TCP on top of IP
packet= ip/tcp
packet.show()
print(packet.summary()) # this function doesnt print anything, just returns, use print
"""output: IP / TCP 192.168.0.100:ftp_data > 8.8.8.8:http S
so TCP is stacked on IP and by default sport(soruce port) is 20(i.e ftp_data), since we said dport=80, which is for http, to 8.8.8.8's http
192.168.0.100 maybe is my subnet Ip 
FTP data channel -> Http service"""
p1 = IP(dst="8.8.8.8")/ICMP()
"""IP / ICMP 192.168.0.100 > 8.8.8.8 echo-request 0
ICMP is stacked on IP, we having something like echo-request instead of http, no port mentioned
it is used to ping and check if a port is up"""
p2 = IP(dst="8.8.8.8")/TCP(dport=80) # this is same as above
p3 = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)
"""Ether / IP / UDP 192.168.0.100:domain > 8.8.8.8:domain
udp on ip and ip on ether, same 192.0.0.100 subnet local ip, from our domain to 8.8.8.8 domain
dport=53 targets domains i.e DNS"""

print(p1.summary())
print(p2.summary())
print(p3.summary())
#we can use p1.sport, p1.dprot to access the ports
"""Field: defines what goes inside the header
default values: Scapy fills them for you if we dont specify anything
methods: like show(), displays whats inside packets, summary() to get summary of the packet
"""
"""This is based on OSI model:
Ethernet-> ip-> TCP/ICMP/UDP-> Data
should be right order"""

"""Summary: 
ICMP: ping, no particaular port , checks if host is alive
TCP: web/ftp/ssh, 80(http), 21(ftp), 22(ssh) , talks to a server
UDP: DNS, streaming, 53(DND), Send quick request without handshake"""