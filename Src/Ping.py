from scapy.all import *

#set a target
target = "127.0.0.1"

#this waits for a response for the destination, we are pinging it wiht ICMP, and with a set timeout of 2 seconds
resp= sr1(IP(dst=target)/ICMP(), timeout=2)
#builds a packet with an echo request, src1 sends it

if resp is None:
    print(f"NO reply from {target}")
    #if we got no response
else:
    print("\t recived packet \t")
    resp.show() #displays the recived packet
    print("\t summary \t")
    print(resp.summary())

    #if you want packet fields
    print("\nType: ", resp.getfieldval("type") if resp.haslayer(ICMP) else "N/A")

#if we dont get any response, windows firewall or router rules might be blocking

"""In resp.show(), we get differnt type of replies ICMP fields to notice
type =0 -> echo reply(good, target replied)
type = 3 -> destination unreachable(port unreachable or blocked)
type = 11 -> Time exceeded

Ip fields to notice
src -> source IP
ttl -> time-to-live(gives hint about hops)
len/checksum-> packet lenght/checksum(usually auto-filler)"""

#above was just ping, now we are going to try to connect using TCP
resp = sr1(IP(dst=target)/TCP(dport=80, flags="S"), timeout = 2)
if resp is None:
     print(f"NO reply to SYN {target}, can be filtered")
    #if we got no response
else:
    resp.show()
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        print(f"TCP flags:{flags}")
        # if flags & 0x12: #0x12 means we send SYN and recived an ACK, but has a flaw, even if we dont get ACK, still it would be true
        #the condtion above is a bitmask, check wether the 0x12 bits are in flags
        # it check if SYN or ACK or both are present, enough but less strick, to properly check for both, if (flags & 0x12) == 0x12: , this is better
        if (flags & 0x12) == 0x12:
            print("Port looks open(SYN +ACK recived)")
        elif (flags & 0x14) == 0x14: # RST+ACK or RST -> port closed
            print("Port looks closed(RST received)")
        else:
            print("No clear TCP response")
"""0x12 and 0x14 are hex digits, they are a part of TCP flag bit mapping, below are few:
FIN = 0x01 
SYN = 0x02 
RST = 0x04 
PSH = 0x08 
ACK = 0x10 
URG = 0x20
ECE = 0x40
CWR = 0x80

so for SYN and ACK, we just SYN + ACK= 0x12
similarly for SYN and RST = 0x14
"""
#output for flags 
print(resp[TCP].flags)
"""output: RA
"""