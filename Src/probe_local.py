from scapy.all import *
target = "127.0.0.1"
port = 8080
syn = IP(dst=target)/TCP(dport=port, flags = "S") #here S is, saying SYN flag
synack = sr1(syn, timeout =2) # send and recieve reply, if took more than 2 seconds, timeout
if not synack:
    print("NO reply to SYN.")
else:
    f = int(synack[TCP].flags)
    if (f & 0x12) == 0x12: #now if we got SYN+ACK
        print("Got SYN+ACK: ", synack[TCP].flags)
        print("flags (hex): ", hex(f))
        my_seq = int(synack[TCP].ack) # sever's ack for ou syn
        their_seq = int(synack[TCP].seq) + 1 # server's initial sequence number
        #my_seq is what we should use as our TCP sequence number for the next packet we send, (we set seq to synack.ack because the server already incremented our seq by 1)
        # their_seq is what we should set as the ack in our packets - it acknowledges the server's seq, so we sue server_seq +1 (we set seq to synack.ack because the server already incremented our seq by 1) 
        ack_pkt = IP(dst=target)/TCP(dport=port, 
                                    sport = int(synack[TCP].dport), # we set sport as dport of the subsequent packets use the same local source port as the initial SYN.
                                    flags="A",
                                    seq = my_seq,
                                    ack = their_seq)
        send(ack_pkt)
        http_payload = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" #\r\n\r\n terminator and Host: header for HTTP/1.1
        get_pkt = IP(dst = target)/TCP(dport = port,
                                       sport = int(synack[TCP].dport),
                                                   flags = "PA", # "PA" sets push+ ACK, asks the receiver to push the data up to the application promptly
                                                   seq=my_seq,
                                                   ack=their_seq)/Raw(load=http_payload) # raw attaches application data (the HTTP GET) to TCP segment
        resp = sr1(get_pkt, timeout=2) #sends the GET and waits for the first reply (the HTTP response segment)

        if resp:
            print("==== Response summary ====")
            resp.show()
            if resp.haslayer(Raw):
                #Raw layer contains the payload bytes; .decode(errors="replace") attempts to convert to text without crashing on binary content(non decodable bytes are replaced)
                try:
                    print("\n ==== Http body (bytes) ===\n", resp[Raw].load.decode(errors="replace"))
                except Exception:
                    print("\n === HTTP body (RAW) ===\n", resp[Raw].load)
        else:
            print("No reply to HTTP Get (try increasing timeout).")
    else:
        print("Reply recived but not SYN+ACK. Flags: ", synack[TCP].flag)
    
"""first we send a syn, and if we recived Ayk, i.e SA, we then send PA, its like a 3 way handshake
but the problem is we can just send PA with a new packect, the packct must have to form similarties or else might be rejected by the target
the payload holds what must be ran on the server"""
