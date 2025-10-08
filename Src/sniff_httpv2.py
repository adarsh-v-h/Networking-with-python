#!/usr/bin/env python3
#this like makes the file runable as ./file_name.py

from scapy.all import sniff, wrpcap, Raw, TCP, IP, rdpcap
"""sniff() captures packts from an interface
wrpcap() writes a list of packets to a .pcap file
rdcap() reads packets from a .pcap
"""
IFACE = "lo" #interface to capture on, "lo" means loopback - good for local server
FILTER = "tcp and port 8080" # so only traffic for port 8080 is passed Scapy
CAPTURE_COUNT = 20 #The number of packets to capture

#these are output files
PCAP_FILE = "local_http.pcap"
REQ_FILE = "http_requests.txt"
RESP_FILE = "http_responses.txt"

SERVER_PORT = 8080 #used to decide packet direction(incoming or outgoing)

def capture():
	print(f"[+] Capturing {CAPTURE_COUNT} packets on {IFACE} (filter: {FILTER})...")
	pkts = sniff(iface=IFACE, filter=FILTER, count=CAPTURE_COUNT, timeout=10)
	# count tell after how many packets stop, timeout tells after how many sec to stop
	print(f"[+] Captured {len(pkts)} packets. Writing {PCAP_FILE} ...")
	wrpcap(PCAP_FILE, pkts)
	return pkts
def extract(pkts):
	open(REQ_FILE, "w").close()
	open(RESP_FILE,"w").close()
	req_count = resp_count = 0
	for i, p in enumerate(pkts, 1): #iterates packets with enumerate so we haeb packet numbers
		if not p.haslayer(TCP): # skip this is a not TCP packet
			continue
		if p.haslayer(Raw): # packets with payload bytes(HTTP text) are processes
			# try to decode payload safely
			raw = p[Raw].load
			text = raw.decode(errors="replace") #turns bytes into string safely(non decodable bytes replaced)
			info = f"--- pkt#{i} time={p.time} {p[IP].src}:{p[TCP].sport} -> {p[IP].dst}:{p[TCP].dport}\n"
			#info header records the packet number, timestamp (p.time),(src:srcport -> dst:dport)
			info += text + "\n\n"

			#determine direction by source port (server uses SERVER_POT)
			try:
				sport = int(p[TCP].sport)
			except Exception:
				sport = None
			if sport == SERVER_PORT: #if this is true we will treat it as server to client response
				with open(RESP_FILE, "a", encoding="utf-8") as f:
					f.write(info)
				resp_count +=1
			else: #else we will treat it as client to server request
				with open(REQ_FILE, "a", encoding="utf-8") as f:
					f.write(info)
				req_count+=1
	print(f"[+] Extracted {req_count} requests -> {REQ_FILE}")
	print(f"[+] Extracted {resp_count} response -> {RESP_FILE}")
def main():
	pkts = capture()
	#if sniff returned an empty list (timeout), also try reading the pcap file if it exists
	if not pkts:
		try:
			print("[*] No packets Captured in-memory, trying to read pcap file if present...")
			pkts = rdpcap(PCAP_FILE)
			print(f"[+] Read {len(pkts)} packsts from {PCAP_FILE}")
		except FileNotFoundError:
			print(" [!] No pcap file found. Existing.")
			return
	extract(pkts)
	#extracts payloads into text files
	print("[+] Done.")

if __name__ == "__main__":
	main()