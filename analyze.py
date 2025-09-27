#!/usr/bin/env python3
import sys
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

def summarize(pcap_file, top_n=5):
    pkts = rdpcap(pcap_file)
    total = len(pkts)
    talkers = Counter()
    protos = Counter()
    for p in pkts:
        if IP in p:
            ip = p[IP]
            talkers[ip.src] += 1
            if TCP in p:
                protos['TCP'] += 1
            elif UDP in p:
                protos['UDP'] += 1
            elif ICMP in p:
                protos['ICMP'] += 1
            else:
                protos['Other'] += 1
        else:
            protos['Non-IP'] += 1

    print(f"PCAP: {pcap_file}")
    print(f"Total packets: {total}")
    print("\\nTop talkers (by packets sent):")
    for ip, cnt in talkers.most_common(top_n):
        print(f"  {ip}: {cnt} packets")

    print("\\nProtocol distribution:")
    for proto, cnt in protos.most_common():
        print(f"  {proto}: {cnt} packets")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: analyze.py <pcap_file>")
        sys.exit(1)
    summarize(sys.argv[1])
