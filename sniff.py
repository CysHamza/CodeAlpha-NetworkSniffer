#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap, get_if_list, get_if_addr
import datetime, signal, sys

LOGFILE = "capture_log.txt"
PCAPFILE = "capture.pcap"
packets = []

def choose_interface():
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
            if addr and not addr.startswith("127."):
                return iface
        except Exception:
            continue
    return None

iface = choose_interface()
if iface:
    print(f"Using interface: {iface}")
else:
    print("No non-loopback interface auto-detected; using scapy default.")

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def format_and_log(pkt):
    packets.append(pkt)
    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        if TCP in pkt:
            details = f"TCP {pkt[TCP].sport} -> {pkt[TCP].dport}"
        elif UDP in pkt:
            details = f"UDP {pkt[UDP].sport} -> {pkt[UDP].dport}"
        elif ICMP in pkt:
            details = f"ICMP type={pkt[ICMP].type}"
        else:
            details = f"Proto={ip.proto}"
        payload_len = len(pkt[Raw].load) if Raw in pkt else 0
        line = f"[{ts()}] {src} -> {dst} | {details} | payload={payload_len} bytes"
    else:
        line = f"[{ts()}] Non-IP packet: {pkt.summary()}"
    print(line)
    try:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print("Failed to write log:", e)

def handle_sigint(sig, frame):
    print("\nStopping capture — saving pcap...")
    try:
        wrpcap(PCAPFILE, packets)
        print(f"Saved {len(packets)} packets to {PCAPFILE}")
    except Exception as e:
        print("Failed to write pcap:", e)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

print("Starting packet capture... (Ctrl+C to stop)")
if iface:
    sniff(prn=format_and_log, store=False, iface=iface)
else:
    sniff(prn=format_and_log, store=False)

