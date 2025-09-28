# CodeAlpha_NetworkSniffer

**Task:** Basic Network Sniffer — CodeAlpha Internship (Task 1)

## What it does
- Captures live packets on the active interface using Scapy.
- Prints timestamped summaries (src → dst, protocol, ports, payload length) to `capture_log.txt`.
- Saves a `capture.pcap` when the capture is stopped (Ctrl+C).
- Demo pcap included: `demo_http_icmp.pcap` (HTTP + ICMP test traffic).

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

