# CodeAlpha_NetworkSniffer

**Task:** Basic Network Sniffer — CodeAlpha Internship (Task 1)

## What it does
- Captures live packets on the active interface.
- Prints timestamped summaries (src → dst, protocol, ports, payload length) to `capture_log.txt`.
- Saves `capture.pcap` when stopped (Ctrl+C) for Wireshark analysis.
- Demo pcap: `demo_http_icmp.pcap` (contains HTTP + ICMP test traffic).

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

