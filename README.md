# CodeAlpha_NetworkSniffer

**Task:** Basic Network Sniffer — CodeAlpha Internship (Task 1)

## 📌 Overview
This project is a **Python-based Network Sniffer** created as part of the CodeAlpha Cyber Security Internship.  
It uses the `scapy` library to capture live packets from the active network interface, log useful details, and save the data for further analysis.

## 🚀 Features
- Captures packets in real-time using Scapy.
- Logs details such as:
  - Timestamp
  - Source → Destination IPs
  - Protocol (TCP/UDP/ICMP/Other)
  - Ports (if available)
  - Payload size
- Saves a `.pcap` file (`capture.pcap`) for analysis in Wireshark.
- Includes a sample PCAP file: `demo_http_icmp.pcap`.

## 🛠️ Setup Instructions
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

