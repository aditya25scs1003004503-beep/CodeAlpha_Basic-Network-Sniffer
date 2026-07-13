# CodeAlpha_NetworkSniffer

**CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer**

A simple Python packet sniffer built with [Scapy](https://scapy.net/) that captures live
network traffic and displays useful information about each packet: source/destination IP,
protocol, ports, and a printable preview of the payload.

## What it does

- Captures packets in real time from a network interface
- Identifies the protocol (TCP, UDP, ICMP, or raw IP)
- Shows source and destination IP addresses and ports
- Prints a short, safe preview of the payload bytes
- Optionally saves the capture to a `.pcap` file (viewable in Wireshark)
- Optionally filters traffic using BPF filter syntax (e.g. `tcp port 80`)

## How it works

1. `scapy.sniff()` opens a raw capture handle on the chosen interface.
2. For every packet received, the `process_packet()` callback runs.
3. The script inspects the packet's layers (`IP`, `TCP`, `UDP`, `ICMP`, `Raw`)
   to pull out addressing, port, and payload information.
4. Results are printed to the console in real time, and optionally written
   to a `.pcap` file for later analysis in Wireshark.

## Requirements

- Python 3.8+
- `scapy` (see `requirements.txt`)
- Root/administrator privileges (required by the OS to capture raw packets)
- On Linux, `libpcap` is recommended: `sudo apt install libpcap-dev`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Sniff on the default interface, unlimited packets (Ctrl+C to stop)
sudo python3 sniffer.py

# Sniff on a specific interface
sudo python3 sniffer.py -i eth0

# Only capture HTTP traffic
sudo python3 sniffer.py -f "tcp port 80"

# Capture exactly 50 packets
sudo python3 sniffer.py -c 50

# Save the capture to a pcap file for Wireshark
sudo python3 sniffer.py --save capture.pcap
```

> **Windows users:** install [Npcap](https://npcap.com/) first, then run
> the script from an Administrator command prompt (no `sudo`).

## Sample output

```
======================================================================
 CodeAlpha Cyber Security Internship - Task 1: Network Sniffer
======================================================================
Interface : auto
Filter    : tcp port 80
Count     : unlimited (Ctrl+C to stop)
----------------------------------------------------------------------
[14:02:11.203] TCP        192.168.1.12:52344 -> :80 -> 93.184.216.34  len=74
[14:02:11.245] TCP        93.184.216.34:80 -> :52344 -> 192.168.1.12  len=1500
            payload: GET / HTTP/1.1..Host: example.com..
```

## ⚠️ Ethical use notice

This tool is for **educational purposes only**. Only capture traffic on networks
you own or have explicit permission to monitor. Unauthorized packet capture may
violate laws such as the Computer Fraud and Abuse Act (US), the Computer Misuse
Act (UK), or equivalent legislation elsewhere.

## Author

Built as part of the CodeAlpha Cyber Security Internship (Task 1).
