#!/usr/bin/env python3
"""
CodeAlpha - Cyber Security Internship
Task 1: Basic Network Sniffer
--------------------------------------
Captures live network traffic and displays useful information about
each packet: source/destination IP, protocol, ports, and a snippet
of the raw payload.

Requires root/administrator privileges to open a raw socket / capture
interface (this is a limitation of the OS, not this script).

Usage:
    sudo python3 sniffer.py                     # sniff on default interface
    sudo python3 sniffer.py -i eth0              # sniff on a specific interface
    sudo python3 sniffer.py -f "tcp port 80"      # apply a BPF filter
    sudo python3 sniffer.py -c 50                 # stop after 50 packets
    sudo python3 sniffer.py --save capture.pcap   # also save to a pcap file

Author: (your name here)
"""

import argparse
import datetime

try:
    from scapy.all import sniff, wrpcap, Raw
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
except ImportError:
    raise SystemExit(
        "scapy is not installed. Install it with:\n"
        "    pip install scapy\n"
        "(On Linux you may also need libpcap: sudo apt install libpcap-dev)"
    )

# Keep track of packets if the user wants to save them to a pcap file
captured_packets = []


def get_protocol_name(packet):
    """Return a human-readable transport/network protocol name."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IP):
        return f"IP proto {packet[IP].proto}"
    return packet.summary().split()[0] if packet else "UNKNOWN"


def format_payload(packet, max_bytes=64):
    """Return a short, safe printable preview of the payload bytes."""
    if not packet.haslayer(Raw):
        return ""
    raw_bytes = bytes(packet[Raw].load)[:max_bytes]
    printable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in raw_bytes
    )
    suffix = "..." if len(bytes(packet[Raw].load)) > max_bytes else ""
    return f"{printable}{suffix}"


def process_packet(packet):
    """Callback invoked by scapy for every captured packet."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = get_protocol_name(packet)

        src_port = dst_port = None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        length = len(packet)
        payload_preview = format_payload(packet)

        port_info = f":{src_port} -> :{dst_port}" if src_port else ""
        print(f"[{timestamp}] {proto:<10} {src_ip}{port_info} -> {dst_ip}  "
              f"len={length}")
        if payload_preview:
            print(f"            payload: {payload_preview}")
    elif packet.haslayer(Ether):
        # Non-IP traffic (ARP, etc.)
        print(f"[{timestamp}] {packet.summary()}")

    captured_packets.append(packet)


def main():
    parser = argparse.ArgumentParser(description="Basic Python network sniffer (CodeAlpha Task 1)")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy auto-selects)")
    parser.add_argument("-f", "--filter", help="BPF filter, e.g. 'tcp port 80' or 'udp' or 'icmp'", default=None)
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    parser.add_argument("--save", help="Save captured packets to a .pcap file", default=None)
    args = parser.parse_args()

    print("=" * 70)
    print(" CodeAlpha Cyber Security Internship - Task 1: Network Sniffer")
    print("=" * 70)
    print(f"Interface : {args.interface or 'auto'}")
    print(f"Filter    : {args.filter or 'none'}")
    print(f"Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 70)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=process_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        raise SystemExit(
            "Permission denied. Packet capture requires elevated privileges.\n"
            "Try running with: sudo python3 sniffer.py"
        )
    except KeyboardInterrupt:
        print("\nStopping capture (Ctrl+C received)...")
    finally:
        if args.save and captured_packets:
            wrpcap(args.save, captured_packets)
            print(f"\nSaved {len(captured_packets)} packets to {args.save}")
        print(f"Total packets captured: {len(captured_packets)}")


if __name__ == "__main__":
    main()
