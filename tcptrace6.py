#!/usr/local/bin/python3

import sys
import argparse
import socket
import time
from scapy.all import *


def resolve_name(hostname):
    try:
        result = socket.getaddrinfo(hostname,None, socket.AF_INET6)
        return result[0][4][0]
    except socket.herror:
        return None


def resolve_ip(ip_address):
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        return f"{ip_address} ({host})"
    except socket.herror:
        return ip_address


def tcp_traceroute_ipv6(
    target, dport=80, max_hops=30, packet_size=64, use_ack=False, iface=None
):
    if packet_size < 64 or packet_size > 1500:
        print("Invalid packet size. Packet size must be between 64 and 1500 bytes.")
        return

    padding_size = packet_size - (
        40 + 20
    )  # 40 bytes for IPv6 header, 20 bytes for TCP header
    padding = b"\x00" * padding_size
    for ttl in range(1, max_hops + 1):
        tcp_flags = "A" if use_ack else "S"
        pkt = (
            IPv6(dst=target, hlim=ttl)
            / TCP(dport=dport, flags=tcp_flags)
            / Raw(load=padding)
        )
        try:
            # Send the packet and receive the response
            start_time = time.time()
            ans, _ = sr(pkt, timeout=2, verbose=0, iface=iface)
            end_time = time.time()
        except PermissionError:
            print(
                "You need to run this script as root or with administrator privileges."
            )
            sys.exit(1)

        BREAK = False
        target_resolved = resolve_name(target)
        if ans:
            reply = ans[0][1]
            rtt = (end_time - start_time) * 1000 # RTT in milliseconds
            resolved_ip = resolve_ip(reply.src)
            if reply.src == target or reply.src == target_resolved:
                BREAK = True
            if reply.haslayer(ICMPv6TimeExceeded):
                print(f"{ttl}: {resolved_ip}, RTT: {rtt:.2f} ms")
                if BREAK:
                    break
            elif reply.haslayer(TCP) and (reply[TCP].flags & 0x3F) == 0x12:
                print(f"{ttl}: {resolved_ip}, RTT: {rtt:.2f} ms")
                break
            else:
                print(f"{ttl}: Unexpected reply")
        else:
            print(f"{ttl}: No reply")


def main():
    parser = argparse.ArgumentParser(description="TCP traceroute with IPv6 support")
    parser.add_argument("host", help="Target host (IPv6 address or hostname)")
    parser.add_argument(
        "-p", "--port", type=int, default=80, help="Destination port (default: 80)"
    )
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        default=64,
        help="Packet size in bytes (default: 64, range: 64-1500)",
    )
    parser.add_argument(
        "-m",
        "--max-hops",
        type=int,
        default=30,
        help="Maximum number of hops (default: 30)",
    )
    parser.add_argument(
        "-a", "--ack", action="store_true", help="Use ACK flag instead of SYN"
    )
    parser.add_argument("-i", "--iface", help="Specify network interface")

    args = parser.parse_args()

    if not (64 <= args.size <= 1500):
        print("Invalid packet size. Packet size must be between 64 and 1500 bytes.")
        sys.exit(1)

    tcp_traceroute_ipv6(
        args.host,
        dport=args.port,
        max_hops=args.max_hops,
        packet_size=args.size,
        use_ack=args.ack,
        iface=args.iface,
    )


if __name__ == "__main__":
    main()
