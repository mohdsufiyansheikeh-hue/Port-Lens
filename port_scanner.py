#!/usr/bin/env python3
"""
Simple TCP port scanner for auditing hosts YOU OWN or have written
permission to test (your own PC, home router, lab VMs, etc.).

Usage examples:
    python port_scanner.py 127.0.0.1
    python port_scanner.py 192.168.1.1 -p 1-1024
    python port_scanner.py localhost -p 22,80,443,8080 -t 1.0 -w 200
    python port_scanner.py 192.168.1.1 --top
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Frequently used ports, for the --top option
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443,
    445, 465, 587, 631, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443, 9200, 27017,
]

# Ports that are risky when exposed, with a short note
RISKY = {
    21: "FTP sends credentials in plain text",
    23: "Telnet is unencrypted; use SSH instead",
    135: "Windows RPC; should not be exposed",
    139: "NetBIOS; should not be exposed",
    445: "SMB; commonly targeted, keep off the internet",
    3389: "RDP; use VPN/MFA, don't expose directly",
    5900: "VNC; often weakly protected",
    6379: "Redis; often has no authentication",
    27017: "MongoDB; often misconfigured without auth",
}


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,100-200' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Port out of range (1-65535): {bad[0]}")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(host: str, port: int, timeout: float):
    """Return port if open, else None (full TCP connect)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner (only scan systems you are authorized to test)."
    )
    parser.add_argument("host", help="Target hostname or IPv4 address")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports, e.g. 80,443 or 1-1024 (default: 1-1024)")
    parser.add_argument("--top", action="store_true",
                        help="Scan only a list of common ports")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Number of parallel threads (default: 100)")
    args = parser.parse_args()

    try:
        ports = TOP_PORTS if args.top else parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"Invalid port specification: {e}")

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        sys.exit(f"Could not resolve host: {args.host}")

    print(f"\nScanning {args.host} ({ip}) - {len(ports)} ports")
    print("Only scan systems you own or have permission to test.\n")

    start = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(scan_port, ip, p, args.timeout) for p in ports]
        try:
            for f in as_completed(futures):
                result = f.result()
                if result:
                    open_ports.append(result)
        except KeyboardInterrupt:
            print("\nInterrupted, showing results so far...")
            for f in futures:
                f.cancel()

    open_ports.sort()
    elapsed = time.time() - start

    if open_ports:
        print(f"{'PORT':<8}{'SERVICE':<14}NOTE")
        print("-" * 60)
        for p in open_ports:
            print(f"{p:<8}{service_name(p):<14}{RISKY.get(p, '')}")
    else:
        print("No open ports found.")

    print(f"\nDone: {len(open_ports)} open of {len(ports)} scanned in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
