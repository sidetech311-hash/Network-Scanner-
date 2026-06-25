#!/usr/bin/env python3
"""
Command-line interface for the Network Scanner
"""

import argparse
from scanner import NetworkScanner
from report import generate_report


def main():
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--start", type=int, default=1, help="Start port")
    parser.add_argument("--end", type=int, default=1024, help="End port")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--no-banners", action="store_true", help="Disable banner grabbing")
    parser.add_argument("--no-hints", action="store_true", help="Disable vulnerability hints")
    parser.add_argument("--output", default="network_scan_report.pdf", help="Output PDF path")
    args = parser.parse_args()

    scanner = NetworkScanner(
        target=args.target,
        start_port=args.start,
        end_port=args.end,
        timeout=args.timeout,
        max_threads=args.threads,
        scan_type=args.protocol,
        grab_banners=not args.no_banners,
        include_hints=not args.no_hints,
    )

    print(f"Scanning {args.target} ({args.protocol.upper()}) ports {args.start}-{args.end} ...")
    result = scanner.scan()
    if not result:
        print("Could not resolve the target.")
        return

    path = generate_report(result, output_path=args.output)
    print(f"Report saved to: {path}")


if __name__ == "__main__":
    main()
