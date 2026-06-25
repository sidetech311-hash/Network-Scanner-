"""
Network Scanner - Personal Companion
A professional port and service scanner for educational and authorized use only.
"""

import socket
import concurrent.futures
from datetime import datetime
from port_scanner import scan_port, scan_udp_port
from service_detect import detect_service
from os_detect import detect_os
from banner_grab import grab_banner, parse_version
from vuln_hints import get_hint
from validation import validate_scan_params, ValidationError


class NetworkScanner:
    def __init__(self, target, start_port=1, end_port=1024, timeout=1.0,
                 max_threads=100, scan_type="tcp", grab_banners=False,
                 include_hints=True, ports=None):
        # Validate all parameters
        try:
            target, start_port, end_port, timeout, max_threads = validate_scan_params(
                target, start_port, end_port, timeout, max_threads
            )
        except ValidationError as e:
            raise ValueError(f"Invalid scan parameters: {e}")
        
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.ports = ports # Optional list of specific ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_type = scan_type  # "tcp" or "udp"
        self.grab_banners = grab_banners
        self.include_hints = include_hints
        self.results = []
        self.os_info = "Unknown"
        self.start_time = None
        self.end_time = None

    def resolve_target(self):
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None

    def scan(self, progress_callback=None):
        """Run the full scan."""
        self.start_time = datetime.now()
        ip = self.resolve_target()
        if not ip:
            return None

        self.os_info = detect_os(ip)

        if self.ports:
            ports_to_scan = self.ports
        else:
            ports_to_scan = range(self.start_port, self.end_port + 1)

        total = len(ports_to_scan)
        scanned = 0
        open_or_filtered = []

        scan_func = scan_port if self.scan_type == "tcp" else scan_udp_port

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(scan_func, ip, port, self.timeout): port
                for port in ports_to_scan
            }
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result and result["state"] in ("open", "open|filtered"):
                        result["service"] = detect_service(port)
                        open_or_filtered.append(result)
                except Exception:
                    pass
                scanned += 1
                if progress_callback:
                    progress_callback(scanned, total)

        # Banner grabbing + vuln hints (TCP only)
        for result in open_or_filtered:
            if self.scan_type == "tcp" and self.grab_banners:
                banner = grab_banner(ip, result["port"], self.timeout)
                result["banner"] = banner
                # Parse version from banner
                result["parsed_version"] = parse_version(banner, result["port"]) if banner else None
            else:
                result["banner"] = None
                result["parsed_version"] = None
            if self.include_hints:
                result["hints"] = get_hint(result["port"])
            else:
                result["hints"] = {}

        self.results = open_or_filtered
        self.end_time = datetime.now()
        return {
            "target": self.target,
            "ip": ip,
            "os": self.os_info,
            "scan_type": self.scan_type.upper(),
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": self.end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": str(self.end_time - self.start_time),
            "open_ports": len(self.results),
            "results": sorted(self.results, key=lambda x: x["port"]),
            "start_port": self.start_port,
            "end_port": self.end_port,
        }
