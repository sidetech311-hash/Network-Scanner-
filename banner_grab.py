"""
Banner grabbing - reads service banners to identify versions.
"""

import socket
import re


def grab_banner(host, port, timeout=2.0):
    """Try to read a service banner from host:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Some services need a probe to send a banner
        probes = {
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\n\r\n",
            21: b"\r\n",
            25: b"EHLO test\r\n",
            110: b"\r\n",
            143: b"\r\n",
        }
        probe = probes.get(port, b"")
        if probe:
            try:
                sock.send(probe)
            except Exception:
                pass

        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            banner = ""
        sock.close()
        return banner if banner else None
    except Exception:
        return None


def parse_version(banner, port):
    """
    Parse software version from banner.
    Returns extracted version string or None.
    """
    if not banner:
        return None
    
    # Common version patterns
    patterns = [
        r"([A-Za-z\-]+)/?([\d.]+)",      # Apache/2.4.41, OpenSSH/7.4
        r"([\w\-]+)\s+(v?[\d.]+)",        # Postfix 2.11.0
        r"(Microsoft-IIS|IIS)/([\d.]+)",  # Microsoft-IIS/10.0
        r"(nginx)/([\d.]+)",              # nginx/1.14.0
        r"(Cisco|Juniper|Palo Alto)",     # Network device brands
    ]
    
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            if len(match.groups()) >= 2:
                return f"{match.group(1)} {match.group(2)}"
            else:
                return match.group(1)
    
    # Fallback: return first 50 chars if it looks like a version string
    if re.search(r'\d+\.\d+', banner):
        return banner[:80]
    
    return None


def get_service_version(host, port, timeout=2.0):
    """
    Grab banner and extract version info.
    Returns dict with banner and parsed_version.
    """
    banner = grab_banner(host, port, timeout)
    version = parse_version(banner, port) if banner else None
    
    return {
        "banner": banner,
        "parsed_version": version,
    }

