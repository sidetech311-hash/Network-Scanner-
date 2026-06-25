"""
Port scanner logic - TCP and UDP scans.
"""

import socket


def scan_port(host, port, timeout=1.0):
    """Attempt a TCP connection to host:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return {"port": port, "state": "open", "protocol": "tcp"}
        return {"port": port, "state": "closed", "protocol": "tcp"}
    except socket.timeout:
        return {"port": port, "state": "filtered", "protocol": "tcp"}
    except Exception:
        return None


def scan_udp_port(host, port, timeout=1.5):
    """
    Send a UDP packet. If we get ICMP port unreachable -> closed.
    If we get a response -> open. If no response -> open|filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return {"port": port, "state": "open", "protocol": "udp"}
        except socket.timeout:
            sock.close()
            return {"port": port, "state": "open|filtered", "protocol": "udp"}
    except Exception:
        return None
