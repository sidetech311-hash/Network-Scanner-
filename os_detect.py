"""
Basic OS detection using TTL values from ping.
Falls back to a socket-based heuristic.
"""

import platform
import subprocess
import re


def get_ttl(host):
    """Get the TTL from a ping response (Windows and Linux/macOS compatible)."""
    try:
        is_windows = platform.system().lower() == "windows"
        cmd = ["ping", "-n", "1", "-w", "1000", host] if is_windows else ["ping", "-c", "1", "-W", "2", host]
        
        # Use the system's ping command
        output = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        match = re.search(r"ttl[=\s]+(\d+)", output, re.IGNORECASE)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None


def ttl_to_os(ttl):
    """Map TTL values to likely OS families."""
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix/macOS (TTL ~64)"
    if ttl <= 128:
        return "Windows (TTL ~128)"
    if ttl <= 255:
        return "Network Device / Older OS (TTL ~255)"
    return "Unknown"


def detect_os(host):
    """Try TTL-based detection, fall back to platform heuristic."""
    ttl = get_ttl(host)
    if ttl is not None:
        return ttl_to_os(ttl)
    return f"Unknown (Local Platform: {platform.system()})"
