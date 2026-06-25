"""
Subnet discovery - finds live hosts in a /24 network.
"""

import socket
import concurrent.futures
import ipaddress


def expand_cidr(target):
    """Accept '192.168.1.0/24' or '192.168.1.1-254' or single IP."""
    hosts = set()

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            for ip in network.hosts():
                hosts.add(str(ip))
            return sorted(hosts, key=lambda x: list(map(int, x.split("."))))
        except ValueError:
            return []

    if "-" in target and "/" not in target:
        try:
            base, rng = target.rsplit(".", 1)
            start, end = rng.split("-")
            start_i, end_i = int(start), int(end)
            for i in range(start_i, end_i + 1):
                hosts.add(f"{base}.{i}")
            return sorted(hosts, key=lambda x: list(map(int, x.split("."))))
        except Exception:
            return []

    hosts.add(target)
    return [target]


def ping_host(host, timeout=0.5):
    """Check if a host responds to a few common TCP ports (80, 443, 22, 445, 3389)."""
    common_ports = [80, 443, 22, 445, 3389]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return host
        except Exception:
            pass
    return None


def get_hostname(ip):
    """Perform a reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "N/A"


def discover_subnet(target, max_threads=100, progress_callback=None):
    """Discover live hosts in a subnet."""
    hosts = expand_cidr(target)
    if not hosts:
        return []

    live_hosts = []
    total = len(hosts)
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_host = {executor.submit(ping_host, h): h for h in hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            scanned += 1
            host = future_to_host[future]
            try:
                result = future.result()
                if result:
                    hostname = get_hostname(result)
                    live_hosts.append({"ip": result, "hostname": hostname})
            except Exception:
                pass
            if progress_callback:
                progress_callback(scanned, total, host)

    return sorted(live_hosts, key=lambda x: list(map(int, x["ip"].split("."))))
