import socket
import concurrent.futures
import ipaddress
import subprocess
import platform


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
    """Check if a host responds to a few common TCP ports (80, 443, 22, 445, 3389) or ICMP ping."""
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
            
    # Fallback to ICMP ping
    try:
        is_windows = platform.system().lower() == "windows"
        cmd = ["ping", "-n", "1", "-w", "300", host] if is_windows else ["ping", "-c", "1", "-W", "1", host]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0)
        if result.returncode == 0:
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


def draw_topology_map(live_hosts, target_subnet):
    """
    Generates a matplotlib figure containing a topology graph of the subnet.
    """
    import networkx as nx
    import matplotlib.pyplot as plt
    
    fig, ax = plt.subplots(figsize=(10, 7), facecolor='#f8fafc') # match stApp bg
    ax.set_facecolor('#f8fafc')
    
    G = nx.Graph()
    
    # Identify Gateway IP (typically .1 of the subnet or the base)
    gateway_ip = None
    if "/" in target_subnet:
        try:
            import ipaddress
            net = ipaddress.ip_network(target_subnet, strict=False)
            gateway_ip = str(next(net.hosts())) # First host IP is usually the gateway
        except Exception:
            pass
            
    if not gateway_ip and live_hosts:
        # Fallback to the first host's subnet root (e.g. 192.168.1.1)
        first_ip = live_hosts[0]["ip"]
        parts = first_ip.split(".")
        if len(parts) == 4:
            gateway_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            
    if not gateway_ip:
        gateway_ip = "192.168.1.1" # Safe fallback
        
    G.add_node(gateway_ip, type="gateway", label=f"Gateway\n{gateway_ip}")
    
    # Add scanner host node representing the machine performing the scan
    scanner_node = "Local Scanner"
    G.add_node(scanner_node, type="scanner", label="Local Scanner\n(This Host)")
    G.add_edge(scanner_node, gateway_ip)
    
    # Add discovered hosts
    for h in live_hosts:
        ip = h["ip"]
        if ip == gateway_ip:
            # Update gateway label if discovered
            G.nodes[gateway_ip]["label"] = f"Gateway / Router\n{gateway_ip}\n{h['hostname']}"
            continue
            
        label = f"{ip}\n{h['hostname'] if h['hostname'] != 'N/A' else ''}".strip()
        G.add_node(ip, type="host", label=label)
        G.add_edge(gateway_ip, ip)
        
    # Define layout
    pos = nx.spring_layout(G, k=0.6, seed=42)
    
    # Node color mapping
    node_colors = []
    node_sizes = []
    
    for node, attrs in G.nodes(data=True):
        ntype = attrs.get("type")
        if ntype == "gateway":
            node_colors.append("#2563eb") # Primary Blue
            node_sizes.append(1000)
        elif ntype == "scanner":
            node_colors.append("#64748b") # Cool slate gray
            node_sizes.append(800)
        else:
            node_colors.append("#22c55e") # Safe Green
            node_sizes.append(600)
            
    # Draw connections
    nx.draw_networkx_edges(G, pos, ax=ax, width=1.5, edge_color="#cbd5e1", style="dashed")
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=node_sizes, alpha=0.9)
    
    # Draw custom labels with nice styling
    labels = nx.get_node_attributes(G, 'label')
    nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=8, font_family="sans-serif", font_color="#0f172a", font_weight="bold")
    
    # Clean up matplotlib borders
    ax.axis("off")
    plt.tight_layout()
    
    return fig
