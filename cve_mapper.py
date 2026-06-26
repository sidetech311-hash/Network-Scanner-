"""
CVE Mapper for Network Scanner
Parses service banners and matches them against offline databases & online APIs.
"""

import re
import requests

def parse_banner(banner):
    """
    Extracts product name and version from a service banner string.
    Returns (product, version) or (None, None).
    """
    if not banner:
        return None, None
        
    banner_clean = banner.strip()
    
    # Common service patterns
    patterns = [
        (r"openssh[_-]([0-9]+\.[0-9]+[p0-9]*)", "openssh"),
        (r"apache/([0-9]+\.[0-9]+\.[0-9]+)", "apache"),
        (r"nginx/([0-9]+\.[0-9]+\.[0-9]+)", "nginx"),
        (r"vsftpd\s+([0-9]+\.[0-9]+\.[0-9]+)", "vsftpd"),
        (r"proftpd\s+([0-9]+\.[0-9]+\.[0-9]+)", "proftpd"),
        (r"mysql\s+([0-9]+\.[0-9]+\.[0-9]+)", "mysql"),
        (r"postgresql\s+([0-9]+\.[0-9]+\.[0-9]+)", "postgresql"),
    ]
    
    for pattern, product in patterns:
        match = re.search(pattern, banner_clean, re.IGNORECASE)
        if match:
            return product, match.group(1)
            
    # Generic fallback: Word followed by version
    fallback_pattern = r"([a-zA-Z0-9_\-]+)/([0-9]+\.[0-9\.]+)"
    match = re.search(fallback_pattern, banner_clean)
    if match:
        return match.group(1).lower(), match.group(2)
        
    fallback_space = r"([a-zA-Z0-9_\-]+)\s+([0-9]+\.[0-9\.]+)"
    match = re.search(fallback_space, banner_clean)
    if match:
        return match.group(1).lower(), match.group(2)
        
    return None, None

def get_offline_cves(product, version):
    """
    Offline heuristics to instantly return critical CVE warnings for common services.
    """
    cves = []
    
    if not product or not version:
        return cves
        
    product = product.lower()
    
    # Helper to parse version numbers safely
    def parse_version_tuple(v_str):
        parts = re.findall(r"([0-9]+)", v_str)
        return tuple(map(int, parts[:3])) if parts else (0, 0, 0)
        
    v_tuple = parse_version_tuple(version)
    
    if product == "openssh":
        # Check RegreSSHion: OpenSSH 8.5p1 to 9.7p1 (exclusive of 9.8)
        if (8, 5, 0) <= v_tuple <= (9, 7, 9):
            cves.append({
                "id": "CVE-2024-6387",
                "severity": "Critical",
                "cvss": 8.1,
                "summary": "RegreSSHion: Remote Unauthenticated Code Execution in OpenSSH's privilege separation child process due to a signal handler race condition."
            })
        elif v_tuple < (8, 5, 0):
            cves.append({
                "id": "CVE-2020-15778",
                "severity": "High",
                "cvss": 7.8,
                "summary": "scp command-line tool allows remote command injection via backtick characters."
            })
            
    elif product == "vsftpd":
        if version == "2.3.4":
            cves.append({
                "id": "CVE-2011-2523",
                "severity": "Critical",
                "cvss": 10.0,
                "summary": "vsftpd 2.3.4 backdoor: Triggered by entering a username ending with a smiley face :) which opens a shell listener on port 6200."
            })
            
    elif product == "proftpd":
        if v_tuple < (1, 3, 6):
            cves.append({
                "id": "CVE-2019-12815",
                "severity": "High",
                "cvss": 7.5,
                "summary": "Unauthenticated arbitrary file copy vulnerability via mod_copy."
            })
            
    elif product == "apache":
        # Check path traversal / RCE in 2.4.49 / 2.4.50
        if version in ["2.4.49", "2.4.50"]:
            cves.append({
                "id": "CVE-2021-41773",
                "severity": "Critical",
                "cvss": 9.8,
                "summary": "Path traversal and remote code execution vulnerability in Apache HTTP Server 2.4.49. Exploit allows file reading and script execution."
            })
        elif v_tuple < (2, 4, 49):
            cves.append({
                "id": "CVE-2017-9798",
                "severity": "Medium",
                "cvss": 5.0,
                "summary": "Optionsbleed: Apache HTTP Server allows memory leakage via Options headers."
            })
            
    elif product == "nginx":
        if v_tuple < (1, 18, 0):
            cves.append({
                "id": "CVE-2021-23017",
                "severity": "High",
                "cvss": 8.1,
                "summary": "Resolver off-by-one vulnerability allowing 1-byte heap buffer overflow and DNS poisoning."
            })
            
    return cves

def get_online_cves(product, version, timeout=3.0):
    """
    Online API lookup querying the open cve.circl.lu directory.
    Safe-guarded by a strict timeout to avoid blocking execution.
    """
    cves = []
    if not product or not version:
        return cves
        
    # Standardize names for CIRCL lookup
    name_map = {
        "openssh": "openssh",
        "apache": "httpd",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "nginx": "nginx"
    }
    
    api_prod = name_map.get(product.lower(), product.lower())
    url = f"https://cve.circl.lu/api/search/{api_prod}"
    
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # If the response is a list (results), search for matching versions
            results = data if isinstance(data, list) else data.get("results", [])
            for item in results:
                # Check if this CVE applies to the version string
                summary = item.get("summary", "")
                cve_id = item.get("id", "")
                cvss = item.get("cvss")
                
                # Check version in summary/vulnerable products (simple regex check)
                if version in summary or any(version in str(p) for p in item.get("vulnerable_configuration", [])):
                    severity = "Low"
                    if cvss:
                        cvss = float(cvss)
                        if cvss >= 9.0:
                            severity = "Critical"
                        elif cvss >= 7.0:
                            severity = "High"
                        elif cvss >= 4.0:
                            severity = "Medium"
                    else:
                        cvss = 0.0
                        
                    cves.append({
                        "id": cve_id,
                        "severity": severity,
                        "cvss": cvss,
                        "summary": summary
                    })
                    
                    if len(cves) >= 5: # Limit to top 5 online CVEs to keep layout neat
                        break
    except Exception:
        pass # Silently proceed on network failure or API timeouts
        
    return cves

def lookup_cves(banner):
    """
    Combined CVE lookup function.
    Runs offline heuristics first, and falls back/complements with online checks.
    """
    product, version = parse_banner(banner)
    if not product or not version:
        return []
        
    cves = get_offline_cves(product, version)
    
    # If offline doesn't find anything, try online
    if not cves:
        cves = get_online_cves(product, version)
        
    return cves
