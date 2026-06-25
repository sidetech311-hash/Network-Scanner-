"""
Vulnerability hints for common open ports.
Educational information only - not a real vulnerability scanner.
"""


VULN_HINTS = {
    21: {
        "service": "FTP",
        "risk": "Medium",
        "hints": [
            "Check for anonymous FTP login (username: anonymous)",
            "FTP transmits credentials in plaintext",
            "Look for outdated vsftpd, ProFTPD, or wu-ftpd versions",
        ],
    },
    22: {
        "service": "SSH",
        "risk": "Low",
        "hints": [
            "Check for weak SSH keys or default credentials",
            "Older OpenSSH versions may have known CVEs",
            "Disable password auth, use key-based authentication",
        ],
    },
    23: {
        "service": "Telnet",
        "risk": "High",
        "hints": [
            "Telnet sends everything in plaintext including passwords",
            "Should be replaced with SSH if at all possible",
            "Common on legacy network equipment",
        ],
    },
    25: {
        "service": "SMTP",
        "risk": "Medium",
        "hints": [
            "Open relay misconfiguration can be abused for spam",
            "Check for outdated mail server software",
            "Verify TLS/STARTTLS support",
        ],
    },
    53: {
        "service": "DNS",
        "risk": "Medium",
        "hints": [
            "Check for open DNS resolvers (amplification risk)",
            "Zone transfer (AXFR) may be allowed to anyone",
            "Older BIND versions have known CVEs",
        ],
    },
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "hints": [
            "Check for outdated web server (Apache, Nginx, IIS)",
            "Look for default pages revealing server version",
            "Verify HTTPS is available for sensitive pages",
        ],
    },
    110: {
        "service": "POP3",
        "risk": "Medium",
        "hints": [
            "POP3 transmits credentials in plaintext",
            "Prefer POP3S (port 995) or IMAPS (port 993)",
        ],
    },
    139: {
        "service": "NetBIOS",
        "risk": "High",
        "hints": [
            "Common attack vector on Windows networks",
            "Look for SMB / file-share enumeration opportunities",
            "Often paired with port 445",
        ],
    },
    143: {
        "service": "IMAP",
        "risk": "Medium",
        "hints": [
            "IMAP transmits credentials in plaintext",
            "Prefer IMAPS (port 993)",
        ],
    },
    161: {
        "service": "SNMP",
        "risk": "High",
        "hints": [
            "Default community string is often 'public'",
            "SNMPv1/v2 has no authentication",
            "Can leak huge amounts of system information",
        ],
    },
    389: {
        "service": "LDAP",
        "risk": "Medium",
        "hints": [
            "Anonymous bind may be enabled",
            "Prefer LDAPS (port 636) for credential protection",
        ],
    },
    443: {
        "service": "HTTPS",
        "risk": "Low",
        "hints": [
            "Check certificate validity and expiration",
            "Look for outdated TLS versions (SSLv3, TLS 1.0/1.1)",
            "Verify strong cipher suites are enforced",
        ],
    },
    445: {
        "service": "SMB",
        "risk": "High",
        "hints": [
            "Famous target of ransomware (WannaCry, NotPetya)",
            "EternalBlue (MS17-010) still found in the wild",
            "Disable SMBv1 and restrict access",
        ],
    },
    3306: {
        "service": "MySQL",
        "risk": "High",
        "hints": [
            "Should not be exposed to the internet",
            "Check for weak/default root passwords",
            "Verify it's not listening on 0.0.0.0",
        ],
    },
    3389: {
        "service": "RDP",
        "risk": "High",
        "hints": [
            "Major brute-force attack target",
            "BlueKeep (CVE-2019-0708) and similar CVEs",
            "Should be behind a VPN, not exposed publicly",
        ],
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "High",
        "hints": [
            "Should not be exposed to the internet",
            "Check default postgres user and weak passwords",
        ],
    },
    5900: {
        "service": "VNC",
        "risk": "High",
        "hints": [
            "Often protected with weak passwords",
            "Prefer running over SSH tunnel",
            "Many VNC versions have unencrypted traffic",
        ],
    },
    6379: {
        "service": "Redis",
        "risk": "Critical",
        "hints": [
            "Frequently deployed with NO authentication",
            "Can lead to full server compromise",
            "Should never be exposed to the internet",
        ],
    },
    27017: {
        "service": "MongoDB",
        "risk": "Critical",
        "hints": [
            "Many MongoDBs have been left open and ransomed",
            "Default install has NO authentication",
            "Bind to 127.0.0.1 and enable auth",
        ],
    },
}


import re

def parse_version_numbers(version_str):
    """Extract major, minor, patch numbers from a version string."""
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', version_str)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    return None


def check_version_vulns(port, service, parsed_version):
    """Check parsed version string against known outdated or vulnerable versions."""
    if not parsed_version:
        return []
        
    extra_hints = []
    
    # 1. SSH / OpenSSH
    if "ssh" in service.lower() or port == 22:
        if "openssh" in parsed_version.lower():
            nums = parse_version_numbers(parsed_version)
            if nums:
                major, minor, patch = nums
                # regreSSHion (CVE-2024-6387) affects OpenSSH < 4.4p1 and 8.5p1 <= OpenSSH < 9.8p1
                if (major < 9) or (major == 9 and minor < 8):
                    extra_hints.append(
                        "CRITICAL: Outdated OpenSSH version. May be vulnerable to RegreSSHion RCE (CVE-2024-6387). "
                        "Upgrade OpenSSH to 9.8p1 or newer immediately."
                    )
                    
    # 2. Apache
    elif "apache" in parsed_version.lower() or port in (80, 443, 8080):
        if "apache" in parsed_version.lower():
            nums = parse_version_numbers(parsed_version)
            if nums:
                major, minor, patch = nums
                if major < 2 or (major == 2 and minor < 4) or (major == 2 and minor == 4 and patch < 59):
                    extra_hints.append(
                        "HIGH: Outdated Apache HTTP Server version. "
                        "May be vulnerable to HTTP/2 DoS (CVE-2024-27316) and multiple CVEs. Upgrade to 2.4.59 or later."
                    )
                    
    # 3. Nginx
    elif "nginx" in parsed_version.lower() or port in (80, 443, 8080):
        if "nginx" in parsed_version.lower():
            nums = parse_version_numbers(parsed_version)
            if nums:
                major, minor, patch = nums
                if major < 1 or (major == 1 and minor < 26):
                    extra_hints.append(
                        "MEDIUM: Legacy Nginx version detected. Upgrade to Nginx 1.26+ stable for security support."
                    )
                    
    return extra_hints


def get_hint(port, parsed_version=None):
    """Return vulnerability hints for a given port, including version-based alerts."""
    base_hint = VULN_HINTS.get(port, {})
    if not base_hint:
        if parsed_version:
            from service_detect import detect_service
            service_name = detect_service(port)
            base_hint = {
                "service": service_name,
                "risk": "Low",
                "hints": []
            }
        else:
            return {}
            
    # Deep copy base hint
    result_hint = {
        "service": base_hint.get("service", "Unknown"),
        "risk": base_hint.get("risk", "Low"),
        "hints": list(base_hint.get("hints", []))
    }
    
    if parsed_version:
        extra = check_version_vulns(port, result_hint["service"], parsed_version)
        if extra:
            result_hint["hints"].extend(extra)
            # Upgrade risk level
            if any("CRITICAL" in h for h in extra):
                result_hint["risk"] = "Critical"
            elif any("HIGH" in h for h in extra):
                result_hint["risk"] = "High"
            elif any("MEDIUM" in h for h in extra) and result_hint["risk"] == "Low":
                result_hint["risk"] = "Medium"
                
    return result_hint

