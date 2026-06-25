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


def get_hint(port):
    """Return vulnerability hints for a given port, or empty dict."""
    return VULN_HINTS.get(port, {})
