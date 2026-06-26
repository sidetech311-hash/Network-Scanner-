"""
Unit tests for the advanced security upgrades in the Network Scanner toolkit.
"""

import unittest
from unittest.mock import MagicMock, patch
import matplotlib.pyplot as plt
import datetime

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from cve_mapper import parse_banner, get_offline_cves, get_online_cves, lookup_cves
from ssl_auditor import audit_ssl_tls
from dir_buster import check_path, bust_directory
from subnet_map import draw_topology_map


class TestCVEVulnerabilityMapper(unittest.TestCase):
    def test_banner_parsing(self):
        # Verify accurate regex product/version extractions
        self.assertEqual(parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"), ("openssh", "8.9p1"))
        self.assertEqual(parse_banner("Apache/2.4.49 (Unix) OpenSSL/1.1.1d"), ("apache", "2.4.49"))
        self.assertEqual(parse_banner("nginx/1.17.10"), ("nginx", "1.17.10"))
        self.assertEqual(parse_banner("vsFTPd 2.3.4"), ("vsftpd", "2.3.4"))
        
    def test_offline_cve_heuristics(self):
        # Verify offline mapping of known critical CVEs
        cves_openssh = get_offline_cves("openssh", "8.9p1")
        self.assertTrue(any(c["id"] == "CVE-2024-6387" for c in cves_openssh)) # RegreSSHion
        
        cves_vsftpd = get_offline_cves("vsftpd", "2.3.4")
        self.assertTrue(any(c["id"] == "CVE-2011-2523" for c in cves_vsftpd)) # Backdoor
        
        cves_apache = get_offline_cves("apache", "2.4.49")
        self.assertTrue(any(c["id"] == "CVE-2021-41773" for c in cves_apache)) # Path traversal / RCE

    @patch("requests.get")
    def test_online_cve_fallback(self, mock_get):
        # Mock successful circl.lu CVE API search response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "CVE-2022-9999",
                "cvss": 9.8,
                "summary": "Mock vulnerability for nginx version 1.15.5",
                "vulnerable_configuration": ["cpe:2.3:a:f5:nginx:1.15.5:*:*:*:*:*:*:*"]
            }
        ]
        mock_get.return_value = mock_response
        
        cves = get_online_cves("nginx", "1.15.5")
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["id"], "CVE-2022-9999")
        self.assertEqual(cves[0]["severity"], "Critical")


class TestDirectoryBuster(unittest.TestCase):
    @patch("requests.head")
    def test_check_path_found(self, mock_head):
        # Mock a successful HEAD probe (status 200)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response
        
        res = check_path("http://localhost", "/.env", "Environment Config")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["path"], "/.env")

    @patch("requests.head")
    def test_check_path_not_found(self, mock_head):
        # Mock a 404 response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_head.return_value = mock_response
        
        res = check_path("http://localhost", "/invalid-path", "Fake")
        self.assertIsNone(res)


class TestSSLAuditor(unittest.TestCase):
    @patch("socket.socket")
    def test_ssl_audit_connection_error(self, mock_socket):
        # Verify auditor handles connection failure gracefully
        mock_socket.side_effect = Exception("Connection refused")
        res = audit_ssl_tls("invalid-host", port=443)
        self.assertFalse(res["connected"])
        self.assertIn("Connection refused", res["error"])


class TestSubnetTopologyVisualizer(unittest.TestCase):
    def test_draw_topology_map(self):
        # Verify a visual matplotlib figure is successfully returned
        live_hosts = [
            {"ip": "192.168.1.1", "hostname": "GatewayRouter"},
            {"ip": "192.168.1.5", "hostname": "Workstation"},
            {"ip": "192.168.1.10", "hostname": "Fileserver"}
        ]
        fig = draw_topology_map(live_hosts, "192.168.1.0/24")
        self.assertIsInstance(fig, plt.Figure)
        plt.close(fig)


if __name__ == "__main__":
    unittest.main()
