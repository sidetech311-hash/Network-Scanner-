import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from ssh_audit import SSHAuditor


class TestSSHAudit(unittest.TestCase):
    def test_generate_warnings_openssh_vuln(self):
        auditor = SSHAuditor("192.168.1.100")
        results = {
            "packages": [{"name": "openssh-server", "version": "8.2p1-4ubuntu0.5"}],
            "listening_ports": [],
            "warnings": []
        }
        auditor._generate_warnings(results)
        self.assertEqual(len(results["warnings"]), 1)
        self.assertIn("RegreSSHion", results["warnings"][0])

    def test_generate_warnings_openssh_safe(self):
        auditor = SSHAuditor("192.168.1.100")
        results = {
            "packages": [{"name": "openssh-server", "version": "9.8p1-1"}],
            "listening_ports": [],
            "warnings": []
        }
        auditor._generate_warnings(results)
        self.assertEqual(len(results["warnings"]), 0)

    def test_generate_warnings_bash_shellshock(self):
        auditor = SSHAuditor("192.168.1.100")
        results = {
            "packages": [{"name": "bash", "version": "3.1-4ubuntu1"}],
            "listening_ports": [],
            "warnings": []
        }
        auditor._generate_warnings(results)
        self.assertEqual(len(results["warnings"]), 1)
        self.assertIn("Shellshock", results["warnings"][0])

    def test_generate_warnings_openssl_legacy(self):
        auditor = SSHAuditor("192.168.1.100")
        results = {
            "packages": [{"name": "openssl", "version": "1.0.2g-1ubuntu4.20"}],
            "listening_ports": [],
            "warnings": []
        }
        auditor._generate_warnings(results)
        self.assertEqual(len(results["warnings"]), 1)
        self.assertIn("outdated openssl", results["warnings"][0].lower())

    def test_generate_warnings_database_wildcard(self):
        auditor = SSHAuditor("192.168.1.100")
        results = {
            "packages": [],
            "listening_ports": [{
                "protocol": "TCP",
                "port": "3306",
                "address": "0.0.0.0:3306",
                "process": "mysqld"
            }],
            "warnings": []
        }
        auditor._generate_warnings(results)
        self.assertEqual(len(results["warnings"]), 1)
        self.assertIn("wildcard interface", results["warnings"][0])


if __name__ == "__main__":
    unittest.main()
