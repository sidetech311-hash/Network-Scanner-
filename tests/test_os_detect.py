import unittest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from os_detect import get_ttl, ttl_to_os, detect_os


class TestOsDetect(unittest.TestCase):
    def test_ttl_to_os_mapping(self):
        self.assertEqual(ttl_to_os(64), "Linux/Unix/macOS (TTL ~64)")
        self.assertEqual(ttl_to_os(128), "Windows (TTL ~128)")
        self.assertEqual(ttl_to_os(255), "Network Device / Older OS (TTL ~255)")
        self.assertEqual(ttl_to_os(None), "Unknown")
        self.assertEqual(ttl_to_os(300), "Unknown")

    @patch("subprocess.check_output")
    def test_get_ttl_linux_mock(self, mock_ping):
        # Simulate Linux/macOS ping response
        mock_ping.return_value = (
            "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
            "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n"
        )
        # Call get_ttl
        ttl = get_ttl("127.0.0.1")
        self.assertEqual(ttl, 64)

    @patch("subprocess.check_output")
    def test_get_ttl_windows_mock(self, mock_ping):
        # Simulate Windows ping response
        mock_ping.return_value = (
            "\nPinging 127.0.0.1 with 32 bytes of data:\n"
            "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128\n"
        )
        # Call get_ttl
        ttl = get_ttl("127.0.0.1")
        self.assertEqual(ttl, 128)

    @patch("subprocess.check_output")
    def test_get_ttl_failure(self, mock_ping):
        # Simulate subprocess failure (host unreachable or timeout)
        mock_ping.side_effect = subprocess.CalledProcessError(1, "ping")
        ttl = get_ttl("192.0.2.1")
        self.assertIsNone(ttl)

    @patch("os_detect.get_ttl")
    def test_detect_os_fallback(self, mock_get_ttl):
        # When get_ttl fails (returns None), it should fall back to local platform name
        mock_get_ttl.return_value = None
        os_info = detect_os("8.8.8.8")
        self.assertTrue("Unknown (Local Platform:" in os_info)


if __name__ == "__main__":
    unittest.main()
