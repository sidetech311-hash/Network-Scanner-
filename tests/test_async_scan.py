import unittest
import asyncio
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from scanner import scan_port_async, NetworkScanner


class TestAsyncScan(unittest.TestCase):
    @patch("asyncio.open_connection")
    def test_scan_port_async_open(self, mock_open):
        mock_writer = MagicMock()
        mock_reader = MagicMock()
        mock_open.return_value = (mock_reader, mock_writer)
        
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(scan_port_async("127.0.0.1", 80, 1.0))
            self.assertIsNotNone(res)
            self.assertEqual(res["port"], 80)
            self.assertEqual(res["state"], "open")
        finally:
            loop.close()

    @patch("asyncio.open_connection")
    def test_scan_port_async_closed(self, mock_open):
        mock_open.side_effect = ConnectionRefusedError()
        
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(scan_port_async("127.0.0.1", 81, 1.0))
            self.assertIsNotNone(res)
            self.assertEqual(res["state"], "closed")
        finally:
            loop.close()

    @patch("asyncio.open_connection")
    def test_scan_port_async_timeout(self, mock_open):
        mock_open.side_effect = asyncio.TimeoutError()
        
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(scan_port_async("127.0.0.1", 80, 0.1))
            self.assertIsNotNone(res)
            self.assertEqual(res["state"], "closed")
        finally:
            loop.close()


if __name__ == "__main__":
    unittest.main()
