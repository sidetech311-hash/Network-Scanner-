import unittest
import sys
from pathlib import Path

# Add project root to sys.path so we can import validation
sys.path.append(str(Path(__file__).parent.parent))

from validation import (
    validate_target,
    validate_port_range,
    validate_timeout,
    validate_max_threads,
    ValidationError
)


class TestValidation(unittest.TestCase):
    def test_validate_target_valid_ip(self):
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("8.8.8.8"), "8.8.8.8")
        self.assertEqual(validate_target("2001:db8::1"), "2001:db8::1")

    def test_validate_target_valid_hostname(self):
        self.assertEqual(validate_target("localhost"), "localhost")
        self.assertEqual(validate_target("google.com"), "google.com")
        self.assertEqual(validate_target("sub.domain-name.co.uk"), "sub.domain-name.co.uk")

    def test_validate_target_invalid(self):
        with self.assertRaises(ValidationError):
            validate_target("")
        with self.assertRaises(ValidationError):
            validate_target("invalid_name#@!")
        with self.assertRaises(ValidationError):
            validate_target("-host.com")
        with self.assertRaises(ValidationError):
            validate_target("a" * 256)

    def test_validate_port_range_valid(self):
        self.assertEqual(validate_port_range(1, 1024), (1, 1024))
        self.assertEqual(validate_port_range("80", "80"), (80, 80))

    def test_validate_port_range_invalid(self):
        with self.assertRaises(ValidationError):
            validate_port_range(0, 100)
        with self.assertRaises(ValidationError):
            validate_port_range(1, 70000)
        with self.assertRaises(ValidationError):
            validate_port_range(100, 80)  # start > end
        with self.assertRaises(ValidationError):
            validate_port_range("not_a_port", 80)
        with self.assertRaises(ValidationError):
            validate_port_range(1, 20000)  # range too large (> 10000)

    def test_validate_timeout(self):
        self.assertEqual(validate_timeout(1.5), 1.5)
        self.assertEqual(validate_timeout("2"), 2.0)
        with self.assertRaises(ValidationError):
            validate_timeout(0.05)  # too small
        with self.assertRaises(ValidationError):
            validate_timeout(35)  # too large
        with self.assertRaises(ValidationError):
            validate_timeout("abc")

    def test_validate_max_threads(self):
        self.assertEqual(validate_max_threads(100), 100)
        self.assertEqual(validate_max_threads("500"), 500)
        with self.assertRaises(ValidationError):
            validate_max_threads(0)
        with self.assertRaises(ValidationError):
            validate_max_threads(1001)
        with self.assertRaises(ValidationError):
            validate_max_threads("many")


if __name__ == "__main__":
    unittest.main()
