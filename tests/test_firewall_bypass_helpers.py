import unittest

from ss7 import firewall_bypass


class TestFirewallBypassHelpers(unittest.TestCase):
    def test_is_valid_ip(self):
        self.assertTrue(firewall_bypass._is_valid_ip("127.0.0.1"))
        self.assertTrue(firewall_bypass._is_valid_ip("8.8.8.8"))
        self.assertFalse(firewall_bypass._is_valid_ip("999.999.1.1"))
        self.assertFalse(firewall_bypass._is_valid_ip("not-an-ip"))

    def test_optional_import(self):
        self.assertIsNotNone(firewall_bypass._optional_import("json"))
        self.assertIsNone(firewall_bypass._optional_import("module_does_not_exist_123"))

    def test_crc32c_deterministic(self):
        data = b"sigploit-test-data"
        crc_1 = firewall_bypass._crc32c(data)
        crc_2 = firewall_bypass._crc32c(data)
        self.assertEqual(crc_1, crc_2)
        self.assertIsInstance(crc_1, int)
        self.assertGreaterEqual(crc_1, 0)
        self.assertLessEqual(crc_1, 0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
