import tempfile
import unittest
from unittest.mock import patch

import system_check


class TestSystemCheck(unittest.TestCase):
    def test_check_import_positive(self):
        self.assertTrue(system_check._check_import("os"))

    def test_check_import_negative(self):
        self.assertFalse(system_check._check_import("definitely_not_a_real_module_12345"))

    def test_check_writeable_tmpdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, msg = system_check._check_writeable(tmp)
            self.assertTrue(ok)
            self.assertEqual(msg, "ok")

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    def test_check_dns_success(self, _mock_dns):
        ok, _msg = system_check._check_dns()
        self.assertTrue(ok)

    @patch("socket.gethostbyname", side_effect=OSError("dns fail"))
    def test_check_dns_failure(self, _mock_dns):
        ok, msg = system_check._check_dns()
        self.assertFalse(ok)
        self.assertIn("dns fail", msg)

    def test_check_python_version_returns_tuple(self):
        ok, ver = system_check._check_python_version()
        self.assertIsInstance(ok, bool)
        self.assertRegex(ver, r"^\d+\.\d+\.\d+$")

    @patch("system_check.os.system")
    @patch("system_check.shutil.which", side_effect=lambda name: "/usr/bin/" + name if name == "go" else None)
    @patch("system_check._check_dns", return_value=(True, "dns ok"))
    @patch("system_check._check_writeable", return_value=(True, "ok"))
    @patch("system_check._check_import", side_effect=lambda name: name in ("scapy", "requests", "colorama", "termcolor", "pyfiglet", "flask"))
    def test_run_system_check_non_interactive_summary(
        self,
        _mock_import,
        _mock_write,
        _mock_dns,
        _mock_which,
        _mock_system,
    ):
        summary = system_check.run_system_check(non_interactive=True)
        self.assertIn("required_missing", summary)
        self.assertIn("optional_missing", summary)
        self.assertIn("tools_missing", summary)
        self.assertTrue(summary["write_ok"])
        self.assertTrue(summary["dns_ok"])


if __name__ == "__main__":
    unittest.main()
