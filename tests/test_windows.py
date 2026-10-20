import unittest
from unittest.mock import patch

from globalban.windows import windows_executable_path


class WindowsExecutablePathTests(unittest.TestCase):
    def test_resolves_netsh_from_windows_system_directory(self):
        with patch(
            "globalban.windows._get_windows_system_directory",
            return_value=r"C:\Windows\System32",
        ):
            self.assertEqual(
                windows_executable_path("netsh"),
                r"C:\Windows\System32\netsh.exe",
            )

    def test_resolves_powershell_from_windows_system_directory(self):
        with patch(
            "globalban.windows._get_windows_system_directory",
            return_value=r"C:\Windows\System32",
        ):
            self.assertEqual(
                windows_executable_path("powershell.exe"),
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            )

    def test_rejects_non_absolute_system_directory(self):
        with patch(
            "globalban.windows._get_windows_system_directory",
            return_value=r"Windows\System32",
        ):
            with self.assertRaisesRegex(OSError, "non-absolute"):
                windows_executable_path("netsh")


if __name__ == "__main__":
    unittest.main()
