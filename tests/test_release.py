from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinal.dns import reverse_lookup
from sentinal.release import main


class ReleaseTests(unittest.TestCase):
    def test_frozen_dns_uses_helper_dispatch_without_starting_gui(self):
        def run(arguments, **options):
            self.assertEqual(arguments[1:3], ["--sentinal-resolve", "8.8.8.8"])
            self.assertEqual(options["timeout"], 2)
            Path(arguments[3]).write_text("dns.google", encoding="utf-8")
            return SimpleNamespace(returncode=0)
        with patch("sentinal.dns.sys.frozen", True, create=True), \
             patch("sentinal.dns.subprocess.run", side_effect=run):
            self.assertEqual(reverse_lookup("8.8.8.8"), "dns.google")

    def test_release_resolver_returns_only_hostname(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hostname.txt"
            with patch("sentinal.release.sys.argv", ["Sentinal.exe", "--sentinal-resolve", "8.8.8.8", str(output)]), \
                 patch("sentinal.release.socket.gethostbyaddr", return_value=("dns.google", [], [])):
                main()
            self.assertEqual(output.read_text(encoding="utf-8"), "dns.google")

    def test_release_resolver_failure_returns_empty_hostname(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hostname.txt"
            with patch("sentinal.release.sys.argv", ["Sentinal.exe", "--sentinal-resolve", "8.8.8.8", str(output)]), \
                 patch("sentinal.release.socket.gethostbyaddr", side_effect=OSError("no PTR")):
                main()
            self.assertEqual(output.read_text(encoding="utf-8"), "")
