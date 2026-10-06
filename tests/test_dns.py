import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinal.dns import DNSResolver, reverse_lookup


class DNSTests(unittest.TestCase):
    def stop(self, resolver):
        resolver.close()
        resolver._thread.join(timeout=3)
        self.assertFalse(resolver.running)

    def wait_for_cache(self, resolver, ip):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            with resolver._lock:
                if ip in resolver._cache:
                    return
            time.sleep(0.005)
        self.fail("DNS result not cached")

    def test_success_timeout_and_invalid_fallback(self):
        with patch("sentinal.dns.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="dns.google\n")) as run:
            self.assertEqual(reverse_lookup("8.8.8.8"), "dns.google")
            self.assertEqual(run.call_args.kwargs["timeout"], 2)
            self.assertNotIn("shell", run.call_args.kwargs)
        with patch("sentinal.dns.subprocess.run", side_effect=subprocess.TimeoutExpired("lookup", 2)):
            self.assertIsNone(reverse_lookup("8.8.8.8"))
        with patch("sentinal.dns.subprocess.run") as run:
            self.assertIsNone(reverse_lookup("invalid;command"))
            run.assert_not_called()

    def test_failed_or_control_hostname_fallback(self):
        for status, value in [(1, ""), (0, "bad\nname"), (0, "bad\x1bname")]:
            with patch("sentinal.dns.subprocess.run", return_value=SimpleNamespace(returncode=status, stdout=value)):
                self.assertIsNone(reverse_lookup("8.8.8.8"))

    def test_positive_cache_and_duplicate_requests(self):
        with patch("sentinal.dns.reverse_lookup", return_value="dns.google") as lookup:
            resolver = DNSResolver()
            self.addCleanup(self.stop, resolver)
            resolver.get("8.8.8.8")
            self.wait_for_cache(resolver, "8.8.8.8")
            for _ in range(20):
                self.assertEqual(resolver.get("8.8.8.8"), "dns.google")
            lookup.assert_called_once()
            self.stop(resolver)

    def test_negative_cache_and_expiry(self):
        with patch("sentinal.dns.reverse_lookup", return_value=None) as lookup:
            resolver = DNSResolver()
            self.addCleanup(self.stop, resolver)
            resolver.get("8.8.8.8")
            self.wait_for_cache(resolver, "8.8.8.8")
            self.assertIsNone(resolver.get("8.8.8.8"))
            lookup.assert_called_once()
            with resolver._lock:
                resolver._cache["8.8.8.8"] = (0, None)
            resolver.get("8.8.8.8")
            deadline = time.monotonic() + 1
            while lookup.call_count < 2 and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(lookup.call_count, 2)
            self.stop(resolver)

    def test_bounded_cache_and_no_requests_after_close(self):
        with patch("sentinal.dns.reverse_lookup", return_value=None):
            resolver = DNSResolver(capacity=2)
            self.addCleanup(self.stop, resolver)
            for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
                resolver.get(ip)
                self.wait_for_cache(resolver, ip)
            self.assertEqual(len(resolver._cache), 2)
            self.stop(resolver)
            resolver.get("4.4.4.4")
            self.assertNotIn("4.4.4.4", resolver._pending)
