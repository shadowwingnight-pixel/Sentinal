import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import psutil

from sentinal.monitor import Endpoint, collect_snapshot


def connection(**changes: object) -> SimpleNamespace:
    values = dict(family=socket.AF_INET, type=socket.SOCK_STREAM,
                  laddr=("127.0.0.1", 1234), raddr=("192.0.2.1", 443),
                  status="ESTABLISHED", pid=42)
    values.update(changes)
    return SimpleNamespace(**values)


class MonitorTests(unittest.TestCase):
    @patch("sentinal.monitor.psutil.Process")
    @patch("sentinal.monitor.psutil.net_connections")
    def test_ipv4_ipv6_tcp_udp_and_missing_addresses(self, net, process):
        net.return_value = [connection(), connection(
            family=socket.AF_INET6, type=socket.SOCK_DGRAM,
            laddr=("::", 5353), raddr=(), status="NONE", pid=None)]
        process.return_value.name.return_value = "example.exe"
        snapshot = collect_snapshot()
        net.assert_called_once_with(kind="inet")
        self.assertIsNotNone(snapshot.timestamp.utcoffset())
        self.assertIsNone(snapshot.warning)
        tcp, udp = snapshot.connections
        self.assertEqual(tcp.protocol, "TCP")
        self.assertEqual(tcp.local, Endpoint("127.0.0.1", 1234))
        self.assertEqual(tcp.remote, Endpoint("192.0.2.1", 443))
        self.assertEqual(tcp.status, "ESTABLISHED")
        self.assertEqual(tcp.pid, 42)
        self.assertEqual(tcp.process_name, "example.exe")
        self.assertEqual(udp.protocol, "UDP")
        self.assertEqual(udp.local, Endpoint("::", 5353))
        self.assertIsNone(udp.remote)
        self.assertIsNone(udp.pid)
        self.assertEqual(udp.process_name, "Unknown")
        process.assert_called_once_with(42)

    @patch("sentinal.monitor.psutil.net_connections", side_effect=psutil.AccessDenied())
    def test_enumeration_denied(self, net):
        snapshot = collect_snapshot()
        self.assertEqual(snapshot.connections, ())
        self.assertIn("Access denied", snapshot.warning)

    def test_process_failures_preserve_connection(self):
        for error, expected in [(psutil.AccessDenied(42), "Access denied"),
                                (psutil.NoSuchProcess(42), "Process exited"),
                                (psutil.ZombieProcess(42), "Zombie process")]:
            with self.subTest(error=type(error).__name__), \
                 patch("sentinal.monitor.psutil.net_connections", return_value=[connection()]), \
                 patch("sentinal.monitor.psutil.Process", side_effect=error):
                self.assertEqual(collect_snapshot().connections[0].process_name, expected)

    @patch("sentinal.monitor.psutil.Process")
    @patch("sentinal.monitor.psutil.net_connections", return_value=[connection(), connection(raddr=())])
    def test_names_cached_within_snapshot_only(self, net, process):
        process.return_value.name.side_effect = ["first.exe", "second.exe"]
        first = collect_snapshot()
        second = collect_snapshot()
        self.assertEqual(process.call_count, 2)
        self.assertTrue(all(row.process_name == "first.exe" for row in first.connections))
        self.assertTrue(all(row.process_name == "second.exe" for row in second.connections))

    @patch("sentinal.monitor.psutil.net_connections", return_value=[])
    def test_empty_snapshot(self, net):
        self.assertEqual(collect_snapshot().connections, ())

    @patch("sentinal.monitor.psutil.Process")
    @patch("sentinal.monitor.psutil.net_connections", return_value=[connection(pid=0, laddr=())])
    def test_pid_zero_and_missing_local(self, net, process):
        process.return_value.name.return_value = "System Idle Process"
        row = collect_snapshot().connections[0]
        self.assertEqual(row.pid, 0)
        self.assertIsNone(row.local)
        process.assert_called_once_with(0)
