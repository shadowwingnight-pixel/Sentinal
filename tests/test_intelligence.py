from dataclasses import replace
import unittest

from sentinal.intelligence import ActivityHistory, destination_scope, filter_connections, prepare_connection, sort_connections
from sentinal.monitor import Endpoint
from test_events import row


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.normal = prepare_connection(row())
        self.warning = prepare_connection(replace(row(), process_name="Unknown"))
        self.high = prepare_connection(replace(row(), process_name="Unknown", status="INVALID", remote=Endpoint("8.8.8.8", 4444)))
        self.entries = (self.normal, self.high, self.warning)

    def test_search_fields_and_case(self):
        for query in ["BROWSER", "8.8.8.8", "443", "HTTPS", "browser 443", "50000"]:
            self.assertIn(self.normal, filter_connections(self.entries, query))
        self.assertEqual(filter_connections(self.entries, "not-present"), [])

    def test_hostname_search(self):
        self.assertEqual(len(filter_connections(self.entries, "dns.google", hostnames={"8.8.8.8": "dns.google"})), 3)

    def test_level_filters(self):
        for name, expected in [("Normal", [self.normal]), ("Warning", [self.warning]), ("High Risk", [self.high])]:
            self.assertEqual(filter_connections(self.entries, level=name), expected)
        self.assertEqual(len(filter_connections(self.entries)), 3)

    def test_risk_sort_is_numeric_highest_first(self):
        ordered = sort_connections(list(self.entries))
        self.assertEqual([entry.risk.score for entry in ordered], [70, 30, 10])
        self.assertEqual(sort_connections(list(self.entries), descending=False)[0], self.normal)

    def test_header_sorting(self):
        for column in ["Process", "Destination", "Service", "Status", "Risk"]:
            self.assertEqual(len(sort_connections(list(self.entries), column, False)), 3)
        self.assertEqual(sort_connections(list(self.entries), "Process", False)[0], self.normal)

    def test_routine_windows_noise_only(self):
        routine = prepare_connection(replace(row(), protocol="UDP", status="NONE", remote=None,
                                              process_name="svchost.exe", local=Endpoint("::", 5353)))
        outbound = prepare_connection(replace(row(), process_name="svchost.exe"))
        suspicious = prepare_connection(replace(routine.connection, status="INVALID", pid=None))
        self.assertTrue(routine.routine)
        self.assertEqual(filter_connections((routine, outbound, suspicious), hide_routine=True), [outbound, suspicious])

    def test_destination_scopes(self):
        for ip, scope in [("127.0.0.1", "Loopback"), ("::1", "Loopback"), ("::ffff:127.0.0.1", "Loopback"),
                          ("192.168.1.1", "LAN / non-public"), ("fe80::1%4", "LAN / non-public"),
                          ("8.8.8.8", "Internet"), ("invalid", "Unknown scope")]:
            self.assertEqual(destination_scope(ip), scope)

    def test_intelligence_detail_sections_and_reasons(self):
        for text in ["Process:", "PID:", "Connection:", "Service:", "State:", "Risk:",
                     "What is happening?", "Why this score?", "(+20)"]:
            self.assertIn(text, self.high.detail)

    def test_activity_counts_and_window(self):
        activity = ActivityHistory()
        activity.add(0, 100, 3)
        activity.add(30, 200, 5)
        activity.add(60, 150, 2)
        self.assertEqual(activity.totals(60), (150, 10))
        self.assertEqual(activity.totals(61), (150, 7))
        self.assertEqual(activity.totals(121), (0, 0))

    def test_500_connection_filter_and_sort(self):
        entries = tuple(prepare_connection(replace(row(), pid=index, local=Endpoint("192.168.1.2", 50000+index))) for index in range(550))
        self.assertEqual(len(sort_connections(filter_connections(entries, "HTTPS"))), 550)
