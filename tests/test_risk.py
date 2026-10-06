from dataclasses import replace
import unittest

from sentinal.monitor import Connection, Endpoint
from sentinal.risk import RiskAssessment, assess_connection, classify_destination, service_name


def connection() -> Connection:
    return Connection("TCP", Endpoint("192.168.1.5", 50000),
                      Endpoint("8.8.8.8", 443), "ESTABLISHED", 42, "msedge.exe")


class RiskTests(unittest.TestCase):
    def test_common_internet_connection(self):
        result = assess_connection(connection())
        self.assertEqual(result.score, 10)
        self.assertEqual(result.level, "GREEN")
        self.assertEqual(sum(reason.points for reason in result.reasons), result.score)

    def test_unfamiliar_public_ip_does_not_change_score(self):
        self.assertEqual(assess_connection(connection()), assess_connection(
            replace(connection(), remote=Endpoint("1.1.1.1", 443))))

    def test_unknown_process_and_uncommon_service(self):
        result = assess_connection(replace(connection(), pid=None, process_name="Unknown",
                                            remote=Endpoint("192.168.1.10", 4444)))
        self.assertEqual(result.score, 40)
        self.assertEqual([reason.points for reason in result.reasons], [20, 20])

    def test_public_unknown_service_and_unexpected_state(self):
        result = assess_connection(replace(connection(), process_name="Access denied",
                                            remote=Endpoint("8.8.8.8", 4444), status="INVALID"))
        self.assertEqual(result.score, 70)
        self.assertEqual(result.level, "RED")
        self.assertEqual(sum(reason.points for reason in result.reasons), 70)

    def test_unresolved_process_markers(self):
        for name in ["Unknown", "unknown process", "Access denied", "Process exited", "Zombie process", ""]:
            with self.subTest(name=name):
                self.assertEqual(assess_connection(replace(connection(), process_name=name)).score, 30)

    def test_listening_interfaces(self):
        for ip, points in [("127.0.0.1", 0), ("::1", 0), ("192.168.1.5", 0),
                           ("0.0.0.0", 20), ("::", 20), ("8.8.8.8", 30)]:
            with self.subTest(ip=ip):
                row = replace(connection(), local=Endpoint(ip, 443), remote=None, status="LISTEN")
                self.assertEqual(assess_connection(row).score, points)

    def test_udp_bound_socket_is_not_an_unknown_remote_service(self):
        row = replace(connection(), protocol="UDP", local=Endpoint("::", 54321), remote=None, status="NONE")
        self.assertEqual(assess_connection(row).score, 20)

    def test_normal_lifecycle_states(self):
        for state in ["SYN_SENT", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1"]:
            self.assertEqual(assess_connection(replace(connection(), status=state)).score, 10)

    def test_level_boundaries(self):
        for score, level in [(0, "GREEN"), (29, "GREEN"), (30, "YELLOW"),
                             (59, "YELLOW"), (60, "RED"), (100, "RED")]:
            self.assertEqual(RiskAssessment(score, ()).level, level)

    def test_address_scopes(self):
        for ip in ["127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1", "::1",
                   "fe80::1%4", "fc00::1", "::ffff:192.168.1.1", "100.64.0.1", "224.0.0.1"]:
            self.assertEqual(classify_destination(ip), "LOCAL", ip)
        for ip in ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"]:
            self.assertEqual(classify_destination(ip), "INTERNET", ip)
        self.assertEqual(classify_destination(None), "NO REMOTE")
        self.assertEqual(classify_destination("invalid"), "UNKNOWN")

    def test_service_hints_are_protocol_specific(self):
        for port, name in {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
                           25: "SMTP", 465: "SMTP", 587: "SMTP", 110: "POP3",
                           995: "POP3", 143: "IMAP", 993: "IMAP", 3389: "RDP"}.items():
            self.assertEqual(service_name("TCP", port), name)
        self.assertEqual(service_name("UDP", 53), "DNS")
        self.assertIsNone(service_name("UDP", 22))
        self.assertIsNone(service_name("TCP", 4444))
