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
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, "GREEN")
        self.assertEqual(sum(reason.points for reason in result.reasons), result.score)

    def test_unfamiliar_public_ip_does_not_change_score(self):
        self.assertEqual(assess_connection(connection()), assess_connection(
            replace(connection(), remote=Endpoint("1.1.1.1", 443))))

    def test_unknown_process_and_uncommon_service(self):
        result = assess_connection(replace(connection(), pid=None, process_name="Unknown",
                                            remote=Endpoint("192.168.1.10", 4444)))
        self.assertEqual(result.score, 30)
        self.assertEqual([reason.points for reason in result.reasons], [20, 10])

    def test_public_unknown_service_and_unexpected_state(self):
        result = assess_connection(replace(connection(), process_name="Access denied",
                                            remote=Endpoint("8.8.8.8", 4444), status="INVALID"))
        self.assertEqual(result.score, 50)
        self.assertEqual(result.level, "YELLOW")
        self.assertEqual(sum(reason.points for reason in result.reasons), 50)

    def test_unresolved_process_markers(self):
        for name, expected in [("Unknown", 20), ("unknown process", 20), ("Access denied", 10),
                               ("Process exited", 5), ("Zombie process", 5), ("", 20)]:
            with self.subTest(name=name):
                self.assertEqual(assess_connection(replace(connection(), process_name=name)).score, expected)

    def test_listening_interfaces(self):
        for ip, points in [("127.0.0.1", 0), ("::1", 0), ("192.168.1.5", 0),
                           ("0.0.0.0", 10), ("::", 10), ("8.8.8.8", 20)]:
            with self.subTest(ip=ip):
                row = replace(connection(), local=Endpoint(ip, 443), remote=None, status="LISTEN")
                self.assertEqual(assess_connection(row).score, points)

    def test_udp_bound_socket_is_not_an_unknown_remote_service(self):
        row = replace(connection(), protocol="UDP", local=Endpoint("::", 54321), remote=None, status="NONE")
        self.assertEqual(assess_connection(row).score, 10)

    def test_windows_udp_service_bindings_are_low_priority(self):
        for name in ["svchost.exe", "System"]:
            for port in [123, 137, 1900, 2177, 5353, 5355]:
                for ip in ["0.0.0.0", "::", "8.8.8.8", "2606:4700:4700::1111"]:
                    row = replace(connection(), protocol="UDP", remote=None, status="NONE",
                                  process_name=name, local=Endpoint(ip, port))
                    result = assess_connection(row)
                    self.assertEqual(result.score, 5)
                    self.assertIn("not identity verification", result.reasons[0].description)

    def test_windows_rpc_and_smb_patterns(self):
        for name, port in [("svchost.exe", 135), ("svchost.exe", 49666), ("lsass.exe", 49664),
                           ("services.exe", 49684), ("System", 445)]:
            row = replace(connection(), remote=None, status="LISTEN", process_name=name,
                          local=Endpoint("0.0.0.0", port))
            self.assertEqual(assess_connection(row).score, 5)

    def test_system_name_is_not_a_blanket_exemption(self):
        row = replace(connection(), remote=None, status="LISTEN", process_name="svchost.exe",
                      local=Endpoint("8.8.8.8", 4444))
        self.assertEqual(assess_connection(row).score, 35)
        outbound = replace(connection(), process_name="svchost.exe", remote=Endpoint("8.8.8.8", 4444))
        self.assertEqual(assess_connection(outbound).score, 10)

    def test_unresolved_bind_and_state_still_accumulate_risk(self):
        row = replace(connection(), protocol="UDP", remote=None, status="INVALID", pid=None,
                      process_name="Unknown", local=Endpoint("0.0.0.0", 4444))
        self.assertEqual(assess_connection(row).score, 60)

    def test_udp_unknown_bind_alone_never_alerts(self):
        for ip in ["0.0.0.0", "8.8.8.8"]:
            row = replace(connection(), protocol="UDP", remote=None, status="NONE", local=Endpoint(ip, 54321))
            self.assertEqual(assess_connection(row).score, 10)

    def test_time_wait_attribution_race(self):
        row = replace(connection(), pid=None, process_name="Unknown", status="TIME_WAIT")
        self.assertEqual(assess_connection(row).score, 5)

    def test_ipv4_mapped_wildcard_exposure(self):
        row = replace(connection(), remote=None, status="LISTEN", local=Endpoint("::ffff:0.0.0.0", 443))
        self.assertEqual(assess_connection(row).score, 10)

    def test_normal_lifecycle_states(self):
        for state in ["SYN_SENT", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1"]:
            self.assertEqual(assess_connection(replace(connection(), status=state)).score, 0)

    def test_known_process_uncommon_outbound_is_normal_without_vendor_trust(self):
        for name in ["ChatGPT.exe", "chrome.exe", "arbitrary-app.exe", "svchost.exe"]:
            for port in [5228, 4444, 60000]:
                with self.subTest(name=name, port=port):
                    result = assess_connection(replace(connection(), process_name=name, remote=Endpoint("8.8.8.8", port)))
                    self.assertEqual(result.score, 10)
                    self.assertEqual(result.priority, "NORMAL")
                    self.assertEqual(result.confidence, "LOW")
                    self.assertEqual(len(result.reasons), 1)

    def test_public_destination_alone_has_no_points(self):
        for ip in ["127.0.0.1", "192.168.1.1", "8.8.8.8", "2606:4700:4700::1111"]:
            self.assertEqual(assess_connection(replace(connection(), remote=Endpoint(ip, 443))).reasons, ())

    def test_independent_indicators_reach_high(self):
        result = assess_connection(replace(connection(), process_name="Unknown", pid=None,
                                             remote=Endpoint("8.8.8.8", 4444), status="INVALID"))
        self.assertEqual(result.score, 60)
        self.assertEqual(result.priority, "HIGH")
        self.assertEqual(result.confidence, "HIGH")
        self.assertEqual([reason.points for reason in result.reasons], [20, 10, 30])

    def test_listener_exposure_is_distinct_from_outbound(self):
        listener = replace(connection(), remote=None, status="LISTEN", local=Endpoint("8.8.8.8", 4444))
        result = assess_connection(listener)
        self.assertEqual(result.score, 35)
        self.assertEqual(result.priority, "WARNING")
        self.assertEqual(result.confidence, "MEDIUM")
        self.assertEqual([reason.points for reason in result.reasons], [20, 15])
        self.assertEqual(assess_connection(replace(listener, process_name="Unknown", pid=None)).score, 55)
        self.assertEqual(assess_connection(replace(listener, local=Endpoint("127.0.0.1", 4444))).score, 0)
        self.assertEqual(assess_connection(replace(connection(), remote=Endpoint("8.8.8.8", 4444))).score, 10)

    def test_unknown_attribution_alone_does_not_warn(self):
        result = assess_connection(replace(connection(), pid=None, process_name="Unknown"))
        self.assertEqual(result.score, 20)
        self.assertEqual(result.priority, "NORMAL")
        combined = assess_connection(replace(connection(), pid=None, process_name="Unknown", remote=Endpoint("8.8.8.8", 5228)))
        self.assertEqual(combined.score, 30)
        self.assertEqual(combined.confidence, "MEDIUM")

    def test_confidence_is_not_a_malware_probability(self):
        normal = assess_connection(connection())
        self.assertEqual(normal.confidence, "LOW")
        self.assertEqual(normal.assessment, "No strong suspicious indicators were observed.")
        self.assertIn("not established", assess_connection(replace(connection(), status="INVALID")).assessment)

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
