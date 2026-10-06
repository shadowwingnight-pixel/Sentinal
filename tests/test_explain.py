from dataclasses import replace
import unittest

from sentinal.explain import explain_connection
from sentinal.monitor import Endpoint
from test_risk import connection


class ExplainTests(unittest.TestCase):
    def test_connected_service_and_exact_reasons(self):
        text = explain_connection(connection())
        for value in ["GREEN [0/100]", "msedge.exe (PID 42)", "INTERNET 8.8.8.8",
                      "HTTPS (443", "ESTABLISHED", "(+0)", "port-based hint", "Confidence: LOW"]:
            self.assertIn(value, text)

    def test_listener_has_no_invented_destination(self):
        text = explain_connection(replace(connection(), remote=None,
                                            local=Endpoint("::", 22), status="LISTEN"))
        self.assertIn("NO REMOTE", text)
        self.assertIn("is listening", text)
        self.assertIn("SSH (22", text)
        self.assertNotIn("is connected to", text)

    def test_pending_socket_does_not_claim_established_connection(self):
        text = explain_connection(replace(connection(), status="SYN_SENT"))
        self.assertIn("has a socket to", text)
        self.assertNotIn("is connected to", text)

    def test_no_points_and_sanitized_process(self):
        text = explain_connection(replace(connection(), remote=Endpoint("127.0.0.1", 443),
                                            process_name="bad\x1b\nname"))
        self.assertIn("GREEN [0/100]", text)
        self.assertIn("(+0)", text)
        self.assertIn("bad??name", text)
        self.assertNotIn("\x1b", text)
