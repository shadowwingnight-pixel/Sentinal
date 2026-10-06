from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinal.events import EventTracker
from sentinal.logger import log_events
from sentinal.monitor import Endpoint
from test_events import row, snapshot


class LoggerTests(unittest.TestCase):
    def test_jsonl_schema_append_and_parent_creation(self):
        tracker = EventTracker()
        events = tracker.update(snapshot(replace(row(), process_name="Unknown\nname")))
        closed = tracker.update(snapshot())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs" / "events.jsonl"
            self.assertIsNone(log_events(events, path))
            self.assertIsNone(log_events(closed, path))
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["process_name"], "Unknown\nname")
        self.assertEqual(records[0]["local_endpoint"], {"ip": "192.168.1.2", "port": 50000})
        self.assertEqual(records[0]["remote_endpoint"], {"ip": "8.8.8.8", "port": 443})
        self.assertEqual(records[0]["service"], "HTTPS")
        self.assertEqual(records[1]["event_type"], "CLOSED")
        self.assertIsNone(records[1]["severity"])
        self.assertEqual(set(records[0]), {"timestamp", "event_type", "process_name", "pid",
                         "protocol", "local_endpoint", "remote_endpoint", "service",
                         "risk_score", "severity", "reasons"})

    def test_severity_and_structured_reasons(self):
        events = EventTracker().update(snapshot(replace(row(), process_name="Unknown", remote=Endpoint("8.8.8.8", 5228))))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log_events(events, path)
            record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["severity"], "WARNING")
        self.assertEqual(record["risk_score"], 30)
        self.assertEqual(sum(reason["points"] for reason in record["reasons"]), 30)

    def test_empty_batch_creates_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs" / "events.jsonl"
            self.assertIsNone(log_events((), path))
            self.assertFalse(path.parent.exists())

    def test_logging_failure_is_diagnostic(self):
        events = EventTracker().update(snapshot(row()))
        with patch("sentinal.logger.Path.open", side_effect=PermissionError("denied")), \
             patch("sentinal.logger.Path.mkdir"):
            self.assertIn("denied", log_events(events))
