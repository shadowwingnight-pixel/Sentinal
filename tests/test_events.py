from dataclasses import replace
from datetime import datetime, timezone
import unittest

from sentinal.events import EventTracker
from sentinal.monitor import Connection, Endpoint, Snapshot


def row() -> Connection:
    return Connection("TCP", Endpoint("192.168.1.2", 50000), Endpoint("8.8.8.8", 443),
                      "ESTABLISHED", 42, "browser.exe")


def snapshot(*rows: Connection, warning: str | None = None) -> Snapshot:
    return Snapshot(datetime.now(timezone.utc), tuple(rows), warning)


class EventTests(unittest.TestCase):
    def test_new_connection(self):
        events = EventTracker().update(snapshot(row()))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "NEW")
        self.assertEqual(events[0].service, "HTTPS")

    def test_closed_connection(self):
        tracker = EventTracker()
        tracker.update(snapshot(row()))
        events = tracker.update(snapshot())
        self.assertEqual(events[0].event_type, "CLOSED")
        self.assertEqual(events[0].connection, row())
        self.assertEqual(tracker.update(snapshot()), ())

    def test_new_listening_and_bound_sockets(self):
        tcp = replace(row(), remote=None, status="LISTEN", local=Endpoint("::", 443))
        udp = replace(tcp, protocol="UDP", status="NONE")
        events = EventTracker().update(snapshot(tcp, udp))
        self.assertEqual([event.event_type for event in events], ["NEW_LISTENER", "NEW_LISTENER"])

    def test_duplicate_rows_and_snapshots(self):
        tracker = EventTracker()
        self.assertEqual(len(tracker.update(snapshot(row(), row()))), 1)
        self.assertEqual(tracker.update(snapshot(row())), ())

    def test_name_and_lifecycle_changes_keep_identity_and_last_metadata(self):
        tracker = EventTracker()
        tracker.update(snapshot(row()))
        changed = replace(row(), process_name="Process exited", status="TIME_WAIT")
        self.assertEqual(tracker.update(snapshot(changed)), ())
        self.assertEqual(tracker.update(snapshot())[0].connection, changed)

    def test_distinct_pids_and_endpoints(self):
        tracker = EventTracker()
        rows = (row(), replace(row(), pid=43), replace(row(), remote=Endpoint("1.1.1.1", 443)),
                replace(row(), local=Endpoint("192.168.1.2", 50001)))
        self.assertEqual(len(tracker.update(snapshot(*rows))), 4)
        self.assertEqual(tracker.update(snapshot(*reversed(rows))), ())

    def test_failed_snapshot_preserves_baseline(self):
        tracker = EventTracker()
        tracker.update(snapshot(row()))
        self.assertEqual(tracker.update(snapshot(warning="Access denied")), ())
        self.assertEqual(tracker.update(snapshot(row())), ())

    def test_reappearance_is_new_activity(self):
        tracker = EventTracker()
        tracker.update(snapshot(row()))
        tracker.update(snapshot())
        self.assertEqual(tracker.update(snapshot(row()))[0].event_type, "NEW")
