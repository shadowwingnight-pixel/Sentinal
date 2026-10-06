from dataclasses import replace
import unittest
from unittest.mock import patch

from sentinal.events import EventTracker
from sentinal.notifications import NotificationGate, NotificationWorker
from sentinal.risk import RiskAssessment
from test_events import row, snapshot


def high_event():
    event = EventTracker().update(snapshot(row()))[0]
    return replace(event, risk=RiskAssessment(70, ()))


class NotificationTests(unittest.TestCase):
    def test_only_high_arrivals_and_no_duplicates(self):
        high = high_event()
        gate = NotificationGate()
        self.assertEqual(gate.select((high,), 0), (high,))
        self.assertEqual(gate.select((high,), 60), ())
        self.assertEqual(gate.select((replace(high, event_type="CLOSED"),), 90), ())
        self.assertEqual(gate.select((replace(high, risk=RiskAssessment(59, ())),), 90), ())

    def test_batching_cooldown_and_new_listener(self):
        first = high_event()
        second = replace(first, connection=replace(first.connection, pid=43), event_type="NEW_LISTENER")
        gate = NotificationGate()
        self.assertEqual(len(gate.select((first, second), 0)), 2)
        third = replace(second, connection=replace(second.connection, pid=44))
        self.assertEqual(gate.select((third,), 5), ())
        self.assertEqual(gate.select((third,), 40), ())
        fourth = replace(third, connection=replace(third.connection, pid=45))
        self.assertEqual(gate.select((fourth,), 40), (fourth,))

    def test_off_does_not_replay_old_alerts(self):
        gate = NotificationGate()
        gate.enabled = False
        high = high_event()
        self.assertEqual(gate.select((high,), 0), ())
        gate.enabled = True
        self.assertEqual(gate.select((high,), 60), ())

    def test_worker_shutdown_removes_icon(self):
        with patch("sentinal.notifications.WindowsNotifier.close") as close:
            worker = NotificationWorker(0)
            worker.close()
            worker._thread.join(timeout=1)
            self.assertFalse(worker.running)
            close.assert_called_once()
