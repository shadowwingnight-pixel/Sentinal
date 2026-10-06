from dataclasses import replace
import unittest

from sentinal.alerts import alert_severity, format_event, risk_severity
from sentinal.events import EventTracker
from sentinal.risk import RiskAssessment
from test_events import row, snapshot


class AlertTests(unittest.TestCase):
    def test_thresholds(self):
        event = EventTracker().update(snapshot(row()))[0]
        for score, severity in [(0, None), (29, None), (30, "WARNING"), (59, "WARNING"),
                                (60, "HIGH"), (100, "HIGH")]:
            with self.subTest(score=score):
                self.assertEqual(risk_severity(score), severity)
                changed = replace(event, risk=RiskAssessment(score, ()))
                self.assertEqual(alert_severity(changed), severity)
                self.assertEqual(alert_severity(replace(changed, event_type="NEW_LISTENER")), severity)
                self.assertIsNone(alert_severity(replace(changed, event_type="CLOSED")))

    def test_warning_wording(self):
        event = EventTracker().update(snapshot(replace(row(), process_name="Unknown")))[0]
        text = format_event(event, alert_only=True)
        self.assertIn("[WARNING]", text)
        self.assertIn("Potentially unusual network activity detected.", text)
        self.assertIn("(+20)", text)

    def test_closed_details_are_last_observation(self):
        tracker = EventTracker()
        tracker.update(snapshot(row()))
        text = format_event(tracker.update(snapshot())[0])
        self.assertIn("[CLOSED]", text)
        self.assertIn("last observation", text)
        self.assertNotIn("Potentially unusual", text)
