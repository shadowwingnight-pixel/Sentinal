from dataclasses import replace
from queue import Empty
from threading import Event
import unittest
from unittest.mock import patch

from sentinal.dashboard import MonitorWorker, PollResult
from sentinal.gui import connection_values, risk_label
from test_events import row, snapshot


class DashboardTests(unittest.TestCase):
    def stop_worker(self, worker):
        worker.stop()
        if worker._thread:
            worker._thread.join(timeout=2)
        self.assertFalse(worker.running)

    def test_background_delivery_and_no_duplicate_worker(self):
        worker = MonitorWorker(interval=60)
        with patch("sentinal.dashboard.collect_snapshot", return_value=snapshot(row())), \
             patch("sentinal.dashboard.log_events", return_value=None) as logger:
            self.addCleanup(self.stop_worker, worker)
            self.assertTrue(worker.start())
            self.assertFalse(worker.start())
            result = worker.results.get(timeout=2)
            self.assertEqual(len(result.events), 1)
            logger.assert_called_once()

    def test_no_log_and_restart_preserve_baseline(self):
        worker = MonitorWorker(interval=60, logging=False)
        with patch("sentinal.dashboard.collect_snapshot", return_value=snapshot(row())), \
             patch("sentinal.dashboard.log_events") as logger:
            self.addCleanup(self.stop_worker, worker)
            worker.start()
            self.assertEqual(len(worker.results.get(timeout=2).events), 1)
            self.stop_worker(worker)
            self.assertTrue(worker.start())
            self.assertEqual(worker.results.get(timeout=2).events, ())
            logger.assert_not_called()

    def test_polling_failure_recovers(self):
        worker = MonitorWorker(interval=0.01, logging=False)
        with patch("sentinal.dashboard.collect_snapshot", side_effect=[OSError("read failed"), snapshot(row())]):
            self.addCleanup(self.stop_worker, worker)
            worker.start()
            failed = worker.results.get(timeout=2)
            self.assertIsNone(failed.snapshot)
            self.assertIn("read failed", failed.diagnostic)
            recovered = worker.results.get(timeout=2)
            self.assertIsNotNone(recovered.snapshot)
            worker.stop()

    def test_stop_during_blocked_collection_discards_result(self):
        entered, release = Event(), Event()
        def collect():
            entered.set()
            release.wait(timeout=2)
            return snapshot(row())
        worker = MonitorWorker(logging=False)
        with patch("sentinal.dashboard.collect_snapshot", side_effect=collect):
            worker.start()
            self.assertTrue(entered.wait(timeout=1))
            worker.stop()
            release.set()
            self.stop_worker(worker)
            with self.assertRaises(Empty):
                worker.results.get_nowait()

    def test_bounded_queue_stops_without_ui_consumer(self):
        worker = MonitorWorker(interval=0.001, logging=False)
        with patch("sentinal.dashboard.collect_snapshot", return_value=snapshot(row())):
            worker.start()
            self.assertLessEqual(worker.results.maxsize, 8)
            self.stop_worker(worker)

    def test_logging_diagnostic_delivered(self):
        worker = MonitorWorker(interval=60)
        with patch("sentinal.dashboard.collect_snapshot", return_value=snapshot(row())), \
             patch("sentinal.dashboard.log_events", return_value="History write denied"):
            self.addCleanup(self.stop_worker, worker)
            worker.start()
            self.assertEqual(worker.results.get(timeout=2).diagnostic, "History write denied")

    def test_gui_labels_and_values(self):
        for score, label in [(0, "NORMAL"), (29, "NORMAL"), (30, "WARNING"), (59, "WARNING"), (60, "HIGH"), (100, "HIGH")]:
            self.assertEqual(risk_label(score), label)
        values = connection_values(row())
        self.assertEqual(values[0], "browser.exe")
        self.assertEqual(values[1], "8.8.8.8:443")
        self.assertEqual(values[2], "HTTPS")
        self.assertEqual(values[4], "NORMAL  0/100")
        self.assertIn("Bound:", connection_values(replace(row(), remote=None, status="LISTEN"))[1])

    def test_restart_discards_old_display_updates(self):
        worker = MonitorWorker(interval=60, logging=False)
        worker.results.put(PollResult(None, diagnostic="Old run"))
        with patch("sentinal.dashboard.collect_snapshot", return_value=snapshot(row())):
            self.addCleanup(self.stop_worker, worker)
            worker.start()
            self.assertIsNotNone(worker.results.get(timeout=2).snapshot)
