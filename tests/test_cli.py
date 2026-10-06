from datetime import datetime, timezone
import io
import unittest
from unittest.mock import patch

from sentinal.cli import format_endpoint, format_snapshot, main
from sentinal.monitor import Connection, Endpoint, Snapshot


def snapshot(warning: str | None = None) -> Snapshot:
    return Snapshot(datetime(2026, 10, 6, tzinfo=timezone.utc), (), warning)


class CliTests(unittest.TestCase):
    def setUp(self):
        logger = patch("sentinal.cli.log_events", return_value=None)
        self.log_events = logger.start()
        self.addCleanup(logger.stop)

    def test_no_log_disables_history_in_every_mode(self):
        row = Connection("TCP", None, Endpoint("8.8.8.8", 4444), "ESTABLISHED", None, "Unknown")
        for mode in [[], ["--explain"], ["--events"], ["--alerts"]]:
            with self.subTest(mode=mode), \
                 patch("sentinal.cli.collect_snapshot", return_value=Snapshot(snapshot().timestamp, (row,))), \
                 patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(main(["--once", "--no-log", *mode]), 0)
        self.log_events.assert_not_called()

    def test_logging_precedes_display_filter(self):
        row = Connection("TCP", None, Endpoint("8.8.8.8", 443), "ESTABLISHED", 42, "browser.exe")
        with patch("sentinal.cli.collect_snapshot", return_value=Snapshot(snapshot().timestamp, (row,))), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--once", "--events", "--min-risk", "30"]), 0)
        self.assertEqual(len(self.log_events.call_args.args[0]), 1)
        self.assertNotIn("browser.exe", output.getvalue())

    def test_alerts_only_and_duplicates(self):
        rows = (Connection("TCP", None, Endpoint("8.8.8.8", 443), "ESTABLISHED", 42, "browser.exe"),
                Connection("TCP", None, Endpoint("8.8.8.8", 4444), "ESTABLISHED", None, "Unknown"))
        with patch("sentinal.cli.collect_snapshot", return_value=Snapshot(snapshot().timestamp, rows)), \
             patch("sentinal.cli.time.sleep", side_effect=[None, KeyboardInterrupt]), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--alerts"]), 0)
        self.assertNotIn("browser.exe", output.getvalue())
        self.assertEqual(output.getvalue().count("[WARNING]"), 1)
        self.log_events.assert_called_once()

    def test_logging_failure_does_not_abort_monitoring(self):
        row = Connection("TCP", None, Endpoint("8.8.8.8", 443), "ESTABLISHED", 42, "browser.exe")
        self.log_events.return_value = "Permission denied"
        with patch("sentinal.cli.collect_snapshot", return_value=Snapshot(snapshot().timestamp, (row,))), \
             patch("sys.stderr", new_callable=io.StringIO) as diagnostic, \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--once", "--events"]), 0)
        self.assertIn("Permission denied", diagnostic.getvalue())
        self.assertIn("[NEW]", output.getvalue())

    def test_invalid_risk_thresholds(self):
        for value in ["-1", "101", "abc", "3.5"]:
            with self.subTest(value=value), patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    main(["--min-risk", value])
                self.assertEqual(error.exception.code, 2)

    def test_threshold_is_inclusive_in_both_views(self):
        rows = (
            Connection("TCP", None, Endpoint("8.8.8.8", 443), "ESTABLISHED", 42, "browser.exe"),
            Connection("TCP", None, Endpoint("8.8.8.8", 443), "ESTABLISHED", None, "Unknown"),
        )
        for flags in [[], ["--explain"]]:
            with self.subTest(flags=flags), \
                 patch("sentinal.cli.collect_snapshot", return_value=Snapshot(snapshot().timestamp, rows)), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(main(["--once", "--min-risk", "30", *flags]), 0)
                self.assertNotIn("browser.exe", output.getvalue())
                self.assertIn("Unknown", output.getvalue())

    @patch("sentinal.cli.time.sleep", side_effect=[None, KeyboardInterrupt])
    @patch("sentinal.cli.collect_snapshot", return_value=snapshot())
    def test_unchanged_snapshots_are_suppressed(self, collect, sleep):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--explain"]), 0)
        self.assertEqual(output.getvalue().count("Sentinal Explain |"), 1)
        self.assertEqual(collect.call_count, 2)

    def test_endpoint_formats(self):
        self.assertEqual(format_endpoint(Endpoint("::1", 80)), "[::1]:80")
        self.assertEqual(format_endpoint(Endpoint("127.0.0.1", 0)), "127.0.0.1:0")
        self.assertEqual(format_endpoint(None), "-")

    def test_table_contains_all_fields_and_sanitizes_names(self):
        row = Connection("UDP", Endpoint("::", 53), None, "NONE", None, "bad\x1b\nname")
        output = format_snapshot(Snapshot(snapshot().timestamp, (row,)))
        for text in ["2026-10-06T00:00:00+00:00", "PROTOCOL", "LOCAL IP/PORT",
                     "REMOTE IP/PORT", "STATUS", "PID", "PROCESS", "[::]:53", "NONE", "bad??name"]:
            self.assertIn(text, output)
        self.assertNotIn("\x1b", output)

    def test_empty_and_denied_are_distinct(self):
        self.assertIn("No TCP/UDP connections found", format_snapshot(snapshot()))
        denied = format_snapshot(snapshot("Access denied"))
        self.assertIn("Warning: Access denied", denied)
        self.assertNotIn("No TCP/UDP", denied)

    @patch("sentinal.cli.time.sleep")
    @patch("sentinal.cli.collect_snapshot", return_value=snapshot())
    def test_once(self, collect, sleep):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--once"]), 0)
        self.assertIn("Sentinal", output.getvalue())
        collect.assert_called_once_with()
        sleep.assert_not_called()

    @patch("sentinal.cli.collect_snapshot", return_value=snapshot("Access denied"))
    def test_once_denied_exit_code(self, collect):
        with patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(["--once"]), 1)

    @patch("sentinal.cli.time.sleep", side_effect=[None, KeyboardInterrupt])
    @patch("sentinal.cli.collect_snapshot", side_effect=[snapshot("Access denied"), snapshot()])
    def test_refresh_recovers_from_denial_and_ctrl_c(self, collect, sleep):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main([]), 0)
        self.assertEqual(collect.call_count, 2)
        self.assertEqual([call.args for call in sleep.call_args_list], [(3,), (3,)])
        self.assertIn("Sentinal stopped", output.getvalue())

    @patch("sentinal.cli.collect_snapshot", side_effect=OSError("socket read failed"))
    def test_os_error_is_reported(self, collect):
        with patch("sys.stderr", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--once"]), 1)
        self.assertIn("socket read failed", output.getvalue())
