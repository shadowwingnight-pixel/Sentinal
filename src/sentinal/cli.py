"""Text interface for local connection snapshots."""

import argparse
import sys
import time
from collections.abc import Sequence

from .monitor import Endpoint, Snapshot, collect_snapshot
from .explain import format_explain_snapshot
from .risk import assess_connection
from .events import EventTracker
from .alerts import alert_severity, format_event
from .logger import log_events

REFRESH_SECONDS = 3


def format_endpoint(endpoint: Endpoint | None) -> str:
    if endpoint is None:
        return "-"
    ip = f"[{endpoint.ip}]" if ":" in endpoint.ip else endpoint.ip
    return f"{ip}:{endpoint.port}"


def _safe_text(value: str) -> str:
    """Prevent control characters in process names from affecting terminals."""
    return "".join(character if character.isprintable() else "?" for character in value)


def format_snapshot(snapshot: Snapshot) -> str:
    lines = [f"Sentinal | {snapshot.timestamp.isoformat(timespec='seconds')}"]
    if snapshot.warning:
        lines.append(f"Warning: {snapshot.warning}")
        return "\n".join(lines)
    rows = [["PROTOCOL", "LOCAL IP/PORT", "REMOTE IP/PORT", "STATUS", "PID", "PROCESS"]]
    for connection in snapshot.connections:
        rows.append([
            connection.protocol, format_endpoint(connection.local),
            format_endpoint(connection.remote), connection.status,
            str(connection.pid) if connection.pid is not None else "-",
            _safe_text(connection.process_name),
        ])
    widths = [max(len(row[index]) for row in rows) for index in range(6)]
    lines.extend("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip()
                 for row in rows)
    if not snapshot.connections:
        lines.append("No TCP/UDP connections found.")
    return "\n".join(lines)


def _risk_threshold(value: str) -> int:
    try:
        threshold = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Risk threshold must be an integer from 0 to 100.") from error
    if not 0 <= threshold <= 100:
        raise argparse.ArgumentTypeError("Risk threshold must be from 0 to 100.")
    return threshold


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Monitor local TCP/UDP connections every 3 seconds.")
    parser.add_argument("--once", action="store_true", help="Print a single snapshot and exit.")
    parser.add_argument("--explain", action="store_true", help="Show explanations and transparent risk scores.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--events", action="store_true", help="Show newly observed and disappeared sockets.")
    modes.add_argument("--alerts", action="store_true", help="Show only new activity with risk >=30.")
    parser.add_argument("--no-log", action="store_true", help="Disable local JSONL event history.")
    parser.add_argument("--min-risk", type=_risk_threshold, default=0,
                        metavar="N", help="Hide connections scoring below N (0-100), in either view.")
    args = parser.parse_args(argv)
    previous: tuple[frozenset, str | None] | None = None
    tracker = EventTracker()
    last_log_error: str | None = None
    last_monitor_warning: str | None = None
    try:
        while True:
            snapshot = collect_snapshot()
            events = tracker.update(snapshot)
            if not args.no_log and events:
                log_error = log_events(events)
                if log_error and log_error != last_log_error:
                    print(f"Sentinal: {log_error}", file=sys.stderr)
                last_log_error = log_error
            visible = Snapshot(snapshot.timestamp, tuple(
                connection for connection in snapshot.connections
                if assess_connection(connection).score >= args.min_risk
            ), snapshot.warning)
            signature = (frozenset(visible.connections), visible.warning)
            if args.events or args.alerts:
                if snapshot.warning and snapshot.warning != last_monitor_warning:
                    print(f"Sentinal: {snapshot.warning}", file=sys.stderr)
                last_monitor_warning = snapshot.warning
                selected = [event for event in events if event.risk.score >= args.min_risk
                            and (not args.alerts or alert_severity(event))]
                if selected:
                    print("\n\n".join(format_event(event, alert_only=args.alerts)
                                       for event in selected), flush=True)
                elif args.once and not snapshot.warning:
                    print("No security alerts." if args.alerts else "No events match the current view.")
            elif args.once or signature != previous:
                if previous is not None:
                    print()
                if args.explain:
                    output = format_explain_snapshot(visible)
                elif not visible.connections and not visible.warning and args.min_risk:
                    output = f"Sentinal | {snapshot.timestamp.isoformat(timespec='seconds')}\nNo connections meet the risk threshold."
                else:
                    output = format_snapshot(visible)
                print(output, flush=True)
                previous = signature
            if args.once:
                return 1 if snapshot.warning else 0
            time.sleep(REFRESH_SECONDS)
    except KeyboardInterrupt:
        print("\nSentinal stopped.")
        return 0
    except OSError as error:
        print(f"Sentinal: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
