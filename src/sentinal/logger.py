"""Append allowlisted socket event metadata to local JSON Lines history."""

from dataclasses import asdict
import json
from pathlib import Path

from .alerts import alert_severity
from .events import ConnectionEvent


def log_events(events: tuple[ConnectionEvent, ...],
               path: Path = Path("logs/events.jsonl")) -> str | None:
    """Return a diagnostic on write failure; never abort monitoring or retry batches.

    A failed batch may be partially written. Retrying would duplicate history.
    """
    if not events:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as history:
            for event in events:
                row = event.connection
                record = {
                    "timestamp": event.timestamp.isoformat(timespec="seconds"),
                    "event_type": event.event_type,
                    "process_name": row.process_name,
                    "pid": row.pid,
                    "protocol": row.protocol,
                    "local_endpoint": asdict(row.local) if row.local else None,
                    "remote_endpoint": asdict(row.remote) if row.remote else None,
                    "service": event.service,
                    "risk_score": event.risk.score,
                    "severity": alert_severity(event),
                    "reasons": [asdict(reason) for reason in event.risk.reasons],
                }
                history.write(json.dumps(record, ensure_ascii=True) + "\n")
    except OSError as error:
        return f"Event history could not be written: {error}"
    return None
