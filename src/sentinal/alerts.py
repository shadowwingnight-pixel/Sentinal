"""Select security alerts and format event metadata without network lookups."""

from typing import Literal

from .events import ConnectionEvent
from .explain import explain_connection

Severity = Literal["WARNING", "HIGH"]
ALERT_MESSAGE = "Potentially unusual network activity detected."


def risk_severity(score: int) -> Severity | None:
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "WARNING"
    return None


def alert_severity(event: ConnectionEvent) -> Severity | None:
    if event.event_type == "CLOSED":
        return None
    return risk_severity(event.risk.score)


def format_event(event: ConnectionEvent, *, alert_only: bool = False) -> str:
    severity = alert_severity(event)
    label = severity if alert_only else event.event_type
    lines = [f"[{label}] {event.timestamp.isoformat(timespec='seconds')}",
             explain_connection(event.connection)]
    if event.event_type == "CLOSED":
        lines.append("Socket disappeared; details and risk describe its last observation.")
    if severity:
        lines.extend([f"Severity: {severity}", ALERT_MESSAGE])
    return "\n".join(lines)
