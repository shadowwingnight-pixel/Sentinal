"""Human-readable views of socket metadata and heuristic assessments."""

from .monitor import Connection, Snapshot
from .risk import assess_connection, classify_destination, service_name


def _safe_text(value: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in value)


def explain_connection(connection: Connection) -> str:
    assessment = assess_connection(connection)
    process = _safe_text(connection.process_name) or "Unknown process"
    pid = str(connection.pid) if connection.pid is not None else "-"
    endpoint = connection.remote or connection.local
    service = service_name(connection.protocol, endpoint.port) if endpoint else None
    label = service or "Unknown service"
    lines = [f"{assessment.level} [{assessment.score}/100]", f"{process} (PID {pid})",
             f"Confidence: {assessment.confidence}"]
    if connection.remote:
        scope = classify_destination(connection.remote.ip)
        lines.append(f"Destination: {scope} {_safe_text(connection.remote.ip)} (port {connection.remote.port})")
        peer = {"INTERNET": "an Internet destination", "LOCAL": "a local/non-public destination",
                "UNKNOWN": "a destination with unknown address scope"}[scope]
        action = "is connected to" if connection.status == "ESTABLISHED" else "has a socket to"
        lines.append(f"Explanation: {process} {action} {peer} using {label} (port-based hint).")
    else:
        lines.append("Destination: NO REMOTE (no remote IP/port)")
        if connection.local:
            lines.append(f"Local endpoint: {_safe_text(connection.local.ip)} (port {connection.local.port})")
        action = "is listening" if connection.status == "LISTEN" else "has a bound UDP socket" if connection.protocol == "UDP" else "has a socket without a remote address"
        lines.append(f"Explanation: {process} {action}; no remote peer is reported.")
    port = str(endpoint.port) if endpoint else "-"
    lines.extend([f"Service: {label} ({port}, {connection.protocol}; inferred from port)",
                  f"State: {_safe_text(connection.status)}"])
    if assessment.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason.description} (+{reason.points})" for reason in assessment.reasons)
    else:
        lines.append("Reason: No configured risk signals added points (+0).")
    lines.append(f"Assessment: {assessment.assessment}")
    return "\n".join(lines)


def format_explain_snapshot(snapshot: Snapshot) -> str:
    lines = [f"Sentinal Explain | {snapshot.timestamp.isoformat(timespec='seconds')}",
             "Heuristic review priority; not a malware verdict. Services are port-based hints."]
    if snapshot.warning:
        lines.append(f"Warning: {snapshot.warning}")
    elif not snapshot.connections:
        lines.append("No connections match the current view.")
    else:
        lines.extend("\n" + explain_connection(connection) for connection in snapshot.connections)
    return "\n".join(lines)
