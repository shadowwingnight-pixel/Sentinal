"""Detect socket arrivals and disappearances between successful snapshots."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from .monitor import Connection, Endpoint, Snapshot
from .risk import RiskAssessment, assess_connection, service_name

EventType = Literal["NEW", "CLOSED", "NEW_LISTENER"]
ConnectionIdentity = tuple[str, Endpoint | None, Endpoint | None, int | None, bool]


def is_listener(connection: Connection) -> bool:
    return connection.status == "LISTEN" or (
        connection.protocol == "UDP" and connection.remote is None
    )


def connection_identity(connection: Connection) -> ConnectionIdentity:
    # Names and lifecycle states can change without creating a new socket.
    return (connection.protocol, connection.local, connection.remote,
            connection.pid, is_listener(connection))


@dataclass(frozen=True)
class ConnectionEvent:
    timestamp: datetime
    event_type: EventType
    connection: Connection
    risk: RiskAssessment
    service: str


def _event(timestamp: datetime, kind: EventType, connection: Connection) -> ConnectionEvent:
    endpoint = connection.remote or connection.local
    service = service_name(connection.protocol, endpoint.port) if endpoint else None
    return ConnectionEvent(timestamp, kind, connection, assess_connection(connection),
                           service or "Unknown service")


class EventTracker:
    """In-memory baseline; first snapshot counts as newly observed activity."""

    def __init__(self) -> None:
        self._previous: dict[ConnectionIdentity, Connection] = {}

    def update(self, snapshot: Snapshot) -> tuple[ConnectionEvent, ...]:
        if snapshot.warning:
            # Failed enumeration is not evidence that sockets disappeared.
            return ()
        current = {connection_identity(row): row for row in snapshot.connections}
        events = [
            _event(snapshot.timestamp, "NEW_LISTENER" if is_listener(row) else "NEW", row)
            for identity, row in current.items() if identity not in self._previous
        ]
        events.extend(
            _event(snapshot.timestamp, "CLOSED", row)
            for identity, row in self._previous.items() if identity not in current
        )
        self._previous = current
        return tuple(events)
