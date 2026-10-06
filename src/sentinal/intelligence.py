"""Prepared GUI metadata, filters, ordering and bounded activity history."""

from collections import deque
from dataclasses import dataclass
import ipaddress

from .cli import format_endpoint
from .explain import explain_connection
from .monitor import Connection
from .risk import RiskAssessment, assess_connection, is_routine_windows_activity, service_name


def destination_scope(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_loopback:
            return "Loopback"
        return "Internet" if address.is_global and not address.is_multicast else "LAN / non-public"
    except ValueError:
        return "Unknown scope"


@dataclass(frozen=True)
class ConnectionInfo:
    connection: Connection
    risk: RiskAssessment
    service: str
    scope: str
    routine: bool
    search_text: str
    detail: str


def prepare_connection(row: Connection) -> ConnectionInfo:
    endpoint = row.remote or row.local
    service = service_name(row.protocol, endpoint.port) if endpoint else None
    service = service or "Unknown service"
    score = assess_connection(row)
    scope = destination_scope(row.remote.ip) if row.remote else "No remote peer"
    explanation = next((line.removeprefix("Explanation: ") for line in explain_connection(row).splitlines()
                        if line.startswith("Explanation: ")), "No explanation available.")
    reasons = "\n".join(f"• {reason.description} (+{reason.points})" for reason in score.reasons)
    detail = (f"Process: {row.process_name}\nPID: {row.pid if row.pid is not None else '-'}\n"
              f"Connection: {row.protocol} / {scope}\nLocal: {format_endpoint(row.local)}\n"
              f"Remote: {format_endpoint(row.remote)}\nService: {service} / {endpoint.port if endpoint else '-'}\n"
              f"State: {row.status}\nRisk: {score.score}/100\n\nWhat is happening?\n{explanation}\n\n"
              f"Why this score?\n{reasons or 'No configured risk signals (+0).'}\n\n"
              "Port and hostname hints do not verify ownership, safety or maliciousness.")
    search = " ".join((row.process_name, str(row.pid), format_endpoint(row.local),
                       format_endpoint(row.remote), service, row.protocol)).casefold()
    return ConnectionInfo(row, score, service, scope, is_routine_windows_activity(row), search, detail)


def filter_connections(entries: tuple[ConnectionInfo, ...], query: str = "", level: str = "All",
                       hide_routine: bool = False, hostnames: dict[str, str] | None = None) -> list[ConnectionInfo]:
    tokens = query.casefold().split()
    names = hostnames or {}
    result = []
    for entry in entries:
        score = entry.risk.score
        if level == "Normal" and score >= 30 or level == "Warning" and not 30 <= score < 60 or level == "High Risk" and score < 60:
            continue
        if hide_routine and entry.routine and score < 30:
            continue
        ip = entry.connection.remote.ip if entry.connection.remote else ""
        text = entry.search_text + " " + names.get(ip, "").casefold()
        if all(token in text for token in tokens):
            result.append(entry)
    return result


def sort_connections(entries: list[ConnectionInfo], column: str = "Risk", descending: bool = True) -> list[ConnectionInfo]:
    def key(entry: ConnectionInfo):
        row = entry.connection
        return {"Process": row.process_name.casefold(), "Destination": format_endpoint(row.remote or row.local),
                "Service": entry.service.casefold(), "Status": row.status, "Risk": entry.risk.score}[column]
    return sorted(entries, key=key, reverse=descending)


@dataclass(frozen=True)
class ActivitySample:
    time: float
    connections: int
    events: int


class ActivityHistory:
    def __init__(self, window: float = 60) -> None:
        self.window = window
        self.samples: deque[ActivitySample] = deque(maxlen=120)

    def add(self, now: float, connections: int, events: int) -> None:
        self.samples.append(ActivitySample(now, connections, events))
        self.prune(now)

    def prune(self, now: float) -> None:
        while self.samples and self.samples[0].time < now - self.window:
            self.samples.popleft()

    def totals(self, now: float) -> tuple[int, int]:
        self.prune(now)
        return (self.samples[-1].connections if self.samples else 0,
                sum(sample.events for sample in self.samples))
