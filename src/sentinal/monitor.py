"""Collect local socket metadata without initiating network traffic."""

from dataclasses import dataclass
from datetime import datetime
import socket

import psutil


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


@dataclass(frozen=True)
class Connection:
    protocol: str
    local: Endpoint | None
    remote: Endpoint | None
    status: str
    pid: int | None
    process_name: str


@dataclass(frozen=True)
class Snapshot:
    timestamp: datetime
    connections: tuple[Connection, ...]
    warning: str | None = None


def _endpoint(address: tuple[str, int] | tuple[()]) -> Endpoint | None:
    return Endpoint(address[0], address[1]) if address else None


def _process_name(pid: int | None) -> str:
    if pid is None:
        return "Unknown"
    try:
        return psutil.Process(pid).name()
    except psutil.AccessDenied:
        return "Access denied"
    except psutil.ZombieProcess:
        return "Zombie process"
    except psutil.NoSuchProcess:
        return "Process exited"


def collect_snapshot() -> Snapshot:
    """Read TCP/UDP IPv4/IPv6 sockets, including listening/bound sockets.

    Names are cached only within a snapshot to avoid stale PID reuse across
    refreshes. Socket enumeration and name resolution are inherently racy.
    """
    timestamp = datetime.now().astimezone()
    try:
        sockets = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return Snapshot(timestamp, (), "Access denied while reading connections.")
    names: dict[int | None, str] = {}
    connections: list[Connection] = []
    for connection in sockets:
        if connection.family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if connection.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            continue
        if connection.pid not in names:
            names[connection.pid] = _process_name(connection.pid)
        connections.append(Connection(
            protocol="TCP" if connection.type == socket.SOCK_STREAM else "UDP",
            local=_endpoint(connection.laddr),
            remote=_endpoint(connection.raddr),
            status=str(connection.status),
            pid=connection.pid,
            process_name=names[connection.pid],
        ))
    connections.sort(key=lambda row: (
        row.protocol, row.local.ip if row.local else "",
        row.local.port if row.local else -1,
        row.remote.ip if row.remote else "",
        row.remote.port if row.remote else -1,
        row.pid if row.pid is not None else -1,
    ))
    return Snapshot(timestamp, tuple(connections))
