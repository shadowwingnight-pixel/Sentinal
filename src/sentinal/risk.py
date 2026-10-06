"""Transparent local heuristics; scores are review priorities, not verdicts."""

from dataclasses import dataclass
import ipaddress

from .monitor import Connection

# Port conventions are hints, not verification of the actual application.
TCP_SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTP",
    587: "SMTP", 636: "LDAPS", 993: "IMAP", 995: "POP3", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM HTTP",
    5986: "WinRM HTTPS", 6379: "Redis", 8080: "HTTP alternate",
    8443: "HTTPS alternate",
}
UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NetBIOS", 138: "NetBIOS", 161: "SNMP", 162: "SNMP trap",
    443: "HTTPS / QUIC", 500: "IKE", 1900: "SSDP", 3389: "RDP",
    4500: "IPsec NAT traversal", 5353: "mDNS", 5355: "LLMNR",
    2177: "Windows peer discovery",
}
WINDOWS_UDP_PORTS = {123, 137, 138, 1900, 2177, 500, 4500, 5353, 5355}
WINDOWS_RPC_NAMES = {"svchost.exe", "services.exe", "lsass.exe", "wininit.exe"}
UNRESOLVED_NAMES = {"unknown", "unknown process", "access denied", "process exited", "zombie process"}
NORMAL_TCP_STATES = {
    "ESTABLISHED", "LISTEN", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
    "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "CLOSING",
}


def service_name(protocol: str, port: int) -> str | None:
    services = TCP_SERVICES if protocol == "TCP" else UDP_SERVICES if protocol == "UDP" else {}
    return services.get(port)


def classify_destination(ip: str | None) -> str:
    """Classify global unicast as INTERNET; non-public addresses as LOCAL.

    LOCAL describes address scope, not proof that a peer is this machine.
    Missing or invalid addresses are explicitly distinguished.
    """
    if ip is None:
        return "NO REMOTE"
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "UNKNOWN"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return "INTERNET" if address.is_global and not address.is_multicast else "LOCAL"


@dataclass(frozen=True)
class RiskReason:
    description: str
    points: int


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    reasons: tuple[RiskReason, ...]

    @property
    def level(self) -> str:
        return "GREEN" if self.score < 30 else "YELLOW" if self.score < 60 else "RED"


def is_routine_windows_activity(connection: Connection) -> bool:
    """Port/name context only, never a verified-process allowlist."""
    if connection.pid is None or connection.remote is not None or connection.local is None:
        return False
    name = connection.process_name.strip().casefold()
    port = connection.local.port
    return (
        connection.protocol == "UDP" and connection.status == "NONE"
        and name in {"svchost.exe", "system"} and port in WINDOWS_UDP_PORTS
    ) or (
        connection.protocol == "TCP" and connection.status == "LISTEN" and (
            name in WINDOWS_RPC_NAMES and (port == 135 or 49152 <= port <= 65535)
            or name == "system" and port in {139, 445}
        )
    )


def assess_connection(connection: Connection) -> RiskAssessment:
    """Add only documented signals, without reputation or remote lookups."""
    reasons: list[RiskReason] = []
    name = connection.process_name.strip().casefold()
    if name == "access denied":
        reasons.append(RiskReason("Process name unavailable due to permissions, not suspicious identity", 10))
    elif name in {"process exited", "zombie process"} or (
            connection.pid is None and connection.status in {"TIME_WAIT", "CLOSE"}):
        reasons.append(RiskReason("Process attribution unavailable during socket/process teardown", 5))
    elif connection.pid is None or not name or name in UNRESOLVED_NAMES:
        reasons.append(RiskReason("Process could not be identified", 20))
    if connection.remote:
        if service_name(connection.protocol, connection.remote.port) is None:
            reasons.append(RiskReason("Uncommon remote service port", 20))
        if classify_destination(connection.remote.ip) == "INTERNET":
            reasons.append(RiskReason("Public Internet destination (exposure context only)", 10))
    listening = connection.status == "LISTEN" or (connection.protocol == "UDP" and connection.remote is None)
    if listening and connection.local:
        try:
            address = ipaddress.ip_address(connection.local.ip.split("%", 1)[0])
        except ValueError:
            address = None
        if address is not None and isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        exposed = address is not None and (address.is_unspecified or
                                           classify_destination(connection.local.ip) == "INTERNET")
        if exposed:
            port = connection.local.port
            windows_pattern = is_routine_windows_activity(connection)
            if windows_pattern:
                reasons.append(RiskReason("Common Windows service binding pattern; name/port hints are not identity verification", 5))
            elif connection.protocol == "UDP":
                points = 5 if service_name("UDP", port) else 10
                reasons.append(RiskReason("UDP binding exposure only; a bound socket does not prove an inbound listener", points))
            elif address.is_unspecified:
                reasons.append(RiskReason("Listening on all interfaces, potentially reachable beyond this machine", 20))
            else:
                reasons.append(RiskReason("Listening on a public interface", 30))
    expected = NORMAL_TCP_STATES if connection.protocol == "TCP" else {"NONE"}
    if connection.status not in expected:
        reasons.append(RiskReason("Unexpected connection state", 20))
    return RiskAssessment(min(100, sum(reason.points for reason in reasons)), tuple(reasons))
