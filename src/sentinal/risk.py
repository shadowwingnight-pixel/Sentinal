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
}
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


def assess_connection(connection: Connection) -> RiskAssessment:
    """Add only documented signals, without reputation or remote lookups."""
    reasons: list[RiskReason] = []
    if (connection.pid is None or not connection.process_name.strip()
            or connection.process_name.strip().casefold() in UNRESOLVED_NAMES):
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
        if address is not None and address.is_unspecified:
            reasons.append(RiskReason("Listening/bound on all interfaces, potentially reachable beyond this machine", 20))
        elif classify_destination(connection.local.ip) == "INTERNET":
            reasons.append(RiskReason("Listening/bound on a public interface", 30))
    expected = NORMAL_TCP_STATES if connection.protocol == "TCP" else {"NONE"}
    if connection.status not in expected:
        reasons.append(RiskReason("Unexpected connection state", 20))
    return RiskAssessment(min(100, sum(reason.points for reason in reasons)), tuple(reasons))
