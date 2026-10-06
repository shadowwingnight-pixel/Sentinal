# Sentinal

Version 0.2: a Windows-focused, CLI-first Python 3.13+ monitor for the local
machine's TCP/UDP sockets. The only runtime dependency is psutil.

## Setup (PowerShell)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
```

## Run

```powershell
.\.venv\Scripts\python.exe -m sentinal.cli
```

Print one snapshot:

```powershell
.\.venv\Scripts\python.exe -m sentinal.cli --once
```

Continuous mode prints a snapshot, waits 3 seconds, and repeats; collection time
adds to that interval. Unchanged visible snapshots are suppressed (timestamps
alone do not trigger output); changed snapshots are printed in full. Disappeared
connections are absent from the next changed snapshot. Press Ctrl+C to stop.
Each snapshot includes a local,
timezone-aware timestamp, protocol, local/remote IP and port, status, PID, and
process name. IPv6 addresses use brackets. Listening TCP sockets and bound UDP
sockets are included; UDP status is normally `NONE`. Missing endpoints and PIDs
display `-`.

Restricted process names display `Access denied`; processes that disappear
display `Process exited`. Enumeration denial produces a warning, continues in
continuous mode, and returns exit code 1 in single-snapshot mode. Successful
single snapshots and Ctrl+C return 0. Visibility depends on OS permissions;
snapshots are best-effort and sockets/processes may change during collection.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use mocked psutil data and require no elevated permissions or network
traffic. `monitor.py` returns immutable structured snapshots; `cli.py` owns
formatting and refresh behavior. Future risk scoring, logging, threat intelligence,
or GUI code can consume snapshots without changing collection or adding a
framework now. Process-name caches expire with each snapshot.

## Explain and risk mode

```powershell
.\.venv\Scripts\python.exe -m sentinal.cli --explain
.\.venv\Scripts\python.exe -m sentinal.cli --explain --min-risk 30
.\.venv\Scripts\python.exe -m sentinal.cli --once --explain
```

The default detailed/raw table remains available. `--min-risk N` accepts an
integer from 0 through 100 and works in either view; entries scoring exactly N
are included. Explain mode shows process/PID, destination scope and port, service,
state, a plain-language explanation, and every added point.

Scores are heuristic review priorities, not malware detections or probabilities.
GREEN is 0-29, YELLOW 30-59, and RED 60-100. A GREEN score does not prove safety.
The rules in `risk.py` are additive, capped at 100:

| Signal | Points |
| --- | ---: |
| Missing PID or unresolved/empty process name | 20 |
| Remote port absent from the protocol-specific common-service table | 20 |
| Public Internet destination (exposure context only) | 10 |
| TCP listener or bound UDP socket on all interfaces | 20 |
| TCP listener or bound UDP socket on a public interface | 30 |
| State outside the recognized TCP lifecycle states or UDP `NONE` | 20 |

The two listening-interface rules are mutually exclusive. Normal TCP lifecycle
states such as `SYN_SENT`, `TIME_WAIT`, and `CLOSE_WAIT` add no points by themselves.
Private-interface listeners add no interface points. Bound UDP sockets do not
prove inbound reachability; wildcard/public binds only indicate possible exposure.
Firewall rules are not inspected. Missing remote endpoints incur no uncommon-port
points; listeners show their local port's service hint instead.

Example: a known process using HTTPS to a public IP scores 10. An unresolved
process using an uncommon remote port on a private IP scores 40; on a public IP
it scores 50. Explain mode lists the exact additions. An unfamiliar IP never
adds reputation points.

`INTERNET` means globally routable unicast address scope. `LOCAL` includes
loopback, private, link-local, multicast, shared and other non-public address
ranges; it does not mean the peer is necessarily this computer. IPv4-mapped IPv6
and IPv6 scope identifiers are supported. Missing remote addresses show
`NO REMOTE`; invalid addresses show `UNKNOWN`.

Service names come from fixed TCP/UDP port conventions, including web, DNS,
mail, SSH, RDP and common Windows services. They do not verify application
protocols, encryption, ownership or legitimacy. No DNS lookup or network request
is performed. `explain.py` owns presentation; `risk.py` owns service hints,
address classification and scoring. No new dependencies were added.

## Scope

Strictly defensive local monitoring using existing OS socket metadata. No remote
targets, scanning, exploitation, credentials, persistence, evasion, packet capture,
or outbound requests. No GUI in this milestone.

API reference: [psutil documentation](https://psutil.io/).
