# Sentinal

Version 0.4: a Windows-focused Python 3.13+ monitor for the local machine's
TCP/UDP sockets, with the existing CLI and a native CustomTkinter dashboard.
Runtime dependencies are psutil and CustomTkinter (plus its small dependencies).

## Setup (PowerShell)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
```

## Run

Native Windows dashboard (requires Python's Tk support and a desktop session):

```powershell
.\.venv\Scripts\python.exe -m sentinal.gui
```

The dark dashboard starts monitoring automatically. Live Connections shows
process, destination (or local bound endpoint), inferred service, state and risk.
Select a row for PID, both endpoints, plain-English explanation and every risk
addition. Summary cards count currently observed sockets (including listeners),
warnings (30-59) and high risk (60-100). GUI indicators are NORMAL / WARNING / HIGH;
CLI GREEN / YELLOW / RED thresholds are unchanged.

Alerts and Event History retain the most recent 300 entries each from the current
GUI session. Full events are appended to `logs/events.jsonl`; prior sessions
remain in that file and are not loaded into the dashboard. Stop Monitoring
immediately marks the view STOPPED and freezes the last displayed snapshot.
Start becomes available after the previous worker finishes, preventing overlap.
Restart preserves the event baseline, so unchanged sockets do not alert again;
changes during the pause are inferred on the next poll. Close the window or use
Ctrl+C to exit. No background monitoring is installed.

`dashboard.py` performs polling and history writes on one background thread.
`gui.py` consumes a bounded queue with Tk `after` callbacks; only the main thread
touches widgets. Polling errors show VISIBILITY LIMITED and mark data as stale;
history write failures appear in the status line. Stop/close never waits for a
blocked OS read on the UI thread. The header's requested "SYSTEM PROTECTED"
text describes the monitoring dashboard; Sentinal does not block threats or
guarantee safety. The adjacent heuristic-priority note remains visible.

Existing CLI commands:

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
formatting and refresh behavior. GUI and CLI reuse the same snapshot, scoring,
explanation, event, alert and JSONL modules. Process-name caches expire with each
snapshot. Unit tests do not create a desktop window. To verify a real GUI window,
live rows, selection, tabs, stop/start and clean shutdown:

```powershell
.\.venv\Scripts\python.exe tests/manual_gui_smoke.py
```

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
| Missing PID or unknown/empty process name (outside teardown) | 20 |
| Process name unavailable due to access permissions | 10 |
| Exited/zombie process, or missing PID in TIME_WAIT/CLOSE | 5 |
| Remote port absent from the protocol-specific common-service table | 20 |
| Public Internet destination (exposure context only) | 10 |
| Expected Windows service binding on wildcard/public interface | 5 |
| Other UDP binding on wildcard/public interface: common/unknown local service | 5 / 10 |
| Other TCP listener on all interfaces | 20 |
| Other TCP listener on a public interface | 30 |
| State outside the recognized TCP lifecycle states or UDP `NONE` | 20 |

Binding rules are mutually exclusive. Normal TCP lifecycle
states such as `SYN_SENT`, `TIME_WAIT`, and `CLOSE_WAIT` add no points by themselves.
Private-interface listeners add no interface points. Bound UDP sockets do not
prove inbound reachability; wildcard/public binds only indicate possible exposure.
Firewall rules are not inspected. Missing remote endpoints incur no uncommon-port
points; listeners show their local port's service hint instead.

Windows context reduces false positives without exempting a process name:
`svchost.exe` / `System` bound UDP on NTP (123), NetBIOS (137/138), SSDP (1900),
peer discovery (2177), IKE/IPsec (500/4500), mDNS (5353) or LLMNR (5355) contributes
only 5 exposure points. TCP RPC (135) or dynamic RPC range (49152-65535) under
`svchost.exe`, `services.exe`, `lsass.exe`, or `wininit.exe`, and System SMB
(139/445), also contribute 5. A PID must be available for these context hints.
No executable signature, path or service identity is verified. A name can be
spoofed; unrelated ports, outbound connections, unknown attribution and
unexpected states are still scored normally. This is a conservative port/name
pattern, not an allowlist or malware detector. A generic UDP bind alone cannot
cross the alert threshold. Windows service port context follows
[Microsoft's port reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements).

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
address classification and scoring. Scoring performs no external queries.

## Events, alerts and history

```powershell
.\.venv\Scripts\python.exe -m sentinal.cli --events
.\.venv\Scripts\python.exe -m sentinal.cli --alerts
.\.venv\Scripts\python.exe -m sentinal.cli --once --events
.\.venv\Scripts\python.exe -m sentinal.cli --events --min-risk 30 --no-log
```

Event mode prints `NEW`, `NEW_LISTENER` (TCP listeners and bound UDP sockets),
and `CLOSED` events. The first successful snapshot is newly observed activity,
not proof sockets were just created. Identity uses protocol, local endpoint,
remote endpoint, PID and listening/bound role; changing process names or TCP
lifecycle states does not create duplicate arrivals. Identical rows are collapsed.
Disappearance is inferred from the next successful snapshot; enumeration denial
preserves the baseline. Closed events use the last observed metadata and score.
A socket that disappears and later reappears produces a new arrival event.
Snapshots cannot detect sockets that appear and disappear between polls, or
distinguish reuse of the same PID/endpoints between polls. An unavailable PID
that later becomes known changes identity. Tracking is in memory for each run.

Alert mode shows only arrivals scoring at least 30: `WARNING` for 30-59 and
`HIGH` for 60-100. It says "Potentially unusual network activity detected."
Unchanged sockets and closed events never generate alerts. A score increase on
an existing socket does not trigger a new-arrival alert. `--min-risk` filters
display in every mode and `--once` returns after one poll. `--events` and
`--alerts` are mutually exclusive; either takes precedence over `--explain`
and includes explanation details. Operational warnings go to stderr even in
alert mode. Ctrl+C exits cleanly.

By default all modes append unfiltered detected events to `logs/events.jsonl`
relative to the current working directory. The directory is created only when
events exist. Each JSON line contains timestamp with offset, event type, process
name, PID, protocol, local/remote endpoint objects (or null), inferred service,
risk score, alert severity (null for non-alerts), and structured reasons with
points. No packet contents, credentials, environment variables, or application
payloads are collected. Socket addresses and process names are local metadata;
`logs/` is ignored by Git. History persists across runs, but each new run starts
a fresh baseline and may log the same currently active sockets again.

CLI `--no-log` disables history in every CLI mode without creating a directory or file.
Write failures report a diagnostic without stopping monitoring; failed batches
are not retried to avoid duplicate entries and may be partially written. No
automatic rotation is configured. `events.py` handles comparison, `alerts.py`
handles alert selection/presentation, and `logger.py` handles allowlisted JSONL
persistence. GUI history is enabled by default; no external APIs are used.

## Scope

Strictly defensive local monitoring using existing OS socket metadata. No remote
targets, scanning, exploitation, credentials, persistence, evasion, packet capture,
or outbound requests. No packet interception, firewall modification or process
termination is performed.

API reference: [psutil documentation](https://psutil.io/).
GUI reference: [CustomTkinter documentation](https://customtkinter.tomschimansky.com/documentation/).
