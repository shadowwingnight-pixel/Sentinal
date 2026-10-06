"""Native dark desktop dashboard. All widget access stays on the Tk thread."""

from collections import deque
from queue import Empty
import tkinter as tk
import time
from tkinter import ttk

import customtkinter as ctk

from .alerts import alert_severity, format_event
from .cli import format_endpoint
from .dashboard import MonitorWorker, PollResult
from .events import ConnectionEvent, connection_identity
from .monitor import Connection
from .risk import assess_connection, service_name
from .intelligence import ActivityHistory, ConnectionInfo, filter_connections, sort_connections
from .dns import DNSResolver
from .notifications import NotificationWorker

BACKGROUND = "#0b1220"
PANEL = "#111d30"
COLORS = {"NORMAL": "#42d9aa", "WARNING": "#f6bd60", "HIGH": "#ff647c"}


def risk_label(score: int) -> str:
    return "NORMAL" if score < 30 else "WARNING" if score < 60 else "HIGH"


def connection_values(row: Connection) -> tuple[str, str, str, str, str]:
    endpoint = row.remote or row.local
    service = service_name(row.protocol, endpoint.port) if endpoint else None
    risk = assess_connection(row)
    return (row.process_name, format_endpoint(row.remote) if row.remote else "Bound: " + format_endpoint(row.local),
            service or "Unknown service", row.status, f"{risk_label(risk.score)}  {risk.score}/100")


class SentinalApp(ctk.CTk):
    def __init__(self, *, logging: bool = True) -> None:
        super().__init__()
        self.title("Sentinal | Defensive Network Monitor")
        self.geometry("1280x800")
        self.minsize(1000, 650)
        self.configure(fg_color=BACKGROUND)
        self.worker = MonitorWorker(logging=logging)
        self.monitoring = False
        self._closing = False
        self._selected_identity = None
        self._rows: dict[str, Connection] = {}
        self._history: deque[ConnectionEvent] = deque(maxlen=300)
        self._alerts: deque[ConnectionEvent] = deque(maxlen=300)
        self._entries: tuple[ConnectionInfo, ...] = ()
        self._visible: dict[str, ConnectionInfo] = {}
        self._sort_column, self._descending = "Risk", True
        self._filter_job = None
        self.activity = ActivityHistory()
        self.dns = DNSResolver()
        self._dns_revision = 0
        self._build()
        self.notifications = NotificationWorker(self.winfo_id())
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind("<Control-c>", lambda _event: self.close())
        self.after(100, self._drain)
        self.start_monitoring()

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text="SENTINAL", font=("Segoe UI", 28, "bold"),
                     text_color=COLORS["NORMAL"]).pack(side="left", padx=24, pady=20)
        self.state_label = ctk.CTkLabel(header, text="", font=("Segoe UI", 15, "bold"))
        self.state_label.pack(side="left", padx=12)
        self.control = ctk.CTkButton(header, text="Stop Monitoring", command=self.toggle_monitoring,
                                     fg_color="#254468", hover_color="#355b85")
        self.control.pack(side="right", padx=24)
        ctk.CTkLabel(self, text="Passive local visibility  /  Heuristic priorities, not a safety guarantee",
                     text_color="#91a6bf").pack(anchor="w", padx=24, pady=(12, 4))
        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", padx=20, pady=12)
        self.counts: list[ctk.CTkLabel] = []
        for index, title in enumerate(("Active Connections", "Warnings", "High Risk")):
            cards.columnconfigure(index, weight=1)
            card = ctk.CTkFrame(cards, fg_color=PANEL)
            card.grid(row=0, column=index, sticky="ew", padx=4)
            ctk.CTkLabel(card, text=title, text_color="#91a6bf").pack(anchor="w", padx=20, pady=(14, 0))
            number = ctk.CTkLabel(card, text="0", font=("Segoe UI", 30, "bold"),
                                  text_color=list(COLORS.values())[index])
            number.pack(anchor="w", padx=20, pady=(0, 14))
            self.counts.append(number)
        graph_frame = ctk.CTkFrame(self, fg_color=PANEL)
        graph_frame.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkLabel(graph_frame, text="LIVE ACTIVITY  •  60 seconds    Connections / Events per poll",
                     text_color="#91a6bf", font=("Segoe UI", 11)).pack(anchor="w", padx=14)
        self.graph = tk.Canvas(graph_frame, height=65, background=PANEL, highlightthickness=0)
        self.graph.pack(fill="x", padx=14, pady=(0, 6))
        self.graph.bind("<Configure>", lambda _event: self._draw_graph())
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 10))
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)
        tabs = self.tabs = ctk.CTkTabview(body, fg_color=PANEL)
        tabs.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        live = tabs.add("Live Connections")
        alerts = tabs.add("Alerts")
        history = tabs.add("Event History")
        toolbar = ctk.CTkFrame(live, fg_color="transparent")
        toolbar.pack(fill="x", pady=(0, 8))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self._schedule_filter())
        ctk.CTkLabel(toolbar, text="Search", text_color="#91a6bf").pack(side="left", padx=(0, 8))
        ctk.CTkEntry(toolbar, placeholder_text="Search process, IP, port or service", textvariable=self.search_var,
                     width=260).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.level = ctk.CTkOptionMenu(toolbar, values=["All", "Normal", "Warning", "High Risk"],
                                      command=lambda _value: self._schedule_filter(), width=110)
        self.level.pack(side="right")
        options = ctk.CTkFrame(live, fg_color="transparent")
        options.pack(fill="x", pady=(0, 8))
        self.hide_routine = ctk.CTkCheckBox(options, text="Hide routine Windows activity", command=self._schedule_filter)
        self.hide_routine.pack(side="left")
        self.notification_toggle = ctk.CTkSwitch(options, text="Desktop Notifications ON", command=self._notification_setting)
        self.notification_toggle.select()
        self.notification_toggle.pack(side="right")
        table_frame = ctk.CTkFrame(live, fg_color="transparent")
        table_frame.pack(fill="both", expand=True)
        self.table = self._table(table_frame)
        self.table.bind("<<TreeviewSelect>>", self._select)
        self.alert_text = self._event_view(alerts, "Security alerts • recent session activity")
        self.history_text = self._event_view(history, "Event history • last 300 events this session; full history in logs/events.jsonl")
        details = ctk.CTkFrame(body, fg_color=PANEL)
        details.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(details, text="CONNECTION INTELLIGENCE", font=("Segoe UI", 15, "bold"),
                     text_color=COLORS["NORMAL"]).pack(anchor="w", padx=16, pady=16)
        self.detail_text = ctk.CTkTextbox(details, fg_color=PANEL, wrap="word", font=("Segoe UI", 13))
        self.detail_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._text(self.detail_text, "Select a connection to inspect its endpoints, explanation and exact risk reasons.")
        self.status = ctk.CTkLabel(self, text="Waiting for first snapshot...", text_color="#91a6bf", anchor="w")
        self.status.pack(fill="x", padx=24, pady=(0, 10))

    def _table(self, parent: ctk.CTkFrame) -> ttk.Treeview:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Sentinal.Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground="#e1eaf5", rowheight=32, borderwidth=0, font=("Segoe UI", 11))
        style.configure("Sentinal.Treeview.Heading", background="#1b2c44", foreground="#b5c9df",
                        font=("Segoe UI", 11, "bold"))
        style.map("Sentinal.Treeview", background=[("selected", "#274b6b")], foreground=[("selected", "white")])
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        columns = ("Process", "Destination", "Service", "Status", "Risk")
        table = ttk.Treeview(parent, columns=columns, show="headings", style="Sentinal.Treeview", selectmode="browse")
        for name, width in zip(columns, (160, 250, 140, 120, 145)):
            table.heading(name, text=name, command=lambda column=name: self._sort(column))
            table.column(name, width=width, minwidth=100)
        for label, color in COLORS.items():
            table.tag_configure(label, foreground=color)
        table.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(parent, orient="vertical", command=table.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(parent, orient="horizontal", command=table.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        return table

    def _event_view(self, parent: ctk.CTkFrame, caption: str) -> ctk.CTkTextbox:
        ctk.CTkLabel(parent, text=caption, wraplength=550, text_color="#91a6bf").pack(fill="x", pady=8)
        text = ctk.CTkTextbox(parent, fg_color=PANEL, wrap="word", font=("Segoe UI", 12))
        text.pack(fill="both", expand=True)
        self._text(text, "No activity observed yet.")
        return text

    @staticmethod
    def _text(widget: ctk.CTkTextbox, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _select(self, _event: tk.Event | None = None) -> None:
        selection = self.table.selection()
        if selection and selection[0] in self._rows:
            row = self._rows[selection[0]]
            self._selected_identity = connection_identity(row)
            info = self._visible[selection[0]]
            hostname = self.dns.get(row.remote.ip) if row.remote else None
            self._text(self.detail_text, (f"Hostname: {hostname}\n\n" if hostname else "") + info.detail)

    def _notification_setting(self) -> None:
        enabled = bool(self.notification_toggle.get())
        self.notifications.gate.enabled = enabled
        self.notification_toggle.configure(text=f"Desktop Notifications {'ON' if enabled else 'OFF'}")

    def _schedule_filter(self) -> None:
        if self._filter_job:
            self.after_cancel(self._filter_job)
        self._filter_job = self.after(150, self._render_table)

    def _sort(self, column: str) -> None:
        self._descending = not self._descending if column == self._sort_column else column == "Risk"
        self._sort_column = column
        self._render_table()

    def _render_table(self) -> None:
        if self._filter_job:
            self.after_cancel(self._filter_job)
        self._filter_job = None
        if self._closing:
            return
        hostnames = {}
        for info in self._entries:
            if info.connection.remote:
                ip = info.connection.remote.ip
                name = self.dns.get(ip)
                if name:
                    hostnames[ip] = name
        entries = sort_connections(filter_connections(self._entries, self.search_var.get(), self.level.get(),
                                                      bool(self.hide_routine.get()), hostnames),
                                   self._sort_column, self._descending)
        scroll_position = self.table.yview()[0]
        self.table.delete(*self.table.get_children())
        self._rows.clear()
        self._visible.clear()
        for index, info in enumerate(entries):
            row = info.connection
            key = str(index)
            self._rows[key], self._visible[key] = row, info
            endpoint = row.remote or row.local
            destination = format_endpoint(row.remote) if row.remote else "Bound: " + format_endpoint(row.local)
            if row.remote:
                name = hostnames.get(row.remote.ip)
                destination = f"{name} | {row.remote.ip}" if name else f"{info.scope} | {row.remote.ip}"
            values = (row.process_name, destination, f"{info.service} / {endpoint.port if endpoint else '-'}",
                      row.status, f"{risk_label(info.risk.score)} {info.risk.score}/100")
            self.table.insert("", "end", iid=key, values=values, tags=(risk_label(info.risk.score),))
            if connection_identity(row) == self._selected_identity:
                self.table.selection_set(key)
        self.table.yview_moveto(scroll_position)
        if self._selected_identity is not None and not self.table.selection():
            self._text(self.detail_text, "Selected connection is hidden by the current filters. Select a visible row.")
        for column in self.table["columns"]:
            marker = " ▼" if self._descending else " ▲"
            self.table.heading(column, text=column + (marker if column == self._sort_column else ""))
        self._select()

    def _draw_graph(self) -> None:
        now = time.monotonic()
        self.activity.prune(now)
        self.graph.delete("all")
        width, height = max(100, self.graph.winfo_width()), 60
        samples = list(self.activity.samples)
        scale = max([1] + [max(sample.connections, sample.events) for sample in samples])
        self.graph.create_line(0, height, width, height, fill="#28405e")
        self.graph.create_text(4, 4, text=f"Scale 0–{scale}  •  green: connections  /  amber: changes",
                               anchor="nw", fill="#91a6bf", font=("Segoe UI", 9))
        for field, color in (("connections", COLORS["NORMAL"]), ("events", COLORS["WARNING"])):
            points = []
            for sample in samples:
                points.extend((max(0, (sample.time - now + 60) / 60 * width),
                               height - getattr(sample, field) / scale * (height - 18)))
            if len(points) >= 4:
                self.graph.create_line(*points, fill=color, width=2)
            elif points:
                x, y = points
                self.graph.create_oval(x-2, y-2, x+2, y+2, fill=color, outline=color)

    def _apply(self, result: PollResult) -> None:
        if result.snapshot is None or result.snapshot.warning:
            message = result.diagnostic or (result.snapshot.warning if result.snapshot else "Polling unavailable")
            self.state_label.configure(text="VISIBILITY LIMITED | MONITORING LIVE", text_color=COLORS["WARNING"])
            self.status.configure(text=f"{message} • displayed data may be stale")
        else:
            snapshot = result.snapshot
            self.state_label.configure(text="SYSTEM PROTECTED | MONITORING LIVE", text_color=COLORS["NORMAL"])
            rows = {connection_identity(row): row for row in snapshot.connections}
            self._entries = result.entries
            scores = [info.risk.score for info in self._entries]
            for label, value in zip(self.counts, (len(rows), sum(30 <= score < 60 for score in scores), sum(score >= 60 for score in scores))):
                label.configure(text=str(value))
            self._render_table()
            self.activity.add(time.monotonic(), len(rows), len(result.events))
            self._draw_graph()
            if self._selected_identity is not None and self._selected_identity not in rows:
                self._selected_identity = None
                self._text(self.detail_text, "Selected socket disappeared. Select another connection.")
            self.status.configure(text=result.diagnostic or f"Updated {snapshot.timestamp.strftime('%H:%M:%S')} • {len(result.events)} changes • local passive monitoring")
        self._history.extend(result.events)
        self.notifications.submit(result.events)
        self._alerts.extend(event for event in result.events if alert_severity(event))
        if result.events:
            self._text(self.history_text, "\n\n".join(format_event(event) for event in reversed(self._history)))
            self._text(self.alert_text, "\n\n".join(format_event(event, alert_only=True) for event in reversed(self._alerts)) or "No security alerts.")

    def _drain(self) -> None:
        if self._closing:
            return
        # Limit each tick so event rendering cannot starve normal Tk interaction.
        for _ in range(2):
            try:
                result = self.worker.results.get_nowait()
            except Empty:
                break
            if self.monitoring:
                self._apply(result)
        if not self.monitoring and not self.worker.running:
            self.control.configure(state="normal")
        if self.dns.revision != self._dns_revision:
            self._dns_revision = self.dns.revision
            if self._filter_job is None:
                self._schedule_filter()
        self.after(100, self._drain)

    def start_monitoring(self) -> None:
        if self.worker.start():
            self.monitoring = True
            self.control.configure(text="Stop Monitoring")
            self.state_label.configure(text="WAITING FOR SNAPSHOT | MONITORING LIVE", text_color=COLORS["NORMAL"])

    def toggle_monitoring(self) -> None:
        if self.monitoring:
            self.monitoring = False
            self.worker.stop()
            self.control.configure(text="Start Monitoring", state="disabled")
            self.state_label.configure(text="MONITORING STOPPED", text_color=COLORS["WARNING"])
            self.status.configure(text="Stopped • table shows the last snapshot; no new polling or alerts")
        else:
            self.start_monitoring()

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self.worker.stop()
        self.dns.close()
        self.notifications.close()
        self.withdraw()
        self._close_deadline = time.monotonic() + 3
        self._finish_close()

    def _finish_close(self) -> None:
        if (self.worker.running or self.dns.running or self.notifications.running) and time.monotonic() < self._close_deadline:
            self.after(50, self._finish_close)
        else:
            self.destroy()


def main() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = SentinalApp()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.close()


if __name__ == "__main__":
    main()
