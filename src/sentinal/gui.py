"""Native dark desktop dashboard. All widget access stays on the Tk thread."""

from collections import deque
from queue import Empty
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from .alerts import alert_severity, format_event
from .cli import format_endpoint
from .dashboard import MonitorWorker, PollResult
from .events import ConnectionEvent, connection_identity
from .explain import explain_connection
from .monitor import Connection
from .risk import assess_connection, service_name

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
        self._build()
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
        self.table = self._table(live)
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
            table.heading(name, text=name)
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
            self._text(self.detail_text, f"Local: {format_endpoint(row.local)}\nRemote: {format_endpoint(row.remote)}\nProtocol: {row.protocol}\n\n" + explain_connection(row))

    def _apply(self, result: PollResult) -> None:
        if result.snapshot is None or result.snapshot.warning:
            message = result.diagnostic or (result.snapshot.warning if result.snapshot else "Polling unavailable")
            self.state_label.configure(text="VISIBILITY LIMITED | MONITORING LIVE", text_color=COLORS["WARNING"])
            self.status.configure(text=f"{message} • displayed data may be stale")
        else:
            snapshot = result.snapshot
            self.state_label.configure(text="SYSTEM PROTECTED | MONITORING LIVE", text_color=COLORS["NORMAL"])
            rows = {connection_identity(row): row for row in snapshot.connections}
            scores = [assess_connection(row).score for row in rows.values()]
            for label, value in zip(self.counts, (len(rows), sum(30 <= score < 60 for score in scores), sum(score >= 60 for score in scores))):
                label.configure(text=str(value))
            scroll_position = self.table.yview()[0]
            self.table.delete(*self.table.get_children())
            self._rows.clear()
            for index, row in enumerate(rows.values()):
                key = str(index)
                self._rows[key] = row
                self.table.insert("", "end", iid=key, values=connection_values(row), tags=(risk_label(assess_connection(row).score),))
                if connection_identity(row) == self._selected_identity:
                    self.table.selection_set(key)
            self.table.yview_moveto(scroll_position)
            if self._selected_identity is not None and self._selected_identity not in rows:
                self._selected_identity = None
                self._text(self.detail_text, "Selected socket disappeared. Select another connection.")
            self.status.configure(text=result.diagnostic or f"Updated {snapshot.timestamp.strftime('%H:%M:%S')} • {len(result.events)} changes • local passive monitoring")
        self._history.extend(result.events)
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
        self._closing = True
        self.worker.stop()
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
