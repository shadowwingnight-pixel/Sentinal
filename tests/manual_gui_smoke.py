"""Run with a Windows desktop: python tests/manual_gui_smoke.py.

Creates a real native window, checks live data, selection, tabs and stop/start,
then closes. No screen automation or external service is used.
"""

import customtkinter as ctk
from dataclasses import replace
import time

from sentinal.gui import SentinalApp
from sentinal.dashboard import PollResult
from sentinal.intelligence import prepare_connection
from sentinal.monitor import Endpoint, Snapshot

ctk.set_appearance_mode("dark")
app = SentinalApp(logging=False)
failures: list[str] = []


def check_live():
    try:
        assert app.winfo_exists()
        assert app.monitoring
        assert app.table.get_children(), "No local sockets displayed"
        first = app.table.get_children()[0]
        app.table.selection_set(first)
        app._select()
        assert "PID" in app.detail_text.get("1.0", "end")
        assert "Local:" in app.detail_text.get("1.0", "end")
        assert "What is happening?" in app.detail_text.get("1.0", "end")
        assert "Why this score?" in app.detail_text.get("1.0", "end")
        app.notification_toggle.deselect()
        app._notification_setting()
        assert not app.notifications.gate.enabled
        original = app._rows[first]
        base = replace(original, process_name="load-test.exe", protocol="TCP", status="ESTABLISHED", pid=42,
                       local=Endpoint("127.0.0.1", 50000), remote=Endpoint("127.0.0.1", 443))
        rows = tuple(replace(base, pid=index, local=Endpoint("127.0.0.1", 50000+index)) for index in range(550))
        snapshot = Snapshot(__import__('datetime').datetime.now().astimezone(), rows)
        prepared = tuple(prepare_connection(row) for row in rows)
        started = time.monotonic()
        app._apply(PollResult(snapshot, entries=prepared))
        assert len(app.table.get_children()) == 550
        assert time.monotonic() - started < 2, "Rendering 550 rows exceeded 2 seconds"
        app.search_var.set("no-such-process")
        app._render_table()
        assert not app.table.get_children()
        app.search_var.set("HTTPS")
        app.level.set("Normal")
        app._render_table()
        assert len(app.table.get_children()) == 550
        app._sort("Process")
        assert app.graph.find_all()
        for tab in ("Alerts", "Event History", "Live Connections"):
            app.tabs.set(tab)
            assert app.tabs.get() == tab
        app.toggle_monitoring()
        assert "STOPPED" in app.state_label.cget("text")
        assert not app.monitoring
        app.after(700, check_restart)
    except Exception as error:
        failures.append(str(error))
        app.close()


def check_restart():
    try:
        assert not app.worker.running
        app.toggle_monitoring()
        assert app.monitoring
        app.after(1000, app.close)
    except Exception as error:
        failures.append(str(error))
        app.close()


app.after(4000, check_live)
app.mainloop()
if failures:
    raise RuntimeError("GUI smoke failed: " + "; ".join(failures))
print("GUI smoke passed: native launch, 550 rows, filtering, sorting, details, graph, notification toggle, stop/start, clean close")
