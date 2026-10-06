"""Run with a Windows desktop: python tests/manual_gui_smoke.py.

Creates a real native window, checks live data, selection, tabs and stop/start,
then closes. No screen automation or external service is used.
"""

import customtkinter as ctk

from sentinal.gui import SentinalApp

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
print("GUI smoke passed: native launch, live table, selection, stop/start, clean close")
