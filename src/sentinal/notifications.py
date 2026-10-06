"""Rate-limited native Windows desktop notices for newly observed HIGH events."""

from collections import OrderedDict
import ctypes
from ctypes import wintypes
import os
from queue import Empty, Full, Queue
from threading import Event, Thread
import time

from .alerts import alert_severity
from .events import ConnectionEvent, connection_identity


class NotificationGate:
    def __init__(self, cooldown: float = 30) -> None:
        self.enabled = True
        self.cooldown = cooldown
        self._last = float("-inf")
        self._seen: OrderedDict[object, None] = OrderedDict()

    def select(self, events: tuple[ConnectionEvent, ...], now: float) -> tuple[ConnectionEvent, ...]:
        fresh = []
        for event in events:
            key = (event.timestamp, event.event_type, connection_identity(event.connection))
            if alert_severity(event) != "HIGH" or key in self._seen:
                continue
            self._seen[key] = None
            if len(self._seen) > 2048:
                self._seen.popitem(last=False)
            fresh.append(event)
        if not self.enabled or not fresh or now - self._last < self.cooldown:
            return ()
        self._last = now
        return tuple(fresh)


class WindowsNotifier:
    def __init__(self, hwnd: int) -> None:
        self.hwnd = hwnd
        self._data = None

    def send(self, count: int) -> None:
        if os.name != "nt":
            return
        class IconData(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                        ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                        ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                        ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD),
                        ("dwStateMask", wintypes.DWORD), ("szInfo", wintypes.WCHAR * 256),
                        ("uVersion", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
                        ("dwInfoFlags", wintypes.DWORD), ("guidItem", ctypes.c_byte * 16),
                        ("hBalloonIcon", wintypes.HICON)]
        shell = ctypes.windll.shell32.Shell_NotifyIconW
        shell.argtypes = [wintypes.DWORD, ctypes.POINTER(IconData)]
        shell.restype = wintypes.BOOL
        if self._data is None:
            data = IconData()
            data.cbSize, data.hWnd, data.uID = ctypes.sizeof(data), self.hwnd, 1
            loader = ctypes.windll.user32.LoadIconW
            loader.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
            loader.restype = wintypes.HICON
            data.hIcon = loader(None, ctypes.c_void_p(32516))
            data.uFlags, data.szTip = 2 | 4, "Sentinal defensive monitoring"
            if not shell(0, ctypes.byref(data)):
                return
            data.uVersion = 4
            shell(4, ctypes.byref(data))
            self._data = data
        data = self._data
        # Class type is recreated per call; use a generic pointer signature.
        shell.argtypes = [wintypes.DWORD, ctypes.c_void_p]
        data.uFlags = 16 | 64  # info + realtime: do not queue obsolete notices
        data.szInfoTitle = "Sentinal | HIGH review priority"
        data.szInfo = f"{count} newly observed high-risk event(s). Potentially unusual network activity detected. Review Sentinal; this is not a malware verdict."
        data.dwInfoFlags = 2 | 128  # warning + respect Windows quiet time
        shell(1, ctypes.byref(data))

    def close(self) -> None:
        if self._data is not None:
            shell = ctypes.windll.shell32.Shell_NotifyIconW
            shell.argtypes = [wintypes.DWORD, ctypes.c_void_p]
            shell(2, ctypes.byref(self._data))
            self._data = None


class NotificationWorker:
    def __init__(self, hwnd: int) -> None:
        self.gate = NotificationGate()
        self._notifier = WindowsNotifier(hwnd)
        self._queue: Queue[int] = Queue(maxsize=1)
        self._stop = Event()
        self._thread = Thread(target=self._run, name="sentinal-notify", daemon=True)
        self._thread.start()

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def submit(self, events: tuple[ConnectionEvent, ...]) -> None:
        selected = self.gate.select(events, time.monotonic())
        if selected:
            try:
                self._queue.put_nowait(len(selected))
            except Full:
                pass

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    count = self._queue.get(timeout=0.1)
                except Empty:
                    continue
                if self.gate.enabled and not self._stop.is_set():
                    try:
                        self._notifier.send(count)
                    except (OSError, AttributeError, ctypes.ArgumentError):
                        pass  # Shell unavailable or notifications restricted
        finally:
            self._notifier.close()

    def close(self) -> None:
        self._stop.set()
