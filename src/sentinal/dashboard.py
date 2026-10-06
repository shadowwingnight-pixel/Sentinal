"""GUI-independent background polling. No Tk calls are made in this module."""

from dataclasses import dataclass
from queue import Empty, Full, Queue
from threading import Event, Thread

from .events import ConnectionEvent, EventTracker
from .logger import log_events
from .monitor import Snapshot, collect_snapshot
from .intelligence import ConnectionInfo, prepare_connection


@dataclass(frozen=True)
class PollResult:
    snapshot: Snapshot | None
    events: tuple[ConnectionEvent, ...] = ()
    diagnostic: str | None = None
    entries: tuple[ConnectionInfo, ...] = ()


class MonitorWorker:
    """One worker per dashboard; a bounded queue provides UI backpressure."""

    def __init__(self, *, interval: float = 3, logging: bool = True) -> None:
        self.results: Queue[PollResult] = Queue(maxsize=8)
        self._stop = Event()
        self._thread: Thread | None = None
        self._tracker = EventTracker()
        self._interval = interval
        self._logging = logging

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.running:
            return False
        # Discard pending display updates from a stopped run before resuming.
        while True:
            try:
                self.results.get_nowait()
            except Empty:
                break
        self._stop.clear()
        self._thread = Thread(target=self._run, name="sentinal-poll", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        # Never join a blocked OS read on the UI thread.
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                snapshot = collect_snapshot()
                if self._stop.is_set():
                    break
                events = self._tracker.update(snapshot)
                diagnostic = log_events(events) if self._logging else None
                entries = tuple(prepare_connection(row) for row in snapshot.connections)
                result = PollResult(snapshot, events, diagnostic, entries)
            except Exception as error:
                # Boundary for unexpected collector failures; permit later recovery.
                result = PollResult(None, diagnostic=f"Polling failed: {error}")
            while not self._stop.is_set():
                try:
                    self.results.put(result, timeout=0.1)
                    break
                except Full:
                    continue
            if self._stop.wait(self._interval):
                break
