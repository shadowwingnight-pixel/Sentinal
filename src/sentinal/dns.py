"""Bounded OS reverse-DNS lookup with positive and negative TTL caches."""

from collections import OrderedDict
import ipaddress
from queue import Empty, Full, Queue
import subprocess
import sys
from threading import Event, Lock, Thread
import time


def reverse_lookup(ip: str, timeout: float = 2) -> str | None:
    try:
        address = str(ipaddress.ip_address(ip.split("%", 1)[0]))
        # The OS resolver has no per-call timeout. Isolate only this lookup in
        # a hidden helper so timeout reaps our own child, never a monitored PID.
        result = subprocess.run(
            [sys.executable, "-c", "import socket,sys; print(socket.gethostbyaddr(sys.argv[1])[0])", address],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        hostname = result.stdout.strip()[:253]
        if result.returncode == 0 and hostname and all(character.isprintable() and not character.isspace() for character in hostname):
            return hostname
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


class DNSResolver:
    """One worker and at most one helper process; get() never waits for DNS."""

    def __init__(self, *, ttl: float = 300, negative_ttl: float = 60, capacity: int = 512) -> None:
        self.ttl, self.negative_ttl, self.capacity = ttl, negative_ttl, capacity
        self._cache: OrderedDict[str, tuple[float, str | None]] = OrderedDict()
        self._pending: set[str] = set()
        self._queue: Queue[str] = Queue(maxsize=64)
        self._lock = Lock()
        self._stop = Event()
        self.revision = 0
        self._thread = Thread(target=self._run, name="sentinal-dns", daemon=True)
        self._thread.start()

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def get(self, ip: str) -> str | None:
        with self._lock:
            cached = self._cache.get(ip)
            if cached and cached[0] > time.monotonic():
                self._cache.move_to_end(ip)
                return cached[1]
            if not self._stop.is_set() and ip not in self._pending:
                try:
                    self._queue.put_nowait(ip)
                    self._pending.add(ip)
                except Full:
                    pass
        return None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                ip = self._queue.get(timeout=0.1)
            except Empty:
                continue
            hostname = reverse_lookup(ip)
            with self._lock:
                self._pending.discard(ip)
                self._cache[ip] = (time.monotonic() + (self.ttl if hostname else self.negative_ttl), hostname)
                self._cache.move_to_end(ip)
                while len(self._cache) > self.capacity:
                    self._cache.popitem(last=False)
                self.revision += 1

    def close(self) -> None:
        self._stop.set()
