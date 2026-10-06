"""Frozen startup adapter for the existing bounded reverse-DNS helper."""

import ipaddress
from pathlib import Path
import socket
import sys


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--sentinal-resolve":
        # Windowed executables have no Python stdout. Return only the hostname
        # through the parent-created temporary file instead of a console pipe.
        address = str(ipaddress.ip_address(sys.argv[2]))
        try:
            name = socket.gethostbyaddr(address)[0]
        except OSError:
            name = ""
        Path(sys.argv[3]).write_text(name, encoding="utf-8")
        return
    from .gui import main as gui_main
    gui_main()
