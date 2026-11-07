"""Minimal QMP client and helpers for QEMU/UTM guests.

Typical use:

    qmp = QmpClient("/tmp/qmp.sock")
    qmp.dump_guest_memory("ram.elf")        # ELF core with p_paddr
    regs = qmp.registers()                  # TTBR0_EL1 / TTBR1_EL1 / CR3

The dump is then opened with ``vmem.Memory.open_elf``.
"""
from __future__ import annotations

import json
import pathlib
import re
import socket
import subprocess


class QmpError(RuntimeError):
    pass


class QmpClient:
    def __init__(self, path: str | pathlib.Path | None = None, *,
                 host: str | None = None, port: int | None = None,
                 timeout: float = 60.0):
        if path is not None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(str(path))
        else:
            sock = socket.create_connection((host or "127.0.0.1", port or 4444),
                                            timeout=timeout)
        self._sock = sock
        self._file = sock.makefile("rwb", buffering=0)
        greeting = self._read()
        if "QMP" not in greeting:
            raise QmpError(f"not a QMP endpoint: {greeting!r}")
        self.command("qmp_capabilities")

    def _read(self) -> dict:
        line = self._file.readline()
        if not line:
            raise QmpError("QMP connection closed")
        return json.loads(line)

    def command(self, name: str, **arguments):
        msg: dict = {"execute": name}
        if arguments:
            msg["arguments"] = arguments
        self._file.write((json.dumps(msg) + "\n").encode())
        while True:
            resp = self._read()
            if "event" in resp:
                continue
            if "error" in resp:
                err = resp["error"]
                raise QmpError(f"{name}: {err.get('desc', err)}")
            return resp.get("return")

    def human(self, command: str) -> str:
        return self.command("human-monitor-command", **{"command-line": command})

    def dump_guest_memory(self, out: str | pathlib.Path, *,
                          fmt: str = "elf", paging: bool = False) -> None:
        """Dump guest RAM.  ``fmt='elf'`` yields PT_LOAD p_paddr segments."""
        self.command("dump-guest-memory", paging=paging,
                     protocol=f"file:{out}", format=fmt)

    def registers(self) -> dict[str, int]:
        text = self.human("info registers")
        out: dict[str, int] = {}
        for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_]*)\s*=\s*([0-9a-fA-F]{4,16})\b",
                             text):
            out[m.group(1).upper()] = int(m.group(2), 16)
        return out

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            self._sock.close()

    def __enter__(self) -> "QmpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def qmp_from_pid(pid: int) -> pathlib.Path | None:
    """Best effort: find a Unix QMP socket in a process's command line.

    Works when QEMU was started with ``-qmp unix:/path,server=on,wait=off``.
    """
    try:
        raw = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
        args = [a.decode(errors="replace") for a in raw.split(b"\0") if a]
    except OSError:
        try:
            out = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                                 capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            return None
        args = out.split()

    for i, arg in enumerate(args):
        value = None
        if arg == "-qmp" and i + 1 < len(args):
            value = args[i + 1]
        elif arg.startswith("-qmp="):
            value = arg.split("=", 1)[1]
        if not value:
            continue
        for part in value.split(","):
            if part.startswith("unix:"):
                return pathlib.Path(part.split(":", 1)[1])
    return None
