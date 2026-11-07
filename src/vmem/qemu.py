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
import time
from collections import OrderedDict


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

    def sendkey(self, key: str) -> None:
        """Send one key (HMP syntax, e.g. 'a', 'ret', 'shift-semicolon')."""
        self.human(f"sendkey {key}")

    def type_text(self, text: str, *, delay: float = 0.04,
                  enter: bool = True) -> None:
        """Type ASCII into the guest.  Useful for the UEFI shell."""
        keymap = {
            " ": "spc", ":": "shift-semicolon", "\\": "backslash",
            ".": "dot", "-": "minus", "/": "slash", "_": "shift-minus",
            '"': "shift-apostrophe", "=": "equal", ",": "comma",
            ";": "semicolon", "'": "apostrophe", "\n": "ret",
            "(": "shift-9", ")": "shift-0", "|": "shift-backslash",
        }
        for ch in text:
            if ch.isalnum():
                key = ch.lower()
            elif ch in keymap:
                key = keymap[ch]
            else:
                raise ValueError(f"cannot type {ch!r}")
            self.sendkey(key)
            time.sleep(delay)
        if enter:
            self.sendkey("ret")

    def screendump(self, path: str | pathlib.Path, *,
                   fmt: str = "png") -> str:
        """Capture the current display (QEMU 7.2+ supports PNG)."""
        self.command("screendump", filename=str(path), format=fmt)
        return str(path)

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


def _parse_xp(text: str) -> bytes | None:
    """Parse HMP ``xp /Ngx`` output into little-endian bytes."""
    chunks = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        payload = line.split(":", 1)[1]
        for token in payload.split():
            token = token.strip()
            if not token.startswith("0x"):
                return None
            chunks.append(int(token, 16).to_bytes(8, "little"))
    return b"".join(chunks) if chunks else None


class QmpRam:
    """Live guest physical memory over QMP, with a 4 KiB page cache.

    ``xp /512gx`` fetches one page per round trip, so walking the EPROCESS
    list costs hundreds of milliseconds instead of thousands of round trips.
    ---

    Pass an instance to ``Memory.open_callback(ram, segments, arch="arm64")``.
    """

    def __init__(self, qmp: QmpClient, page_cache: int = 8192):
        self.qmp = qmp
        self.page_cache = page_cache
        self._pages: OrderedDict[int, bytes] = OrderedDict()
        self.qmp_reads = 0

    def _page(self, page: int) -> bytes:
        data = self._pages.get(page)
        if data is not None:
            self._pages.move_to_end(page)
            return data
        data = _parse_xp(self.qmp.human(f"xp /512gx {page:#x}")) or b""
        if len(data) < 0x1000:
            data = data + b"\0" * (0x1000 - len(data))
        self.qmp_reads += 1
        self._pages[page] = data
        if len(self._pages) > self.page_cache:
            self._pages.popitem(last=False)
        return data

    def __call__(self, offset: int, length: int) -> bytes:
        out = bytearray(length)
        pos = 0
        while pos < length:
            addr = offset + pos
            page = addr & ~0xFFF
            data = self._page(page)
            start = addr - page
            take = min(0x1000 - start, length - pos)
            out[pos:pos + take] = data[start:start + take]
            pos += take
        return bytes(out)
