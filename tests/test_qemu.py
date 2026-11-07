"""Tests for the live QMP memory provider (no QEMU required)."""
from __future__ import annotations

from vmem.qemu import QmpRam, _parse_xp


class FakeQmp:
    def __init__(self):
        self.calls: list[str] = []

    def human(self, command: str) -> str:
        self.calls.append(command)
        page = int(command.rsplit(" ", 1)[1], 16)
        values = " ".join(f"0x{(page + i * 8):016x}" for i in range(512))
        return f"{page:#x}: {values}\n"


def test_parse_xp():
    text = ("0x1000: 0x0000000000000001 0x0000000000000002\n"
            "0x1010: 0x0000000000000003 0x0000000000000004\n")
    data = _parse_xp(text)
    assert data == b"".join(i.to_bytes(8, "little") for i in (1, 2, 3, 4))


def test_parse_xp_rejects_garbage():
    assert _parse_xp("xp: Invalid address") is None


def test_qmp_ram_page_cache_and_reads():
    qmp = FakeQmp()
    ram = QmpRam(qmp, page_cache=4)

    first = ram(0x2000, 8)
    second = ram(0x2008, 8)
    assert first == (0x2000).to_bytes(8, "little")
    assert second == (0x2008).to_bytes(8, "little")
    assert len(qmp.calls) == 1          # second read came from the page cache

    third = ram(0x1FF8, 8)
    fourth = ram(0x2000, 8)
    assert ram(0x1FF8, 16) == third + fourth   # crosses the page boundary
    assert len(qmp.calls) == 2                 # 0x1000 fetched once, 0x2000 cached
