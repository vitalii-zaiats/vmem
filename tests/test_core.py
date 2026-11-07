"""Tests for the C core, driven through the Python binding.

Everything is synthetic: we build a physical-memory image, fabricate page
tables and EPROCESS blocks, and check translation, scanning and enumeration.
"""
from __future__ import annotations

import pathlib
import struct

import pytest

from vmem import Memory, Windows, load_profile

PAGE = 0x1000


class Image:
    def __init__(self, size: int):
        self.buf = bytearray(size)

    def u64(self, off: int, value: int) -> None:
        struct.pack_into("<Q", self.buf, off, value)

    def u32(self, off: int, value: int) -> None:
        struct.pack_into("<I", self.buf, off, value)

    def write(self, off: int, data: bytes) -> None:
        self.buf[off:off + len(data)] = data

    def save(self, path: pathlib.Path) -> pathlib.Path:
        path.write_bytes(self.buf)
        return path


def allocator(start: int = 0x1000):
    nxt = start

    def alloc() -> int:
        nonlocal nxt
        pa = nxt
        nxt += PAGE
        return pa

    return alloc


# ------------------------------------------------------------------ #
# page table builders                                                #
# ------------------------------------------------------------------ #

def arm64_map(img: Image, table_pa: int, va: int, pa: int, alloc) -> None:
    l0 = table_pa
    l1, l2, l3 = alloc(), alloc(), alloc()
    img.u64(l0 + ((va >> 39) & 0x1FF) * 8, l1 | 3)
    img.u64(l1 + ((va >> 30) & 0x1FF) * 8, l2 | 3)
    img.u64(l2 + ((va >> 21) & 0x1FF) * 8, l3 | 3)
    img.u64(l3 + ((va >> 12) & 0x1FF) * 8,
            (pa & 0x0000FFFFFFFFF000) | 3)


def x86_64_map(img: Image, pml4: int, va: int, pa: int, alloc) -> None:
    pdpt, pd, pt = alloc(), alloc(), alloc()
    img.u64(pml4 + ((va >> 39) & 0x1FF) * 8, pdpt | 3)
    img.u64(pdpt + ((va >> 30) & 0x1FF) * 8, pd | 3)
    img.u64(pd + ((va >> 21) & 0x1FF) * 8, pt | 3)
    img.u64(pt + ((va >> 12) & 0x1FF) * 8,
            (pa & 0x000FFFFFFFFFF000) | 3)


# ------------------------------------------------------------------ #
# tests                                                              #
# ------------------------------------------------------------------ #

def test_arm64_translate_and_read(tmp_path):
    va = 0x00000040001234
    pa = 0x00080000
    img = Image(0x100000)
    alloc = allocator()
    ttbr = alloc()
    arm64_map(img, ttbr, va, pa, alloc)
    img.write((pa & ~0xFFF) | (va & 0xFFF), b"hello arm64")
    core = img.save(tmp_path / "arm64.raw")

    mem = Memory.open_flat(core, arch="arm64")
    space = mem.space(ttbr)

    assert space.translate(va) == (pa & ~0xFFF) | (va & 0xFFF)
    assert space.read(va, 5) == b"hello"
    assert space.cstring(va) == "hello arm64"
    assert space.translate(va + 0x40000) is None


def test_arm64_ttbr1_kernel_half(tmp_path):
    va = 0xFFFF800000001234
    pa = 0x00090000
    img = Image(0x100000)
    alloc = allocator()
    ttbr0 = alloc()
    ttbr1 = alloc()
    arm64_map(img, ttbr1, va, pa, alloc)
    img.write((pa & ~0xFFF) | (va & 0xFFF), b"kernel")
    core = img.save(tmp_path / "ttbr1.raw")

    mem = Memory.open_flat(core, arch="arm64")
    # TTBR1 with the ASID in bits 63:48, which must be masked off.
    space = mem.space(0, ttbr1 | 0xFFFF000000000000)
    assert space.translate(va) == (pa & ~0xFFF) | (va & 0xFFF)
    assert space.read(va, 6) == b"kernel"
    # The low half must not use TTBR1.
    assert space.translate(0x1234) is None


def test_x86_64_translate_page_and_2mb(tmp_path):
    va4k = 0x0000000012345678
    va2m = 0x0000010000000000  # PML4 slot 2, cannot clash with the 4K map
    img = Image(0x400000)
    alloc = allocator()
    pml4 = alloc()
    x86_64_map(img, pml4, va4k, 0x000A0000, alloc)

    # 2 MiB page: PD entry with PS bit set.
    pdpt, pd = alloc(), alloc()
    img.u64(pml4 + ((va2m >> 39) & 0x1FF) * 8, pdpt | 3)
    img.u64(pdpt + ((va2m >> 30) & 0x1FF) * 8, pd | 3)
    img.u64(pd + ((va2m >> 21) & 0x1FF) * 8, 0x00200000 | 0x80 | 3)

    img.write(0x000A0678, b"four-k")
    img.write(0x00200000 + (va2m & 0x1FFFFF), b"two-meg")
    core = img.save(tmp_path / "x64.raw")

    mem = Memory.open_flat(core, arch="x86_64")
    space = mem.space(pml4)
    assert space.read(va4k, 6) == b"four-k"
    assert space.read(va2m, 7) == b"two-meg"


def test_scan_across_chunk_boundary(tmp_path):
    img = Image(24 * 1024 * 1024)
    needle = b"BOUNDARY-PATTERN"
    where = 8 * 1024 * 1024 - 5
    img.write(where, needle)
    core = img.save(tmp_path / "scan.raw")

    mem = Memory.open_flat(core, arch="x86_64")
    hits = list(mem.scan(needle))
    assert hits == [where]


def test_scan_overlap_not_duplicated(tmp_path):
    img = Image(1 << 20)
    img.write(0x1000, b"AAAA")
    core = img.save(tmp_path / "overlap.raw")
    mem = Memory.open_flat(core, arch="x86_64")
    assert list(mem.scan(b"AAAA")) == [0x1000]


def _fake_eprocess(img: Image, base: int, offsets: dict[str, int], *,
                   name: str, pid: int, dtb: int, threads: int = 4,
                   vsize: int = 0x100000, ppid: int = 0) -> None:
    img.write(base + offsets["image_file_name"], name.encode())
    img.u64(base + offsets["unique_process_id"], pid)
    img.u64(base + offsets["directory_table_base"], dtb)
    img.u64(base + offsets["active_process_links"], 0xFFFF800000001000)
    img.u32(base + offsets["active_threads"], threads)
    img.u64(base + offsets["virtual_size"], vsize)
    if offsets.get("inherited_from_unique_process_id"):
        img.u64(base + offsets["inherited_from_unique_process_id"], ppid)


def test_windows_scan_enumerates_arm64(tmp_path):
    prof = load_profile("win11-26300-arm64")
    off = prof.as_dict()

    img = Image(16 << 20)
    _fake_eprocess(img, 0x00200000, off, name="System", pid=4, dtb=0x1000)
    _fake_eprocess(img, 0x00210000, off, name="explorer.exe", pid=1234,
                   dtb=0x2000, ppid=4)
    core = img.save(tmp_path / "win.raw")

    mem = Memory.open_flat(core, arch="arm64")
    win = Windows(mem, off)
    procs = win.processes()

    by_pid = {p["pid"]: p for p in procs}
    assert by_pid[4]["name"] == "System"
    assert by_pid[1234]["name"] == "explorer.exe"
    assert by_pid[1234]["threads"] == 4
    assert by_pid[1234]["ppid"] == 4


def test_windows_find_by_name_and_pid(tmp_path):
    prof = load_profile("win11-26300-arm64")
    off = prof.as_dict()
    img = Image(16 << 20)
    _fake_eprocess(img, 0x00200000, off, name="System", pid=4, dtb=0x1000)
    _fake_eprocess(img, 0x00210000, off, name="notepad.exe", pid=77,
                   dtb=0x2000)
    core = img.save(tmp_path / "win2.raw")

    win = Windows(Memory.open_flat(core, arch="arm64"), off)
    assert win.find_name("NOTEPAD")["pid"] == 77
    assert win.find_pid(77)["name"] == "notepad.exe"
    assert win.find_pid(9999) is None


def test_elf_core_backend(tmp_path):
    """A minimal ELF core with two PT_LOAD segments and a 4 GiB hole."""
    data = bytearray(0x1200)
    # ELF header
    struct.pack_into("<4sBBBBB7x", data, 0, b"\x7fELF", 2, 1, 1, 0, 0)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     4, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    # two program headers
    struct.pack_into("<IIQQQQQQ", data, 64,
                     1, 4, 0x1000, 0, 0x100000, 0x100, 0x100, 0x100)
    struct.pack_into("<IIQQQQQQ", data, 120,
                     1, 4, 0x1100, 0, 0x100000000, 0x100, 0x100, 0x100)
    data[0x1000:0x1000 + 8] = b"low-mem!"
    data[0x1100:0x1100 + 9] = b"high-mem!"
    path = tmp_path / "core.elf"
    path.write_bytes(data)

    mem = Memory.open_elf(path)
    assert mem.arch == "arm64"
    assert mem.read(0x100000, 8) == b"low-mem!"
    assert mem.read(0x100000000, 9) == b"high-mem!"
    # hole between 0x101000 and 0x100000000 reads as zero
    assert mem.read(0x101000, 4) == b"\0\0\0\0"
    assert mem.read_exact(0x101000, 4) is None
