"""Extract EPROCESS offsets from a PDB (and fetch it from Microsoft's server).

No third-party dependencies: this implements just enough of MSF 7.0 and the
TPI type stream to read a struct's member offsets, which is all we need.

    python -m vmem.symbols ntoskrnl.exe --arch arm64
"""
from __future__ import annotations

import argparse
import os
import pathlib
import struct
import sys
import urllib.request

from .profiles import EprocessOffsets

MSDL = "https://msdl.microsoft.com/download/symbols"

# struct name, member name
_MEMBERS = {
    "unique_process_id": ("_EPROCESS", "UniqueProcessId"),
    "active_process_links": ("_EPROCESS", "ActiveProcessLinks"),
    "image_file_name": ("_EPROCESS", "ImageFileName"),
    "virtual_size": ("_EPROCESS", "VirtualSize"),
    "active_threads": ("_EPROCESS", "ActiveThreads"),
    "peb": ("_EPROCESS", "Peb"),
    "inherited_from_unique_process_id": ("_EPROCESS",
                                         "InheritedFromUniqueProcessId"),
}

_NUMERIC = {
    0x8000: (3, "<b"), 0x8001: (4, "<h"), 0x8002: (4, "<H"),
    0x8003: (6, "<i"), 0x8004: (6, "<I"),
    0x8005: (10, "<q"), 0x8006: (10, "<Q"),
}


# ------------------------------------------------------------------ #
# PE debug directory: find the PDB name and symbol-server key        #
# ------------------------------------------------------------------ #

def pe_debug_info(path: str | os.PathLike[str]) -> dict[str, str]:
    data = pathlib.Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE file")

    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    pe32plus = struct.unpack_from("<H", data, opt)[0] == 0x20B
    dd = opt + (112 if pe32plus else 96)
    ndd = struct.unpack_from("<I", data, opt + (108 if pe32plus else 92))[0]
    secs = opt + size_opt

    sections = []
    for i in range(nsec):
        s = secs + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((vaddr, max(vsize, rawsize), rawptr))

    def rva2off(rva: int) -> int:
        for vaddr, size, rawptr in sections:
            if vaddr <= rva < vaddr + size:
                return rawptr + (rva - vaddr)
        raise ValueError(f"rva {rva:#x} is outside every section")

    if ndd <= 6:
        raise ValueError("PE has no debug directory")
    dbg_rva, dbg_size = struct.unpack_from("<II", data, dd + 6 * 8)
    if not dbg_rva:
        raise ValueError("PE debug directory is empty")

    off = rva2off(dbg_rva)
    for i in range(dbg_size // 28):
        p = off + i * 28
        typ, size, addr, ptr = struct.unpack_from("<IIII", data, p + 12)
        if typ != 2 or size < 24:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        c = ptr or rva2off(addr)
        if data[c:c + 4] != b"RSDS":
            continue
        d1, d2, d3 = struct.unpack_from("<IHH", data, c + 4)
        rest = data[c + 12:c + 20]
        age = struct.unpack_from("<I", data, c + 20)[0]
        name = data[c + 24:c + 24 + size].split(b"\0")[0].decode("latin1")
        guid = f"{d1:08X}{d2:04X}{d3:04X}{rest.hex().upper()}"
        return {"pdb": name, "key": f"{guid}{age:X}", "guid": guid,
                "age": str(age)}
    raise ValueError("no CodeView record in the PE debug directory")


def download_pdb(pe_path: str | os.PathLike[str],
                 cache_dir: str | os.PathLike[str] | None = None) -> pathlib.Path:
    info = pe_debug_info(pe_path)
    if cache_dir is None:
        cache_dir = pathlib.Path(
            os.environ.get("VMEM_SYMBOL_CACHE", "~/.cache/vmem/symbols")
        ).expanduser()
    cache = pathlib.Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / info["pdb"]
    if dest.exists():
        return dest

    url = f"{MSDL}/{info['pdb']}/{info['key']}/{info['pdb']}"
    tmp = dest.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
    tmp.replace(dest)
    return dest


# ------------------------------------------------------------------ #
# MSF 7.0 + TPI                                                     #
# ------------------------------------------------------------------ #

def _msf_stream(data: bytes, want: int) -> bytes:
    if not data[:32].startswith(b"Microsoft C/C++ MSF 7.00"):
        raise ValueError("not an MSF 7.0 PDB")
    (page_size, _free, _pages, dir_bytes, _unknown,
     block_map) = struct.unpack_from("<6I", data, 32)

    n_dir = (dir_bytes + page_size - 1) // page_size
    dir_pages = struct.unpack_from(f"<{n_dir}I", data, block_map * page_size)
    directory = b"".join(
        data[p * page_size:(p + 1) * page_size] for p in dir_pages
    )[:dir_bytes]

    nstreams = struct.unpack_from("<I", directory, 0)[0]
    sizes = struct.unpack_from(f"<{nstreams}I", directory, 4)
    off = 4 + 4 * nstreams
    table = []
    for size in sizes:
        npages = (size + page_size - 1) // page_size
        pages = struct.unpack_from(f"<{npages}I", directory, off) if npages else ()
        off += 4 * npages
        table.append((size, pages))
    size, pages = table[want]
    return b"".join(data[p * page_size:(p + 1) * page_size] for p in pages)[:size]


def _load_tpi(data: bytes) -> dict[int, tuple[int, bytes]]:
    _ver, hdr_size, ti_min, _ti_max, rec_bytes = struct.unpack_from("<5I", data, 0)
    pos = hdr_size
    end = hdr_size + rec_bytes
    types: dict[int, tuple[int, bytes]] = {}
    ti = ti_min
    while pos + 4 <= end:
        length = struct.unpack_from("<H", data, pos)[0]
        if length < 2:
            break
        leaf = struct.unpack_from("<H", data, pos + 2)[0]
        types[ti] = (leaf, data[pos + 4:pos + 2 + length])
        pos += 2 + length
        ti += 1
    if pos != end:
        raise ValueError("TPI stream is truncated or malformed")
    return types


def _find_struct(types: dict[int, tuple[int, bytes]], name: str):
    needle = name.encode() + b"\0"
    best = None
    for ti, (leaf, body) in types.items():
        if leaf not in (0x1504, 0x1505, 0x1519) or needle not in body:
            continue
        if len(body) < 18:
            continue
        count, prop = struct.unpack_from("<HH", body, 0)
        field, _derived, _vshape = struct.unpack_from("<III", body, 4)
        p = 16
        size = -1
        numleaf = struct.unpack_from("<H", body, p)[0]
        if numleaf in _NUMERIC:
            ln, fmt = _NUMERIC[numleaf]
            if p + ln <= len(body):
                size = struct.unpack_from(fmt, body, p + 2)[0]
            p += ln
        else:
            size = numleaf
            p += 2
        if body[p:].split(b"\0")[0] != needle[:-1]:
            continue
        cand = {"index": ti, "count": count, "prop": prop,
                "fieldlist": field, "size": size}
        if prop & 0x80 or field == 0 or count == 0:
            best = best or cand
            continue
        return cand
    return best


def _parse_fields(types: dict[int, tuple[int, bytes]], fieldlist: int,
                  depth: int = 0) -> list[tuple[str, int]]:
    if depth > 8 or fieldlist not in types:
        return []
    leaf, body = types[fieldlist]
    if leaf != 0x1203:
        return []

    out: list[tuple[str, int]] = []
    p, n = 0, len(body)
    while p + 2 <= n:
        if 0xF0 <= body[p] <= 0xF3:  # LF_PAD0..3, one byte each
            p += 1
            continue
        lf = struct.unpack_from("<H", body, p)[0]
        if lf == 0x150D:  # LF_MEMBER
            o = struct.unpack_from("<H", body, p + 8)[0]
            if o in _NUMERIC:
                ln, fmt = _NUMERIC[o]
                offset = struct.unpack_from(fmt, body, p + 10)[0]
                olen = ln
            else:
                offset = o
                olen = 2
            npos = p + 8 + olen
            name = body[npos:].split(b"\0")[0].decode("latin1", "replace")
            out.append((name, offset))
            p += 8 + olen + len(name) + 1
        elif lf == 0x1404:  # LF_INDEX, continuation field list
            out.extend(_parse_fields(types, struct.unpack_from("<I", body, p + 4)[0],
                                     depth + 1))
            p += 8
        elif lf == 0x1400:  # LF_BCLASS
            o = struct.unpack_from("<H", body, p + 8)[0] if p + 10 <= n else 0
            p += 8 + (_NUMERIC[o][0] if o in _NUMERIC else 2)
        elif lf == 0x1409:  # LF_VFUNCTAB
            p += 8
        else:
            break
    return out


def struct_fields(pdb_path: str | os.PathLike[str], name: str) -> dict[str, int]:
    data = pathlib.Path(pdb_path).read_bytes()
    types = _load_tpi(_msf_stream(data, 2))
    found = _find_struct(types, name)
    if not found:
        raise KeyError(f"{name} not found in {pdb_path}")
    return dict(_parse_fields(types, found["fieldlist"]))


def eprocess_offsets(pdb_path: str | os.PathLike[str], arch: str,
                     name: str | None = None) -> EprocessOffsets:
    data = pathlib.Path(pdb_path).read_bytes()
    types = _load_tpi(_msf_stream(data, 2))

    def fields(struct_name: str) -> dict[str, int]:
        found = _find_struct(types, struct_name)
        if not found:
            raise KeyError(f"{struct_name} not found in {pdb_path}")
        return dict(_parse_fields(types, found["fieldlist"]))

    eproc = fields("_EPROCESS")
    kproc = fields("_KPROCESS")

    values = {}
    for key, (struct_name, member) in _MEMBERS.items():
        values[key] = eproc[member]
    values["directory_table_base"] = eproc.get("Pcb", 0) + kproc["DirectoryTableBase"]

    if name is None:
        name = f"{pathlib.Path(pdb_path).stem}-{arch}"
    return EprocessOffsets.from_mapping(name, arch, values)


# ------------------------------------------------------------------ #
# CLI                                                               #
# ------------------------------------------------------------------ #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m vmem.symbols")
    ap.add_argument("target", help="ntoskrnl.exe, or a .pdb")
    ap.add_argument("--arch", default="x86_64", choices=["x86_64", "arm64"])
    ap.add_argument("--cache", default=None, help="symbol cache directory")
    args = ap.parse_args(argv)

    path = pathlib.Path(args.target)
    if path.suffix.lower() != ".pdb":
        info = pe_debug_info(path)
        print(f"pdb={info['pdb']} key={info['key']}", file=sys.stderr)
        path = download_pdb(path, args.cache)
        print(f"cached at {path}", file=sys.stderr)

    prof = eprocess_offsets(path, args.arch)
    print(f"# {prof.name}")
    for key, value in prof.as_dict().items():
        print(f"{key} = 0x{value:X}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
