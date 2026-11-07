"""Command line interface."""
from __future__ import annotations

import argparse
import pathlib
import sys

from . import Memory, Windows, load_profile
from .profiles import PROFILE_DIR, list_profiles, parse_windbg
from .qemu import QmpClient, qmp_from_pid


def _default_profile(arch: str) -> str:
    return "win11-26300-arm64" if arch == "arm64" else "win11-25h2-x64"


def _open(args) -> Memory:
    path = pathlib.Path(args.core)
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        return Memory.open_elf(path, arch=args.arch)
    if not args.arch:
        raise SystemExit("flat dumps need --arch {x86_64,arm64}")
    return Memory.open_flat(path, arch=args.arch, gpa_base=args.gpa_base,
                            below_4g=args.below_4g)


def _windows(args) -> Windows:
    mem = _open(args)
    name = args.profile or _default_profile(mem.arch)
    prof = load_profile(name)
    return Windows(mem, prof.as_dict())


def _hexdump(data: bytes, base: int) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:016X}  {hexpart:<47}  {text}")
    return "\n".join(lines)


def cmd_info(args) -> int:
    mem = _open(args)
    print(f"arch      : {mem.arch}")
    print(f"size      : {mem.size:#x} ({mem.size / (1 << 20):.1f} MiB)")
    print(f"gpa range : {mem.min_gpa:#x} .. {mem.max_gpa:#x}")
    print("segments  :")
    for gpa, size, off in mem.segments:
        print(f"  gpa {gpa:#012x}  size {size:#012x}  file offset {off:#x}")
    return 0


def cmd_ps(args) -> int:
    win = _windows(args)
    procs = win.processes()
    print(f"# {len(procs)} processes  (system_pa={win.system_pa:#x} "
          f"kernel_base={win.kernel_base:#x})")
    print(f"{'PID':>8}  {'PPID':>8}  {'THR':>4}  {'VSIZE':>12}  NAME")
    for p in procs:
        print(f"{p['pid']:>8}  {p['ppid']:>8}  {p['threads']:>4}  "
              f"{p['vsize']:>12}  {p['name']}")
    return 0


def cmd_read(args) -> int:
    if args.pa is not None:
        mem = _open(args)
        data = mem.read(args.pa, args.length)
        base = args.pa
    else:
        win = _windows(args)
        target = args.pid if args.pid is not None else args.name
        if target is None:
            print("read: give --pa, or --pid/--name with --va", file=sys.stderr)
            return 2
        space = win.space(target)
        data = space.read(args.va, args.length)
        base = args.va

    if args.out:
        pathlib.Path(args.out).write_bytes(data)
        print(f"wrote {len(data)} bytes to {args.out}")
    else:
        print(_hexdump(data, base))
    return 0


def cmd_scan(args) -> int:
    mem = _open(args)
    if args.hex:
        needle = bytes.fromhex(args.hex)
    else:
        needle = args.pattern.encode()
    for gpa in mem.scan(needle, start=args.start, end=args.end):
        print(f"{gpa:#012x}")
    return 0


def cmd_qemu_dump(args) -> int:
    socket_path = args.qmp
    if socket_path is None and args.pid is not None:
        socket_path = qmp_from_pid(args.pid)
    if socket_path is None:
        print("qemu-dump: --qmp is required (could not detect it)", file=sys.stderr)
        return 2
    with QmpClient(socket_path) as qmp:
        if args.registers:
            for k, v in sorted(qmp.registers().items()):
                print(f"{k} = {v:#x}")
        qmp.dump_guest_memory(args.out, fmt=args.format)
    print(f"wrote {args.out}")
    return 0


def cmd_profile(args) -> int:
    if args.action == "list":
        for name in list_profiles():
            print(name)
        return 0
    if args.action == "show":
        prof = load_profile(args.name)
        print(f"# {prof.name} ({prof.arch})")
        for k, v in prof.as_dict().items():
            print(f"{k} = 0x{v:X}")
        return 0
    if args.action == "from-windbg":
        text = pathlib.Path(args.file).read_text()
        prof = parse_windbg(text, name=args.name or "windbg", arch=args.arch)
        print(f"# {prof.name} ({prof.arch})")
        for k, v in prof.as_dict().items():
            print(f"{k} = 0x{v:X}")
        return 0
    if args.action == "from-pdb":
        from .symbols import eprocess_offsets
        prof = eprocess_offsets(args.file, args.arch, name=args.name)
        print(f"# {prof.name} ({prof.arch})")
        for k, v in prof.as_dict().items():
            print(f"{k} = 0x{v:X}")
        return 0
    raise SystemExit(f"unknown profile action {args.action!r}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vmem")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def core_args(p):
        p.add_argument("--core", required=True,
                       help="ELF core dump, or a raw physical memory dump")
        p.add_argument("--arch", choices=["x86_64", "arm64"], default=None)
        p.add_argument("--gpa-base", type=lambda s: int(s, 0), default=0,
                       help="raw dumps only: GPA of file offset 0")
        p.add_argument("--below-4g", type=lambda s: int(s, 0), default=0,
                       help="raw dumps only: bytes below the 4 GiB hole")

    p = sub.add_parser("info", help="describe a core dump")
    core_args(p)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("ps", help="list guest processes")
    core_args(p)
    p.add_argument("--profile", default=None)
    p.set_defaults(func=cmd_ps)

    p = sub.add_parser("read", help="read physical or virtual memory")
    core_args(p)
    p.add_argument("--pa", type=lambda s: int(s, 0), default=None)
    p.add_argument("--va", type=lambda s: int(s, 0), default=0)
    p.add_argument("--pid", type=int, default=None)
    p.add_argument("--name", default=None)
    p.add_argument("--len", dest="length", type=lambda s: int(s, 0), default=64)
    p.add_argument("--out", default=None)
    p.add_argument("--profile", default=None)
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("scan", help="scan physical memory")
    core_args(p)
    p.add_argument("--pattern", default=None)
    p.add_argument("--hex", default=None)
    p.add_argument("--start", type=lambda s: int(s, 0), default=0)
    p.add_argument("--end", type=lambda s: int(s, 0), default=0)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("qemu-dump", help="dump guest RAM over QMP")
    p.add_argument("--qmp", default=None)
    p.add_argument("--pid", type=int, default=None)
    p.add_argument("--out", required=True)
    p.add_argument("--format", default="elf", choices=["elf", "kdump-elf", "win-dmp"])
    p.add_argument("--registers", action="store_true")
    p.set_defaults(func=cmd_qemu_dump)

    p = sub.add_parser("profile", help="inspect offset profiles")
    p.add_argument("action", choices=["list", "show", "from-windbg", "from-pdb"])
    p.add_argument("name", nargs="?", default=None)
    p.add_argument("file", nargs="?", default=None)
    p.add_argument("--arch", choices=["x86_64", "arm64"], default="x86_64")
    p.set_defaults(func=cmd_profile)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
