"""EPROCESS offset profiles.

Offsets are data, not code: they depend on the Windows build and on the
architecture, so they are kept in TOML files and can also be imported from
WinDbg output or from a PDB (see vmem.symbols).
"""
from __future__ import annotations

import dataclasses
import pathlib
import re
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

PROFILE_DIR = pathlib.Path(__file__).with_name("profiles")

_FIELDS = (
    "directory_table_base",
    "unique_process_id",
    "active_process_links",
    "image_file_name",
    "virtual_size",
    "active_threads",
    "peb",
    "inherited_from_unique_process_id",
)

_OPTIONAL = ("peb", "inherited_from_unique_process_id")


@dataclasses.dataclass(frozen=True)
class EprocessOffsets:
    name: str
    arch: str
    directory_table_base: int
    unique_process_id: int
    active_process_links: int
    image_file_name: int
    virtual_size: int
    active_threads: int
    peb: int = 0
    inherited_from_unique_process_id: int = 0

    def as_dict(self) -> dict[str, int]:
        """The mapping accepted by :class:`vmem.Windows`."""
        return {f: int(getattr(self, f)) for f in _FIELDS}

    @classmethod
    def from_mapping(cls, name: str, arch: str,
                     values: dict[str, Any]) -> "EprocessOffsets":
        kw = {f: int(values[f]) for f in _FIELDS if f in values}
        missing = [f for f in _FIELDS if f not in kw and f not in _OPTIONAL]
        if missing:
            raise ValueError(f"profile {name!r} is missing: {', '.join(missing)}")
        return cls(name=name, arch=arch, **kw)


def list_profiles() -> list[str]:
    return sorted(p.stem for p in PROFILE_DIR.glob("*.toml"))


def load_profile(name_or_path: str | pathlib.Path) -> EprocessOffsets:
    p = pathlib.Path(name_or_path)
    if not p.exists():
        p = PROFILE_DIR / f"{name_or_path}.toml"
    if not p.exists():
        raise FileNotFoundError(
            f"unknown profile {name_or_path!r}; available: {list_profiles()}"
        )
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    arch = data.get("arch", "x86_64")
    return EprocessOffsets.from_mapping(
        data.get("name", p.stem), arch, data.get("offsets", {})
    )


# WinDbg prints members as "   +0x01c0 UniqueProcessId  : Ptr64 Void" and
# older/other tools as "+0x1C0  UniqueProcessId".  Both are handled.
_LINE = re.compile(r"^\s*\+0x([0-9a-fA-F]+)\s+([A-Za-z_][\w]*)")


def parse_windbg(text: str, name: str = "windbg", arch: str = "x86_64") -> EprocessOffsets:
    found = {member: int(off, 16) for off, member in _LINE.findall(text)}
    return EprocessOffsets.from_mapping(name, arch, found)
