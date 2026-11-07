"""vmem -- guest physical/virtual memory access.

The C extension ``vmem._core`` knows nothing about Windows; the profile and
convenience layers live here in Python.
"""
from __future__ import annotations

from ._core import ARM64, X86_64, Memory, Scanner, Space, Windows, version
from .profiles import EprocessOffsets, load_profile, parse_windbg

__all__ = [
    "ARM64",
    "X86_64",
    "Memory",
    "Scanner",
    "Space",
    "Windows",
    "EprocessOffsets",
    "load_profile",
    "parse_windbg",
    "version",
]

__version__ = version
