# vmem

Guest **physical and virtual memory access** for Windows guests, with a
hypervisor-agnostic C core and a thin CPython binding.

The design goal is a hard split:

```
src/core/        pure C11, no Python.h, no knowledge of the hypervisor
src/bindings/    only argument parsing and object conversion
src/vmem/        profiles, QEMU/QMP helpers, PDB symbols, CLI
```

The core turns "some source of guest physical memory" into a table of
`(guest physical address -> host offset)` segments, and everything above that
— page-table translation, scanning, `EPROCESS` enumeration — is identical for
QEMU, VirtualBox, a file dump, or anything else that can produce bytes.

## Quick start

```sh
cd ~/Documents/vmem
uv sync --extra dev

uv run pytest -q        # Python tests
make test-core          # pure C test, no Python involved
```

## Getting a memory image

### QEMU / UTM (recommended)

Start QEMU with a QMP socket:

```sh
qemu-system-aarch64 ... -qmp unix:/tmp/qmp.sock,server=on,wait=off
```

Then dump guest RAM as an ELF core (segments carry `p_paddr`, so the 4 GiB PCI
hole is described exactly):

```sh
uv run vmem qemu-dump --qmp /tmp/qmp.sock --out win.elf --registers
```

`--registers` prints `TTBR0_EL1`, `TTBR1_EL1`, `TCR_EL1` (or `CR3` on x86-64);
`TTBR1_EL1` is the kernel page-table base, which is useful for kernel-space
reads.  UTM uses QEMU underneath; point `--qmp` at its socket, or pass `--pid`
and let `vmem.qemu.qmp_from_pid()` look for `-qmp` on the command line.

You can also use a raw dump (`qemu` `pmemsave`, a physical-memory reader, ...)
and describe the layout yourself:

```sh
uv run vmem info --core ram.bin --arch arm64 --below-4g 0xC0000000
```

### Apple Silicon macOS (HVF): ready-made Win11 ARM64 VM

`scripts/qemu-win11.sh` creates a headless QEMU/HVF VM plus an unattended
install (Pro, local account `vmem`/`vmem`, TPM/Secure Boot checks bypassed):

```sh
./scripts/qemu-win11.sh install     # one-time, ~20-30 min
./scripts/qemu-win11.sh run         # boot installed Windows, QMP ready
./scripts/qemu-win11.sh dump        # writes ~/VMs/vmem-win11/win.elf
uv run vmem info --core ~/VMs/vmem-win11/win.elf
uv run vmem ps   --core ~/VMs/vmem-win11/win.elf
```

Other commands: `shot [png]`, `status`, `type <text>`, `key <key>`, `stop`.

What this setup had to work around (all handled by the script now):

- **ISO on USB CD.** ArmVirtQemu has no AHCI driver and Windows ARM64 WinPE
  has no PIIX-IDE driver, so a CD on the default bus boots but is unreadable
  to setup. A USB CD is seen by both firmware and WinPE.
- **UEFI boot order is empty**, so the firmware lands in the UEFI shell. From
  the mapping table run `fsN:\efi\boot\bootaa64.efi` (e.g. `fs1:`) and press a
  key at the "Press any key to boot from CD or DVD" prompt.
- **Answer file on a tiny ISO9660 disc** (second USB CD). Windows Setup picks
  it up on its own; FAT stick images built with `vvfat`/`hdiutil`/`mtools` all
  failed in WinPE with QEMU 11.1 on macOS.
- **UDF ISO caveat:** the retail ISO is UDF, so `xorriso` cannot re-master it
  (it only copies the ISO9660 stub). Hence the separate answer-file disc.
- The retail ISO is index 1=Home, 2=Home SL, 3=Pro; the generic Pro key is
  used so setup doesn't stop at the product-key page.

### Live reads over QMP (no snapshot)

The same `ActiveProcessLinks` walk runs against a *running* VM. QMP is used for
reads (`xp /512gx`, one 4 KiB page per round trip, page-cached), so no dump file
is written during the walk.

A passive reader cannot cheaply discover the System `EPROCESS` anchor: finding
it normally means scanning 4 GiB, which is impractical over QMP. The anchor is
stable for the life of the boot, so take it once from a dump:

```sh
./scripts/qemu-win11.sh dump
uv run vmem ps --core ~/VMs/vmem-win11/win.elf     # prints system_pa=0x...
```

Then read the live guest directly (no further snapshots):

```sh
uv run vmem ps --qmp ~/VMs/vmem-win11/qmp.sock --system-pa 0x10d0b4080
```

```python
from vmem import Memory, Windows, load_profile
from vmem.qemu import QmpClient, QmpRam

qmp = QmpClient("~/VMs/vmem-win11/qmp.sock")
ram = QmpRam(qmp)                       # callable(offset, length) -> bytes
mem = Memory.open_callback(ram, [(0x40000000, 4 << 30, 0x40000000)],
                           arch="arm64")
win = Windows(mem, load_profile("win11-26300-arm64").as_dict(),
              system_pa=0x10d0b4080)
for p in win.processes():
    ...
```

A guest reboot changes the anchor, so re-derive it. For snapshot-free anchoring
too, start QEMU with `-object memory-backend-file,...,share=on
-machine memory-backend=mem` and map the RAM file live; a full scan is then
cheap and the anchor can be discovered on the fly.

### VirtualBox

`VBoxManage debugvm <vm> dumpvmcore --filename=core.elf` produces the same ELF
format and works with `Memory.open_elf`.  **Caveat:** on VirtualBox 7.2.20 for
macOS/ARM64 this asserts in `DBGFR3CoreWrite.cpp` (`dbgfR3GetCoreCpu`) and
aborts the running VM.  Do not run it against a live VM on that build.

### Linux live process

```python
from vmem import Memory
mem = Memory.open_procmem(pid)              # QEMU memfd, or largest anon rw map
mem = Memory.open_procmem_segments(pid, [(0, 0x80000000, host_start), ...])
```

Anonymous mappings cannot be `mmap`ed from another process, so this path reads
through `/proc/<pid>/mem`; the memfd path is a plain `pread`. The same pipeline
works from the CLI:

```sh
uv run vmem ps --vm-pid <qemu-pid> --arch x86_64
uv run vmem ps --vm-pid <qemu-pid> --arch x86_64 --profile my-win11-x64
```

Unlike the QMP path this does not need `--system-pa`: a full 4 GiB scan over
`pread` is fast enough to find the System EPROCESS on the fly. Make sure the
profile matches the guest build — the shipped `win11-25h2-x64` values are
carried over from the original tool and unverified. Regenerate with:

```sh
uv run python -m vmem.symbols ntoskrnl.exe --arch x86_64
```

## CLI

```sh
uv run vmem info  --core win.elf
uv run vmem ps    --core win.elf
uv run vmem read  --core win.elf --pa 0x1f0000 --len 64
uv run vmem read  --core win.elf --pid 1234 --va 0x7ff6a0000000 --len 64
uv run vmem scan  --core win.elf --pattern explorer.exe
uv run vmem profile list
uv run vmem profile show win11-26300-arm64
```

`ps` prints PID, PPID, thread count, virtual size and image name:

```
# 3 processes  (system_pa=0x200000 kernel_base=0x1000)
     PID      PPID   THR         VSIZE  NAME
       4         0     4       1048576  System
    1234         4     4       1048576  explorer.exe
```

## Python API

```python
from vmem import Memory, Windows, load_profile

mem = Memory.open_elf("win.elf")            # arch from e_machine
prof = load_profile("win11-26300-arm64")
win = Windows(mem, prof.as_dict())

for p in win.processes():
    print(f"{p['pid']:6} {p['ppid']:6} {p['name']}")

space = win.space("explorer.exe")           # or win.space(pid)
print(hex(space.base0))
print(space.read(0x7FF6A0000000, 16))
print(space.cstring(0x7FF6A0000000))
print(space.translate(0x7FF6A0000000))
```

Raw physical access and scanning:

```python
mem.read(gpa, n)            # zero-filled
mem.read_exact(gpa, n)      # None if the range is not fully backed
mem.u64(gpa), mem.i32(gpa), mem.f64(gpa)
for gpa in mem.scan(b"pattern", start=0, end=mem.max_gpa):
    ...
```

## Profiles and symbols

Offsets are data, not code.  Profiles live in `src/vmem/profiles/*.toml`:

```toml
name = "win11-26300-arm64"
arch = "arm64"
[offsets]
directory_table_base = 0x028
unique_process_id    = 0x1C0
active_process_links = 0x1C8
image_file_name      = 0x328
virtual_size         = 0x218
active_threads       = 0x370
peb                  = 0x2D0
inherited_from_unique_process_id = 0x2C0
```

The shipped ARM64 profile was extracted from the real `ntkrnlmp.pdb`
(build 26300.9457, GUID `7A9F162A39E89C67CD02CF2126D51A65`, age 1).

Regenerate or add a build:

```sh
# From a PE: reads the CodeView record, fetches the PDB from msdl.microsoft.com,
# parses MSF 7.0 + TPI (no third-party dependencies).
uv run python -m vmem.symbols ntoskrnl.exe --arch arm64

# From an existing PDB
uv run vmem profile from-pdb ntkrnlmp.pdb --arch arm64
```

You can also paste `dt nt!_EPROCESS` output:

```sh
uv run vmem profile from-windbg eprocess.txt --arch arm64
```

> The old x86-64 offsets (`UniqueProcessId = 0x1D0`, ...) are **wrong on
> ARM64** — `_KPROCESS`/`_EPROCESS` are smaller there.  Using them silently
> reads garbage.

## Design notes

**Segments, not one mapping.**  `vmem_mem` is a sorted list of segments, each
either directly mapped or read through a source callback.  That handles QEMU
memory slots, large pages, and the 4 GiB PCI hole without special cases.

**ARM64 translation.**  4 KiB granule, 4 levels (shifts 39/30/21/12), TTBR0 for
the low half and TTBR1 for the high half selected by bit 63, 1 GiB/2 MiB block
descriptors.  TTBR values carry an ASID in bits 63:48 and are masked.  x86-64
supports 1 GiB/2 MiB pages the same way the original code did.

**Two enumeration strategies.**  `ActiveProcessLinks` walking is exact and fast
when a usable kernel page-table base exists.  When it does not (notably ARM64,
where `EPROCESS.DirectoryTableBase` is a TTBR0 value and the kernel lives in
TTBR1), the code falls back to a physical scan for `EPROCESS` blocks validating
`ImageFileName`, `UniqueProcessId`, `DirectoryTableBase` and a canonical
`ActiveProcessLinks` pointer.  So enumeration works even with no symbol
knowledge of the kernel address space.

**Scanning is boundary-correct.**  Chunks carry the last `needle_len - 1` bytes
into the next one; the original implementation searched each 64 MiB chunk
independently and silently missed matches crossing a boundary.

**Errors are explicit.**  `read()` zero-fills holes (like a debugger);
`read_exact()` returns `None` when any byte is not backed.  Physical reads that
fall outside the guest address space never fault the process.

## Status / limitations

- Windows x64 and ARM64 page tables only; no 16 KiB/64 KiB ARM64 granules yet.
- No pagefile access: paged-out `EPROCESS` fields read as zero.
- No PEB / module walking yet (`EPROCESS.Peb` is exposed; the next step is
  `PEB.Ldr` -> `InMemoryOrderModuleList`).
- The core does not release the GIL during large reads/scans yet; the Python
  binding is serial for now.
- Live VirtualBox RAM on macOS is not supported (SIP/`task_for_pid`); use a core
  dump from QEMU/UTM, a raw dump, or a guest-side acquisition tool.
