#!/usr/bin/env bash
#
# Headless Windows 11 ARM64 VM under QEMU/HVF, prepared for vmem.
#
#   scripts/qemu-win11.sh install     # unattended install from the ISO
#   scripts/qemu-win11.sh run         # boot the installed disk, QMP ready
#   scripts/qemu-win11.sh shot [png]  # screenshot via QMP
#   scripts/qemu-win11.sh status      # QMP status
#   scripts/qemu-win11.sh type <text> # type into the guest (UEFI shell/WinPE)
#   scripts/qemu-win11.sh key <key>   # one HMP key, e.g. shift-f10, ret
#   scripts/qemu-win11.sh dump [elf]  # vmem qemu-dump via QMP
#   scripts/qemu-win11.sh stop        # quit the VM
#
# Notes on this platform:
#  * ArmVirtQemu has no AHCI driver, and Windows ARM64 has no PIIX IDE driver.
#    So the ISO must be on USB (bootable by firmware *and* readable by WinPE).
#  * The firmware has no default boot order, so it drops to the UEFI shell.
#    At the shell, run the path shown in the mapping table, e.g.:
#        fs1:\efi\boot\bootaa64.efi
#    and press a key at the "Press any key to boot from CD or DVD" prompt.
#  * Autounattend.xml is delivered on a tiny ISO9660 disc, which Windows Setup
#    finds by itself (FAT stick images were not readable by WinPE here).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VM_DIR="${VM_DIR:-$HOME/VMs/vmem-win11}"
ISO="${ISO:-$HOME/Downloads/Windows11_Client_arm64_en-us_26300_9457.iso}"
FIRMWARE="${FIRMWARE:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"
DISK="$VM_DIR/win.raw"
VARS="$VM_DIR/vars.fd"
AU_ISO="$VM_DIR/unattend.iso"
QMP="$VM_DIR/qmp.sock"

MEM="${MEM:-4096}"
CPUS="${CPUS:-6}"
DISK_SIZE="${DISK_SIZE:-64G}"
DISPLAY_MODE="${DISPLAY_MODE:-none}"

die() { echo "error: $*" >&2; exit 1; }

build_disk() {
    [ -f "$DISK" ] && return
    echo "creating $DISK ($DISK_SIZE)"
    qemu-img create -f raw "$DISK" "$DISK_SIZE" >/dev/null
}

init() {
    mkdir -p "$VM_DIR"
    [ -f "$VARS" ] || dd if=/dev/zero of="$VARS" bs=1048576 count=64 2>/dev/null
    build_disk
    # A tiny ISO9660 disc for Autounattend.xml: Windows reads ISO natively,
    # whereas QEMU's USB-stick FAT images trip WinPE up.
    if [ ! -f "$AU_ISO" ]; then
        local d="$VM_DIR/au-staging"
        rm -rf "$d"; mkdir -p "$d"
        cp "$SCRIPT_DIR/autounattend.xml" "$d/Autounattend.xml"
        hdiutil makehybrid -o "$AU_ISO" -iso -joliet \
            -default-volume-name UNATTEND "$d" >/dev/null
        rm -rf "$d"
    fi
}

base_args=(
    -M virt,accel=hvf,highmem=on
    -cpu host
    -smp "$CPUS"
    -m "$MEM"
    -drive if=pflash,format=raw,readonly=on,file="$FIRMWARE"
    -drive if=pflash,format=raw,file="$VARS"
    -drive if=none,id=disk,file="$DISK",format=raw,cache=writeback,discard=unmap
    -device nvme,drive=disk,serial=VMEM001
    -device qemu-xhci,id=xhci
    -device usb-kbd
    -device usb-tablet
    -device ramfb
    -qmp "unix:$QMP,server=on,wait=off"
)

qmp() {
    uv run --quiet --project "$PROJECT_DIR" python - "$QMP" "$@" <<'PY'
import sys
from vmem.qemu import QmpClient

sock, cmd, *rest = sys.argv[1:]
with QmpClient(sock) as c:
    if cmd == "status":
        print(c.command("query-status"))
    elif cmd == "shot":
        c.screendump(rest[0])
        print(rest[0])
    elif cmd == "quit":
        c.command("quit")
    elif cmd == "type":
        c.type_text(" ".join(rest))
    elif cmd == "key":
        c.sendkey(rest[0])
    else:
        raise SystemExit(f"unknown qmp command {cmd}")
PY
}

case "${1:-}" in
install)
    init
    [ -f "$ISO" ] || die "ISO not found: $ISO"
    [ -f "$FIRMWARE" ] || die "UEFI firmware not found: $FIRMWARE"
    rm -f "$QMP"
    exec qemu-system-aarch64 "${base_args[@]}" \
        -drive if=none,id=cd,file="$ISO",media=cdrom,readonly=on,file.locking=off \
        -device usb-storage,drive=cd \
        -drive if=none,id=au,file="$AU_ISO",media=cdrom,readonly=on \
        -device usb-storage,drive=au \
        -display "$DISPLAY_MODE"
    ;;
run)
    init
    [ -f "$DISK" ] || die "no disk; run 'install' first"
    rm -f "$QMP"
    exec qemu-system-aarch64 "${base_args[@]}" \
        -display "$DISPLAY_MODE"
    ;;
shot)
    qmp shot "${2:-$VM_DIR/shot.png}"
    ;;
status)
    qmp status
    ;;
type)
    qmp type "$2"
    ;;
key)
    qmp key "$2"
    ;;
quit|stop)
    qmp quit
    ;;
dump)
    out="${2:-$VM_DIR/win.elf}"
    uv run --project "$PROJECT_DIR" vmem qemu-dump \
        --qmp "$QMP" --out "$out" --registers
    echo "core: $out"
    echo "try: uv run vmem info --core $out"
    ;;
*)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
