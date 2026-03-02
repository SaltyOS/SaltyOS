#!/usr/bin/env bash
# tools/run-qemu.sh — Centralized QEMU launcher for SaltyOS
# Usage: tools/run-qemu.sh <build-dir> [options]
#
# Options:
#   --mem SIZE        Memory size (default: 512M)
#   --smp N           CPU count (default: 1)
#   --debug           Enable interrupt/reset logging (-d int,cpu_reset -D qemu.log)
#   --headless        Disable GUI (-display none)
#   --gdb             Start GDB server (-s -S)
#   --uefi            Boot with OVMF UEFI firmware
#   --no-net          Skip virtio-net attachment
#   --disk FILE       Override boot disk path
#   --extra-disk FILE Attach an additional virtio-blk disk (repeatable)
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

usage() {
    sed -n '3,13p' "$0" | sed 's/^# \?//'
    exit 1
}

[[ $# -lt 1 ]] && usage
BUILD_DIR="$1"; shift

MEM="512M"
SMP=""
DEBUG=false
HEADLESS=false
GDB=false
UEFI=false
NO_DATA=false
NO_NET=false
DISK=""
EXTRA_DISKS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mem)      MEM="${2:?--mem requires a value}"; shift 2 ;;
        --smp)      SMP="${2:?--smp requires a value}"; shift 2 ;;
        --debug)    DEBUG=true;   shift ;;
        --headless) HEADLESS=true; shift ;;
        --gdb)      GDB=true;    shift ;;
        --uefi)     UEFI=true;   shift ;;
        --no-data)  NO_DATA=true; shift ;; # Deprecated no-op (kept for compatibility)
        --no-net)   NO_NET=true;  shift ;;
        --disk)     DISK="${2:?--disk requires a value}"; shift 2 ;;
        --extra-disk) EXTRA_DISKS+=("${2:?--extra-disk requires a value}"); shift 2 ;;
        *)          die "unknown option: $1" ;;
    esac
done

# --- Base command ---
CMD=(qemu-system-x86_64
    -machine q35
    -cpu qemu64
    -m "$MEM"
    -serial stdio
    -no-reboot
    -no-shutdown
)

[[ -n "$SMP" ]] && CMD+=(-smp "$SMP")

# --- Boot disk ---
if $UEFI; then
    BOOT_DISK="${DISK:-$BUILD_DIR/saltyos-uefi.img}"
    # Auto-build UEFI image if missing
    if [[ ! -f "$BOOT_DISK" && -z "$DISK" ]]; then
        echo "Building UEFI disk image..." >&2
        meson compile -C "$BUILD_DIR" uefi_image
    fi
    [[ -f "$BOOT_DISK" ]] || die "UEFI disk not found: $BOOT_DISK"

    # Discover OVMF firmware
    ovmf_code="${OVMF_CODE:-}"
    ovmf_vars="${OVMF_VARS:-}"
    if [[ -z "$ovmf_code" ]]; then
        for cand in \
            /usr/share/edk2-ovmf/OVMF_CODE.fd \
            /usr/share/OVMF/OVMF_CODE_4M.fd \
            /usr/share/ovmf/OVMF.fd \
            /usr/share/qemu/OVMF.fd; do
            [[ -f "$cand" ]] && { ovmf_code="$cand"; break; }
        done
    fi
    if [[ -z "$ovmf_vars" ]]; then
        for cand in \
            /usr/share/edk2-ovmf/OVMF_VARS.fd \
            /usr/share/OVMF/OVMF_VARS_4M.fd \
            /usr/share/OVMF/OVMF_VARS.fd; do
            [[ -f "$cand" ]] && { ovmf_vars="$cand"; break; }
        done
    fi
    [[ -n "$ovmf_code" ]] || die "OVMF firmware not found. Set OVMF_CODE (and optionally OVMF_VARS)."

    if [[ -n "$ovmf_vars" && -f "$ovmf_vars" ]]; then
        ovmf_vars_runtime="$BUILD_DIR/OVMF_VARS.fd"
        [[ -f "$ovmf_vars_runtime" ]] || cp "$ovmf_vars" "$ovmf_vars_runtime"
        CMD+=(-drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
              -drive "if=pflash,format=raw,file=$ovmf_vars_runtime")
    else
        CMD+=(-bios "$ovmf_code")
    fi
    CMD+=(-drive "file=$BOOT_DISK,format=raw,if=none,id=bootdisk"
          -device virtio-blk-pci,drive=bootdisk)
else
    BOOT_DISK="${DISK:-$BUILD_DIR/saltyos.img}"
    [[ -f "$BOOT_DISK" ]] || die "boot disk not found: $BOOT_DISK"
    CMD+=(-drive "file=$BOOT_DISK,format=raw,if=none,id=bootdisk"
          -device virtio-blk-pci,drive=bootdisk)
fi

# --- Optional extra disks (manual, explicit) ---
if $NO_DATA; then
    echo "warning: --no-data is deprecated and has no effect (no auto data disks are attached)" >&2
fi
for i in "${!EXTRA_DISKS[@]}"; do
    extra="${EXTRA_DISKS[$i]}"
    [[ -f "$extra" ]] || die "extra disk not found: $extra"
    drive_id="extra${i}"
    CMD+=(-drive "file=$extra,format=raw,if=none,id=$drive_id"
          -device virtio-blk-pci,drive="$drive_id")
done

# --- Networking ---
if ! $NO_NET; then
    CMD+=(-netdev user,id=net0
          -device virtio-net-pci,netdev=net0)
fi

# --- Debug logging ---
$DEBUG && CMD+=(-d int,cpu_reset -D qemu.log)

# --- Headless ---
$HEADLESS && CMD+=(-display none)

# --- GDB server ---
$GDB && CMD+=(-s -S)

exec "${CMD[@]}"
