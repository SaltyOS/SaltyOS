#!/usr/bin/env bash
# tools/run-qemu.sh — Centralized QEMU launcher for SaltyOS
# Usage: tools/run-qemu.sh <build-dir> [options]
#
# Options:
#   --arch ARCH       Target architecture (x86_64 or aarch64; auto-detected if omitted)
#   --mem SIZE        Memory size (default: 512M)
#   --smp N           CPU count (default: 1)
#   --debug           Enable interrupt/reset logging (-d int,cpu_reset -D qemu.log)
#   --headless        Disable GUI (-display none)
#   --gdb             Start GDB server (-s -S)
#   --uefi            Boot with OVMF/AAVMF UEFI firmware
#   --utm             Launch through UTM on macOS instead of invoking QEMU directly
#   --utm-name NAME   Override the UTM VM name (default: SaltyOS-<arch>)
#   --no-net          Skip virtio-net attachment
#   --net-mode MODE   user, tap, vmnet-shared, vmnet-host, or vmnet-bridged (default: user)
#   --tap-ifname IF   TAP interface name for --net-mode tap (default: tap0)
#   --vmnet-ifname IF Host interface name for --net-mode vmnet-bridged
#   --hvf             Enable Hypervisor.framework acceleration in UTM (default)
#   --no-hvf          Disable HVF in UTM (use TCG emulation)
#   --legacy-virtio   Force legacy (transitional) virtio devices
#   --disk FILE       Override boot disk path
#   --extra-disk FILE Attach an additional virtio-blk disk (repeatable)
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

usage() {
    sed -n '3,17p' "$0" | sed 's/^# \?//'
    exit 1
}

[[ $# -lt 1 ]] && usage
BUILD_DIR="$1"; shift

ARCH=""
MEM="512M"
SMP=""
DEBUG=false
HEADLESS=false
GDB=false
UEFI=false
UTM=false
UTM_NAME=""
NO_DATA=false
NO_NET=false
NET_MODE="user"
TAP_IFNAME="tap0"
VMNET_IFNAME=""
USE_HVF=true
LEGACY_VIRTIO=false
DISK=""
EXTRA_DISKS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)     ARCH="${2:?--arch requires a value}"; shift 2 ;;
        --mem)      MEM="${2:?--mem requires a value}"; shift 2 ;;
        --smp)      SMP="${2:?--smp requires a value}"; shift 2 ;;
        --debug)    DEBUG=true;   shift ;;
        --headless) HEADLESS=true; shift ;;
        --gdb)      GDB=true;    shift ;;
        --uefi)     UEFI=true;   shift ;;
        --utm)      UTM=true;    shift ;;
        --utm-name) UTM_NAME="${2:?--utm-name requires a value}"; shift 2 ;;
        --no-data)  NO_DATA=true; shift ;; # Deprecated no-op (kept for compatibility)
        --no-net)   NO_NET=true;  shift ;;
        --net-mode) NET_MODE="${2:?--net-mode requires a value}"; shift 2 ;;
        --tap-ifname) TAP_IFNAME="${2:?--tap-ifname requires a value}"; shift 2 ;;
        --vmnet-ifname) VMNET_IFNAME="${2:?--vmnet-ifname requires a value}"; shift 2 ;;
        --hvf)      USE_HVF=true; shift ;;
        --no-hvf)   USE_HVF=false; shift ;;
        --legacy-virtio) LEGACY_VIRTIO=true; shift ;;
        --disk)     DISK="${2:?--disk requires a value}"; shift 2 ;;
        --extra-disk) EXTRA_DISKS+=("${2:?--extra-disk requires a value}"); shift 2 ;;
        *)          die "unknown option: $1" ;;
    esac
done

# Auto-detect architecture from build directory
if [[ -z "$ARCH" ]]; then
    # Try reading from meson build options
    meson_opts="$BUILD_DIR/meson-info/intro-buildoptions.json"
    if [[ -f "$meson_opts" ]] && command -v python3 >/dev/null 2>&1; then
        ARCH=$(python3 -c "
import json, sys
opts = json.load(open('$meson_opts'))
for o in opts:
    if o['name'] == 'arch':
        print(o['value'])
        sys.exit(0)
print('x86_64')
" 2>/dev/null) || ARCH="x86_64"
    else
        ARCH="x86_64"
    fi
fi

# aarch64 always uses UEFI (no BIOS boot)
if [[ "$ARCH" == "aarch64" ]]; then
    UEFI=true
fi

if $UTM; then
    $GDB && die "--gdb is not supported with --utm"
    $LEGACY_VIRTIO && die "--legacy-virtio is not supported with --utm"

    UTM_CMD=(bash tools/run-utm.sh "$BUILD_DIR" --arch "$ARCH" --mem "$MEM" --net-mode "$NET_MODE")
    [[ -n "$SMP" ]] && UTM_CMD+=(--smp "$SMP")
    $DEBUG && UTM_CMD+=(--debug)
    $HEADLESS && UTM_CMD+=(--headless)
    $UEFI && UTM_CMD+=(--uefi)
    $NO_NET && UTM_CMD+=(--no-net)
    $USE_HVF || UTM_CMD+=(--no-hvf)
    [[ -n "$UTM_NAME" ]] && UTM_CMD+=(--utm-name "$UTM_NAME")
    [[ -n "$VMNET_IFNAME" ]] && UTM_CMD+=(--vmnet-ifname "$VMNET_IFNAME")
    [[ -n "$DISK" ]] && UTM_CMD+=(--disk "$DISK")
    if [[ ${#EXTRA_DISKS[@]} -gt 0 ]]; then
        for extra in "${EXTRA_DISKS[@]}"; do
            UTM_CMD+=(--extra-disk "$extra")
        done
    fi
    exec "${UTM_CMD[@]}"
fi

# --- Architecture-specific QEMU configuration ---
case "$ARCH" in
    x86_64)
        QEMU=qemu-system-x86_64
        MACHINE=q35
        CPU=default
        BLK_DEVICE="virtio-blk-pci"
        if $LEGACY_VIRTIO; then
            NET_DEVICE="virtio-net-pci"
        else
            NET_DEVICE="virtio-net-pci,disable-legacy=on"
        fi
        EXTRA_DEVICES=""
        ;;
    aarch64)
        QEMU=qemu-system-aarch64
        MACHINE="virt,gic-version=3"
        CPU=cortex-a72
        if $LEGACY_VIRTIO; then
            BLK_DEVICE="virtio-blk-pci"
            NET_DEVICE="virtio-net-pci"
        else
            BLK_DEVICE="virtio-blk-pci,disable-legacy=on"
            NET_DEVICE="virtio-net-pci,disable-legacy=on"
        fi
        EXTRA_DEVICES="-device ramfb"
        ;;
    *)
        die "unsupported architecture: $ARCH"
        ;;
esac

CMD=($QEMU
    -machine "$MACHINE"
    -cpu "$CPU"
    -m "$MEM"
    -serial stdio
    -no-reboot
    -no-shutdown
)

[[ -n "$SMP" ]] && CMD+=(-smp "$SMP")
[[ -n "$EXTRA_DEVICES" ]] && CMD+=($EXTRA_DEVICES)

# --- Boot disk ---
if $UEFI; then
    BOOT_DISK="${DISK:-$BUILD_DIR/saltyos-uefi.img}"
    # Auto-build UEFI image if missing
    if [[ ! -f "$BOOT_DISK" && -z "$DISK" ]]; then
        echo "Building UEFI disk image..." >&2
        meson compile -C "$BUILD_DIR" uefi_image
    fi
    [[ -f "$BOOT_DISK" ]] || die "UEFI disk not found: $BOOT_DISK"

    # Discover OVMF/AAVMF firmware
    ovmf_code="${OVMF_CODE:-}"
    ovmf_vars="${OVMF_VARS:-}"
    if [[ -z "$ovmf_code" ]]; then
        if [[ "$ARCH" == "aarch64" ]]; then
            for cand in \
                /usr/share/AAVMF/AAVMF_CODE.fd \
                /usr/share/edk2/aarch64/QEMU_EFI-pflash.raw \
                /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
                /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
                /usr/local/share/qemu/edk2-aarch64-code.fd; do
                [[ -f "$cand" ]] && { ovmf_code="$cand"; break; }
            done
        else
            for cand in \
                /usr/share/edk2-ovmf/OVMF_CODE.fd \
                /usr/share/OVMF/OVMF_CODE_4M.fd \
                /usr/share/ovmf/OVMF.fd \
                /usr/share/qemu/OVMF.fd \
                /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
                /usr/local/share/qemu/edk2-x86_64-code.fd; do
                [[ -f "$cand" ]] && { ovmf_code="$cand"; break; }
            done
        fi
    fi
    if [[ -z "$ovmf_vars" ]]; then
        if [[ "$ARCH" == "aarch64" ]]; then
            for cand in \
                /usr/share/AAVMF/AAVMF_VARS.fd \
                /usr/share/edk2/aarch64/vars-template-pflash.raw \
                /opt/homebrew/share/qemu/edk2-arm-vars.fd \
                /usr/local/share/qemu/edk2-arm-vars.fd; do
                [[ -f "$cand" ]] && { ovmf_vars="$cand"; break; }
            done
        else
            for cand in \
                /usr/share/edk2-ovmf/OVMF_VARS.fd \
                /usr/share/OVMF/OVMF_VARS_4M.fd \
                /usr/share/OVMF/OVMF_VARS.fd \
                /opt/homebrew/share/qemu/edk2-i386-vars.fd \
                /usr/local/share/qemu/edk2-i386-vars.fd; do
                [[ -f "$cand" ]] && { ovmf_vars="$cand"; break; }
            done
        fi
    fi
    [[ -n "$ovmf_code" ]] || die "OVMF/AAVMF firmware not found. Set OVMF_CODE (and optionally OVMF_VARS)."

    if [[ -n "$ovmf_vars" && -f "$ovmf_vars" ]]; then
        ovmf_vars_runtime="$BUILD_DIR/OVMF_VARS.fd"
        [[ -f "$ovmf_vars_runtime" ]] || cp "$ovmf_vars" "$ovmf_vars_runtime"
        CMD+=(-drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
              -drive "if=pflash,format=raw,file=$ovmf_vars_runtime")
    else
        CMD+=(-bios "$ovmf_code")
    fi
    CMD+=(-drive "file=$BOOT_DISK,format=raw,if=none,id=bootdisk"
          -device "$BLK_DEVICE,drive=bootdisk")
else
    BOOT_DISK="${DISK:-$BUILD_DIR/saltyos.img}"
    [[ -f "$BOOT_DISK" ]] || die "boot disk not found: $BOOT_DISK"
    CMD+=(-drive "file=$BOOT_DISK,format=raw,if=none,id=bootdisk"
          -device "$BLK_DEVICE,drive=bootdisk")
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
          -device "$BLK_DEVICE,drive=$drive_id")
done

# --- Networking ---
if ! $NO_NET; then
    case "$NET_MODE" in
        user)
            CMD+=(-netdev user,id=net0)
            ;;
        tap)
            [[ -n "$TAP_IFNAME" ]] || die "--tap-ifname is required for --net-mode tap"
            CMD+=(-netdev "tap,id=net0,ifname=$TAP_IFNAME,script=no,downscript=no")
            ;;
        vmnet-shared)
            CMD+=(-netdev vmnet-shared,id=net0)
            ;;
        vmnet-host)
            CMD+=(-netdev vmnet-host,id=net0)
            ;;
        vmnet-bridged)
            [[ -n "$VMNET_IFNAME" ]] || die "--vmnet-ifname is required for --net-mode vmnet-bridged"
            CMD+=(-netdev "vmnet-bridged,id=net0,ifname=$VMNET_IFNAME")
            ;;
        *)
            die "unsupported net mode: $NET_MODE"
            ;;
    esac
    CMD+=(-device "$NET_DEVICE,netdev=net0")
fi

# --- Debug logging ---
$DEBUG && CMD+=(-d int,cpu_reset -D qemu.log)

# --- Headless ---
$HEADLESS && CMD+=(-display none)

# --- GDB server ---
$GDB && CMD+=(-s)

exec "${CMD[@]}"
