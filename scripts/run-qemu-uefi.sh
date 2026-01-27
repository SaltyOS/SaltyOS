#!/bin/bash

# Find OVMF firmware
OVMF_CODE=""
OVMF_VARS=""

if [ -f "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd" ]; then
    OVMF_CODE="/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"
    OVMF_VARS="/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"
elif [ -f "/usr/share/edk2-ovmf/OVMF_CODE.fd" ]; then
    OVMF_CODE="/usr/share/edk2-ovmf/OVMF_CODE.fd"
    OVMF_VARS="/usr/share/edk2-ovmf/OVMF_VARS.fd"
elif [ -f "/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd" ]; then
    OVMF_CODE="/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd"
    OVMF_VARS="/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd"
fi

if [ -z "$OVMF_CODE" ]; then
    echo "Error: OVMF firmware not found!"
    echo "Please install edk2-ovmf or OVMF package."
    exit 1
fi

# Use a writable copy for OVMF_VARS so UEFI can save boot entries
VARS_COPY="build/ovmf_vars.fd"
if [ ! -f "$VARS_COPY" ]; then
    cp "$OVMF_VARS" "$VARS_COPY"
fi

# Check if disk image exists
if [ ! -f "build/saltyos-uefi.img" ]; then
    echo "Error: build/saltyos-uefi.img not found!"
    echo "Run ./scripts/build.sh first."
    exit 1
fi

echo "Starting QEMU with UEFI firmware..."
echo "Press Ctrl+A, X to exit"
echo

# Use curses VGA output by default so stage2/kernel VGA text is visible.
# Override with DISPLAY_OPTS env var if you want a GUI (e.g. "-display gtk")
# or headless (e.g. "-nographic").
DISPLAY_OPTS=${DISPLAY_OPTS:--display gtk}

qemu-system-x86_64 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$VARS_COPY" \
    -drive format=raw,file=build/saltyos-uefi.img \
    -boot order=c \
    -serial mon:stdio \
    ${DISPLAY_OPTS} \
    -m 4096M \
    -smp 1 \
    -no-reboot \
    -no-shutdown -d int -no-reboot -D qemu.log
