#!/bin/bash

# Check if disk image exists
if [ ! -f "build/saltyos-bios.img" ]; then
    echo "Error: build/saltyos-bios.img not found!"
    echo "Run ./scripts/build.sh first."
    exit 1
fi

echo "Starting QEMU with BIOS..."
echo "Press Ctrl+A, X to exit"
echo

# Use curses VGA output by default so stage2/kernel VGA text is visible.
# Override with DISPLAY_OPTS env var if you want a GUI (e.g. "-display gtk")
# or headless (e.g. "-nographic").
DISPLAY_OPTS=${DISPLAY_OPTS:--display gtk}

qemu-system-x86_64 \
    -drive format=raw,file=build/saltyos-bios.img \
    -serial mon:stdio \
    ${DISPLAY_OPTS} \
    -m 4096M \
    -smp 1 \
    -no-reboot \
    -no-shutdown -d int -no-reboot -D qemu.log
