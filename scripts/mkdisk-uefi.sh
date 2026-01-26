#!/bin/bash
set -e

# Create UEFI disk image (FAT32 with EFI System Partition)
echo "Creating UEFI disk image..."

# Check if required files exist
if [ ! -f "build/BOOTX64.EFI" ]; then
    echo "Error: build/BOOTX64.EFI not found!"
    echo "Run ./scripts/build.sh first."
    exit 1
fi

if [ ! -f "build/kernel.elf" ]; then
    echo "Error: build/kernel.elf not found!"
    echo "Run ./scripts/build.sh first."
    exit 1
fi

# Create EFI directory structure
mkdir -p build/uefi-disk/EFI/BOOT

# Copy bootloader
cp build/BOOTX64.EFI build/uefi-disk/EFI/BOOT/

# Copy kernel
cp build/kernel.elf build/uefi-disk/

# Create disk image
dd if=/dev/zero of=build/saltyos-uefi.img bs=1M count=64 2>/dev/null

# Format as FAT32
if command -v mkfs.vfat &> /dev/null; then
    mkfs.vfat -F 32 build/saltyos-uefi.img
else
    echo "Warning: mkfs.vfat not found, skipping filesystem creation"
    exit 0
fi

# Copy files to disk image using mcopy
if command -v mcopy &> /dev/null; then
    echo "Copying files to disk image..."

    # First create the EFI/BOOT directory in the image
    mmd -i build/saltyos-uefi.img ::/EFI
    mmd -i build/saltyos-uefi.img ::/EFI/BOOT

    # Copy files
    mcopy -i build/saltyos-uefi.img build/uefi-disk/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/
    mcopy -i build/saltyos-uefi.img build/uefi-disk/kernel.elf ::/

    echo "Files copied successfully."
else
    echo "Error: mcopy not found (install mtools package)"
    echo "  Debian/Ubuntu: sudo apt install mtools"
    echo "  Fedora: sudo dnf install mtools"
    echo "  Arch: sudo pacman -S mtools"
    exit 1
fi

echo "UEFI disk image created: build/saltyos-uefi.img"
