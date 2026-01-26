#!/bin/bash
set -e

# Create BIOS disk image (MBR + stage1 + stage2 + kernel)
echo "Creating BIOS disk image..."

# Create 64MB disk image
dd if=/dev/zero of=build/saltyos-bios.img bs=1M count=64 2>/dev/null

# Write MBR (stage1) - must be exactly 512 bytes
if [ -f "build/stage1.bin" ]; then
    dd if=build/stage1.bin of=build/saltyos-bios.img bs=512 count=1 conv=notrunc 2>/dev/null
    echo "Stage1 (MBR) written to disk"
else
    echo "Warning: build/stage1.bin not found, BIOS bootloader incomplete"
fi

# Write stage2 starting at sector 2 (1-based). Stage1 reads 32 sectors
# starting at CL=2 (1-based), which corresponds to dd seek=1 (0-based).
if [ -f "build/stage2.bin" ]; then
    dd if=build/stage2.bin \
       of=build/saltyos-bios.img \
       bs=512 \
       seek=1 \
       conv=notrunc \
       2>/dev/null
    echo "Stage2 written to disk (at sector 2)"
else
    echo "Warning: build/stage2.bin not found, BIOS bootloader incomplete"
fi

# Write kernel starting at sector 33
# This matches 'mov dword [current_sector], 33' in stage2.asm
if [ -f "build/kernel.elf" ]; then
    dd if=build/kernel.elf \
       of=build/saltyos-bios.img \
       bs=512 \
       seek=33 \
       conv=notrunc \
       2>/dev/null
    echo "Kernel written to disk (at sector 33)"
else
    echo "Warning: build/kernel.elf not found"
fi

# Write userspace ELF starting at sector 2048
if [ -f "build/userspace.elf" ]; then
    dd if=build/userspace.elf \
       of=build/saltyos-bios.img \
       bs=512 \
       seek=2048 \
       conv=notrunc \
       2>/dev/null
    echo "Userspace written to disk (at sector 2048)"
else
    echo "Warning: build/userspace.elf not found"
fi

echo "BIOS disk image created: build/saltyos-bios.img"
