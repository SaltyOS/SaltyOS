#!/bin/bash
set -e

# Create BIOS disk image (MBR + stage1 + stage2 + kernel)
echo "Creating BIOS disk image..."
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Create 64MB disk image
dd if=/dev/zero of=build/saltyos-bios.img bs=1M count=64 2>/dev/null

# Write MBR (stage1) - must be exactly 512 bytes
if [ -f "build/stage1.bin" ]; then
    dd if=build/stage1.bin of=build/saltyos-bios.img bs=512 count=1 conv=notrunc 2>/dev/null
    echo "Stage1 (MBR) written to disk"
else
    echo "Warning: build/stage1.bin not found, BIOS bootloader incomplete"
fi

# Write stage2 starting at sector 2 (1-based). Stage1 reads 64 sectors
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

# Write bootcore ELF starting at sector 4096
if [ -f "build/bootcore.elf" ]; then
    dd if=build/bootcore.elf \
       of=build/saltyos-bios.img \
       bs=512 \
       seek=4096 \
       conv=notrunc \
       2>/dev/null
    echo "Bootcore written to disk (at sector 4096)"
else
    echo "Warning: build/bootcore.elf not found"
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

# Write initrd (size header + data) starting at sector 2048
if [ -f "build/initrd.img" ]; then
    ROOT_DIR="$ROOT_DIR" python3 - <<'PY'
import os
root = os.environ.get("ROOT_DIR")
if not root:
    raise SystemExit("ROOT_DIR not set")
initrd = os.path.join(root, 'build', 'initrd.img')
hdr = os.path.join(root, 'build', 'initrd.hdr')
size = os.path.getsize(initrd)
with open(hdr, 'wb') as f:
    f.write(size.to_bytes(8, 'little'))
    f.write(b'\\x00' * (512 - 8))
PY
    dd if=build/initrd.hdr \
       of=build/saltyos-bios.img \
       bs=512 \
       seek=2048 \
       conv=notrunc \
       2>/dev/null
    dd if=build/initrd.img \
       of=build/saltyos-bios.img \
       bs=512 \
       seek=2049 \
       conv=notrunc \
       2>/dev/null
    echo "Initrd written to disk (at sector 2048)"
else
    echo "Warning: build/initrd.img not found"
fi

echo "BIOS disk image created: build/saltyos-bios.img"
