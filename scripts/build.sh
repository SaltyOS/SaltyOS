#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Building SaltyOS Phase 1..."
echo

# Create build directory
mkdir -p "$ROOT_DIR/build"

cd "$ROOT_DIR"

RUST_SYSROOT="$(rustc --print sysroot)"
if [ ! -f "$RUST_SYSROOT/lib/rustlib/src/rust/library/Cargo.lock" ]; then
    echo "Error: rust-src component not found for sysroot: $RUST_SYSROOT"
    echo "Install it with: rustup component add rust-src"
    exit 1
fi

# Build UEFI bootloader
echo "Building UEFI bootloader..."
RUSTC_BOOTSTRAP=1 cargo build \
    -Z build-std=core,compiler_builtins \
    --target "$ROOT_DIR/target-specs/x86_64-saltyos-uefi.json" \
    --package saltyos-bootloader-uefi \
    --release

# Build kernel (BIOS bootloader is pure assembly, no Rust build needed)
echo "Building kernel..."
RUSTC_BOOTSTRAP=1 cargo build \
    -Z build-std=core,compiler_builtins \
    --target "$ROOT_DIR/target-specs/x86_64-saltyos-kernel.json" \
    --package saltyos-kernel \
    --release

# Build bootcore (BIOS helper binary)
echo "Building bootcore..."
RUSTC_BOOTSTRAP=1 cargo rustc \
    -Z build-std=core,compiler_builtins \
    --target "$ROOT_DIR/target-specs/x86_64-saltyos-bios.json" \
    --package saltyos-bootloader-core \
    --bin bootcore \
    --release \
    -- -C relocation-model=static -C link-arg=-T"$ROOT_DIR/bootloader/core/linker.ld"

# Copy artifacts to build directory
echo "Copying artifacts..."

# UEFI bootloader (as EFI file)
cp target/x86_64-saltyos-uefi/release/saltyos-bootloader-uefi.efi \
   "$ROOT_DIR/build/BOOTX64.EFI" 2>/dev/null || \
cp target/x86_64-saltyos-uefi/release/saltyos-bootloader-uefi \
   "$ROOT_DIR/build/BOOTX64.EFI"

# Kernel
cp target/x86_64-saltyos-kernel/release/saltyos-kernel \
   "$ROOT_DIR/build/kernel.elf"

# Bootcore
cp target/x86_64-saltyos-bios/release/bootcore \
   "$ROOT_DIR/build/bootcore.elf"

# Build userspace demo ELF
echo "Building userspace..."
if command -v nasm >/dev/null 2>&1 && command -v ld >/dev/null 2>&1; then
    nasm -f elf64 \
        "$ROOT_DIR/userspace/hello.asm" \
        -o "$ROOT_DIR/build/userspace.o"
    ld -m elf_x86_64 \
        -nostdlib \
        -T "$ROOT_DIR/userspace/link.ld" \
        -o "$ROOT_DIR/build/userspace.elf" \
        "$ROOT_DIR/build/userspace.o"
else
    echo "Error: nasm or ld not found, cannot build userspace"
    exit 1
fi

# Build initrd (cpio) with userspace init
echo "Building initrd..."
"$ROOT_DIR/scripts/mkinitrd.sh"

# BIOS stage1 and stage2 (pure assembly)
if command -v nasm &> /dev/null; then
    nasm -f bin \
        "$ROOT_DIR/bootloader/bios/src/stage1.asm" \
        -o "$ROOT_DIR/build/stage1.bin"
    echo "Stage1 (MBR) assembled"

    nasm -f bin \
        -I "$ROOT_DIR/bootloader/common/include/" \
        "$ROOT_DIR/bootloader/bios/src/stage2.asm" \
        -o "$ROOT_DIR/build/stage2.bin"
    echo "Stage2 assembled"
else
    echo "Error: nasm not found, cannot build BIOS bootloader"
    exit 1
fi

# Create disk images
echo "Creating disk images..."
"$ROOT_DIR/scripts/mkdisk-uefi.sh"
"$ROOT_DIR/scripts/mkdisk-bios.sh"

echo
echo "Build complete!"
echo "  UEFI disk image: $ROOT_DIR/build/saltyos-uefi.img"
echo "  BIOS disk image: $ROOT_DIR/build/saltyos-bios.img"
