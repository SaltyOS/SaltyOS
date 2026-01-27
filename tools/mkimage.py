#!/usr/bin/env python3
"""
SaltyOS Disk Image Generator
SPDX-License-Identifier: GPL-2.0-only

Creates a bootable disk image with:
- MBR bootloader (sector 0)
- Stage 2 (sectors 1-128)
- Stage 3 (sectors 129-192)
- Kernel ELF (sectors 193+)
"""

import argparse
import os
import struct
import sys
from pathlib import Path


# Constants
SECTOR_SIZE = 512

# Disk layout (must match Stage 2 entry.asm constants)
MBR_LBA = 0
STAGE2_LBA = 1
STAGE2_SECTORS = 128        # 64KB reserved for Stage 2
STAGE3_LBA = STAGE2_LBA + STAGE2_SECTORS  # 129
STAGE3_SECTORS = 64         # 32KB reserved for Stage 3
KERNEL_LBA = STAGE3_LBA + STAGE3_SECTORS  # 193


def read_file(path: Path) -> bytes:
    """Read entire file as bytes."""
    with open(path, 'rb') as f:
        return f.read()


def write_file(path: Path, data: bytes) -> None:
    """Write bytes to file."""
    with open(path, 'wb') as f:
        f.write(data)


def pad_to_sectors(data: bytes, num_sectors: int) -> bytes:
    """Pad data to exact number of sectors."""
    target_size = num_sectors * SECTOR_SIZE
    if len(data) > target_size:
        raise ValueError(f"Data size {len(data)} exceeds {num_sectors} sectors ({target_size} bytes)")
    return data.ljust(target_size, b'\x00')


def pad_to_sector_boundary(data: bytes) -> bytes:
    """Pad data to sector boundary."""
    remainder = len(data) % SECTOR_SIZE
    if remainder != 0:
        data += b'\x00' * (SECTOR_SIZE - remainder)
    return data


def create_disk_image(
    output: Path,
    mbr_path: Path,
    stage2_path: Path,
    stage3_path: Path,
    kernel_path: Path,
    size_mb: int = 8
) -> None:
    """Create a bootable disk image."""
    
    print(f"Creating disk image: {output}")
    print(f"  Layout:")
    print(f"    MBR:     sector 0")
    print(f"    Stage 2: sectors {STAGE2_LBA}-{STAGE2_LBA + STAGE2_SECTORS - 1}")
    print(f"    Stage 3: sectors {STAGE3_LBA}-{STAGE3_LBA + STAGE3_SECTORS - 1}")
    print(f"    Kernel:  sectors {KERNEL_LBA}+")
    print()
    
    # Read MBR
    print(f"  MBR: {mbr_path}")
    mbr_data = read_file(mbr_path)
    if len(mbr_data) != SECTOR_SIZE:
        raise ValueError(f"MBR must be exactly {SECTOR_SIZE} bytes, got {len(mbr_data)}")
    
    # Read Stage 2
    print(f"  Stage 2: {stage2_path}")
    stage2_data = read_file(stage2_path)
    print(f"    Size: {len(stage2_data)} bytes ({(len(stage2_data) + SECTOR_SIZE - 1) // SECTOR_SIZE} sectors)")
    stage2_data = pad_to_sectors(stage2_data, STAGE2_SECTORS)
    
    # Read Stage 3
    print(f"  Stage 3: {stage3_path}")
    stage3_data = read_file(stage3_path)
    print(f"    Size: {len(stage3_data)} bytes ({(len(stage3_data) + SECTOR_SIZE - 1) // SECTOR_SIZE} sectors)")
    stage3_data = pad_to_sectors(stage3_data, STAGE3_SECTORS)
    
    # Read Kernel
    print(f"  Kernel: {kernel_path}")
    kernel_data = read_file(kernel_path)
    kernel_data = pad_to_sector_boundary(kernel_data)
    kernel_sectors = len(kernel_data) // SECTOR_SIZE
    print(f"    Size: {len(kernel_data)} bytes ({kernel_sectors} sectors)")
    
    # Calculate total image size
    total_sectors = size_mb * 1024 * 1024 // SECTOR_SIZE
    
    # Create image
    image = bytearray(total_sectors * SECTOR_SIZE)
    
    # Write components
    image[MBR_LBA * SECTOR_SIZE : MBR_LBA * SECTOR_SIZE + len(mbr_data)] = mbr_data
    image[STAGE2_LBA * SECTOR_SIZE : STAGE2_LBA * SECTOR_SIZE + len(stage2_data)] = stage2_data
    image[STAGE3_LBA * SECTOR_SIZE : STAGE3_LBA * SECTOR_SIZE + len(stage3_data)] = stage3_data
    image[KERNEL_LBA * SECTOR_SIZE : KERNEL_LBA * SECTOR_SIZE + len(kernel_data)] = kernel_data
    
    # Write image to file
    write_file(output, bytes(image))
    print(f"\n  Created {output} ({size_mb}MB)")
    print(f"\nTo test with QEMU:")
    print(f"  qemu-system-x86_64 -drive format=raw,file={output} -serial stdio -nographic")


def main():
    parser = argparse.ArgumentParser(
        description='Create SaltyOS bootable disk image'
    )
    parser.add_argument(
        '--arch', '-a',
        default='x86_64',
        choices=['x86_64', 'aarch64'],
        help='Target architecture'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=Path('saltyos.img'),
        help='Output image path'
    )
    parser.add_argument(
        '--mbr',
        type=Path,
        help='MBR bootloader binary'
    )
    parser.add_argument(
        '--stage2',
        type=Path,
        help='Stage 2 binary'
    )
    parser.add_argument(
        '--stage3',
        type=Path,
        help='Stage 3 binary'
    )
    parser.add_argument(
        '--kernel', '-k',
        type=Path,
        help='Kernel ELF binary'
    )
    parser.add_argument(
        '--size', '-s',
        type=int,
        default=8,
        help='Disk image size in MB'
    )
    parser.add_argument(
        '--build-dir', '-b',
        type=Path,
        help='Build directory to find binaries'
    )
    
    args = parser.parse_args()
    
    # Auto-detect paths from build directory
    if args.build_dir:
        if not args.mbr:
            args.mbr = args.build_dir / 'boot' / 'mbr.bin'
        if not args.stage2:
            args.stage2 = args.build_dir / 'boot' / 'stage2.bin'
        if not args.stage3:
            args.stage3 = args.build_dir / 'boot' / 'stage3.bin'
        if not args.kernel:
            args.kernel = args.build_dir / 'kernel' / 'kernel.elf'
    
    # Validate paths
    for name, path in [('MBR', args.mbr), ('Stage2', args.stage2), 
                       ('Stage3', args.stage3), ('Kernel', args.kernel)]:
        if not path:
            print(f"Error: --{name.lower()} is required", file=sys.stderr)
            sys.exit(1)
        if not path.exists():
            print(f"Error: {name} not found: {path}", file=sys.stderr)
            sys.exit(1)
    
    create_disk_image(
        output=args.output,
        mbr_path=args.mbr,
        stage2_path=args.stage2,
        stage3_path=args.stage3,
        kernel_path=args.kernel,
        size_mb=args.size
    )


if __name__ == '__main__':
    main()
