#!/usr/bin/env python3
"""
SaltyOS Disk Image Generator
SPDX-License-Identifier: GPL-2.0-only

Creates a bootable disk image with:
- BIOS: MBR, Stage 2, Stage 3, Kernel
- UEFI: GPT, ESP (FAT32), EFI applications
"""

import argparse
import os
import struct
import sys
import subprocess
import uuid
import zlib
from pathlib import Path


# Constants
SECTOR_SIZE = 512

# Disk layout (BIOS)
MBR_LBA = 0
STAGE2_LBA = 1
STAGE2_SECTORS = 128        # 64KB reserved for Stage 2
STAGE3_LBA = STAGE2_LBA + STAGE2_SECTORS  # 129
STAGE3_SECTORS = 64         # 32KB reserved for Stage 3
KERNEL_LBA = STAGE3_LBA + STAGE3_SECTORS  # 193

# GPT configuration
GPT_HEADER_LBA = 1
GPT_ENTRIES_START_LBA = 2
GPT_ENTRIES_COUNT = 128
GPT_ENTRY_SIZE = 128
GPT_ENTRIES_SECTORS = (GPT_ENTRIES_COUNT * GPT_ENTRY_SIZE) // SECTOR_SIZE  # 32 sectors

# ESP configuration (1MB aligned)
ESP_START_LBA = 2048        # Standard alignment for 4K sectors
ESP_SIZE_SECTORS = 65536    # 32MB for ESP (enough for EFI files)

# GPT partition type GUIDs
EFI_SYSTEM_PARTITION_GUID = uuid.UUID('C12A7328-F81F-11D2-BA4B-00A0C93EC93B')


def guid_to_bytes(guid: uuid.UUID) -> bytes:
    """Convert UUID to mixed-endian GUID bytes for GPT."""
    # GPT uses mixed-endian: first 3 components little-endian, last 2 big-endian
    return guid.bytes_le


def crc32_bytes(data: bytes) -> int:
    """Calculate CRC32 for GPT (uses standard zlib CRC32)."""
    return zlib.crc32(data) & 0xFFFFFFFF


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


def create_protective_mbr(total_sectors: int) -> bytes:
    """Create a protective MBR for GPT disk."""
    mbr = bytearray(SECTOR_SIZE)

    # Boot code area (0x000-0x1BD) - leave as zeros

    # Partition table starts at 0x1BE
    # Single partition entry covering the whole disk as type 0xEE (GPT protective)
    partition_entry = bytearray(16)

    # Boot indicator (0x00 = not bootable)
    partition_entry[0] = 0x00

    # Starting CHS (0x00, 0x02, 0x00 = sector 1 in CHS)
    partition_entry[1] = 0x00  # Head
    partition_entry[2] = 0x02  # Sector (bits 0-5), Cylinder high (bits 6-7)
    partition_entry[3] = 0x00  # Cylinder low

    # Partition type: 0xEE = GPT protective
    partition_entry[4] = 0xEE

    # Ending CHS (use max values for large disks)
    partition_entry[5] = 0xFF  # Head
    partition_entry[6] = 0xFF  # Sector + Cylinder high
    partition_entry[7] = 0xFF  # Cylinder low

    # Starting LBA (little-endian): 1
    partition_entry[8:12] = struct.pack('<I', 1)

    # Size in sectors (little-endian): total_sectors - 1
    size_sectors = min(total_sectors - 1, 0xFFFFFFFF)  # Cap at 32-bit max
    partition_entry[12:16] = struct.pack('<I', size_sectors)

    # Write partition entry to MBR
    mbr[0x1BE:0x1CE] = partition_entry

    # MBR signature
    mbr[0x1FE] = 0x55
    mbr[0x1FF] = 0xAA

    return bytes(mbr)


def create_gpt_header(
    disk_guid: uuid.UUID,
    total_sectors: int,
    entries_crc32: int,
    is_backup: bool = False
) -> bytes:
    """Create a GPT header."""
    header = bytearray(92)  # GPT header is 92 bytes

    # Signature: "EFI PART"
    header[0:8] = b'EFI PART'

    # Revision: 1.0
    header[8:12] = struct.pack('<I', 0x00010000)

    # Header size: 92 bytes
    header[12:16] = struct.pack('<I', 92)

    # Header CRC32: will be filled later
    header[16:20] = struct.pack('<I', 0)

    # Reserved
    header[20:24] = struct.pack('<I', 0)

    # Locations depend on whether this is primary or backup
    if is_backup:
        my_lba = total_sectors - 1
        alternate_lba = 1
        first_usable_lba = GPT_ENTRIES_START_LBA + GPT_ENTRIES_SECTORS
        last_usable_lba = total_sectors - GPT_ENTRIES_SECTORS - 2
        entries_start_lba = total_sectors - GPT_ENTRIES_SECTORS - 1
    else:
        my_lba = 1
        alternate_lba = total_sectors - 1
        first_usable_lba = GPT_ENTRIES_START_LBA + GPT_ENTRIES_SECTORS
        last_usable_lba = total_sectors - GPT_ENTRIES_SECTORS - 2
        entries_start_lba = GPT_ENTRIES_START_LBA

    # My LBA
    header[24:32] = struct.pack('<Q', my_lba)

    # Alternate LBA
    header[32:40] = struct.pack('<Q', alternate_lba)

    # First usable LBA
    header[40:48] = struct.pack('<Q', first_usable_lba)

    # Last usable LBA
    header[48:56] = struct.pack('<Q', last_usable_lba)

    # Disk GUID
    header[56:72] = guid_to_bytes(disk_guid)

    # Partition entries starting LBA
    header[72:80] = struct.pack('<Q', entries_start_lba)

    # Number of partition entries
    header[80:84] = struct.pack('<I', GPT_ENTRIES_COUNT)

    # Size of partition entry
    header[84:88] = struct.pack('<I', GPT_ENTRY_SIZE)

    # CRC32 of partition entries
    header[88:92] = struct.pack('<I', entries_crc32)

    # Calculate header CRC32
    header_crc = crc32_bytes(bytes(header))
    header[16:20] = struct.pack('<I', header_crc)

    # Pad to sector size
    return bytes(header).ljust(SECTOR_SIZE, b'\x00')


def create_gpt_partition_entry(
    type_guid: uuid.UUID,
    partition_guid: uuid.UUID,
    start_lba: int,
    end_lba: int,
    name: str
) -> bytes:
    """Create a GPT partition entry."""
    entry = bytearray(GPT_ENTRY_SIZE)

    # Partition type GUID
    entry[0:16] = guid_to_bytes(type_guid)

    # Unique partition GUID
    entry[16:32] = guid_to_bytes(partition_guid)

    # Starting LBA
    entry[32:40] = struct.pack('<Q', start_lba)

    # Ending LBA
    entry[40:48] = struct.pack('<Q', end_lba)

    # Attributes (0 = none)
    entry[48:56] = struct.pack('<Q', 0)

    # Partition name (UTF-16LE, max 36 characters)
    name_bytes = name.encode('utf-16-le')[:72]  # 36 chars * 2 bytes
    entry[56:56 + len(name_bytes)] = name_bytes

    return bytes(entry)


def create_efi_image(
    output: Path,
    build_dir: Path,
    stage2_efi_path: Path,
    stage1_efi_path: Path,
    stage3_path: Path,
    kernel_path: Path,
    size_mb: int = 64
) -> None:
    """Create a UEFI bootable disk image with GPT and ESP."""

    # Calculate disk geometry
    total_sectors = size_mb * 1024 * 1024 // SECTOR_SIZE
    esp_end_lba = ESP_START_LBA + ESP_SIZE_SECTORS - 1

    # Ensure disk is large enough
    min_sectors = esp_end_lba + GPT_ENTRIES_SECTORS + 2
    if total_sectors < min_sectors:
        print(f"Error: Disk too small. Need at least {min_sectors} sectors, have {total_sectors}")
        sys.exit(1)

    print(f"Creating GPT UEFI disk image: {output}")
    print(f"  Disk size: {size_mb}MB ({total_sectors} sectors)")
    print(f"  Layout:")
    print(f"    LBA 0:           Protective MBR")
    print(f"    LBA 1:           GPT Header")
    print(f"    LBA 2-33:        GPT Partition Entries")
    print(f"    LBA {ESP_START_LBA}-{esp_end_lba}:  ESP (FAT32, {ESP_SIZE_SECTORS * SECTOR_SIZE // 1024 // 1024}MB)")
    print(f"    LBA {total_sectors - GPT_ENTRIES_SECTORS - 1}-{total_sectors - 2}:  Backup GPT Entries")
    print(f"    LBA {total_sectors - 1}:        Backup GPT Header")
    print(f"  ESP contents:")
    print(f"    EFI/BOOT/BOOTX64.EFI")
    print(f"    EFI/SALTYOS/stage2.efi")
    print(f"    EFI/SALTYOS/stage3.bin")
    print(f"    EFI/SALTYOS/kernel.elf")
    print()

    # Validate EFI files exist
    efi_files = {
        'EFI/BOOT/BOOTX64.EFI': stage1_efi_path,
        'EFI/SALTYOS/stage2.efi': stage2_efi_path,
        'EFI/SALTYOS/stage3.bin': stage3_path,
        'EFI/SALTYOS/kernel.elf': kernel_path,
    }

    for efi_path, file_path in efi_files.items():
        if not file_path.exists():
            print(f"  Error: {file_path} not found")
            sys.exit(1)
        print(f"  {efi_path}: {file_path} ({os.path.getsize(file_path)} bytes)")

    # Generate GUIDs
    disk_guid = uuid.uuid4()
    esp_guid = uuid.uuid4()
    print(f"\n  Disk GUID: {disk_guid}")
    print(f"  ESP GUID:  {esp_guid}")

    # Create partition entries
    print(f"\n  Creating GPT partition entries...")
    entries = bytearray(GPT_ENTRIES_COUNT * GPT_ENTRY_SIZE)

    # ESP partition entry
    esp_entry = create_gpt_partition_entry(
        type_guid=EFI_SYSTEM_PARTITION_GUID,
        partition_guid=esp_guid,
        start_lba=ESP_START_LBA,
        end_lba=esp_end_lba,
        name="EFI System Partition"
    )
    entries[0:GPT_ENTRY_SIZE] = esp_entry

    entries_bytes = bytes(entries)
    entries_crc = crc32_bytes(entries_bytes)

    # Create disk image
    print(f"  Creating disk image...")
    image = bytearray(total_sectors * SECTOR_SIZE)

    # Write protective MBR (LBA 0)
    print(f"  Writing protective MBR...")
    mbr = create_protective_mbr(total_sectors)
    image[0:SECTOR_SIZE] = mbr

    # Write primary GPT header (LBA 1)
    print(f"  Writing primary GPT header...")
    gpt_header = create_gpt_header(disk_guid, total_sectors, entries_crc, is_backup=False)
    image[GPT_HEADER_LBA * SECTOR_SIZE:(GPT_HEADER_LBA + 1) * SECTOR_SIZE] = gpt_header

    # Write primary GPT entries (LBA 2-33)
    print(f"  Writing primary GPT entries...")
    entries_start = GPT_ENTRIES_START_LBA * SECTOR_SIZE
    entries_end = entries_start + len(entries_bytes)
    image[entries_start:entries_end] = entries_bytes

    # Write backup GPT entries (before backup header)
    backup_entries_lba = total_sectors - GPT_ENTRIES_SECTORS - 1
    print(f"  Writing backup GPT entries at LBA {backup_entries_lba}...")
    backup_entries_start = backup_entries_lba * SECTOR_SIZE
    backup_entries_end = backup_entries_start + len(entries_bytes)
    image[backup_entries_start:backup_entries_end] = entries_bytes

    # Write backup GPT header (last sector)
    backup_header_lba = total_sectors - 1
    print(f"  Writing backup GPT header at LBA {backup_header_lba}...")
    backup_gpt_header = create_gpt_header(disk_guid, total_sectors, entries_crc, is_backup=True)
    image[backup_header_lba * SECTOR_SIZE:(backup_header_lba + 1) * SECTOR_SIZE] = backup_gpt_header

    # Create ESP as a temporary file
    esp_img = output.with_suffix('.esp')

    try:
        # Create empty ESP file
        esp_size_bytes = ESP_SIZE_SECTORS * SECTOR_SIZE
        print(f"  Creating ESP (FAT32, {esp_size_bytes // 1024 // 1024}MB)...")
        with open(esp_img, 'wb') as f:
            f.truncate(esp_size_bytes)

        # Format ESP as FAT32 (need larger size for FAT32, use FAT16 for 32MB)
        fat_type = '16' if esp_size_bytes < 64 * 1024 * 1024 else '32'
        subprocess.run([
            'mkfs.vfat',
            '-F', fat_type,
            '-n', 'ESP',
            str(esp_img)
        ], check=True)

        # Create directory structure and copy files
        print(f"  Copying EFI files to ESP...")

        subprocess.run(['mmd', '-i', str(esp_img), '::/EFI'], check=True)
        subprocess.run(['mmd', '-i', str(esp_img), '::/EFI/BOOT'], check=True)
        subprocess.run(['mmd', '-i', str(esp_img), '::/EFI/SALTYOS'], check=True)

        subprocess.run([
            'mcopy', '-i', str(esp_img),
            str(stage1_efi_path), '::/EFI/BOOT/BOOTX64.EFI'
        ], check=True)

        subprocess.run([
            'mcopy', '-i', str(esp_img),
            str(stage2_efi_path), '::/EFI/SALTYOS/stage2.efi'
        ], check=True)

        subprocess.run([
            'mcopy', '-i', str(esp_img),
            str(stage3_path), '::/EFI/SALTYOS/stage3.bin'
        ], check=True)

        subprocess.run([
            'mcopy', '-i', str(esp_img),
            str(kernel_path), '::/EFI/SALTYOS/kernel.elf'
        ], check=True)

        # Read ESP and write to disk image at ESP_START_LBA
        print(f"  Writing ESP to disk image at LBA {ESP_START_LBA}...")
        with open(esp_img, 'rb') as f:
            esp_data = f.read()

        esp_offset = ESP_START_LBA * SECTOR_SIZE
        image[esp_offset:esp_offset + len(esp_data)] = esp_data

    finally:
        if esp_img.exists():
            esp_img.unlink()

    # Write image to file
    print(f"  Writing final image...")
    with open(output, 'wb') as f:
        f.write(bytes(image))

    print(f"\n  Created {output} ({size_mb}MB)")
    print(f"\nTo test with QEMU (UEFI):")
    print(f"  qemu-system-x86_64 -bios /usr/share/OVMF/OVMF_CODE.fd \\")
    print(f"    -drive file={output},format=raw -serial stdio")


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
        '--size', '-s',
        type=int,
        default=8,
        help='Disk image size in MB'
    )
    parser.add_argument(
        '--build-dir', '-b',
        type=Path,
        default=Path('build'),
        help='Build directory to find binaries'
    )
    parser.add_argument(
        '--efi',
        action='store_true',
        help='Create UEFI image (with ESP) instead of BIOS image'
    )

    args = parser.parse_args()

    if args.efi:
        # UEFI mode
        stage1_efi = args.build_dir / 'boot' / 'BOOTX64.EFI'
        stage2_efi = args.build_dir / 'boot' / 'stage2.efi'
        stage3 = args.build_dir / 'boot' / 'stage3.bin'
        kernel = args.build_dir / 'kernel' / 'kernel.elf'

        # Validate paths
        for name, path in [('Stage1 EFI', stage1_efi), ('Stage2 EFI', stage2_efi),
                           ('Stage3', stage3), ('Kernel', kernel)]:
            if not path.exists():
                print(f"Error: {name} not found: {path}", file=sys.stderr)
                sys.exit(1)

        create_efi_image(
            output=args.output,
            build_dir=args.build_dir,
            stage1_efi_path=stage1_efi,
            stage2_efi_path=stage2_efi,
            stage3_path=stage3,
            kernel_path=kernel,
            size_mb=args.size
        )
    else:
        # BIOS mode (original)
        mbr = args.build_dir / 'boot' / 'mbr.bin'
        stage2 = args.build_dir / 'boot' / 'stage2.bin'
        stage3 = args.build_dir / 'boot' / 'stage3.bin'
        kernel = args.build_dir / 'kernel' / 'kernel.elf'

        # Validate paths
        for name, path in [('MBR', mbr), ('Stage2', stage2),
                           ('Stage3', stage3), ('Kernel', kernel)]:
            if not path.exists():
                print(f"Error: {name} not found: {path}", file=sys.stderr)
                sys.exit(1)

        create_disk_image(
            output=args.output,
            mbr_path=mbr,
            stage2_path=stage2,
            stage3_path=stage3,
            kernel_path=kernel,
            size_mb=args.size
        )


if __name__ == '__main__':
    main()
