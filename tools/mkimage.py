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

# Boot Manifest constants
BOOT_MANIFEST_MAGIC = 0x53414C54594D414E  # "SALTYMAN" in little-endian
BOOT_MANIFEST_VERSION = 1

# Manifest entry types
MANIFEST_ENTRY_KERNEL = 1
MANIFEST_ENTRY_INITRD = 2
MANIFEST_ENTRY_STAGE3 = 3
MANIFEST_ENTRY_CONFIG = 4

# Disk layout (BIOS) - Boot Reserved Area (BRA)
MBR_LBA = 0
BRA_START_LBA = 2048                        # 1 MiB offset
MANIFEST_LBA = BRA_START_LBA                # Manifest at BRA start
MANIFEST_SECTORS = 64                       # 32 KB for manifest
STAGE2_LBA = BRA_START_LBA + MANIFEST_SECTORS  # 2112
STAGE2_SECTORS = 128                        # 64 KB for Stage 2
STAGE3_LBA = STAGE2_LBA + STAGE2_SECTORS    # 2240
STAGE3_SECTORS = 512                        # 256 KB for Stage 3
KERNEL_LBA = STAGE3_LBA + STAGE3_SECTORS    # 2752

# Legacy layout (for backwards compatibility)
LEGACY_STAGE2_LBA = 1
LEGACY_STAGE2_SECTORS = 128
LEGACY_STAGE3_LBA = LEGACY_STAGE2_LBA + LEGACY_STAGE2_SECTORS
LEGACY_STAGE3_SECTORS = 64
LEGACY_KERNEL_LBA = LEGACY_STAGE3_LBA + LEGACY_STAGE3_SECTORS

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
LINUX_FILESYSTEM_GUID = uuid.UUID('0FC63DAF-8483-4772-8E79-3D69D8477DE4')

# BIOS MBR partition type IDs
MBR_PART_TYPE_LINUX_FS = 0x83

# Rootfs partition placement (1 MiB alignment)
ROOTFS_ALIGN_SECTORS = 2048


def guid_to_bytes(guid: uuid.UUID) -> bytes:
    """Convert UUID to mixed-endian GUID bytes for GPT."""
    # GPT uses mixed-endian: first 3 components little-endian, last 2 big-endian
    return guid.bytes_le


def crc32_bytes(data: bytes) -> int:
    """Calculate CRC32 for GPT (uses standard zlib CRC32)."""
    return zlib.crc32(data) & 0xFFFFFFFF


# CRC64-ECMA-182 lookup table (polynomial 0x42F0E1EBA9EA3693)
_CRC64_TABLE = None

def _init_crc64_table():
    global _CRC64_TABLE
    poly = 0x42F0E1EBA9EA3693
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table.append(crc)
    _CRC64_TABLE = table

def crc64_ecma(data: bytes) -> int:
    """Calculate CRC64-ECMA-182 matching manifest_crc64() in manifest.h."""
    global _CRC64_TABLE
    if _CRC64_TABLE is None:
        _init_crc64_table()
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc = _CRC64_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


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


def align_up(value: int, alignment: int) -> int:
    """Round value up to the next multiple of alignment."""
    if alignment <= 0:
        raise ValueError(f"alignment must be > 0, got {alignment}")
    return ((value + alignment - 1) // alignment) * alignment


def create_manifest_extent(lba: int, sector_count: int) -> bytes:
    """Create a ManifestExtent structure (16 bytes)."""
    return struct.pack('<QII', lba, sector_count, 0)


def create_manifest_entry(
    entry_type: int,
    entry_id: int,
    size_bytes: int,
    load_align: int,
    extents: list
) -> bytes:
    """Create a BootManifestEntry structure (160 bytes)."""
    entry = bytearray(160)

    # type (2 bytes)
    struct.pack_into('<H', entry, 0, entry_type)
    # flags (2 bytes)
    struct.pack_into('<H', entry, 2, 0)
    # id (4 bytes)
    struct.pack_into('<I', entry, 4, entry_id)
    # size_bytes (8 bytes)
    struct.pack_into('<Q', entry, 8, size_bytes)
    # load_align (8 bytes)
    struct.pack_into('<Q', entry, 16, load_align)
    # extent_count (4 bytes)
    struct.pack_into('<I', entry, 24, len(extents))
    # reserved (4 bytes)
    struct.pack_into('<I', entry, 28, 0)

    # extents (8 * 16 bytes = 128 bytes)
    for i, (lba, sectors) in enumerate(extents[:8]):
        extent_offset = 32 + i * 16
        entry[extent_offset:extent_offset + 16] = create_manifest_extent(lba, sectors)

    return bytes(entry)


def create_boot_manifest(
    stage3_lba: int,
    stage3_size: int,
    kernel_lba: int,
    kernel_size: int,
    initrd_lba: int = 0,
    initrd_size: int = 0
) -> bytes:
    """Create a Boot Manifest with header and entries."""

    # Calculate entry table offset (after header)
    header_size = 40  # BootManifestHeader size
    entry_table_offset = header_size

    # Create entries
    entries = []

    # Stage 3 entry
    stage3_sectors = (stage3_size + SECTOR_SIZE - 1) // SECTOR_SIZE
    entries.append(create_manifest_entry(
        entry_type=MANIFEST_ENTRY_STAGE3,
        entry_id=0,
        size_bytes=stage3_size,
        load_align=4096,
        extents=[(stage3_lba, stage3_sectors)]
    ))

    # Kernel entry
    kernel_sectors = (kernel_size + SECTOR_SIZE - 1) // SECTOR_SIZE
    entries.append(create_manifest_entry(
        entry_type=MANIFEST_ENTRY_KERNEL,
        entry_id=1,
        size_bytes=kernel_size,
        load_align=2 * 1024 * 1024,  # 2MB alignment
        extents=[(kernel_lba, kernel_sectors)]
    ))

    # Initrd entry (optional)
    if initrd_lba and initrd_size:
        initrd_sectors = (initrd_size + SECTOR_SIZE - 1) // SECTOR_SIZE
        entries.append(create_manifest_entry(
            entry_type=MANIFEST_ENTRY_INITRD,
            entry_id=2,
            size_bytes=initrd_size,
            load_align=4096,
            extents=[(initrd_lba, initrd_sectors)]
        ))

    # Create header
    entry_count = len(entries)
    entries_data = b''.join(entries)
    manifest_size = header_size + len(entries_data)

    header = bytearray(header_size)

    # magic (8 bytes)
    struct.pack_into('<Q', header, 0, BOOT_MANIFEST_MAGIC)
    # version (2 bytes)
    struct.pack_into('<H', header, 8, BOOT_MANIFEST_VERSION)
    # header_size (2 bytes)
    struct.pack_into('<H', header, 10, header_size)
    # manifest_size (4 bytes)
    struct.pack_into('<I', header, 12, manifest_size)
    # flags (4 bytes) - HAS_CHECKSUM = (1 << 0)
    MANIFEST_HDR_FLAG_HAS_CHECKSUM = 1 << 0
    struct.pack_into('<I', header, 16, MANIFEST_HDR_FLAG_HAS_CHECKSUM)
    # arch (2 bytes) - 1 = x86_64
    struct.pack_into('<H', header, 20, 1)
    # entry_count (2 bytes)
    struct.pack_into('<H', header, 22, entry_count)
    # entry_table_off (8 bytes)
    struct.pack_into('<Q', header, 24, entry_table_offset)
    # checksum (8 bytes) - set to 0 for CRC computation
    struct.pack_into('<Q', header, 32, 0)

    # Compute CRC64 over the full manifest (header + entries) with checksum=0
    full_manifest = bytes(header) + entries_data
    checksum = crc64_ecma(full_manifest)

    # Write the computed checksum back into the header
    struct.pack_into('<Q', header, 32, checksum)

    return bytes(header) + entries_data


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


def patch_mbr_linux_partition(
    mbr_data: bytes,
    start_lba: int,
    sector_count: int,
    partition_index: int = 0,
) -> bytes:
    """Patch a classic MBR partition entry into an existing bootable MBR sector."""
    if len(mbr_data) != SECTOR_SIZE:
        raise ValueError(f"MBR must be exactly {SECTOR_SIZE} bytes, got {len(mbr_data)}")
    if start_lba <= 0:
        raise ValueError(f"Invalid partition start LBA: {start_lba}")
    if sector_count <= 0:
        raise ValueError(f"Invalid partition sector count: {sector_count}")
    if start_lba > 0xFFFFFFFF or sector_count > 0xFFFFFFFF:
        raise ValueError(
            f"MBR partition exceeds 32-bit LBA limits: start={start_lba} sectors={sector_count}"
        )
    if not (0 <= partition_index < 4):
        raise ValueError(f"Invalid MBR partition index: {partition_index}")

    mbr = bytearray(mbr_data)
    if mbr[0x1FE] != 0x55 or mbr[0x1FF] != 0xAA:
        raise ValueError("MBR signature missing (0x55AA)")

    part_table_off = 0x1BE
    part_entry_size = 16

    # Clear all partition entries so the image has a single authoritative rootfs partition.
    mbr[part_table_off:part_table_off + 4 * part_entry_size] = b'\x00' * (4 * part_entry_size)

    off = part_table_off + partition_index * part_entry_size
    entry = bytearray(16)
    entry[0] = 0x00  # non-bootable; boot is handled by custom MBR/stage2
    entry[1:4] = b'\xFF\xFF\xFF'  # CHS (unused, set to max for LBA mode)
    entry[4] = MBR_PART_TYPE_LINUX_FS
    entry[5:8] = b'\xFF\xFF\xFF'
    entry[8:12] = struct.pack('<I', start_lba)
    entry[12:16] = struct.pack('<I', sector_count)
    mbr[off:off + 16] = entry

    # Preserve signature explicitly.
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
    initrd_path: Path = None,
    size_mb: int = 64,
    rootfs_path: Path = None,
) -> None:
    """Create a UEFI bootable disk image with GPT and ESP."""
    rootfs_path = Path(rootfs_path) if rootfs_path is not None else None

    # Calculate disk geometry and optional rootfs placement.
    esp_end_lba = ESP_START_LBA + ESP_SIZE_SECTORS - 1
    rootfs_actual_size = 0
    rootfs_sector_count = 0
    rootfs_start_lba = 0
    rootfs_end_lba = 0
    if rootfs_path is not None:
        rootfs_actual_size = os.path.getsize(rootfs_path)
        rootfs_sector_count = (rootfs_actual_size + SECTOR_SIZE - 1) // SECTOR_SIZE
        rootfs_start_lba = align_up(esp_end_lba + 1, ROOTFS_ALIGN_SECTORS)
        rootfs_end_lba = rootfs_start_lba + rootfs_sector_count - 1

    min_sectors = esp_end_lba + GPT_ENTRIES_SECTORS + 2
    required_sectors = min_sectors
    if rootfs_path is not None:
        # Backup GPT entries + backup header must remain after the rootfs partition.
        required_sectors = max(
            required_sectors,
            rootfs_start_lba + rootfs_sector_count + GPT_ENTRIES_SECTORS + 1,
        )
    requested_sectors = size_mb * 1024 * 1024 // SECTOR_SIZE
    total_sectors = max(requested_sectors, required_sectors)

    print(f"Creating GPT UEFI disk image: {output}")
    if total_sectors > requested_sectors:
        grown_mb = (total_sectors * SECTOR_SIZE + (1024 * 1024 - 1)) // (1024 * 1024)
        print(
            f"  Expanding image from {size_mb}MB to {grown_mb}MB "
            f"to fit embedded payloads"
        )
    print(
        f"  Disk size: "
        f"{(total_sectors * SECTOR_SIZE + (1024 * 1024 - 1)) // (1024 * 1024)}MB "
        f"({total_sectors} sectors)"
    )
    print(f"  Layout:")
    print(f"    LBA 0:           Protective MBR")
    print(f"    LBA 1:           GPT Header")
    print(f"    LBA 2-33:        GPT Partition Entries")
    print(f"    LBA {ESP_START_LBA}-{esp_end_lba}:  ESP (FAT32, {ESP_SIZE_SECTORS * SECTOR_SIZE // 1024 // 1024}MB)")
    if rootfs_path is not None:
        print(
            f"    LBA {rootfs_start_lba}-{rootfs_end_lba}:  "
            f"rootfs (SaltyFS payload, {rootfs_sector_count} sectors)"
        )
    print(f"    LBA {total_sectors - GPT_ENTRIES_SECTORS - 1}-{total_sectors - 2}:  Backup GPT Entries")
    print(f"    LBA {total_sectors - 1}:        Backup GPT Header")
    print(f"  ESP contents:")
    efi_boot_name = stage1_efi_path.name  # BOOTX64.EFI or BOOTAA64.EFI
    print(f"    EFI/BOOT/{efi_boot_name}")
    print(f"    EFI/SALTYOS/stage2.efi")
    print(f"    EFI/SALTYOS/stage3.bin")
    print(f"    EFI/SALTYOS/kernel.elf")
    if initrd_path and initrd_path.exists():
        print(f"    EFI/SALTYOS/initrd.img")
    print()

    # Validate EFI files exist
    efi_files = {
        f'EFI/BOOT/{efi_boot_name}': stage1_efi_path,
        'EFI/SALTYOS/stage2.efi': stage2_efi_path,
        'EFI/SALTYOS/stage3.bin': stage3_path,
        'EFI/SALTYOS/kernel.elf': kernel_path,
    }

    for efi_path, file_path in efi_files.items():
        if not file_path.exists():
            print(f"  Error: {file_path} not found")
            sys.exit(1)
        print(f"  {efi_path}: {file_path} ({os.path.getsize(file_path)} bytes)")
    if rootfs_path is not None:
        print(f"  rootfs payload: {rootfs_path} ({rootfs_actual_size} bytes)")

    # Generate GUIDs
    disk_guid = uuid.uuid4()
    esp_guid = uuid.uuid4()
    rootfs_guid = uuid.uuid4() if rootfs_path is not None else None
    print(f"\n  Disk GUID: {disk_guid}")
    print(f"  ESP GUID:  {esp_guid}")
    if rootfs_guid is not None:
        print(f"  rootfs GUID: {rootfs_guid}")

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

    if rootfs_path is not None:
        rootfs_entry = create_gpt_partition_entry(
            type_guid=LINUX_FILESYSTEM_GUID,
            partition_guid=rootfs_guid,
            start_lba=rootfs_start_lba,
            end_lba=rootfs_end_lba,
            name="SaltyOS rootfs",
        )
        entries[GPT_ENTRY_SIZE:2 * GPT_ENTRY_SIZE] = rootfs_entry

    entries_bytes = bytes(entries)
    entries_crc = crc32_bytes(entries_bytes)

    print(f"  Creating disk image...")
    backup_entries_lba = total_sectors - GPT_ENTRIES_SECTORS - 1
    backup_header_lba = total_sectors - 1
    with open(output, 'wb') as out_f:
        out_f.truncate(total_sectors * SECTOR_SIZE)

        # Write protective MBR (LBA 0)
        print(f"  Writing protective MBR...")
        mbr = create_protective_mbr(total_sectors)
        out_f.seek(0)
        out_f.write(mbr)

        # Write primary GPT header (LBA 1)
        print(f"  Writing primary GPT header...")
        gpt_header = create_gpt_header(disk_guid, total_sectors, entries_crc, is_backup=False)
        out_f.seek(GPT_HEADER_LBA * SECTOR_SIZE)
        out_f.write(gpt_header)

        # Write primary GPT entries (LBA 2-33)
        print(f"  Writing primary GPT entries...")
        out_f.seek(GPT_ENTRIES_START_LBA * SECTOR_SIZE)
        out_f.write(entries_bytes)

        # Write backup GPT entries (before backup header)
        print(f"  Writing backup GPT entries at LBA {backup_entries_lba}...")
        out_f.seek(backup_entries_lba * SECTOR_SIZE)
        out_f.write(entries_bytes)

        # Write backup GPT header (last sector)
        print(f"  Writing backup GPT header at LBA {backup_header_lba}...")
        backup_gpt_header = create_gpt_header(disk_guid, total_sectors, entries_crc, is_backup=True)
        out_f.seek(backup_header_lba * SECTOR_SIZE)
        out_f.write(backup_gpt_header)

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
                str(stage1_efi_path), f'::/EFI/BOOT/{stage1_efi_path.name}'
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

            # Copy initrd if provided
            if initrd_path and initrd_path.exists():
                print(f"  Copying initrd to ESP...")
                subprocess.run([
                    'mcopy', '-i', str(esp_img),
                    str(initrd_path), '::/EFI/SALTYOS/initrd.img'
                ], check=True)

            # Stream ESP to disk image at ESP_START_LBA
            print(f"  Writing ESP to disk image at LBA {ESP_START_LBA}...")
            out_f.seek(ESP_START_LBA * SECTOR_SIZE)
            with open(esp_img, 'rb') as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    out_f.write(chunk)

        finally:
            if esp_img.exists():
                esp_img.unlink()

        if rootfs_path is not None:
            print(f"  Writing rootfs payload to disk image at LBA {rootfs_start_lba}...")
            out_f.seek(rootfs_start_lba * SECTOR_SIZE)
            with open(rootfs_path, 'rb') as rf:
                while True:
                    chunk = rf.read(1024 * 1024)
                    if not chunk:
                        break
                    out_f.write(chunk)
            rootfs_padded_size = rootfs_sector_count * SECTOR_SIZE
            pad_bytes = rootfs_padded_size - rootfs_actual_size
            if pad_bytes:
                out_f.write(b'\x00' * pad_bytes)

    actual_mb = (total_sectors * SECTOR_SIZE + (1024 * 1024 - 1)) // (1024 * 1024)
    print(f"\n  Created {output} ({actual_mb}MB)")
    print(f"\nTo test with QEMU (UEFI):")
    print(f"  qemu-system-x86_64 -bios /usr/share/OVMF/OVMF_CODE.fd \\")
    print(f"    -drive file={output},format=raw -serial stdio")


def create_disk_image(
    output: Path,
    mbr_path: Path,
    stage2_path: Path,
    stage3_path: Path,
    kernel_path: Path,
    initrd_path: Path = None,
    size_mb: int = 8,
    rootfs_path: Path = None,
) -> None:
    """Create a bootable disk image with Boot Manifest."""

    print(f"Creating disk image: {output}")
    print(f"  Layout (Boot Reserved Area at LBA {BRA_START_LBA}):")
    print(f"    MBR:      sector 0")
    print(f"    Manifest: sectors {MANIFEST_LBA}-{MANIFEST_LBA + MANIFEST_SECTORS - 1}")
    print(f"    Stage 2:  sectors {STAGE2_LBA}-{STAGE2_LBA + STAGE2_SECTORS - 1}")
    print(f"    Stage 3:  sectors {STAGE3_LBA}-{STAGE3_LBA + STAGE3_SECTORS - 1}")
    print(f"    Kernel:   sectors {KERNEL_LBA}+")
    print()

    # Read MBR
    print(f"  MBR: {mbr_path}")
    mbr_data = read_file(mbr_path)
    if len(mbr_data) != SECTOR_SIZE:
        raise ValueError(f"MBR must be exactly {SECTOR_SIZE} bytes, got {len(mbr_data)}")

    # Read Stage 2
    print(f"  Stage 2: {stage2_path}")
    stage2_data = read_file(stage2_path)
    stage2_actual_size = len(stage2_data)
    print(f"    Size: {stage2_actual_size} bytes ({(stage2_actual_size + SECTOR_SIZE - 1) // SECTOR_SIZE} sectors)")
    stage2_data = pad_to_sectors(stage2_data, STAGE2_SECTORS)

    # Read Stage 3
    print(f"  Stage 3: {stage3_path}")
    stage3_data = read_file(stage3_path)
    stage3_actual_size = len(stage3_data)
    print(f"    Size: {stage3_actual_size} bytes ({(stage3_actual_size + SECTOR_SIZE - 1) // SECTOR_SIZE} sectors)")
    stage3_data = pad_to_sectors(stage3_data, STAGE3_SECTORS)

    # Read Kernel
    print(f"  Kernel: {kernel_path}")
    kernel_data = read_file(kernel_path)
    kernel_actual_size = len(kernel_data)
    kernel_data = pad_to_sector_boundary(kernel_data)
    kernel_sectors = len(kernel_data) // SECTOR_SIZE
    print(f"    Size: {kernel_actual_size} bytes ({kernel_sectors} sectors)")

    # Read Initrd (optional)
    initrd_lba = 0
    initrd_actual_size = 0
    initrd_data = b''
    if initrd_path and initrd_path.exists():
        print(f"  Initrd: {initrd_path}")
        initrd_data = read_file(initrd_path)
        initrd_actual_size = len(initrd_data)
        initrd_data = pad_to_sector_boundary(initrd_data)
        initrd_lba = KERNEL_LBA + kernel_sectors
        initrd_sectors = len(initrd_data) // SECTOR_SIZE
        print(f"    Size: {initrd_actual_size} bytes ({initrd_sectors} sectors)")
        print(f"    LBA:  {initrd_lba}")

    # Rootfs partition payload (optional)
    rootfs_actual_size = 0
    rootfs_sector_count = 0
    rootfs_start_lba = 0
    rootfs_path = Path(rootfs_path) if rootfs_path is not None else None

    # Create Boot Manifest
    print(f"  Creating Boot Manifest...")
    manifest_data = create_boot_manifest(
        stage3_lba=STAGE3_LBA,
        stage3_size=stage3_actual_size,
        kernel_lba=KERNEL_LBA,
        kernel_size=kernel_actual_size,
        initrd_lba=initrd_lba,
        initrd_size=initrd_actual_size,
    )
    manifest_data = pad_to_sectors(manifest_data, MANIFEST_SECTORS)
    print(f"    Manifest size: {len(manifest_data)} bytes")

    # Validate that all boot components fit and compute end-of-boot extent.
    last_used_sector = KERNEL_LBA + kernel_sectors
    if initrd_data:
        last_used_sector = initrd_lba + len(initrd_data) // SECTOR_SIZE
    required_sectors = last_used_sector

    if rootfs_path is not None:
        print(f"  Rootfs: {rootfs_path}")
        rootfs_actual_size = os.path.getsize(rootfs_path)
        rootfs_sector_count = (rootfs_actual_size + SECTOR_SIZE - 1) // SECTOR_SIZE
        rootfs_start_lba = align_up(last_used_sector, ROOTFS_ALIGN_SECTORS)
        rootfs_end_lba = rootfs_start_lba + rootfs_sector_count - 1
        required_sectors = rootfs_start_lba + rootfs_sector_count
        print(
            f"    Size: {rootfs_actual_size} bytes ({rootfs_sector_count} sectors)"
        )
        print(
            f"    Partition: type=0x{MBR_PART_TYPE_LINUX_FS:02x} "
            f"LBA {rootfs_start_lba}-{rootfs_end_lba}"
        )
        mbr_data = patch_mbr_linux_partition(
            mbr_data=mbr_data,
            start_lba=rootfs_start_lba,
            sector_count=rootfs_sector_count,
        )

    # Calculate total image size (user size is treated as a minimum).
    requested_sectors = size_mb * 1024 * 1024 // SECTOR_SIZE
    total_sectors = requested_sectors
    if required_sectors > total_sectors:
        total_sectors = align_up(required_sectors, ROOTFS_ALIGN_SECTORS)
        grown_mb = (total_sectors * SECTOR_SIZE + (1024 * 1024 - 1)) // (1024 * 1024)
        print(
            f"  Expanding image from {size_mb}MB to {grown_mb}MB "
            f"to fit embedded payloads"
        )

    # Create sparse image and write components directly to avoid large RAM usage.
    with open(output, 'wb') as f:
        f.truncate(total_sectors * SECTOR_SIZE)

        # Write boot components
        f.seek(MBR_LBA * SECTOR_SIZE)
        f.write(mbr_data)
        f.seek(MANIFEST_LBA * SECTOR_SIZE)
        f.write(manifest_data)
        f.seek(STAGE2_LBA * SECTOR_SIZE)
        f.write(stage2_data)
        f.seek(STAGE3_LBA * SECTOR_SIZE)
        f.write(stage3_data)
        f.seek(KERNEL_LBA * SECTOR_SIZE)
        f.write(kernel_data)

        if initrd_data:
            f.seek(initrd_lba * SECTOR_SIZE)
            f.write(initrd_data)

        # Stream-copy rootfs payload into the rootfs partition region.
        if rootfs_path is not None:
            f.seek(rootfs_start_lba * SECTOR_SIZE)
            with open(rootfs_path, 'rb') as rf:
                while True:
                    chunk = rf.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            rootfs_padded_size = rootfs_sector_count * SECTOR_SIZE
            pad_bytes = rootfs_padded_size - rootfs_actual_size
            if pad_bytes:
                f.write(b'\x00' * pad_bytes)

    actual_mb = (total_sectors * SECTOR_SIZE + (1024 * 1024 - 1)) // (1024 * 1024)
    print(f"\n  Created {output} ({actual_mb}MB)")
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
        '--kernel',
        type=Path,
        default=None,
        help='Kernel ELF path (defaults to build-dir/kernel/kernel.elf)'
    )
    parser.add_argument(
        '--efi',
        action='store_true',
        help='Create UEFI image (with ESP) instead of BIOS image'
    )
    parser.add_argument(
        '--initrd',
        type=Path,
        default=None,
        help='Path to initrd CPIO archive (optional)'
    )
    parser.add_argument(
        '--rootfs',
        type=Path,
        default=None,
        help='Embed raw rootfs image as a Linux filesystem partition'
    )

    args = parser.parse_args()

    if args.efi:
        # UEFI mode
        efi_name = 'BOOTAA64.EFI' if args.arch == 'aarch64' else 'BOOTX64.EFI'
        stage1_efi = args.build_dir / 'boot' / efi_name
        stage2_efi = args.build_dir / 'boot' / 'stage2.efi'
        stage3 = args.build_dir / 'boot' / 'stage3_uefi.bin'
        kernel = args.kernel if args.kernel is not None else args.build_dir / 'kernel' / 'kernel.elf'

        # Validate paths
        for name, path in [('Stage1 EFI', stage1_efi), ('Stage2 EFI', stage2_efi),
                           ('Stage3', stage3), ('Kernel', kernel)]:
            if not path.exists():
                print(f"Error: {name} not found: {path}", file=sys.stderr)
                sys.exit(1)
        if args.rootfs is not None and not args.rootfs.exists():
            print(f"Error: Rootfs image not found: {args.rootfs}", file=sys.stderr)
            sys.exit(1)

        create_efi_image(
            output=args.output,
            build_dir=args.build_dir,
            stage1_efi_path=stage1_efi,
            stage2_efi_path=stage2_efi,
            stage3_path=stage3,
            kernel_path=kernel,
            initrd_path=args.initrd,
            size_mb=args.size,
            rootfs_path=args.rootfs,
        )
    else:
        # BIOS mode (original)
        mbr = args.build_dir / 'boot' / 'mbr.bin'
        stage2 = args.build_dir / 'boot' / 'stage2.bin'
        stage3 = args.build_dir / 'boot' / 'stage3.bin'
        kernel = args.kernel if args.kernel is not None else args.build_dir / 'kernel' / 'kernel.elf'

        # Validate paths
        for name, path in [('MBR', mbr), ('Stage2', stage2),
                           ('Stage3', stage3), ('Kernel', kernel)]:
            if not path.exists():
                print(f"Error: {name} not found: {path}", file=sys.stderr)
                sys.exit(1)
        if args.rootfs is not None and not args.rootfs.exists():
            print(f"Error: Rootfs image not found: {args.rootfs}", file=sys.stderr)
            sys.exit(1)

        create_disk_image(
            output=args.output,
            mbr_path=mbr,
            stage2_path=stage2,
            stage3_path=stage3,
            kernel_path=kernel,
            initrd_path=args.initrd,
            size_mb=args.size,
            rootfs_path=args.rootfs,
        )


if __name__ == '__main__':
    main()
