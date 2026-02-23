#!/usr/bin/env python3
"""
SaltyFS Image Generator
SPDX-License-Identifier: GPL-2.0-only

Creates a SaltyFS filesystem image matching docs/design/saltyfs.md on-disk format.
Generates superblock, allocation bitmap, root directory B-tree, and test files.

Usage:
    python3 tools/mksaltyfs.py -o test_data.img -s 64M
    python3 tools/mksaltyfs.py -o test_data.img -s 64M --add-file hello.txt "Hello from SaltyFS!"
"""

import argparse
import os
import struct
import sys
import time
import uuid
from pathlib import Path

BLOCK_SIZE = 4096
SECTOR_SIZE = 512

# Superblock magic
SALTYFS_MAGIC = b"SALTYFS\0"

# B-tree node magic
BTREE_NODE_MAGIC = b"BTND"

# Item types (docs/design/saltyfs.md:154-160)
SALTY_INODE_ITEM = 0x01
SALTY_INODE_REF = 0x02
SALTY_DIR_ITEM = 0x03
SALTY_DIR_INDEX = 0x04
SALTY_EXTENT_DATA = 0x05

# Extent types
EXTENT_INLINE = 0
EXTENT_REGULAR = 1
EXTENT_PREALLOC = 2

# Inode modes
S_IFDIR = 0o040000
S_IFREG = 0o100000

# Inode numbers
ROOT_INO = 1
FIRST_FILE_INO = 2


def crc32c_table():
    """Generate CRC32c lookup table."""
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
        table.append(crc & 0xFFFFFFFF)
    return table

CRC32C_TABLE = crc32c_table()


def crc32c(data: bytes) -> int:
    """Compute CRC32c checksum."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def fnv1a_hash(name: bytes) -> int:
    """FNV-1a hash matching handlers.rs:24-31."""
    h = 0xcbf29ce484222325
    for b in name:
        h ^= b
        h = (h * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def pack_btree_key(object_id: int, item_type: int, offset: int) -> bytes:
    """Pack a BTreeKey (packed struct: u64, u8, u64 = 17 bytes)."""
    return struct.pack("<QBQ", object_id, item_type, offset)


def pack_btree_item(key: bytes, data_offset: int, data_size: int) -> bytes:
    """Pack a BTreeItem: key(17) + offset(4) + size(4) = 25 bytes."""
    return key + struct.pack("<II", data_offset, data_size)


def pack_inode(
    generation=1, size=0, blocks=0, block_group=0,
    nlink=1, uid=0, gid=0, mode=0,
    atime=0, mtime=0, ctime=0, crtime=0,
    flags=0, sequence=0,
) -> bytes:
    """Pack a SaltyInode (docs/design/saltyfs.md:162-183)."""
    return struct.pack(
        "<QQQQ"   # generation, size, blocks, block_group
        "IIII"     # nlink, uid, gid, mode
        "QQQQ"    # atime, mtime, ctime, crtime
        "II"       # flags, sequence
        "32s",     # reserved
        generation, size, blocks, block_group,
        nlink, uid, gid, mode,
        atime, mtime, ctime, crtime,
        flags, sequence,
        b"\x00" * 32,
    )


def pack_dir_item(child_ino: int, name: bytes, dir_type: int = 0) -> bytes:
    """Pack a DirItem + name."""
    header = struct.pack("<QHBx", child_ino, len(name), dir_type)
    return header + name


def pack_extent_data_inline(generation: int, data: bytes) -> bytes:
    """Pack an inline ExtentData."""
    header = struct.pack(
        "<QQ"      # generation, ram_bytes
        "BBHBxxx"  # compression, encryption, other_encoding, extent_type, reserved
        "QQQQ",   # disk_bytenr, disk_num_bytes, offset, num_bytes (unused for inline)
        generation, len(data),
        0, 0, 0, EXTENT_INLINE,
        0, 0, 0, 0,
    )
    return header + data


def pack_extent_data_regular(
    generation: int, ram_bytes: int,
    disk_bytenr: int, disk_num_bytes: int,
    offset: int, num_bytes: int,
) -> bytes:
    """Pack a regular (non-inline) ExtentData."""
    return struct.pack(
        "<QQ"
        "BBHBxxx"
        "QQQQ",
        generation, ram_bytes,
        0, 0, 0, EXTENT_REGULAR,
        disk_bytenr, disk_num_bytes, offset, num_bytes,
    )


def build_btree_leaf(
    owner: int, generation: int, block_nr: int,
    items: list,
) -> bytes:
    """
    Build a B-tree leaf node.

    items: list of (BTreeKey bytes, item data bytes) tuples.
    Returns a full block (BLOCK_SIZE bytes).
    """
    header_size = 64  # BTreeNodeHeader
    item_entry_size = 25  # BTreeItem: key(17) + offset(4) + size(4)

    num_items = len(items)

    # Data area starts after header + all item entries
    data_area_start = header_size + num_items * item_entry_size

    # Build item entries and collect data
    item_entries = bytearray()
    data_area = bytearray()
    current_data_offset = data_area_start

    for key_bytes, item_data in items:
        item_entry = pack_btree_item(key_bytes, current_data_offset, len(item_data))
        item_entries.extend(item_entry)
        data_area.extend(item_data)
        current_data_offset += len(item_data)

    # Build header (checksum filled later)
    header = struct.pack(
        "<4sI"     # magic, checksum (placeholder)
        "QQQ"      # owner, generation, block_nr
        "IHH"      # num_items, level(0=leaf), flags
        "24s",     # reserved
        BTREE_NODE_MAGIC, 0,
        owner, generation, block_nr,
        num_items, 0, 0,
        b"\x00" * 24,
    )

    block = bytearray(BLOCK_SIZE)
    block[:len(header)] = header
    block[header_size:header_size + len(item_entries)] = item_entries
    offset = header_size + len(item_entries)
    # Data is placed at the offsets recorded in items
    # Reconstruct: items already have correct offsets
    for key_bytes, item_data in items:
        pass
    # Actually, data_area starts at data_area_start
    block[data_area_start:data_area_start + len(data_area)] = data_area

    # Compute checksum (with checksum field zeroed)
    checksum = crc32c(bytes(block))
    struct.pack_into("<I", block, 4, checksum)

    return bytes(block)


def build_superblock(
    total_blocks: int,
    used_blocks: int,
    root_tree: int,
    root_inode: int,
    generation: int = 1,
    label: str = "saltyfs",
) -> bytes:
    """Build a 4KB superblock."""
    now = int(time.time())
    fs_uuid = uuid.uuid4().bytes
    dev_uuid = uuid.uuid4().bytes

    label_bytes = label.encode("ascii")[:64].ljust(64, b"\x00")

    # Calculate bitmap and log sizes
    bitmap_blocks = (total_blocks + BLOCK_SIZE * 8 - 1) // (BLOCK_SIZE * 8)
    log_start = 2 + bitmap_blocks  # after primary + backup superblocks + bitmap
    log_size = min(64 * 1024 * 1024 // BLOCK_SIZE, total_blocks // 8)  # 64MB or 1/8 of disk

    sb = bytearray(BLOCK_SIZE)

    # Identity (0x000)
    struct.pack_into("<8sII", sb, 0x000,
                     SALTYFS_MAGIC, 1, 0)

    # UUIDs (0x010)
    sb[0x010:0x020] = fs_uuid
    sb[0x020:0x030] = dev_uuid

    # Geometry (0x030)
    struct.pack_into("<QQQQ", sb, 0x030,
                     BLOCK_SIZE, total_blocks, used_blocks, 0)

    # Tree roots (0x050)
    struct.pack_into("<QQQQ", sb, 0x050,
                     root_tree, 0, 0, 0)

    # Log (0x070)
    struct.pack_into("<QQQQ", sb, 0x070,
                     log_start, log_size, 0, 0)

    # State (0x090)
    struct.pack_into("<QQQQ", sb, 0x090,
                     generation, now, now, 1)

    # Root inode (0x0B0)
    struct.pack_into("<Q", sb, 0x0B0, root_inode)

    # Checksums (0x0B8)
    struct.pack_into("<II", sb, 0x0B8, 0, 0)  # CRC32c, reserved

    # Label (0x0C0)
    sb[0x0C0:0x100] = label_bytes

    # Checksum (last 4 bytes)
    checksum = crc32c(bytes(sb))
    struct.pack_into("<I", sb, BLOCK_SIZE - 4, checksum)

    return bytes(sb)


def parse_size(size_str: str) -> int:
    """Parse size string like '64M', '1G', '256K'."""
    size_str = size_str.strip().upper()
    multipliers = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if size_str[-1] in multipliers:
        return int(size_str[:-1]) * multipliers[size_str[-1]]
    return int(size_str)


def create_saltyfs_image(output_path: Path, size: int, files: list):
    """
    Create a SaltyFS image with the given files.

    files: list of (name, content_bytes) tuples.
    """
    total_blocks = size // BLOCK_SIZE
    if total_blocks < 16:
        print("Error: Image too small (need at least 16 blocks)", file=sys.stderr)
        sys.exit(1)

    # Layout:
    # Block 0: Primary Superblock
    # Block 1: Backup Superblock
    # Block 2..N: Allocation Bitmap
    # Block N+1..M: Intent Log (empty)
    # Block M+1: Root B-tree node
    # Block M+2..: File data blocks

    bitmap_blocks = (total_blocks + BLOCK_SIZE * 8 - 1) // (BLOCK_SIZE * 8)
    log_start = 2 + bitmap_blocks
    log_size = min(64 * 1024 * 1024 // BLOCK_SIZE, total_blocks // 8)
    if log_size < 1:
        log_size = 1

    root_tree_block = log_start + log_size
    next_data_block = root_tree_block + 1

    generation = 1
    now_ns = int(time.time()) * 1_000_000_000  # nanoseconds since epoch

    # Build B-tree items
    btree_items = []

    # Root directory inode (ino=1)
    root_inode_data = pack_inode(
        generation=generation,
        size=0,
        blocks=0,
        nlink=2,
        mode=S_IFDIR | 0o755,
        atime=now_ns, mtime=now_ns, ctime=now_ns, crtime=now_ns,
    )
    btree_items.append((
        pack_btree_key(ROOT_INO, SALTY_INODE_ITEM, 0),
        root_inode_data,
    ))

    # Create file inodes and directory entries
    next_ino = FIRST_FILE_INO
    file_data_blocks = []

    for fname, content in files:
        file_ino = next_ino
        next_ino += 1

        fname_bytes = fname.encode("ascii")

        # File inode
        file_blocks = (len(content) + BLOCK_SIZE - 1) // BLOCK_SIZE
        file_inode_data = pack_inode(
            generation=generation,
            size=len(content),
            blocks=file_blocks,
            nlink=1,
            mode=S_IFREG | 0o644,
            atime=now_ns, mtime=now_ns, ctime=now_ns, crtime=now_ns,
        )
        btree_items.append((
            pack_btree_key(file_ino, SALTY_INODE_ITEM, 0),
            file_inode_data,
        ))

        # Directory entry under root
        dir_item_data = pack_dir_item(file_ino, fname_bytes, dir_type=1)
        btree_items.append((
            pack_btree_key(ROOT_INO, SALTY_DIR_ITEM, fnv1a_hash(fname_bytes)),
            dir_item_data,
        ))

        # Extent data
        if len(content) <= 256:
            # Inline extent
            extent_data = pack_extent_data_inline(generation, content)
            btree_items.append((
                pack_btree_key(file_ino, SALTY_EXTENT_DATA, 0),
                extent_data,
            ))
        else:
            # Regular extent: data stored in separate blocks
            data_block = next_data_block
            num_data_blocks = (len(content) + BLOCK_SIZE - 1) // BLOCK_SIZE
            next_data_block += num_data_blocks

            disk_bytenr = data_block * BLOCK_SIZE
            disk_num_bytes = num_data_blocks * BLOCK_SIZE

            extent_data = pack_extent_data_regular(
                generation=generation,
                ram_bytes=len(content),
                disk_bytenr=disk_bytenr,
                disk_num_bytes=disk_num_bytes,
                offset=0,
                num_bytes=len(content),
            )
            btree_items.append((
                pack_btree_key(file_ino, SALTY_EXTENT_DATA, 0),
                extent_data,
            ))

            file_data_blocks.append((data_block, content))

    used_blocks = next_data_block

    # Sort items by key to maintain B-tree invariant
    def btree_key_sort(item):
        key_bytes = item[0]
        object_id = struct.unpack_from("<Q", key_bytes, 0)[0]
        item_type = key_bytes[8]
        offset = struct.unpack_from("<Q", key_bytes, 9)[0]
        return (object_id, item_type, offset)

    btree_items.sort(key=btree_key_sort)

    # Build the root B-tree leaf node
    root_btree = build_btree_leaf(
        owner=0,
        generation=generation,
        block_nr=root_tree_block,
        items=btree_items,
    )

    # Build superblock
    superblock = build_superblock(
        total_blocks=total_blocks,
        used_blocks=used_blocks,
        root_tree=root_tree_block,
        root_inode=ROOT_INO,
        generation=generation,
    )

    # Build allocation bitmap
    bitmap = bytearray(bitmap_blocks * BLOCK_SIZE)
    for i in range(used_blocks):
        bitmap[i // 8] |= 1 << (i % 8)

    # Write the image
    with open(output_path, "wb") as f:
        # Block 0: Primary superblock
        f.write(superblock)

        # Block 1: Backup superblock
        f.write(superblock)

        # Blocks 2..N: Allocation bitmap
        f.write(bytes(bitmap))

        # Blocks N+1..M: Intent log (zeroed)
        f.write(b"\x00" * (log_size * BLOCK_SIZE))

        # Root B-tree node
        f.write(root_btree)

        # File data blocks
        current_pos = (root_tree_block + 1) * BLOCK_SIZE
        for data_block, content in file_data_blocks:
            target_pos = data_block * BLOCK_SIZE
            if target_pos > current_pos:
                f.write(b"\x00" * (target_pos - current_pos))
            padded = content + b"\x00" * (BLOCK_SIZE - (len(content) % BLOCK_SIZE or BLOCK_SIZE))
            if len(content) % BLOCK_SIZE == 0:
                padded = content
            else:
                padded = content + b"\x00" * (BLOCK_SIZE - len(content) % BLOCK_SIZE)
            f.write(padded)
            current_pos = target_pos + len(padded)

        # Pad to full size
        remaining = size - f.tell()
        if remaining > 0:
            # Write in chunks to avoid memory issues
            chunk = b"\x00" * min(remaining, 1024 * 1024)
            while remaining > 0:
                to_write = min(remaining, len(chunk))
                f.write(chunk[:to_write])
                remaining -= to_write

    total_size = os.path.getsize(output_path)
    print(f"Created SaltyFS image: {output_path} ({total_size} bytes, "
          f"{total_blocks} blocks, {len(files)} files)")


def main():
    parser = argparse.ArgumentParser(
        description="Create SaltyFS filesystem image for SaltyOS"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        required=True,
        help="Output image path",
    )
    parser.add_argument(
        "--size", "-s",
        default="64M",
        help="Image size (e.g., 64M, 1G, 256K). Default: 64M",
    )
    parser.add_argument(
        "--add-file",
        nargs=2,
        action="append",
        default=[],
        metavar=("NAME", "CONTENT"),
        help="Add a file with given name and text content",
    )
    parser.add_argument(
        "--add-file-from",
        nargs=2,
        action="append",
        default=[],
        metavar=("NAME", "PATH"),
        help="Add a file with content read from a path",
    )
    parser.add_argument(
        "--label",
        default="saltyfs",
        help="Volume label (default: saltyfs)",
    )

    args = parser.parse_args()

    size = parse_size(args.size)

    files = []

    # Default test files if none specified
    if not args.add_file and not args.add_file_from:
        files.append(("hello.txt", b"Hello from SaltyFS!\n"))
        files.append(("readme.txt", b"SaltyOS SaltyFS test filesystem.\n"
                       b"This image was generated by mksaltyfs.py.\n"))
        # A larger file to test regular (non-inline) extents
        large_content = b"Line %04d: The quick brown fox jumps over the lazy dog.\n"
        large_data = b""
        for i in range(200):
            large_data += large_content.replace(b"%04d", f"{i:04d}".encode())
        files.append(("large.txt", large_data))
    else:
        for name, content in args.add_file:
            files.append((name, content.encode("utf-8")))
        for name, path in args.add_file_from:
            with open(path, "rb") as f:
                files.append((name, f.read()))

    create_saltyfs_image(args.output, size, files)


if __name__ == "__main__":
    main()
