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

# B-tree on-disk sizes (match userland/fs/saltyfs/src/types.rs packed layouts)
BTREE_NODE_HEADER_SIZE = 64
BTREE_ITEM_SIZE = 25       # BTreeItem = BTreeKey(17) + offset(4) + size(4)
BTREE_POINTER_SIZE = 33    # BTreePointer = BTreeKey(17) + block_nr(8) + generation(8)


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


def pack_btree_pointer(key: bytes, block_nr: int, generation: int) -> bytes:
    """Pack a BTreePointer: key(17) + block_nr(8) + generation(8) = 33 bytes."""
    return key + struct.pack("<QQ", block_nr, generation)


def unpack_btree_key(key_bytes: bytes) -> tuple[int, int, int]:
    """Unpack BTreeKey bytes into a sortable tuple."""
    return struct.unpack("<QBQ", key_bytes)


def btree_item_sort_key(item: tuple[bytes, bytes]) -> tuple[int, int, int]:
    """Sort key for (BTreeKey bytes, item data bytes) tuples."""
    return unpack_btree_key(item[0])


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
    header_size = BTREE_NODE_HEADER_SIZE
    item_entry_size = BTREE_ITEM_SIZE

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

    if data_area_start + len(data_area) > BLOCK_SIZE:
        raise ValueError(
            f"Leaf node overflow: {num_items} items require "
            f"{data_area_start + len(data_area)} bytes (> {BLOCK_SIZE})"
        )

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
    block[data_area_start:data_area_start + len(data_area)] = data_area

    # Compute checksum (with checksum field zeroed)
    checksum = crc32c(bytes(block))
    struct.pack_into("<I", block, 4, checksum)

    return bytes(block)


def build_btree_internal(
    owner: int, generation: int, block_nr: int, level: int,
    pointers: list[tuple[bytes, int]],
) -> bytes:
    """
    Build an internal B-tree node (level > 0).

    pointers: list of (first_key_bytes_in_child, child_block_nr), sorted by key.
    """
    if level <= 0:
        raise ValueError(f"Invalid internal node level: {level}")
    if not pointers:
        raise ValueError("Internal node must contain at least one pointer")

    total_size = BTREE_NODE_HEADER_SIZE + len(pointers) * BTREE_POINTER_SIZE
    if total_size > BLOCK_SIZE:
        raise ValueError(
            f"Internal node overflow: {len(pointers)} pointers require "
            f"{total_size} bytes (> {BLOCK_SIZE})"
        )

    header = struct.pack(
        "<4sI"
        "QQQ"
        "IHH"
        "24s",
        BTREE_NODE_MAGIC, 0,
        owner, generation, block_nr,
        len(pointers), level, 0,
        b"\x00" * 24,
    )

    block = bytearray(BLOCK_SIZE)
    block[:len(header)] = header

    off = BTREE_NODE_HEADER_SIZE
    for key_bytes, child_block_nr in pointers:
        ptr = pack_btree_pointer(key_bytes, child_block_nr, generation)
        block[off:off + BTREE_POINTER_SIZE] = ptr
        off += BTREE_POINTER_SIZE

    checksum = crc32c(bytes(block))
    struct.pack_into("<I", block, 4, checksum)
    return bytes(block)


def split_leaf_items_for_nodes(items: list[tuple[bytes, bytes]]) -> list[list[tuple[bytes, bytes]]]:
    """Split sorted leaf items into as many 4KB leaf nodes as needed."""
    if not items:
        return []

    leaves: list[list[tuple[bytes, bytes]]] = []
    cur: list[tuple[bytes, bytes]] = []
    cur_data_size = 0

    for key_bytes, item_data in items:
        item_data_len = len(item_data)
        new_count = len(cur) + 1
        need = BTREE_NODE_HEADER_SIZE + new_count * BTREE_ITEM_SIZE + cur_data_size + item_data_len

        if need > BLOCK_SIZE and cur:
            leaves.append(cur)
            cur = []
            cur_data_size = 0
            new_count = 1
            need = BTREE_NODE_HEADER_SIZE + new_count * BTREE_ITEM_SIZE + item_data_len

        if need > BLOCK_SIZE:
            raise ValueError(
                "Single leaf item exceeds block size: "
                f"key={unpack_btree_key(key_bytes)} item_size={item_data_len}"
            )

        cur.append((key_bytes, item_data))
        cur_data_size += item_data_len

    if cur:
        leaves.append(cur)

    return leaves


def build_btree_blocks(
    items: list[tuple[bytes, bytes]],
    generation: int,
    tree_start_block: int,
    owner: int = 0,
) -> tuple[int, list[tuple[int, bytes]]]:
    """
    Build a multi-leaf B-tree from sorted metadata items.

    Returns (root_block_nr, [(block_nr, block_bytes), ...]).
    """
    if not items:
        raise ValueError("Cannot build B-tree with zero items")

    sorted_items = sorted(items, key=btree_item_sort_key)
    leaf_chunks = split_leaf_items_for_nodes(sorted_items)

    # Level 0 (leaves)
    levels: list[list[dict]] = [[
        {
            "level": 0,
            "first_key": chunk[0][0],
            "leaf_items": chunk,
        }
        for chunk in leaf_chunks
    ]]

    max_ptrs = (BLOCK_SIZE - BTREE_NODE_HEADER_SIZE) // BTREE_POINTER_SIZE
    if max_ptrs < 1:
        raise ValueError("B-tree internal node capacity is zero")

    # Build upper internal levels until a single root remains
    current = levels[0]
    while len(current) > 1:
        next_level_nodes: list[dict] = []
        for i in range(0, len(current), max_ptrs):
            children = current[i:i + max_ptrs]
            next_level_nodes.append({
                "level": children[0]["level"] + 1,
                "first_key": children[0]["first_key"],
                "children": children,
            })
        levels.append(next_level_nodes)
        current = next_level_nodes

    # Assign contiguous block numbers to all nodes (leaves first, root last)
    next_block = tree_start_block
    for nodes in levels:
        for node in nodes:
            node["block_nr"] = next_block
            next_block += 1

    blocks: list[tuple[int, bytes]] = []
    for nodes in levels:
        for node in nodes:
            block_nr = node["block_nr"]
            if node["level"] == 0:
                block_bytes = build_btree_leaf(owner, generation, block_nr, node["leaf_items"])
            else:
                ptrs = []
                for child in node["children"]:
                    ptrs.append((child["first_key"], child["block_nr"]))
                block_bytes = build_btree_internal(owner, generation, block_nr, node["level"], ptrs)
            blocks.append((block_nr, block_bytes))

    root = levels[-1][0]["block_nr"]
    blocks.sort(key=lambda x: x[0])
    return root, blocks


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


def create_saltyfs_image(output_path: Path, size: int, files: list, label: str = "saltyfs"):
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
    # Block M+1..K: Root B-tree nodes (multi-level)
    # Block K+1..: File data blocks

    bitmap_blocks = (total_blocks + BLOCK_SIZE * 8 - 1) // (BLOCK_SIZE * 8)
    log_start = 2 + bitmap_blocks
    log_size = min(64 * 1024 * 1024 // BLOCK_SIZE, total_blocks // 8)
    if log_size < 1:
        log_size = 1

    root_tree_block = log_start + log_size
    generation = 1
    now_ns = int(time.time()) * 1_000_000_000  # nanoseconds since epoch

    def build_metadata_items_and_data(first_data_block: int) -> tuple[list, list, int]:
        """
        Build metadata items plus regular-file data block placements.

        first_data_block is the first free block after all tree blocks.
        Returns (btree_items, file_data_blocks, next_free_block).
        """
        btree_items = []
        next_data_block = first_data_block

        # --- Collect unique parent directories from file paths ---
        dir_paths = set()
        for fname, _content in files:
            parts = fname.strip('/').split('/')
            for i in range(1, len(parts)):  # skip the filename itself
                dir_paths.add('/'.join(parts[:i]))

        # Sort by depth (parents before children)
        sorted_dirs = sorted(dir_paths, key=lambda d: d.count('/'))

        # Root directory inode (ino=1)
        # nlink = 2 (self + parent) + number of immediate child directories
        root_child_dirs = sum(1 for d in sorted_dirs if '/' not in d)
        root_inode_data = pack_inode(
            generation=generation,
            size=0,
            blocks=0,
            nlink=2 + root_child_dirs,
            mode=S_IFDIR | 0o755,
            atime=now_ns, mtime=now_ns, ctime=now_ns, crtime=now_ns,
        )
        btree_items.append((
            pack_btree_key(ROOT_INO, SALTY_INODE_ITEM, 0),
            root_inode_data,
        ))

        # Assign inode numbers to directories and create their B-tree items
        next_ino = FIRST_FILE_INO
        dir_ino_map = {}  # "bin" -> inode_num, "bin/sub" -> inode_num, etc.
        file_data_blocks = []

        for d in sorted_dirs:
            dir_ino = next_ino
            next_ino += 1
            dir_ino_map[d] = dir_ino

            dir_name = d.rsplit('/', 1)[-1]  # last component
            parent_path = d.rsplit('/', 1)[0] if '/' in d else ''
            parent_ino = dir_ino_map.get(parent_path, ROOT_INO)

            # Directory inode
            dir_inode_data = pack_inode(
                generation=generation, size=0, blocks=0, nlink=2,
                mode=S_IFDIR | 0o755,
                atime=now_ns, mtime=now_ns, ctime=now_ns, crtime=now_ns,
            )
            btree_items.append((
                pack_btree_key(dir_ino, SALTY_INODE_ITEM, 0),
                dir_inode_data,
            ))

            # DIR_ITEM in parent
            name_bytes = dir_name.encode("ascii")
            dir_item_data = pack_dir_item(dir_ino, name_bytes, dir_type=4)  # 4 = directory
            btree_items.append((
                pack_btree_key(parent_ino, SALTY_DIR_ITEM, fnv1a_hash(name_bytes)),
                dir_item_data,
            ))

            # INODE_REF: (dir_ino, SALTY_INODE_REF, parent_ino) → name
            # Enables O(log n) reverse lookup for GETPARENT
            btree_items.append((
                pack_btree_key(dir_ino, SALTY_INODE_REF, parent_ino),
                name_bytes,
            ))

        # Create file inodes and directory entries
        for fname, content in files:
            file_ino = next_ino
            next_ino += 1

            # Resolve parent directory and basename
            stripped = fname.strip('/')
            if '/' in stripped:
                parent_path, basename = stripped.rsplit('/', 1)
                parent_ino = dir_ino_map.get(parent_path, ROOT_INO)
            else:
                basename = stripped
                parent_ino = ROOT_INO

            fname_bytes = basename.encode("ascii")

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

            # Directory entry under correct parent
            dir_item_data = pack_dir_item(file_ino, fname_bytes, dir_type=1)
            btree_items.append((
                pack_btree_key(parent_ino, SALTY_DIR_ITEM, fnv1a_hash(fname_bytes)),
                dir_item_data,
            ))

            # INODE_REF: (file_ino, SALTY_INODE_REF, parent_ino) → name
            # Enables O(log n) reverse lookup for GETPARENT
            btree_items.append((
                pack_btree_key(file_ino, SALTY_INODE_REF, parent_ino),
                fname_bytes,
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

        btree_items.sort(key=btree_item_sort_key)
        return btree_items, file_data_blocks, next_data_block

    # Pass 1: build metadata with placeholder data placement to determine tree size.
    probe_items, _probe_data_blocks, _probe_next_block = build_metadata_items_and_data(root_tree_block + 1)
    _probe_root_block, probe_tree_blocks = build_btree_blocks(
        probe_items,
        generation=generation,
        tree_start_block=root_tree_block,
        owner=0,
    )

    tree_block_count = len(probe_tree_blocks)
    data_start_block = root_tree_block + tree_block_count

    # Pass 2: rebuild metadata with final data extents after tree size is known.
    btree_items, file_data_blocks, next_data_block = build_metadata_items_and_data(data_start_block)
    root_tree_root_block, tree_blocks = build_btree_blocks(
        btree_items,
        generation=generation,
        tree_start_block=root_tree_block,
        owner=0,
    )

    if len(tree_blocks) != tree_block_count:
        raise RuntimeError(
            "B-tree block count changed between probe and final pass "
            f"({tree_block_count} -> {len(tree_blocks)})"
        )

    used_blocks = next_data_block
    if used_blocks > total_blocks:
        print(
            f"Error: Image too small ({total_blocks} blocks) for metadata+data "
            f"({used_blocks} blocks used)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Build superblock
    superblock = build_superblock(
        total_blocks=total_blocks,
        used_blocks=used_blocks,
        root_tree=root_tree_root_block,
        root_inode=ROOT_INO,
        generation=generation,
        label=label,
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

        # Root B-tree blocks (leaves + internal nodes, contiguous)
        current_pos = root_tree_block * BLOCK_SIZE
        for tree_block_nr, tree_block_bytes in tree_blocks:
            target_pos = tree_block_nr * BLOCK_SIZE
            if target_pos > current_pos:
                f.write(b"\x00" * (target_pos - current_pos))
            f.write(tree_block_bytes)
            current_pos = target_pos + len(tree_block_bytes)

        # File data blocks
        for data_block, content in file_data_blocks:
            target_pos = data_block * BLOCK_SIZE
            if target_pos > current_pos:
                f.write(b"\x00" * (target_pos - current_pos))
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
    print(
        f"Created SaltyFS image: {output_path} ({total_size} bytes, "
        f"{total_blocks} blocks, {len(files)} files, {tree_block_count} tree blocks)"
    )


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

    create_saltyfs_image(args.output, size, files, label=args.label)


if __name__ == "__main__":
    main()
