#!/usr/bin/env python3
"""
SaltyOS CPIO Archive Generator
SPDX-License-Identifier: GPL-2.0-only

Generates a CPIO newc format archive from a list of files.
Used to create the initrd image containing the init ELF.

Usage:
    python3 tools/mkcpio.py --output initrd.cpio init.elf=build/userland/init.elf
    python3 tools/mkcpio.py --output initrd.cpio --port-dir build/ports \
        --manifest build/ports/bash.manifest \
        --manifest build/ports/freebsd-utils.manifest \
        init.elf=build/userland/init.elf
"""

import argparse
import os
import struct
import sys
from pathlib import Path

CPIO_HEADER_SIZE = 110
DEFAULT_PAGE_ALIGN = 4096
DEFAULT_PAGE_ALIGN_EXTENSIONS = ('.elf', '.so')


def cpio_newc_header(ino, mode, filesize, namesize):
    """Create a CPIO newc header (110 bytes ASCII)."""
    # "070701" magic + 13 fields of 8 hex chars each
    return (
        f"070701"
        f"{ino:08X}"          # c_ino
        f"{mode:08X}"         # c_mode (regular file, 0644)
        f"{0:08X}"            # c_uid
        f"{0:08X}"            # c_gid
        f"{1:08X}"            # c_nlink
        f"{0:08X}"            # c_mtime
        f"{filesize:08X}"     # c_filesize
        f"{0:08X}"            # c_devmajor
        f"{0:08X}"            # c_devminor
        f"{0:08X}"            # c_rdevmajor
        f"{0:08X}"            # c_rdevminor
        f"{namesize:08X}"     # c_namesize
        f"{0:08X}"            # c_check
    ).encode('ascii')


def align4(n):
    """Round up to 4-byte boundary."""
    return (n + 3) & ~3


def append_cpio_entry(archive, ino, name, data):
    """Append one newc entry to archive."""
    filesize = len(data)
    namesize = len(name) + 1  # Include NUL terminator

    # Header (110 bytes)
    header = cpio_newc_header(ino, 0o100644, filesize, namesize)
    archive.extend(header)

    # Filename + NUL
    archive.extend(name.encode('ascii'))
    archive.append(0)

    # Pad filename to 4-byte boundary (header + name must be 4-aligned)
    header_plus_name = CPIO_HEADER_SIZE + namesize
    pad_name = align4(header_plus_name) - header_plus_name
    archive.extend(b'\x00' * pad_name)

    # File data
    archive.extend(data)

    # Pad data to 4-byte boundary
    pad_data = align4(filesize) - filesize
    archive.extend(b'\x00' * pad_data)


def should_page_align_entry(name, exts):
    lower = name.lower()
    return any(lower.endswith(ext) for ext in exts)


def calc_next_data_start(archive_len, name):
    namesize = len(name) + 1
    return align4(archive_len + CPIO_HEADER_SIZE + namesize)


def calc_pad_payload_size(cur_archive_len, next_name, pad_name, page_align):
    """Find minimal pad payload bytes so next_name data starts page-aligned."""
    for pad_payload in range(0, page_align):
        trial_offset = cur_archive_len
        # Simulate pad entry
        pad_name_size = len(pad_name) + 1
        pad_data_start = align4(trial_offset + CPIO_HEADER_SIZE + pad_name_size)
        trial_offset = align4(pad_data_start + pad_payload)
        # Simulate next entry data start
        next_data_start = calc_next_data_start(trial_offset, next_name)
        if (next_data_start % page_align) == 0:
            return pad_payload
    return None


def create_cpio_archive(entries, output_path, page_align_exts):
    """Create a CPIO newc archive from a list of (name, filepath) tuples."""
    archive = bytearray()
    ino = 1
    pad_idx = 0

    for name, filepath in entries:
        # For ELF/shared objects, align entry data start to 4KB so rtld can
        # use direct page-granularity map_device without per-page copies.
        if should_page_align_entry(name, page_align_exts):
            next_data_start = calc_next_data_start(len(archive), name)
            if (next_data_start % DEFAULT_PAGE_ALIGN) != 0:
                pad_name = f".pad/{pad_idx:04d}"
                pad_payload = calc_pad_payload_size(
                    len(archive), name, pad_name, DEFAULT_PAGE_ALIGN
                )
                if pad_payload is None:
                    raise RuntimeError(f"failed to align CPIO entry: {name}")
                append_cpio_entry(archive, ino, pad_name, b'\x00' * pad_payload)
                ino += 1
                pad_idx += 1

        data = filepath.read_bytes()
        append_cpio_entry(archive, ino, name, data)

        ino += 1

    # Trailer entry
    trailer_name = "TRAILER!!!"
    namesize = len(trailer_name) + 1
    header = cpio_newc_header(0, 0, 0, namesize)
    archive.extend(header)
    archive.extend(trailer_name.encode('ascii'))
    archive.append(0)

    # Pad trailer name to 4-byte boundary
    header_plus_name = CPIO_HEADER_SIZE + namesize
    pad_name = align4(header_plus_name) - header_plus_name
    archive.extend(b'\x00' * pad_name)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(archive))
    return len(archive)


def load_manifest(manifest_path, port_dir):
    """Load entries from a manifest file (initrd_path=filename per line)."""
    entries = []
    with open(manifest_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            name, filename = line.split('=', 1)
            name = name.strip()
            filename = filename.strip()
            # Resolve filename relative to the manifest's directory
            manifest_dir = Path(manifest_path).parent
            filepath = manifest_dir / filename
            if not filepath.exists() and port_dir:
                filepath = Path(port_dir) / filename
            entries.append((name, filepath))
    return entries


def main():
    parser = argparse.ArgumentParser(
        description='Create CPIO newc archive for SaltyOS initrd'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        required=True,
        help='Output CPIO archive path'
    )
    parser.add_argument(
        'entries',
        nargs='*',
        help='Files to include: name=path (e.g., init.elf=build/userland/init.elf)'
    )
    parser.add_argument(
        '--manifest',
        action='append',
        default=[],
        help='Load initrd entries from manifest file (initrd_path=filename)'
    )
    parser.add_argument(
        '--port-dir',
        type=Path,
        default=None,
        help='Base directory for resolving manifest file paths'
    )
    parser.add_argument(
        '--page-align-extensions',
        default=','.join(DEFAULT_PAGE_ALIGN_EXTENSIONS),
        help='Comma-separated suffixes that should have 4KB-aligned data starts (default: .elf,.so)'
    )

    args = parser.parse_args()

    page_align_exts = tuple(
        ext.strip().lower()
        for ext in args.page_align_extensions.split(',')
        if ext.strip()
    )

    entries = []

    # Load positional entries (system binaries, services)
    for entry_str in args.entries:
        if '=' not in entry_str:
            print(f"Error: Entry must be name=path, got: {entry_str}", file=sys.stderr)
            sys.exit(1)

        name, filepath_str = entry_str.split('=', 1)
        filepath = Path(filepath_str)

        if not filepath.exists():
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)

        entries.append((name, filepath))

    # Load manifest entries (port outputs)
    for manifest_path in args.manifest:
        if not Path(manifest_path).exists():
            print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
            sys.exit(1)
        manifest_entries = load_manifest(manifest_path, args.port_dir)
        for name, filepath in manifest_entries:
            if not filepath.exists():
                print(f"Error: File not found (from manifest {manifest_path}): {filepath}", file=sys.stderr)
                sys.exit(1)
        entries.extend(manifest_entries)

    if not entries:
        print("Error: No entries to archive", file=sys.stderr)
        sys.exit(1)

    total_size = create_cpio_archive(entries, args.output, page_align_exts)
    print(f"Created CPIO archive: {args.output} ({total_size} bytes, {len(entries)} entries)")


if __name__ == '__main__':
    main()
