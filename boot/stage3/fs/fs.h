/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Filesystem Abstraction
 *
 * Provides a unified interface for file access.
 * The mandatory boot path uses raw extents (no filesystem).
 * Filesystem support is optional for convenience.
 */

#ifndef BOOT_STAGE3_FS_FS_H
#define BOOT_STAGE3_FS_FS_H

#include "../../common/manifest.h"
#include "../../common/types.h"
#include "../disk/disk.h"

/* Filesystem types */
#define FS_TYPE_RAW 0     /* Raw extent access */
#define FS_TYPE_FAT32 1   /* FAT32 filesystem */
#define FS_TYPE_SALTYFS 2 /* SaltyFS (native) */

/* Filesystem error codes */
#define FS_OK 0
#define FS_ERR_NOT_FOUND 1
#define FS_ERR_IO 2
#define FS_ERR_INVALID 3
#define FS_ERR_NOT_IMPL 4
#define FS_ERR_NO_SPACE 5

/* File handle */
struct FSFile {
  uint8_t fs_type;   /* FS_TYPE_* */
  uint64_t size;     /* File size */
  uint64_t position; /* Current read position */

  /* For raw extent access */
  const struct BootManifestEntry *entry;
  struct DiskDevice *disk;

  /* For filesystem access */
  void *fs_data; /* Filesystem-specific data */
};

/*
 * Load file from manifest entry (raw extent access)
 *
 * @param disk: Disk device to read from
 * @param entry: Manifest entry describing the file
 * @param buffer: Destination buffer
 * @param buffer_size: Size of destination buffer
 *
 * Returns: Number of bytes read, or negative error code
 */
ssize_t fs_load_from_entry(struct DiskDevice *disk,
                           const struct BootManifestEntry *entry, void *buffer,
                           size_t buffer_size);

/*
 * Load file by reading raw extents
 *
 * @param disk: Disk device
 * @param extents: Array of extents
 * @param extent_count: Number of extents
 * @param buffer: Destination buffer
 * @param buffer_size: Size of buffer
 *
 * Returns: Number of bytes read, or negative error code
 */
ssize_t fs_load_extents(struct DiskDevice *disk,
                        const struct ManifestExtent *extents,
                        uint32_t extent_count, void *buffer,
                        size_t buffer_size);

#endif /* BOOT_STAGE3_FS_FS_H */
