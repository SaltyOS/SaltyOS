/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Raw Extent Loader
 *
 * Loads files directly from raw disk extents specified in the Boot Manifest.
 * This is the mandatory boot path - no filesystem required.
 */

#include "../../common/print.h"
#include "../../common/string.h"
#include "../config.h"
#include "fs.h"

ssize_t fs_load_extents(struct DiskDevice *disk,
                        const struct ManifestExtent *extents,
                        uint32_t extent_count, void *buffer,
                        size_t buffer_size) {
  uint8_t *dest = (uint8_t *)buffer;
  size_t total_read = 0;

  for (uint32_t i = 0; i < extent_count; i++) {
    if (extents[i].sector_count == 0)
      continue;

    uint64_t lba = extents[i].lba;
    uint32_t sectors = extents[i].sector_count;
    size_t bytes = (size_t)sectors * disk->sector_size;

    /* Check buffer space */
    if (total_read + bytes > buffer_size) {
      size_t remaining = buffer_size - total_read;
      uint32_t full_sectors = remaining / disk->sector_size;
      size_t tail = remaining % disk->sector_size;

      /* Read full sectors directly into buffer */
      if (full_sectors > 0) {
        int err = disk_read(disk, lba, full_sectors, dest);
        if (err != DISK_OK)
          return -FS_ERR_IO;
        dest += (size_t)full_sectors * disk->sector_size;
        total_read += (size_t)full_sectors * disk->sector_size;
        lba += full_sectors;
      }

      /* Read partial trailing sector via temp buffer */
      if (tail > 0) {
        uint8_t sector_buf[512];
        int err = disk_read(disk, lba, 1, sector_buf);
        if (err != DISK_OK)
          return -FS_ERR_IO;
        memcpy(dest, sector_buf, tail);
        total_read += tail;
      }
      break;
    }

#if CONFIG_DEBUG
    print_str("  Extent ");
    print_dec(i);
    print_str(": LBA ");
    print_dec(lba);
    print_str(" sectors ");
    print_dec(sectors);
    print_char('\n');
#endif

    int err = disk_read(disk, lba, sectors, dest);
    if (err != DISK_OK) {
      print_str("Error reading extent ");
      print_dec(i);
      print_str(": ");
      print_dec(err);
      print_char('\n');
      return -FS_ERR_IO;
    }

    dest += bytes;
    total_read += bytes;

    if (total_read >= buffer_size)
      break;
  }

  return (ssize_t)total_read;
}

ssize_t fs_load_from_entry(struct DiskDevice *disk,
                           const struct BootManifestEntry *entry, void *buffer,
                           size_t buffer_size) {
  if (!disk || !entry || !buffer)
    return -FS_ERR_INVALID;

  if (entry->extent_count == 0 || entry->extent_count > MAX_EXTENTS)
    return -FS_ERR_INVALID;

#if CONFIG_DEBUG
  print_str("Loading entry type ");
  print_dec(entry->type);
  print_str(" size ");
  print_dec(entry->size_bytes);
  print_str(" extents ");
  print_dec(entry->extent_count);
  print_char('\n');
#endif

  /* Limit read to actual file size */
  size_t to_read = buffer_size;
  if (entry->size_bytes < to_read)
    to_read = entry->size_bytes;

  ssize_t read = fs_load_extents(disk, entry->extents, entry->extent_count,
                                 buffer, to_read);

  if (read < 0)
    return read;

  /* Verify we read enough */
  if ((uint64_t)read < entry->size_bytes && (size_t)read < buffer_size) {
    print_line("Warning: Short read");
  }

  return read;
}
