/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - BIOS Disk Driver
 *
 * Uses BTX trampoline to perform disk I/O via BIOS INT 13h
 * while running in 32-bit protected mode.
 */

#include "../../common/arch/x86/bios/btx.h"
#include "../../common/print.h"
#include "../../common/string.h"
#include "disk.h"

/* Bounce buffer for reading above 1MB (BIOS INT 13h needs real-mode addressable
 * memory) */
#define BOUNCE_BUF 0x60000
#define BOUNCE_SIZE 0x10000 /* 64KB */
#define BOUNCE_SECTORS (BOUNCE_SIZE / 512)

/* Global boot disk */
struct DiskDevice g_boot_disk;

int disk_init(uint8_t boot_drive) {
  g_boot_disk.type = DISK_TYPE_BIOS;
  g_boot_disk.drive_num = boot_drive;
  g_boot_disk.sector_size = 512;
  g_boot_disk.sector_count = 0; /* Unknown */
  g_boot_disk.mem_base = NULL;
  g_boot_disk.mem_size = 0;

  return DISK_OK;
}

int disk_read(struct DiskDevice *disk, uint64_t lba, uint32_t count,
              void *buffer) {
  if (!disk || !buffer)
    return DISK_ERR_PARAMS;

  if (disk->type == DISK_TYPE_MEMORY) {
    /* Handle memory-mapped disk */
    uint64_t offset = lba * disk->sector_size;
    uint64_t size = (uint64_t)count * disk->sector_size;

    if (offset + size > disk->mem_size)
      return DISK_ERR_READ;

    uint8_t *src = (uint8_t *)disk->mem_base + offset;
    uint8_t *dst = (uint8_t *)buffer;
    for (uint64_t i = 0; i < size; i++)
      dst[i] = src[i];

    return DISK_OK;
  }

  if (disk->type == DISK_TYPE_BIOS) {
    /*
     * Use BTX to perform BIOS disk read.
     * BTX provides real-mode access from protected mode.
     *
     * BIOS INT 13h requires the buffer to be in real-mode
     * addressable memory (< 1MB). For buffers above 1MB,
     * we use a bounce buffer at 0x60000 and memcpy.
     */

    if ((uintptr_t)buffer < 0x100000) {
      /* Direct read - buffer is in low memory */
      int result = btx_disk_read(disk->drive_num, lba, (uint16_t)count, buffer);
      if (result != 0)
        return DISK_ERR_READ;
      return DISK_OK;
    }

    /* Bounce buffer path for reads above 1MB */
    uint8_t *dest = (uint8_t *)buffer;
    uint64_t cur_lba = lba;
    uint32_t remaining = count;

    while (remaining > 0) {
      uint32_t chunk = remaining;
      if (chunk > BOUNCE_SECTORS)
        chunk = BOUNCE_SECTORS;

      int result = btx_disk_read(disk->drive_num, cur_lba, (uint16_t)chunk,
                                 (void *)BOUNCE_BUF);
      if (result != 0)
        return DISK_ERR_READ;

      memcpy(dest, (void *)BOUNCE_BUF, chunk * 512);
      dest += chunk * 512;
      cur_lba += chunk;
      remaining -= chunk;
    }

    return DISK_OK;
  }

  return DISK_ERR_NOT_INIT;
}

int disk_read_bytes(struct DiskDevice *disk, uint64_t offset, size_t size,
                    void *buffer) {
  if (!disk || !buffer)
    return DISK_ERR_PARAMS;

  if (disk->type == DISK_TYPE_MEMORY) {
    if (offset + size > disk->mem_size)
      return DISK_ERR_READ;

    uint8_t *src = (uint8_t *)disk->mem_base + offset;
    uint8_t *dst = (uint8_t *)buffer;
    for (size_t i = 0; i < size; i++)
      dst[i] = src[i];

    return DISK_OK;
  }

  /* For BIOS disk, read must be sector-aligned */
  if (disk->type == DISK_TYPE_BIOS) {
    /* Calculate sector-aligned read */
    uint64_t start_sector = offset / disk->sector_size;
    uint64_t end_sector =
        (offset + size + disk->sector_size - 1) / disk->sector_size;
    uint32_t sector_count = (uint32_t)(end_sector - start_sector);

    /* We need a temporary buffer for unaligned reads */
    /* For simplicity, require aligned reads for BIOS disk */
    if (offset % disk->sector_size != 0 || size % disk->sector_size != 0) {
      print_line("Error: Unaligned disk read not supported");
      return DISK_ERR_PARAMS;
    }

    return disk_read(disk, start_sector, sector_count, buffer);
  }

  return DISK_ERR_NOT_INIT;
}

void disk_init_memory(struct DiskDevice *disk, void *base, size_t size) {
  disk->type = DISK_TYPE_MEMORY;
  disk->drive_num = 0;
  disk->sector_size = 512;
  disk->sector_count = size / 512;
  disk->mem_base = base;
  disk->mem_size = size;
}
