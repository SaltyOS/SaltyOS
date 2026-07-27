/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Disk Abstraction
 *
 * Provides a unified interface for disk access.
 */

#ifndef BOOT_STAGE3_DISK_DISK_H
#define BOOT_STAGE3_DISK_DISK_H

#include "../../common/types.h"

/* Disk types */
#define DISK_TYPE_BIOS 1   /* BIOS INT 13h */
#define DISK_TYPE_UEFI 2   /* UEFI Block I/O */
#define DISK_TYPE_MEMORY 3 /* Memory-mapped (preloaded) */

/* Disk error codes */
#define DISK_OK 0
#define DISK_ERR_NOT_INIT 1
#define DISK_ERR_READ 2
#define DISK_ERR_WRITE 3
#define DISK_ERR_PARAMS 4

/* Disk device structure */
struct DiskDevice {
  uint8_t type;          /* DISK_TYPE_* */
  uint8_t drive_num;     /* BIOS drive number (for DISK_TYPE_BIOS) */
  uint16_t sector_size;  /* Typically 512 */
  uint64_t sector_count; /* Total sectors (0 if unknown) */

  /* For memory-mapped disks */
  void *mem_base;  /* Base address of data */
  size_t mem_size; /* Size of data */
};

/* Global boot disk */
extern struct DiskDevice g_boot_disk;

/*
 * Initialize disk subsystem
 *
 * @param boot_drive: BIOS drive number
 *
 * Returns: 0 on success, error code otherwise
 */
int disk_init(uint8_t boot_drive);

/*
 * Read sectors from disk
 *
 * @param disk: Disk device
 * @param lba: Starting LBA
 * @param count: Number of sectors to read
 * @param buffer: Destination buffer
 *
 * Returns: 0 on success, error code otherwise
 */
int disk_read(struct DiskDevice *disk, uint64_t lba, uint32_t count,
              void *buffer);

/*
 * Read bytes from disk (handles partial sectors)
 *
 * @param disk: Disk device
 * @param offset: Byte offset from start
 * @param size: Number of bytes to read
 * @param buffer: Destination buffer
 *
 * Returns: 0 on success, error code otherwise
 */
int disk_read_bytes(struct DiskDevice *disk, uint64_t offset, size_t size,
                    void *buffer);

/*
 * Create a memory-mapped disk from preloaded data
 *
 * @param disk: Disk device to initialize
 * @param base: Base address of preloaded data
 * @param size: Size of preloaded data
 */
void disk_init_memory(struct DiskDevice *disk, void *base, size_t size);

#endif /* BOOT_STAGE3_DISK_DISK_H */
