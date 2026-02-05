/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Memory-mapped Disk Driver
 *
 * Provides disk-like access to preloaded data in memory.
 * This is the primary method used by Stage 3 since all data
 * is loaded by Stage 2 before entering long mode.
 */

#include "disk.h"
#include "../../common/string.h"

/*
 * Create a memory-mapped disk view of a buffer
 */
void memory_disk_create(struct DiskDevice *disk, void *base, size_t size)
{
    disk->type = DISK_TYPE_MEMORY;
    disk->drive_num = 0xFF;  /* Not a real drive */
    disk->sector_size = 512;
    disk->sector_count = size / 512;
    disk->mem_base = base;
    disk->mem_size = size;
}

/*
 * Read sectors from memory disk
 */
int memory_disk_read_sectors(struct DiskDevice *disk, uint64_t lba,
                             uint32_t count, void *buffer)
{
    if (!disk || disk->type != DISK_TYPE_MEMORY)
        return DISK_ERR_NOT_INIT;

    if (!disk->mem_base)
        return DISK_ERR_NOT_INIT;

    uint64_t offset = lba * disk->sector_size;
    uint64_t size = (uint64_t)count * disk->sector_size;

    if (offset + size > disk->mem_size)
        return DISK_ERR_READ;

    memcpy(buffer, (uint8_t *)disk->mem_base + offset, size);
    return DISK_OK;
}

/*
 * Read arbitrary bytes from memory disk
 */
int memory_disk_read_bytes(struct DiskDevice *disk, uint64_t offset,
                           size_t size, void *buffer)
{
    if (!disk || disk->type != DISK_TYPE_MEMORY)
        return DISK_ERR_NOT_INIT;

    if (!disk->mem_base)
        return DISK_ERR_NOT_INIT;

    if (offset + size > disk->mem_size)
        return DISK_ERR_READ;

    memcpy(buffer, (uint8_t *)disk->mem_base + offset, size);
    return DISK_OK;
}

/*
 * Get direct pointer to data at offset (zero-copy access)
 */
void *memory_disk_get_ptr(struct DiskDevice *disk, uint64_t offset)
{
    if (!disk || disk->type != DISK_TYPE_MEMORY)
        return NULL;

    if (!disk->mem_base || offset >= disk->mem_size)
        return NULL;

    return (uint8_t *)disk->mem_base + offset;
}

/*
 * Get direct pointer to data at LBA
 */
void *memory_disk_get_sector_ptr(struct DiskDevice *disk, uint64_t lba)
{
    return memory_disk_get_ptr(disk, lba * disk->sector_size);
}
