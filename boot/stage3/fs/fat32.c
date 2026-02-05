/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - FAT32 Filesystem Driver
 *
 * Optional FAT32 support for loading files from formatted media.
 * This is NOT required for the mandatory boot path (raw extents).
 *
 * Status: Stub implementation - not yet functional.
 */

#include "fs.h"
#include "../config.h"

#if CONFIG_FS_FAT32

/* FAT32 Boot Sector / BPB */
struct FAT32_BPB {
    uint8_t  jmp[3];
    uint8_t  oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  num_fats;
    uint16_t root_entries;      /* 0 for FAT32 */
    uint16_t total_sectors_16;  /* 0 for FAT32 */
    uint8_t  media_type;
    uint16_t fat_size_16;       /* 0 for FAT32 */
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;

    /* FAT32 specific */
    uint32_t fat_size_32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;
    uint16_t fs_info_sector;
    uint16_t backup_boot_sector;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_signature;
    uint32_t volume_serial;
    uint8_t  volume_label[11];
    uint8_t  fs_type[8];
} PACKED;

/* Directory entry */
struct FAT32_DirEntry {
    uint8_t  name[11];
    uint8_t  attr;
    uint8_t  nt_reserved;
    uint8_t  create_time_tenth;
    uint16_t create_time;
    uint16_t create_date;
    uint16_t access_date;
    uint16_t first_cluster_hi;
    uint16_t write_time;
    uint16_t write_date;
    uint16_t first_cluster_lo;
    uint32_t file_size;
} PACKED;

/* Directory entry attributes */
#define FAT_ATTR_READ_ONLY  0x01
#define FAT_ATTR_HIDDEN     0x02
#define FAT_ATTR_SYSTEM     0x04
#define FAT_ATTR_VOLUME_ID  0x08
#define FAT_ATTR_DIRECTORY  0x10
#define FAT_ATTR_ARCHIVE    0x20
#define FAT_ATTR_LONG_NAME  0x0F

/* FAT32 context */
struct FAT32_Context {
    struct DiskDevice *disk;
    uint32_t fat_start_lba;
    uint32_t data_start_lba;
    uint32_t root_cluster;
    uint32_t sectors_per_cluster;
    uint32_t bytes_per_sector;
};

/*
 * Initialize FAT32 filesystem
 *
 * Returns: 0 on success, error code otherwise
 */
int fat32_init(struct DiskDevice *disk, struct FAT32_Context *ctx)
{
    (void)disk;
    (void)ctx;
    /* TODO: Implement FAT32 initialization */
    return FS_ERR_NOT_IMPL;
}

/*
 * Open a file by path
 *
 * Returns: 0 on success, error code otherwise
 */
int fat32_open(struct FAT32_Context *ctx, const char *path, struct FSFile *file)
{
    (void)ctx;
    (void)path;
    (void)file;
    /* TODO: Implement file open */
    return FS_ERR_NOT_IMPL;
}

/*
 * Read from file
 *
 * Returns: Number of bytes read, or negative error code
 */
ssize_t fat32_read(struct FAT32_Context *ctx, struct FSFile *file,
                   void *buffer, size_t size)
{
    (void)ctx;
    (void)file;
    (void)buffer;
    (void)size;
    /* TODO: Implement file read */
    return -FS_ERR_NOT_IMPL;
}

#endif /* CONFIG_FS_FAT32 */
