/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - SaltyFS Filesystem Driver
 *
 * Optional SaltyFS support for loading files from native filesystem.
 * This is NOT required for the mandatory boot path (raw extents).
 *
 * Status: Stub implementation - filesystem design pending.
 */

#include "../config.h"
#include "fs.h"

#if CONFIG_FS_SALTYFS

/* SaltyFS magic: "SALTYFS\0" */
#define SALTYFS_MAGIC 0x5346595453414C53ULL

/* SaltyFS superblock */
struct SaltyFS_Superblock {
  uint64_t magic;
  uint32_t version;
  uint32_t flags;
  uint64_t block_size;
  uint64_t total_blocks;
  uint64_t free_blocks;
  uint64_t root_inode;
  uint64_t inode_table_block;
  uint64_t block_bitmap_block;
  uint64_t checksum;
} PACKED;

/* SaltyFS inode */
struct SaltyFS_Inode {
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint32_t nlinks;
  uint64_t size;
  uint64_t atime;
  uint64_t mtime;
  uint64_t ctime;
  uint64_t blocks[12];      /* Direct blocks */
  uint64_t indirect_block;  /* Single indirect */
  uint64_t double_indirect; /* Double indirect */
  uint64_t triple_indirect; /* Triple indirect */
} PACKED;

/* SaltyFS context */
struct SaltyFS_Context {
  struct DiskDevice *disk;
  struct SaltyFS_Superblock sb;
};

/*
 * Initialize SaltyFS filesystem
 *
 * Returns: 0 on success, error code otherwise
 */
int saltyfs_init(struct DiskDevice *disk, struct SaltyFS_Context *ctx) {
  (void)disk;
  (void)ctx;
  /* TODO: Implement SaltyFS initialization */
  return FS_ERR_NOT_IMPL;
}

/*
 * Open a file by path
 *
 * Returns: 0 on success, error code otherwise
 */
int saltyfs_open(struct SaltyFS_Context *ctx, const char *path,
                 struct FSFile *file) {
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
ssize_t saltyfs_read(struct SaltyFS_Context *ctx, struct FSFile *file,
                     void *buffer, size_t size) {
  (void)ctx;
  (void)file;
  (void)buffer;
  (void)size;
  /* TODO: Implement file read */
  return -FS_ERR_NOT_IMPL;
}

#endif /* CONFIG_FS_SALTYFS */
