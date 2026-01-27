/* SaltyOS SaltyFS Read-Only Driver
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Minimal read-only driver for booting
 */

#include "../../common/types.h"

/* SaltyFS magic number */
#define SALTYFS_MAGIC 0x53414C545946530ULL  /* "SALTYFS\0" */

/* Block size */
#define SALTYFS_BLOCK_SIZE 4096

/* Superblock (stored at block 0) */
struct saltyfs_super {
    uint64_t magic;
    uint64_t version;
    uint64_t block_count;
    uint64_t free_blocks;
    uint64_t root_inode;
    uint64_t inode_count;
    uint64_t snapshot_root;
    uint8_t  uuid[16];
    char     label[64];
    uint8_t  reserved[384];
};

/* Inode structure */
struct saltyfs_inode {
    uint64_t mode;
    uint64_t uid;
    uint64_t gid;
    uint64_t size;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint64_t block_count;
    uint64_t direct[12];
    uint64_t indirect;
    uint64_t double_indirect;
    uint64_t triple_indirect;
    uint8_t  reserved[40];
};

/* Directory entry */
struct saltyfs_dirent {
    uint64_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
    char     name[244];
};

/* File types */
#define SALTYFS_FT_UNKNOWN  0
#define SALTYFS_FT_REG      1
#define SALTYFS_FT_DIR      2
#define SALTYFS_FT_SYMLINK  7

/* Mount state */
static struct {
    bool mounted;
    struct saltyfs_super super;
    uint64_t device_start_lba;
} saltyfs_state = { .mounted = false };

/* Block read function (provided by driver layer) */
extern int disk_read_blocks(uint64_t lba, uint32_t count, void *buffer);

/* Mount filesystem */
int saltyfs_mount(uint64_t partition_lba) {
    if (saltyfs_state.mounted) {
        return -1;  /* Already mounted */
    }

    saltyfs_state.device_start_lba = partition_lba;

    /* Read superblock */
    if (disk_read_blocks(partition_lba, 1, &saltyfs_state.super) != 0) {
        return -2;
    }

    /* Verify magic */
    if (saltyfs_state.super.magic != SALTYFS_MAGIC) {
        return -3;
    }

    saltyfs_state.mounted = true;
    return 0;
}

/* Read file by path */
int saltyfs_read_file(const char *path, void *buffer, size_t max_size, size_t *out_size) {
    if (!saltyfs_state.mounted) {
        return -1;
    }

    /* TODO: Implement path traversal */
    /* 1. Start at root inode */
    /* 2. Parse path components */
    /* 3. Look up each component in directory */
    /* 4. Read final file data */

    (void)path;
    (void)buffer;
    (void)max_size;
    (void)out_size;

    return -1;  /* Not implemented */
}

/* Unmount filesystem */
void saltyfs_unmount(void) {
    saltyfs_state.mounted = false;
}
