/* SaltyOS VFS Server
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Virtual filesystem with ramfs (in-memory filesystem) and devfs.
 * Mounts initrd CPIO as read-only /initrd/. Device files at /dev/.
 *
 * IPC protocol:
 *   Label  1 = OPEN     Label  8 = ACCESS
 *   Label  2 = READ     Label  9 = UNLINK
 *   Label  3 = WRITE    Label 10 = RENAME
 *   Label  4 = CLOSE    Label 11 = MKDIR
 *   Label  5 = STAT     Label 12 = RMDIR
 *   Label  6 = LSEEK    Label 13 = OPENDIR
 *   Label  7 = FSTAT    Label 14 = READDIR
 *                        Label 15 = LSTAT
 *
 * Cap layout (set by init/procmgr):
 *   0 = self TCB    4 = console EP
 *   1 = self VSpace 8 = nameserv EP
 *   2 = self CSpace
 *   3 = server endpoint
 */

#include "salty.h"
#include "cpio.h"

/* Cap layout */
#define CAP_SELF_TCB     0
#define CAP_SELF_VSPACE  1
#define CAP_SELF_CSPACE  2
#define CAP_SERVER_EP    3
#define VFS_CAP_CONSOLE_EP  4
#define VFS_CAP_NAMESERV_EP 8

/* IPC buffer setup */
#define IPC_BUF_VADDR       0x0000000000200000ULL

/* Protocol labels */
#define VFS_OPEN    1
#define VFS_READ    2
#define VFS_WRITE   3
#define VFS_CLOSE   4
#define VFS_STAT    5
#define VFS_LSEEK   6
#define VFS_FSTAT   7
#define VFS_ACCESS  8
#define VFS_UNLINK  9
#define VFS_RENAME  10
#define VFS_MKDIR   11
#define VFS_RMDIR   12
#define VFS_OPENDIR 13
#define VFS_READDIR 14
#define VFS_LSTAT   15

/* File type constants */
#define FTYPE_NONE          0
#define FTYPE_CHAR_DEVICE   1
#define FTYPE_REGULAR       2
#define FTYPE_DIRECTORY     3

/* Open flags (match lib/libsalty/posix.h) */
#define O_ACCMODE 0x0003
#define O_RDONLY  0x0000
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_CREAT   0x0040
#define O_EXCL    0x0080
#define O_TRUNC   0x0200
#define O_APPEND  0x0400

/* Inode mode flags (POSIX-compatible) */
#define S_IFMT    0170000
#define S_IFDIR   0040000
#define S_IFCHR   0020000
#define S_IFREG   0100000

/* Device types */
#define DEV_CONSOLE  0
#define DEV_NULL     1
#define DEV_ZERO     2

/* Console IPC message labels */
#define CONSOLE_WRITE  1
#define CONSOLE_READ   2

/* Limits */
#define MAX_INODES      128
#define MAX_DIRENTS      32
#define MAX_WRITABLE     32
#define WRITABLE_SIZE  8192
#define MAX_CLIENTS      16
#define MAX_FDS          32
#define MAX_PATH_LEN     64
#define MAX_NAME_LEN     32

/* FD types */
#define FD_TYPE_NONE     0
#define FD_TYPE_DEVICE   1
#define FD_TYPE_FILE     2
#define FD_TYPE_DIR      3

/* ======================================================================
 * Ramfs data structures
 * ====================================================================== */

struct ramfs_dirent {
    uint8_t  active;
    uint32_t ino;
    char     name[MAX_NAME_LEN];
    uint8_t  name_len;
};

struct ramfs_inode {
    uint8_t  active;
    uint8_t  readonly;
    uint32_t ino;
    uint32_t mode;
    uint32_t nlink;
    uint64_t size;
    uint32_t mtime;
    uint32_t parent_ino;
    uint8_t  type;          /* FTYPE_* */
    uint8_t  dev_type;      /* DEV_* for char devices */

    /* Directory entries (for directories) */
    struct ramfs_dirent dirents[MAX_DIRENTS];

    /* Data pointers */
    const uint8_t *ro_data;     /* initrd pointer (read-only) */
    uint8_t       *rw_data;     /* BSS pool pointer (writable) */
};

static struct ramfs_inode inodes[MAX_INODES];
static uint32_t next_ino = 1;

/* Writable file data pool (in BSS) */
static uint8_t writable_pool[MAX_WRITABLE][WRITABLE_SIZE];
static uint8_t writable_used[MAX_WRITABLE];

/* Per-client file descriptor table */
struct fd_entry {
    uint8_t  active;
    uint8_t  type;       /* FD_TYPE_* */
    uint32_t inode;      /* inode number */
    uint64_t offset;     /* file offset */
    uint32_t dir_cursor; /* readdir position */
    uint8_t  dev_type;   /* DEV_* for device fds */
    uint32_t flags;      /* O_* flags */
};

struct client_state {
    uint64_t        badge;
    uint8_t         active;
    struct fd_entry fds[MAX_FDS];
};

static struct client_state clients[MAX_CLIENTS];

/* Initrd mapping address (set by init/procmgr at 16 MB) */
#define INITRD_VADDR  0x0000000001000000ULL

/* ======================================================================
 * Helper functions
 * ====================================================================== */

static int str_equal(const char *a, uint8_t alen, const char *b, uint8_t blen) {
    if (alen != blen) return 0;
    for (uint8_t i = 0; i < alen; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static int str_copy(char *dst, int max, const char *src, int len) {
    int n = len < max ? len : max;
    for (int i = 0; i < n; i++) dst[i] = src[i];
    return n;
}

static struct ramfs_inode *inode_by_ino(uint32_t ino) {
    for (int i = 0; i < MAX_INODES; i++) {
        if (inodes[i].active && inodes[i].ino == ino)
            return &inodes[i];
    }
    return (struct ramfs_inode *)0;
}

static struct ramfs_inode *alloc_inode(void) {
    for (int i = 0; i < MAX_INODES; i++) {
        if (!inodes[i].active) {
            inodes[i].active = 1;
            inodes[i].ino = next_ino++;
            inodes[i].readonly = 0;
            inodes[i].nlink = 1;
            inodes[i].size = 0;
            inodes[i].mtime = 0;
            inodes[i].parent_ino = 0;
            inodes[i].ro_data = 0;
            inodes[i].rw_data = 0;
            for (int j = 0; j < MAX_DIRENTS; j++)
                inodes[i].dirents[j].active = 0;
            return &inodes[i];
        }
    }
    return (struct ramfs_inode *)0;
}

static uint8_t *alloc_writable(void) {
    for (int i = 0; i < MAX_WRITABLE; i++) {
        if (!writable_used[i]) {
            writable_used[i] = 1;
            for (int j = 0; j < WRITABLE_SIZE; j++)
                writable_pool[i][j] = 0;
            return writable_pool[i];
        }
    }
    return (uint8_t *)0;
}

/* Add directory entry to a directory inode */
static int dir_add_entry(struct ramfs_inode *dir, const char *name,
                          uint8_t name_len, uint32_t child_ino) {
    for (int i = 0; i < MAX_DIRENTS; i++) {
        if (!dir->dirents[i].active) {
            dir->dirents[i].active = 1;
            dir->dirents[i].ino = child_ino;
            dir->dirents[i].name_len = name_len;
            str_copy(dir->dirents[i].name, MAX_NAME_LEN, name, name_len);
            return 0;
        }
    }
    return -1;
}

/* Find entry in directory by name */
static struct ramfs_dirent *dir_find_entry(struct ramfs_inode *dir,
                                             const char *name, uint8_t name_len) {
    for (int i = 0; i < MAX_DIRENTS; i++) {
        if (dir->dirents[i].active &&
            str_equal(dir->dirents[i].name, dir->dirents[i].name_len,
                      name, name_len))
            return &dir->dirents[i];
    }
    return (struct ramfs_dirent *)0;
}

/* Remove entry from directory by name */
static int dir_remove_entry(struct ramfs_inode *dir,
                              const char *name, uint8_t name_len) {
    for (int i = 0; i < MAX_DIRENTS; i++) {
        if (dir->dirents[i].active &&
            str_equal(dir->dirents[i].name, dir->dirents[i].name_len,
                      name, name_len)) {
            dir->dirents[i].active = 0;
            return 0;
        }
    }
    return -1;
}

/* ======================================================================
 * Path resolution
 * ====================================================================== */

/* Root inode is always ino 1 */
#define ROOT_INO 1

/* Resolve absolute path to inode. Returns inode or NULL. */
static struct ramfs_inode *resolve_path(const char *path, uint8_t path_len) {
    if (path_len == 0) return (struct ramfs_inode *)0;

    struct ramfs_inode *current = inode_by_ino(ROOT_INO);
    if (!current) return (struct ramfs_inode *)0;

    /* Root itself */
    if (path_len == 1 && path[0] == '/')
        return current;

    /* Skip leading / */
    int pos = 0;
    if (path[0] == '/') pos = 1;

    while (pos < path_len) {
        if (current->type != FTYPE_DIRECTORY)
            return (struct ramfs_inode *)0;

        /* Extract next component */
        int start = pos;
        while (pos < path_len && path[pos] != '/') pos++;
        int comp_len = pos - start;
        if (comp_len == 0) {
            pos++;
            continue;
        }

        /* Skip trailing slash */
        if (pos < path_len && path[pos] == '/') pos++;

        /* Look up component */
        struct ramfs_dirent *de = dir_find_entry(current, path + start,
                                                   (uint8_t)comp_len);
        if (!de)
            return (struct ramfs_inode *)0;

        current = inode_by_ino(de->ino);
        if (!current)
            return (struct ramfs_inode *)0;
    }

    return current;
}

/* Resolve parent directory and return child name component.
 * Sets *child_name and *child_len on success. */
static struct ramfs_inode *resolve_parent(const char *path, uint8_t path_len,
                                            const char **child_name,
                                            uint8_t *child_len) {
    if (path_len == 0) return (struct ramfs_inode *)0;

    /* Find last slash */
    int last_slash = -1;
    for (int i = path_len - 1; i >= 0; i--) {
        if (path[i] == '/') { last_slash = i; break; }
    }

    if (last_slash < 0) return (struct ramfs_inode *)0;

    /* Extract parent path */
    char parent_path[MAX_PATH_LEN];
    uint8_t parent_len;
    if (last_slash == 0) {
        parent_path[0] = '/';
        parent_len = 1;
    } else {
        parent_len = (uint8_t)last_slash;
        for (int i = 0; i < parent_len; i++)
            parent_path[i] = path[i];
    }

    *child_name = path + last_slash + 1;
    *child_len = (uint8_t)(path_len - last_slash - 1);

    /* Strip trailing slash from child name */
    while (*child_len > 0 && (*child_name)[*child_len - 1] == '/')
        (*child_len)--;

    return resolve_path(parent_path, parent_len);
}

/* ======================================================================
 * Initialization: build ramfs tree
 * ====================================================================== */

static struct ramfs_inode *root_inode;

static void init_ramfs(void) {
    /* Initialize all inodes */
    for (int i = 0; i < MAX_INODES; i++)
        inodes[i].active = 0;
    for (int i = 0; i < MAX_WRITABLE; i++)
        writable_used[i] = 0;

    /* Create root directory (ino 1) */
    root_inode = alloc_inode();
    root_inode->type = FTYPE_DIRECTORY;
    root_inode->mode = S_IFDIR | 0755;
    root_inode->nlink = 2;

    /* Create /dev directory */
    struct ramfs_inode *dev_dir = alloc_inode();
    dev_dir->type = FTYPE_DIRECTORY;
    dev_dir->mode = S_IFDIR | 0755;
    dev_dir->nlink = 2;
    dev_dir->parent_ino = root_inode->ino;
    dir_add_entry(root_inode, "dev", 3, dev_dir->ino);

    /* Create /dev/console */
    struct ramfs_inode *console = alloc_inode();
    console->type = FTYPE_CHAR_DEVICE;
    console->mode = S_IFCHR | 0666;
    console->dev_type = DEV_CONSOLE;
    console->parent_ino = dev_dir->ino;
    dir_add_entry(dev_dir, "console", 7, console->ino);

    /* Create /dev/null */
    struct ramfs_inode *null_dev = alloc_inode();
    null_dev->type = FTYPE_CHAR_DEVICE;
    null_dev->mode = S_IFCHR | 0666;
    null_dev->dev_type = DEV_NULL;
    null_dev->parent_ino = dev_dir->ino;
    dir_add_entry(dev_dir, "null", 4, null_dev->ino);

    /* Create /dev/zero */
    struct ramfs_inode *zero_dev = alloc_inode();
    zero_dev->type = FTYPE_CHAR_DEVICE;
    zero_dev->mode = S_IFCHR | 0666;
    zero_dev->dev_type = DEV_ZERO;
    zero_dev->parent_ino = dev_dir->ino;
    dir_add_entry(dev_dir, "zero", 4, zero_dev->ino);

    /* Create /initrd directory */
    struct ramfs_inode *initrd_dir = alloc_inode();
    initrd_dir->type = FTYPE_DIRECTORY;
    initrd_dir->mode = S_IFDIR | 0555;
    initrd_dir->readonly = 1;
    initrd_dir->nlink = 2;
    initrd_dir->parent_ino = root_inode->ino;
    dir_add_entry(root_inode, "initrd", 6, initrd_dir->ino);

    /* Mount initrd CPIO into /initrd/ */
    const uint8_t *initrd = (const uint8_t *)INITRD_VADDR;
    size_t initrd_size = cpio_archive_size(initrd, 1024 * 1024);

    salty_serial_puts("[VFS] Initrd size: ");
    salty_serial_hex(initrd_size);
    salty_serial_puts(" bytes\n");

    size_t offset = 0;
    struct cpio_entry_ext entry;
    int file_count = 0;

    while (cpio_next_ext(initrd, initrd_size, &offset, &entry)) {
        /* Skip "." */
        if (entry.name_len == 1 && entry.name[0] == '.')
            continue;

        if (entry.name_len >= MAX_NAME_LEN)
            continue;

        /* Create inode for this file */
        struct ramfs_inode *file_inode = alloc_inode();
        if (!file_inode) break;

        file_inode->readonly = 1;
        file_inode->ino = entry.ino ? entry.ino : file_inode->ino;
        file_inode->mode = entry.mode ? entry.mode : (S_IFREG | 0444);
        file_inode->nlink = entry.nlink ? entry.nlink : 1;
        file_inode->mtime = entry.mtime;
        file_inode->size = entry.data_len;
        file_inode->ro_data = entry.data;
        file_inode->parent_ino = initrd_dir->ino;

        if ((entry.mode & S_IFMT) == S_IFDIR)
            file_inode->type = FTYPE_DIRECTORY;
        else
            file_inode->type = FTYPE_REGULAR;

        /* Add to /initrd/ directory */
        dir_add_entry(initrd_dir, entry.name, (uint8_t)entry.name_len,
                       file_inode->ino);
        file_count++;

        salty_serial_puts("[VFS] initrd: ");
        for (size_t i = 0; i < entry.name_len; i++)
            salty_serial_putc(entry.name[i]);
        salty_serial_puts(" (");
        salty_serial_hex(entry.data_len);
        salty_serial_puts(")\n");
    }

    salty_serial_puts("[VFS] Mounted ");
    salty_serial_hex((uint64_t)file_count);
    salty_serial_puts(" initrd files\n");
}

/* ======================================================================
 * Client management
 * ====================================================================== */

static struct client_state *get_client(uint64_t badge) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].badge == badge)
            return &clients[i];
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].badge = badge;
            clients[i].active = 1;
            for (int j = 0; j < MAX_FDS; j++)
                clients[i].fds[j].active = 0;
            return &clients[i];
        }
    }
    return (struct client_state *)0;
}

/* Extract path from IPC message starting at regs[reg_offset] */
static uint8_t extract_path(const struct salty_msg *msg, int reg_offset,
                              char *path) {
    uint8_t path_len = (uint8_t)msg->regs[reg_offset];
    if (path_len > MAX_PATH_LEN) path_len = MAX_PATH_LEN;
    const uint8_t *raw = (const uint8_t *)&msg->regs[reg_offset + 1];
    for (uint8_t i = 0; i < path_len; i++)
        path[i] = (char)raw[i];
    return path_len;
}

static int flags_allow_read(uint32_t flags) {
    return (flags & O_ACCMODE) != O_WRONLY;
}

static int flags_allow_write(uint32_t flags) {
    uint32_t mode = flags & O_ACCMODE;
    return mode == O_WRONLY || mode == O_RDWR;
}

/* ======================================================================
 * Request handlers
 * ====================================================================== */

static void handle_open(const struct salty_msg *msg, struct salty_msg *reply,
                          uint64_t badge) {
    char path[MAX_PATH_LEN];
    uint32_t flags = (uint32_t)msg->regs[1];
    uint8_t path_len = extract_path(msg, 2, path);

    if (path_len == 0) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    struct ramfs_inode *inode = resolve_path(path, path_len);

    /* If not found, create only with O_CREAT. */
    if (!inode) {
        if ((flags & O_CREAT) == 0) {
            reply->label = SALTY_NOT_FOUND;
            return;
        }

        /* Try to create in parent directory */
        const char *child_name;
        uint8_t child_len;
        struct ramfs_inode *parent = resolve_parent(path, path_len,
                                                      &child_name, &child_len);
        if (parent && parent->type == FTYPE_DIRECTORY &&
            !parent->readonly && child_len > 0) {
            inode = alloc_inode();
            if (inode) {
                inode->type = FTYPE_REGULAR;
                inode->mode = S_IFREG | 0644;
                inode->parent_ino = parent->ino;
                inode->rw_data = 0;
                dir_add_entry(parent, child_name, child_len, inode->ino);
            }
        }

        if (!inode) {
            salty_serial_puts("[VFS] OPEN: not found '");
            for (uint8_t i = 0; i < path_len; i++) salty_serial_putc(path[i]);
            salty_serial_puts("'\n");
            reply->label = SALTY_NOT_FOUND;
            return;
        }
    } else if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
        reply->label = SALTY_ALREADY_EXISTS;
        return;
    }

    /* Validate access mode against inode type. */
    if (inode->type == FTYPE_DIRECTORY) {
        if (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0) {
            reply->label = SALTY_INVALID_OPERATION;
            return;
        }
    }

    if (inode->type == FTYPE_REGULAR) {
        if (inode->readonly && (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0)) {
            reply->label = SALTY_INVALID_OPERATION;
            return;
        }

        if ((flags & O_TRUNC) && flags_allow_write(flags)) {
            inode->size = 0;
        }
    }

    struct client_state *cli = get_client(badge);
    if (!cli) {
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Allocate fd */
    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (!cli->fds[fd].active) {
            cli->fds[fd].active = 1;
            cli->fds[fd].inode = inode->ino;
            cli->fds[fd].offset = 0;
            cli->fds[fd].dir_cursor = 0;
            cli->fds[fd].flags = flags;

            if (inode->type == FTYPE_CHAR_DEVICE) {
                cli->fds[fd].type = FD_TYPE_DEVICE;
                cli->fds[fd].dev_type = inode->dev_type;
            } else if (inode->type == FTYPE_DIRECTORY) {
                cli->fds[fd].type = FD_TYPE_DIR;
            } else {
                cli->fds[fd].type = FD_TYPE_FILE;
                if ((flags & O_APPEND) != 0)
                    cli->fds[fd].offset = inode->size;
            }

            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = (uint64_t)fd;
            return;
        }
    }

    reply->label = SALTY_OUT_OF_MEMORY;
}

static void handle_read(const struct salty_msg *msg, struct salty_msg *reply,
                          uint64_t badge) {
    int fd = (int)msg->regs[0];
    uint64_t count = msg->regs[1];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    if (count > 152) count = 152;

    if (!flags_allow_read(cli->fds[fd].flags)) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    switch (cli->fds[fd].type) {
    case FD_TYPE_DEVICE:
        switch (cli->fds[fd].dev_type) {
        case DEV_CONSOLE: {
            struct salty_msg creq, creply;
            creq.label = CONSOLE_READ;
            creq.length = 0;
            for (int i = 0; i < 4; i++) creq.regs[i] = 0;

            int err = salty_call(VFS_CAP_CONSOLE_EP, &creq, &creply);
            if (err != 0 || creply.label != SALTY_OK) {
                reply->label = SALTY_INVALID_OPERATION;
                return;
            }
            uint64_t c = creply.regs[0];
            if (c == (uint64_t)-1) {
                reply->label = SALTY_OK;
                reply->length = 1;
                reply->regs[0] = 0;
            } else {
                reply->label = SALTY_OK;
                reply->length = 2;
                reply->regs[0] = 1;
                uint8_t *data = (uint8_t *)&reply->regs[1];
                data[0] = (uint8_t)c;
            }
            break;
        }
        case DEV_NULL:
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = 0;
            break;
        case DEV_ZERO: {
            reply->label = SALTY_OK;
            reply->length = 1 + (uint64_t)((count + 7) / 8);
            reply->regs[0] = count;
            uint8_t *data = (uint8_t *)&reply->regs[1];
            for (uint64_t i = 0; i < count; i++)
                data[i] = 0;
            break;
        }
        default:
            reply->label = SALTY_INVALID_OPERATION;
            break;
        }
        break;

    case FD_TYPE_FILE: {
        struct ramfs_inode *inode = inode_by_ino(cli->fds[fd].inode);
        if (!inode) {
            reply->label = SALTY_INVALID_ARGUMENT;
            return;
        }

        uint64_t offset = cli->fds[fd].offset;
        if (offset >= inode->size) {
            /* EOF */
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = 0;
            return;
        }

        uint64_t avail = inode->size - offset;
        if (count > avail) count = avail;

        const uint8_t *src;
        if (inode->ro_data)
            src = inode->ro_data + offset;
        else if (inode->rw_data)
            src = inode->rw_data + offset;
        else {
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = 0;
            return;
        }

        reply->label = SALTY_OK;
        reply->length = 1 + (uint64_t)((count + 7) / 8);
        reply->regs[0] = count;
        uint8_t *dst = (uint8_t *)&reply->regs[1];
        for (uint64_t i = 0; i < count; i++)
            dst[i] = src[i];

        cli->fds[fd].offset = offset + count;
        break;
    }

    default:
        reply->label = SALTY_INVALID_OPERATION;
        break;
    }
}

static void handle_write(const struct salty_msg *msg, struct salty_msg *reply,
                           uint64_t badge) {
    int fd = (int)msg->regs[0];
    uint64_t count = msg->regs[1];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    if (count > 144) count = 144;

    if (!flags_allow_write(cli->fds[fd].flags)) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    switch (cli->fds[fd].type) {
    case FD_TYPE_DEVICE:
        switch (cli->fds[fd].dev_type) {
        case DEV_CONSOLE: {
            const uint8_t *src = (const uint8_t *)&msg->regs[2];
            uint64_t sent = 0;
            while (sent < count) {
                struct salty_msg creq, creply;
                uint64_t chunk = count - sent;
                if (chunk > 24) chunk = 24;

                creq.label = CONSOLE_WRITE;
                creq.length = 1 + (uint64_t)((chunk + 7) / 8);
                creq.regs[0] = chunk;
                creq.regs[1] = 0;
                creq.regs[2] = 0;
                creq.regs[3] = 0;

                uint8_t *dst = (uint8_t *)&creq.regs[1];
                for (uint64_t i = 0; i < chunk; i++)
                    dst[i] = src[sent + i];

                int err = salty_call(VFS_CAP_CONSOLE_EP, &creq, &creply);
                if (err != 0 || creply.label != SALTY_OK) break;
                sent += chunk;
            }
            reply->label = sent > 0 ? SALTY_OK : SALTY_INVALID_OPERATION;
            reply->length = 1;
            reply->regs[0] = sent;
            break;
        }
        case DEV_NULL:
        case DEV_ZERO:
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = count;
            break;
        default:
            reply->label = SALTY_INVALID_OPERATION;
            break;
        }
        break;

    case FD_TYPE_FILE: {
        struct ramfs_inode *inode = inode_by_ino(cli->fds[fd].inode);
        if (!inode || inode->readonly) {
            reply->label = SALTY_INVALID_OPERATION;
            return;
        }

        if (!inode->rw_data) {
            inode->rw_data = alloc_writable();
            if (!inode->rw_data) {
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        uint64_t offset = cli->fds[fd].offset;
        if ((cli->fds[fd].flags & O_APPEND) != 0)
            offset = inode->size;

        if (offset >= WRITABLE_SIZE)
            count = 0;
        else if (offset + count > WRITABLE_SIZE)
            count = WRITABLE_SIZE - offset;

        const uint8_t *src = (const uint8_t *)&msg->regs[2];
        for (uint64_t i = 0; i < count; i++)
            inode->rw_data[offset + i] = src[i];

        cli->fds[fd].offset = offset + count;
        if (cli->fds[fd].offset > inode->size)
            inode->size = cli->fds[fd].offset;

        reply->label = SALTY_OK;
        reply->length = 1;
        reply->regs[0] = count;
        break;
    }

    default:
        reply->label = SALTY_INVALID_OPERATION;
        break;
    }
}

static void handle_close(const struct salty_msg *msg, struct salty_msg *reply,
                           uint64_t badge) {
    int fd = (int)msg->regs[0];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    cli->fds[fd].active = 0;
    reply->label = SALTY_OK;
}

static void handle_lseek(const struct salty_msg *msg, struct salty_msg *reply,
                           uint64_t badge) {
    int fd = (int)msg->regs[0];
    int64_t offset = (int64_t)msg->regs[1];
    int whence = (int)msg->regs[2];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    if (cli->fds[fd].type != FD_TYPE_FILE) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    struct ramfs_inode *inode = inode_by_ino(cli->fds[fd].inode);
    if (!inode) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    int64_t new_offset;
    switch (whence) {
    case 0: /* SEEK_SET */
        new_offset = offset;
        break;
    case 1: /* SEEK_CUR */
        new_offset = (int64_t)cli->fds[fd].offset + offset;
        break;
    case 2: /* SEEK_END */
        new_offset = (int64_t)inode->size + offset;
        break;
    default:
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    if (new_offset < 0) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    cli->fds[fd].offset = (uint64_t)new_offset;
    reply->label = SALTY_OK;
    reply->length = 1;
    reply->regs[0] = (uint64_t)new_offset;
}

/* Fill stat reply regs from inode */
static void fill_stat_reply(struct salty_msg *reply, struct ramfs_inode *inode) {
    reply->label = SALTY_OK;
    reply->length = 8;
    reply->regs[0] = (uint64_t)inode->ino;
    reply->regs[1] = (uint64_t)inode->mode;
    reply->regs[2] = (uint64_t)inode->nlink;
    reply->regs[3] = (uint64_t)inode->size;
    reply->regs[4] = 0; /* uid */
    reply->regs[5] = 0; /* gid */
    reply->regs[6] = (uint64_t)inode->mtime;
    reply->regs[7] = (uint64_t)inode->type;
}

static void handle_fstat(const struct salty_msg *msg, struct salty_msg *reply,
                           uint64_t badge) {
    int fd = (int)msg->regs[0];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    struct ramfs_inode *inode = inode_by_ino(cli->fds[fd].inode);
    if (!inode) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    fill_stat_reply(reply, inode);
}

static void handle_stat(const struct salty_msg *msg, struct salty_msg *reply) {
    char path[MAX_PATH_LEN];
    uint8_t path_len = extract_path(msg, 0, path);

    struct ramfs_inode *inode = resolve_path(path, path_len);
    if (!inode) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    fill_stat_reply(reply, inode);
}

static void handle_access(const struct salty_msg *msg, struct salty_msg *reply) {
    /* regs[0] = mode, regs[1] = path_len, regs[2..] = path */
    char path[MAX_PATH_LEN];
    uint8_t path_len = extract_path(msg, 1, path);

    struct ramfs_inode *inode = resolve_path(path, path_len);
    if (!inode) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    reply->label = SALTY_OK;
}

static void handle_unlink(const struct salty_msg *msg, struct salty_msg *reply) {
    char path[MAX_PATH_LEN];
    uint8_t path_len = extract_path(msg, 0, path);

    const char *child_name;
    uint8_t child_len;
    struct ramfs_inode *parent = resolve_parent(path, path_len,
                                                  &child_name, &child_len);
    if (!parent || parent->readonly) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    struct ramfs_dirent *de = dir_find_entry(parent, child_name, child_len);
    if (!de) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    struct ramfs_inode *inode = inode_by_ino(de->ino);
    if (!inode || inode->type == FTYPE_DIRECTORY) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    de->active = 0;
    inode->active = 0;
    reply->label = SALTY_OK;
}

static void handle_rename(const struct salty_msg *msg, struct salty_msg *reply) {
    /* regs[0] = old_len, regs[1] = new_len, regs[2..] = old_path, then new_path */
    uint8_t old_len = (uint8_t)msg->regs[0];
    uint8_t new_len = (uint8_t)msg->regs[1];
    if (old_len > MAX_PATH_LEN) old_len = MAX_PATH_LEN;
    if (new_len > MAX_PATH_LEN) new_len = MAX_PATH_LEN;

    char old_path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];
    const uint8_t *raw = (const uint8_t *)&msg->regs[2];
    for (uint8_t i = 0; i < old_len; i++) old_path[i] = (char)raw[i];
    raw = (const uint8_t *)&msg->regs[2 + (old_len + 7) / 8];
    for (uint8_t i = 0; i < new_len; i++) new_path[i] = (char)raw[i];

    /* Resolve old parent + child */
    const char *old_child;
    uint8_t old_child_len;
    struct ramfs_inode *old_parent = resolve_parent(old_path, old_len,
                                                      &old_child, &old_child_len);
    if (!old_parent || old_parent->readonly) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    struct ramfs_dirent *de = dir_find_entry(old_parent, old_child, old_child_len);
    if (!de) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }
    uint32_t ino = de->ino;

    /* Resolve new parent + child */
    const char *new_child;
    uint8_t new_child_len;
    struct ramfs_inode *new_parent = resolve_parent(new_path, new_len,
                                                      &new_child, &new_child_len);
    if (!new_parent || new_parent->readonly) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    /* Remove from old location */
    de->active = 0;

    /* Remove any existing entry at new location */
    struct ramfs_dirent *existing = dir_find_entry(new_parent, new_child,
                                                     new_child_len);
    if (existing) {
        struct ramfs_inode *old_inode = inode_by_ino(existing->ino);
        if (old_inode) old_inode->active = 0;
        existing->active = 0;
    }

    /* Add at new location */
    dir_add_entry(new_parent, new_child, new_child_len, ino);
    reply->label = SALTY_OK;
}

static void handle_mkdir(const struct salty_msg *msg, struct salty_msg *reply) {
    /* regs[0] = mode, regs[1] = path_len, regs[2..] = path */
    char path[MAX_PATH_LEN];
    uint8_t path_len = extract_path(msg, 1, path);

    /* Check doesn't already exist */
    struct ramfs_inode *existing = resolve_path(path, path_len);
    if (existing) {
        reply->label = SALTY_ALREADY_EXISTS;
        return;
    }

    const char *child_name;
    uint8_t child_len;
    struct ramfs_inode *parent = resolve_parent(path, path_len,
                                                  &child_name, &child_len);
    if (!parent || parent->type != FTYPE_DIRECTORY || parent->readonly) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    struct ramfs_inode *dir = alloc_inode();
    if (!dir) {
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    dir->type = FTYPE_DIRECTORY;
    dir->mode = S_IFDIR | ((uint32_t)msg->regs[0] & 0777);
    dir->nlink = 2;
    dir->parent_ino = parent->ino;

    dir_add_entry(parent, child_name, child_len, dir->ino);
    reply->label = SALTY_OK;
}

static void handle_rmdir(const struct salty_msg *msg, struct salty_msg *reply) {
    char path[MAX_PATH_LEN];
    uint8_t path_len = extract_path(msg, 0, path);

    struct ramfs_inode *inode = resolve_path(path, path_len);
    if (!inode || inode->type != FTYPE_DIRECTORY) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    if (inode->readonly) {
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    /* Check directory is empty */
    for (int i = 0; i < MAX_DIRENTS; i++) {
        if (inode->dirents[i].active) {
            reply->label = SALTY_INVALID_OPERATION;
            return;
        }
    }

    /* Remove from parent */
    const char *child_name;
    uint8_t child_len;
    struct ramfs_inode *parent = resolve_parent(path, path_len,
                                                  &child_name, &child_len);
    if (parent)
        dir_remove_entry(parent, child_name, child_len);

    inode->active = 0;
    reply->label = SALTY_OK;
}

static void handle_opendir(const struct salty_msg *msg, struct salty_msg *reply,
                              uint64_t badge) {
    char path[MAX_PATH_LEN];
    uint8_t path_len = extract_path(msg, 0, path);

    struct ramfs_inode *inode = resolve_path(path, path_len);
    if (!inode || inode->type != FTYPE_DIRECTORY) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    struct client_state *cli = get_client(badge);
    if (!cli) {
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Allocate fd for directory */
    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (!cli->fds[fd].active) {
            cli->fds[fd].active = 1;
            cli->fds[fd].type = FD_TYPE_DIR;
            cli->fds[fd].inode = inode->ino;
            cli->fds[fd].offset = 0;
            cli->fds[fd].dir_cursor = 0;
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = (uint64_t)fd;
            return;
        }
    }

    reply->label = SALTY_OUT_OF_MEMORY;
}

static void handle_readdir(const struct salty_msg *msg, struct salty_msg *reply,
                              uint64_t badge) {
    int fd = (int)msg->regs[0];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active ||
        cli->fds[fd].type != FD_TYPE_DIR) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    struct ramfs_inode *dir = inode_by_ino(cli->fds[fd].inode);
    if (!dir) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    /* Find next active dirent starting from cursor */
    uint32_t cursor = cli->fds[fd].dir_cursor;
    for (int i = (int)cursor; i < MAX_DIRENTS; i++) {
        if (dir->dirents[i].active) {
            struct ramfs_inode *child = inode_by_ino(dir->dirents[i].ino);
            uint8_t d_type = 0;
            if (child) {
                switch (child->type) {
                case FTYPE_REGULAR:     d_type = 8; break; /* DT_REG */
                case FTYPE_DIRECTORY:   d_type = 4; break; /* DT_DIR */
                case FTYPE_CHAR_DEVICE: d_type = 2; break; /* DT_CHR */
                }
            }

            uint8_t name_len = dir->dirents[i].name_len;
            reply->label = SALTY_OK;
            reply->length = 5 + (uint64_t)((name_len + 7) / 8);
            reply->regs[0] = (uint64_t)name_len;
            reply->regs[1] = 0; /* reserved */
            reply->regs[2] = (uint64_t)dir->dirents[i].ino;
            reply->regs[3] = (uint64_t)d_type;

            /* Pack name into regs[4..] */
            for (int j = 4; j < 20; j++) reply->regs[j] = 0;
            uint8_t *dst = (uint8_t *)&reply->regs[4];
            for (uint8_t j = 0; j < name_len; j++)
                dst[j] = (uint8_t)dir->dirents[i].name[j];

            cli->fds[fd].dir_cursor = (uint32_t)(i + 1);
            return;
        }
    }

    /* End of directory */
    reply->label = SALTY_OK;
    reply->length = 1;
    reply->regs[0] = 0;
}

/* ======================================================================
 * Main entry
 * ====================================================================== */

void _start(void) {
    salty_serial_puts("[VFS] SaltyOS VFS server starting\n");

    int err = salty_tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if (err != 0) {
        salty_serial_puts("[VFS] FAIL: set IPC buffer err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        goto idle;
    }
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)IPC_BUF_VADDR);

    salty_serial_puts("[VFS] IPC buffer ready\n");

    /* Initialize ramfs and mount initrd */
    init_ramfs();

    salty_serial_puts("[VFS] Filesystem ready\n");

    /* Register with name server */
    if (VFS_CAP_NAMESERV_EP != 0) {
        struct salty_msg reg_msg, reg_reply;
        reg_msg.label = 1; /* NS_REGISTER */
        reg_msg.regs[0] = 3; /* length of "vfs" */
        reg_msg.length = 1 + (uint64_t)((reg_msg.regs[0] + 7) / 8);
        const char *svc_name = "vfs";
        uint8_t *ns_dst = (uint8_t *)&reg_msg.regs[1];
        for (int i = 0; i < 3; i++) ns_dst[i] = (uint8_t)svc_name[i];
        reg_msg.regs[2] = 0;
        reg_msg.regs[3] = 0;

        salty_set_send_cap(0, CAP_SERVER_EP);

        err = salty_call(VFS_CAP_NAMESERV_EP, &reg_msg, &reg_reply);
        if (err == 0 && reg_reply.label == SALTY_OK) {
            salty_serial_puts("[VFS] registered with nameserv\n");
        } else {
            salty_serial_puts("[VFS] WARN: nameserv registration failed\n");
        }
    }

    /* Initial recv */
    struct salty_msg msg;
    uint64_t badge = 0;

    err = salty_recv(CAP_SERVER_EP, &msg, &badge);
    if (err != 0) {
        salty_serial_puts("[VFS] initial recv failed\n");
        goto idle;
    }

    /* Server loop */
    for (;;) {
        struct salty_msg reply;
        reply.label = 0;
        reply.length = 0;
        for (int i = 0; i < 20; i++) reply.regs[i] = 0;

        switch (msg.label) {
        case VFS_OPEN:
            handle_open(&msg, &reply, badge);
            break;
        case VFS_READ:
            handle_read(&msg, &reply, badge);
            break;
        case VFS_WRITE:
            handle_write(&msg, &reply, badge);
            break;
        case VFS_CLOSE:
            handle_close(&msg, &reply, badge);
            break;
        case VFS_STAT:
            handle_stat(&msg, &reply);
            break;
        case VFS_LSEEK:
            handle_lseek(&msg, &reply, badge);
            break;
        case VFS_FSTAT:
            handle_fstat(&msg, &reply, badge);
            break;
        case VFS_ACCESS:
            handle_access(&msg, &reply);
            break;
        case VFS_UNLINK:
            handle_unlink(&msg, &reply);
            break;
        case VFS_RENAME:
            handle_rename(&msg, &reply);
            break;
        case VFS_MKDIR:
            handle_mkdir(&msg, &reply);
            break;
        case VFS_RMDIR:
            handle_rmdir(&msg, &reply);
            break;
        case VFS_OPENDIR:
            handle_opendir(&msg, &reply, badge);
            break;
        case VFS_READDIR:
            handle_readdir(&msg, &reply, badge);
            break;
        case VFS_LSTAT:
            handle_stat(&msg, &reply); /* no symlinks yet */
            break;
        default:
            salty_serial_puts("[VFS] unknown label=");
            salty_serial_hex(msg.label);
            salty_serial_puts("\n");
            reply.label = SALTY_INVALID_OPERATION;
            break;
        }

        err = salty_reply_recv(CAP_SERVER_EP, &reply, &msg, &badge);
        if (err != 0) {
            salty_serial_puts("[VFS] reply_recv failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            break;
        }
    }

idle:
    for (;;) { salty_yield(); }
}
