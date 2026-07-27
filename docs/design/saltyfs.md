# SaltyFS Design

This document describes SaltyFS, the Copy-on-Write filesystem for SaltyOS.

## Overview

SaltyFS is a modern, COW (Copy-on-Write) filesystem designed for SaltyOS with the following goals:

- **Snapshots**: Instant, space-efficient filesystem snapshots
- **Data Integrity**: Checksums for all data and metadata
- **Crash Consistency**: Always consistent on-disk state
- **Efficient Writes**: Log-structured with COW semantics
- **Compression**: Transparent data compression (optional)
- **Boot Support**: Read-only driver in Stage 3 bootloader

## Design Influences

SaltyFS draws inspiration from:
- **Btrfs**: COW B-trees, snapshots, checksums
- **ZFS**: Transaction groups, intent log
- **F2FS**: Flash-friendly log structure
- **bcachefs**: Modern COW filesystem design

## On-Disk Layout

### Overall Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ Superblock (Primary)          │ 4 KB (LBA 0)                    │
├─────────────────────────────────────────────────────────────────┤
│ Superblock (Backup)           │ 4 KB (LBA 1)                    │
├─────────────────────────────────────────────────────────────────┤
│ Allocation Bitmap             │ Variable size                   │
├─────────────────────────────────────────────────────────────────┤
│ Intent Log                    │ 64 MB (configurable)            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                     Data + Metadata Blocks                      │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Extent Trees                                           │   │
│  │  Directory Trees                                        │   │
│  │  Inode Tables                                           │   │
│  │  Data Extents                                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Superblock (Backup 2)         │ 4 KB (near end)                 │
└─────────────────────────────────────────────────────────────────┘
```

### Superblock

```c
// 4 KB Superblock structure
struct SaltySuperblock {
    // Identity (offset 0x000)
    uint8_t  magic[8];          // "SALTYFS\0"
    uint32_t version;           // Filesystem version
    uint32_t incompat_flags;    // Unknown bits refuse mount (bit 0=XATTR, bit 1=CASEFOLD)

    // UUIDs (offset 0x010)
    uint8_t  fs_uuid[16];       // Filesystem UUID
    uint8_t  device_uuid[16];   // Device UUID

    // Geometry (offset 0x030)
    uint64_t block_size;        // Block size (4KB default)
    uint64_t total_blocks;      // Total blocks in filesystem
    uint64_t used_blocks;       // Currently used blocks
    uint64_t reserved_blocks;   // Reserved for root

    // Tree roots (offset 0x050)
    uint64_t root_tree;         // Root of the tree of trees
    uint64_t extent_tree;       // Extent allocation tree
    uint64_t checksum_tree;     // Checksums tree
    uint64_t snapshot_tree;     // Snapshot tree root

    // Log (offset 0x070)
    uint64_t log_start;         // Intent log start block
    uint64_t log_size;          // Intent log size in blocks
    uint64_t log_head;          // Current log head
    uint64_t log_tail;          // Current log tail

    // State (offset 0x090)
    uint64_t generation;        // Transaction generation
    uint64_t last_mount_time;
    uint64_t last_write_time;
    uint64_t mount_count;

    // Root inode (offset 0x0B0)
    uint64_t root_inode;        // Root directory inode number

    // Checksums (offset 0x0B8)
    uint32_t checksum_type;     // CRC32, xxHash, etc.
    uint32_t reserved1;

    // Label (offset 0x0C0)
    char     label[64];         // Volume label

    // Feature fields (offset 0x100; introduced in the xattr/casefold/multi-user revision)
    uint32_t compat_flags;      // Hint-only, unknown bits ignored
    uint32_t compat_ro_flags;   // Unknown bits force read-only mount
    uint32_t casefold_version;  // Unicode version of the casefold table (major*1e6 + minor*1e3 + patch)
    uint32_t reserved2;

    // Padding and checksum
    uint8_t  reserved[3820];    // 0x110 .. 0xFFC
    uint32_t checksum;          // Superblock checksum
};
```

### Feature flags

Three independent 32-bit fields gate filesystem features (btrfs-style):

| Field             | Semantics on unknown bit                                   |
|-------------------|------------------------------------------------------------|
| `incompat_flags`  | Mount refused (driver cannot safely touch the image)       |
| `compat_ro_flags` | Mount succeeds but the whole filesystem runs read-only     |
| `compat_flags`    | Silently ignored (optimization hints only)                 |

Currently defined bits:

| Bit | Field             | Name                        | Meaning                                         |
|-----|-------------------|-----------------------------|-------------------------------------------------|
| 0   | `incompat_flags`  | `SALTYFS_INCOMPAT_XATTR`    | Image may contain `XATTR_ITEM` entries          |
| 1   | `incompat_flags`  | `SALTYFS_INCOMPAT_CASEFOLD` | Image may contain `SALTY_INODE_CASEFOLD` dirs   |

When `SALTYFS_INCOMPAT_CASEFOLD` is set, the driver additionally requires
`casefold_version == CASEFOLD_VERSION_UNICODE_15_1` (15.1.0 encoded as
`15_001_000`). A version mismatch refuses the mount.

Images produced by older `mksaltyfs.py` versions leave the entire 0x100..
0x110 region zero, which is interpreted as "no new features" and mounts
normally.

Legacy: the 4-byte slot at offset 0x00C was previously named `flags` and
unused. It has been renamed `incompat_flags` without format change.

### B-Tree Structure

All metadata uses COW B-trees:

```c
// B-tree node header (64 bytes)
struct BTreeNodeHeader {
    uint8_t  magic[4];          // "BTND"
    uint32_t checksum;          // Node checksum
    
    uint64_t owner;             // Owning tree ID
    uint64_t generation;        // Transaction generation
    uint64_t block_nr;          // This block number
    
    uint32_t num_items;         // Number of items
    uint16_t level;             // 0 = leaf, >0 = internal
    uint16_t flags;             // Node flags
    
    uint8_t  reserved[24];
};

// B-tree key
struct BTreeKey {
    uint64_t object_id;         // Inode number or tree ID
    uint8_t  type;              // Item type
    uint64_t offset;            // Offset within object
} __attribute__((packed));

// B-tree item (in leaf nodes)
struct BTreeItem {
    struct BTreeKey key;
    uint32_t offset;            // Offset to data in node
    uint32_t size;              // Size of data
};

// B-tree pointer (in internal nodes)  
struct BTreePointer {
    struct BTreeKey key;        // First key in child
    uint64_t block_nr;          // Child block number
    uint64_t generation;        // Child generation
};
```

### Inode Structure

```c
// Item type constants
#define SALTY_INODE_ITEM     0x01
#define SALTY_INODE_REF      0x02  // Name reference
#define SALTY_DIR_ITEM       0x03
#define SALTY_DIR_INDEX      0x04
#define SALTY_EXTENT_DATA    0x05
#define SALTY_EXTENT_REF     0x06  // Reserved for extent refcounting (v2+)
#define SALTY_XATTR_ITEM     0x07

// Inode flag bits (SaltyInode.flags)
#define SALTY_INODE_CASEFOLD 0x01  // Directory uses Unicode Simple Case-Folding
#define SALTY_INODE_HIDDEN   0x02  // Not referenced by any directory entry; used for indirect xattr storage

// Inode item (embedded in B-tree leaf)
struct SaltyInode {
    uint64_t generation;
    uint64_t size;              // File size in bytes
    uint64_t blocks;            // Allocated blocks
    uint64_t block_group;       // Allocation hint
    
    uint32_t nlink;             // Hard link count
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;              // Permissions
    
    uint64_t atime;             // Access time (ns since epoch)
    uint64_t mtime;             // Modify time
    uint64_t ctime;             // Change time
    uint64_t crtime;            // Creation time
    
    uint32_t flags;             // Inode flags
    uint32_t sequence;          // NFS generation
    
    uint8_t  reserved[32];
};
```

### Extent Tree

File data is stored in extents:

```c
// Extent data item
struct ExtentData {
    uint64_t generation;
    uint64_t ram_bytes;         // Uncompressed size
    uint8_t  compression;       // Compression type
    uint8_t  encryption;        // Encryption type
    uint16_t other_encoding;    // Other encoding
    uint8_t  type;              // Inline, regular, prealloc
    uint8_t  reserved[3];
    
    // For non-inline extents:
    uint64_t disk_bytenr;       // On-disk location
    uint64_t disk_num_bytes;    // On-disk size
    uint64_t offset;            // Offset within extent
    uint64_t num_bytes;         // Bytes from this extent
};

// Extent types
#define EXTENT_INLINE       0   // Data inline in B-tree
#define EXTENT_REGULAR      1   // Normal extent
#define EXTENT_PREALLOC     2   // Preallocated, unwritten
```

## Copy-on-Write Semantics

### Write Operation

```mermaid
graph TD
    A[Write Request] --> B{Block Modified?}
    B -->|Yes| C[Allocate New Block]
    C --> D[Copy + Modify]
    D --> E[Update Parent Pointer]
    E --> F{Parent Modified?}
    F -->|Yes| C
    F -->|No| G[Update Root]
    B -->|No| H[Done]
```

### COW B-Tree Update

```
Before Write:                    After Write:
                                
    [Root A]                        [Root B] (new)
       |                               |
   [Node A]                        [Node B] (new)
   /      \                        /      \
[Leaf A] [Leaf B]             [Leaf A] [Leaf C] (new)
                                         ↑
                              Modified data here
```

### Implementation

```rust
/// COW write to filesystem
fn cow_write(
    fs: &mut SaltyFs,
    inode: InodeRef,
    offset: u64,
    data: &[u8],
) -> Result<usize, FsError> {
    let block_size = fs.superblock.block_size;
    let mut written = 0;
    
    while written < data.len() {
        let block_offset = (offset + written as u64) / block_size;
        let in_block_offset = (offset + written as u64) % block_size;
        let to_write = min(
            data.len() - written,
            block_size as usize - in_block_offset as usize,
        );
        
        // Allocate new block
        let new_block = fs.alloc_block()?;
        
        // If partial write, copy existing data first
        if in_block_offset > 0 || to_write < block_size as usize {
            if let Some(old_extent) = inode.find_extent(block_offset)? {
                fs.copy_block(old_extent.disk_bytenr, new_block)?;
            } else {
                fs.zero_block(new_block)?;
            }
        }
        
        // Write new data
        fs.write_block_partial(
            new_block,
            in_block_offset,
            &data[written..written + to_write],
        )?;
        
        // Update extent tree (this triggers COW up the tree)
        inode.update_extent(block_offset, new_block)?;
        
        written += to_write;
    }
    
    Ok(written)
}
```

## Snapshots

### Snapshot Creation

Snapshots are instant and space-efficient:

```rust
/// Create a snapshot of the filesystem
fn create_snapshot(
    fs: &mut SaltyFs,
    name: &str,
) -> Result<SnapshotId, FsError> {
    // Start transaction
    let txn = fs.begin_transaction()?;
    
    // Create snapshot entry
    let snapshot = Snapshot {
        id: fs.next_snapshot_id(),
        name: name.to_string(),
        root_tree: fs.superblock.root_tree,  // Just copy pointer!
        generation: fs.superblock.generation,
        creation_time: now(),
    };
    
    // Insert into snapshot tree
    fs.snapshot_tree.insert(snapshot.id, snapshot)?;
    
    // Commit transaction
    txn.commit()?;
    
    Ok(snapshot.id)
}
```

### Space Sharing

Snapshots share blocks with current filesystem:

```
Snapshot 1 Root ───┐       Current Root ───┐
                   │                       │
                   ▼                       ▼
              [Shared Node]           [New Node]
                   │                 /          \
                   │                /            \
                   ▼               ▼              ▼
              [Shared Leaf]   [Shared Leaf]   [New Leaf]
```

### Reference Counting

Blocks are reference-counted for snapshot management:

```c
// Extent reference item
struct ExtentRef {
    uint64_t owner;         // Tree owning this reference
    uint64_t offset;        // Offset in owner
    uint32_t count;         // Reference count
};
```

## Intent Log

For crash consistency, writes go to the intent log first:

### Log Structure

```c
// Log entry header
struct LogEntryHeader {
    uint32_t magic;         // "SLOG"
    uint32_t checksum;
    uint64_t generation;
    uint32_t type;          // Log entry type
    uint32_t length;        // Data length
};

// Log entry types
#define LOG_INODE_UPDATE    1
#define LOG_EXTENT_ALLOC    2
#define LOG_EXTENT_FREE     3
#define LOG_DIR_INSERT      4
#define LOG_DIR_DELETE      5
#define LOG_TREE_UPDATE     6
```

### Write Path

```mermaid
sequenceDiagram
    participant App
    participant VFS
    participant SaltyFS
    participant Log
    participant Disk

    App->>VFS: write(fd, data)
    VFS->>SaltyFS: write_inode()
    SaltyFS->>Log: append(intent)
    Log->>Disk: write log block
    Disk-->>Log: ack
    Log-->>SaltyFS: logged
    SaltyFS->>Disk: write data (COW)
    SaltyFS->>Disk: update metadata
    SaltyFS->>Log: commit()
    Log->>Disk: write commit record
    SaltyFS-->>App: bytes written
```

### Crash Recovery

```rust
/// Recover filesystem after crash
fn recover(fs: &mut SaltyFs) -> Result<(), FsError> {
    // Read log from head to tail
    let log = read_intent_log(fs)?;
    
    for entry in log.iter() {
        match entry.entry_type {
            LOG_INODE_UPDATE => {
                // Check if update was committed
                if !is_committed(fs, &entry) {
                    // Replay the update
                    replay_inode_update(fs, &entry)?;
                }
            }
            // ... handle other entry types
            _ => {}
        }
    }
    
    // Clear log after recovery
    clear_intent_log(fs)?;
    
    Ok(())
}
```

## Checksums

All data and metadata blocks have checksums:

### Checksum Types

```rust
#[repr(u32)]
pub enum ChecksumType {
    Crc32c = 0,
    Xxhash64 = 1,
    Sha256 = 2,  // For paranoid mode
}
```

### Checksum Tree

Checksums are stored in a separate B-tree:

```c
// Checksum item
struct ChecksumItem {
    uint64_t block_nr;      // Block number
    uint32_t checksum;      // Checksum value
    uint32_t reserved;
};
```

### Verification

```rust
/// Read block with checksum verification
fn read_block_verified(
    fs: &SaltyFs,
    block_nr: u64,
) -> Result<Block, FsError> {
    let block = fs.read_block(block_nr)?;
    
    // Look up expected checksum
    let expected = fs.checksum_tree.lookup(block_nr)?;
    
    // Calculate actual checksum
    let actual = calculate_checksum(&block, fs.checksum_type);
    
    if actual != expected {
        return Err(FsError::ChecksumMismatch {
            block: block_nr,
            expected,
            actual,
        });
    }
    
    Ok(block)
}
```

## Compression

Optional transparent compression:

### Compression Types

```rust
#[repr(u8)]
pub enum CompressionType {
    None = 0,
    Lz4 = 1,      // Fast, good ratio
    Zstd = 2,     // Better ratio, still fast
    Zlib = 3,     // Maximum compatibility
}
```

### Compressed Extent

```
┌─────────────────────────────────────────────────────────────┐
│  Extent Data Item                                           │
├─────────────────────────────────────────────────────────────┤
│  ram_bytes: 65536      (uncompressed size)                  │
│  compression: Zstd                                          │
│  disk_num_bytes: 24576 (compressed size on disk)            │
└─────────────────────────────────────────────────────────────┘
```

## Boot Support

### Read-Only Driver

The Stage 3 bootloader includes a minimal SaltyFS driver:

```c
// boot/stage3/fs/saltyfs.c

struct SaltyFsContext {
    uint64_t partition_lba;
    struct SaltySuperblock sb;
    uint64_t snapshot_root;  // Current snapshot or main root
};

// Mount filesystem (read-only)
int saltyfs_mount(struct SaltyFsContext *ctx, uint64_t partition_lba) {
    ctx->partition_lba = partition_lba;
    
    // Read primary superblock
    if (read_block(partition_lba, &ctx->sb) != 0) {
        return -1;
    }
    
    // Verify magic
    if (memcmp(ctx->sb.magic, "SALTYFS\0", 8) != 0) {
        // Try backup superblock
        if (read_block(partition_lba + 1, &ctx->sb) != 0) {
            return -1;
        }
    }
    
    // Verify checksum
    if (!verify_superblock_checksum(&ctx->sb)) {
        return -1;
    }
    
    ctx->snapshot_root = ctx->sb.root_tree;
    return 0;
}

// Read file from filesystem
int saltyfs_read_file(
    struct SaltyFsContext *ctx,
    const char *path,
    void *buffer,
    size_t *size
) {
    // 1. Parse path and walk directory tree
    uint64_t inode = resolve_path(ctx, path);
    if (inode == 0) return -1;
    
    // 2. Read inode item
    struct SaltyInode inode_item;
    if (read_inode(ctx, inode, &inode_item) != 0) return -1;
    
    // 3. Read extent data
    return read_extents(ctx, inode, buffer, size);
}
```

### Snapshot Boot

Boot from a filesystem snapshot:

```ini
# /boot/saltyos.cfg
[snapshot-recovery]
title = SaltyOS (Recovery Snapshot)
snapshot = 42
kernel = /boot/kernel.elf
initrd = /boot/initrd.img
```

```c
// Set snapshot for boot
int saltyfs_set_snapshot(struct SaltyFsContext *ctx, uint64_t snapshot_id) {
    // Look up snapshot in snapshot tree
    struct Snapshot snap;
    if (lookup_snapshot(ctx, snapshot_id, &snap) != 0) {
        return -1;
    }
    
    // Use snapshot's root tree
    ctx->snapshot_root = snap.root_tree;
    return 0;
}
```

## Userspace Driver

The full read-write SaltyFS driver runs in userspace at `userland/drivers/filesystems/saltyfs/`.

### VFS Interface

```rust
// userland/drivers/filesystems/saltyfs/src/main.rs

pub struct SaltyFsDriver {
    device: BlockDevice,
    superblock: Superblock,
    // Caches
    block_cache: LruCache<u64, Block>,
    inode_cache: LruCache<u64, Inode>,
}

impl FsDriver for SaltyFsDriver {
    fn mount(&mut self, device: &str) -> Result<(), FsError>;
    fn unmount(&mut self) -> Result<(), FsError>;
    
    fn lookup(&self, parent: InodeId, name: &str) -> Result<InodeId, FsError>;
    fn read(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;
    fn write(&mut self, inode: InodeId, offset: u64, buf: &[u8]) -> Result<usize, FsError>;
    
    fn create(&mut self, parent: InodeId, name: &str, mode: u32) -> Result<InodeId, FsError>;
    fn unlink(&mut self, parent: InodeId, name: &str) -> Result<(), FsError>;
    fn mkdir(&mut self, parent: InodeId, name: &str, mode: u32) -> Result<InodeId, FsError>;
    fn rmdir(&mut self, parent: InodeId, name: &str) -> Result<(), FsError>;
    
    // Snapshot operations
    fn create_snapshot(&mut self, name: &str) -> Result<SnapshotId, FsError>;
    fn delete_snapshot(&mut self, id: SnapshotId) -> Result<(), FsError>;
    fn list_snapshots(&self) -> Result<Vec<Snapshot>, FsError>;
}
```

## Performance Considerations

### Write Amplification

COW can cause write amplification (modifying one block updates whole path to root).

Mitigations:
- **Delayed allocation**: Batch writes before COW
- **Intent log**: Absorb small writes
- **B-tree node size**: Larger nodes = shallower trees

### Fragmentation

Log-structured writes can fragment files over time.

Mitigations:
- **Online defragmentation**: Background task
- **Extent preallocation**: Reserve contiguous space
- **Auto-defrag option**: Defrag on read if too fragmented

### Memory Usage

Large filesystems need significant metadata cache.

Recommendations:
- **Minimum RAM**: 256 MB for basic operation
- **Recommended**: 1+ GB for good performance
- **Server**: Cache size proportional to filesystem size

## Extended Attributes (xattr)

SaltyFS stores extended attributes as B-tree items keyed by
`(inode, TRONA_XATTR_ITEM = 0x07, fnv1a_hash(name))`. Collisions use the
same linear-probing scheme as `DIR_ITEM` (up to 16 slots).

### On-disk payload

Every XATTR_ITEM starts with an 8-byte header:

```c
struct XattrHeader {
    uint16_t name_len;    // bytes in the following name slice (≤ 255)
    uint8_t  flags;       // bit 0: 0 = INLINE, 1 = INDIRECT
    uint8_t  reserved0;
    uint32_t value_len;   // real value length (always populated)
};
```

Two storage shapes share this header — a btrfs + ZFS hybrid:

1. **INLINE** (btrfs-like, used for small values). The value bytes follow
   the name in the same leaf:

   ```
   [header | name bytes | value bytes]
   ```

   Used whenever `8 + name_len + value_len ≤ SALTY_XATTR_INLINE_MAX` (200).
   Above that limit the driver falls back to the indirect shape.

2. **INDIRECT** (ZFS-like, for large values). The payload carries a name
   and a hidden inode reference:

   ```
   [header | name bytes | ref_ino: u64]
   ```

   `ref_ino` points at a companion inode carrying `SALTY_INODE_HIDDEN`.
   The hidden inode is **not** referenced by any directory entry — its
   only reference is the indirect XATTR_ITEM above. Its value bytes are
   stored through the regular `EXTENT_DATA` machinery, which means:

   - Large xattrs reuse the whole file write/read/truncate stack.
   - Copy-on-write, future snapshot sharing, and block allocation follow
     the same rules as regular file data.
   - There is no xattr-specific block lifecycle to reason about.

`value_len` in the header always reflects the logical value size so that
callers issuing a size query do not need to distinguish INLINE vs
INDIRECT.

### Namespaces

Only the POSIX-ish prefixes `user.`, `trusted.`, `security.`, and
`system.` are accepted. Capability-based access control for the last
three is deferred to the multi-user auth work.

### Set / Get / Remove / List

All four operations are exposed as server labels
`BACKEND_{GET,SET,REMOVE,LIST}XATTR` (23..26) and exchange name/value
bytes over the VFS shared-memory channel (`VFS_SHM_VADDR`). See
`userland/drivers/filesystems/saltyfs/src/xattr.rs` for the exact IPC
register layout and the full rollback matrix (hidden-inode allocation,
extent write failures, and XATTR_ITEM insert failures all leave the old
state intact or cleanly reclaim the new allocation).

Inode destruction (`nlink == 0` in `handle_unlink_fs` or
`handle_rename_fs`) invokes `delete_all_xattrs`, which tears down both
inline and indirect entries — including the hidden inodes backing
indirect values — before the main inode's extents are freed.

## Case-folding directories

Directories marked with `SALTY_INODE_CASEFOLD` use Unicode 15.1 Simple
Case-Folding on DIR_ITEM keys and name comparisons. Semantics mirror
Linux ext4's `EXT4_CASEFOLD_FL`:

- The bit is stored in `SaltyInode.flags` on the parent directory.
- `mkdir`, `create`, and `symlink` propagate the bit from the parent
  inode to the child, so entire subtrees stay casefold-coherent.
- The filesystem-level bit `SALTYFS_INCOMPAT_CASEFOLD` must be set, and
  `Superblock.casefold_version` must match the driver's supported
  Unicode version (`CASEFOLD_VERSION_UNICODE_15_1 = 15_001_000`).
  Version mismatches refuse the mount outright.

### What is folded

The in-tree table (`userland/drivers/filesystems/saltyfs/src/casefold_table.rs`)
is generated from Unicode 15.1.0 `CaseFolding.txt` using
`tools/gen_casefold.py`, keeping status `C` (Common) and `S` (Simple)
mappings only. The driver drops:

- **Full** (`F`) mappings — they expand one codepoint to many, so they
  cannot be represented as 1:1 `(u32, u32)` pairs without altering
  UTF-8 byte-length assumptions.
- **Turkic** (`T`) mappings — they are locale-dependent and would
  conflict with the default behaviour for non-Turkish locales.
- **NFD / NFC normalization** — two visually identical names with
  different canonical forms are still considered distinct entries.

Callers that enter a casefold directory must provide valid UTF-8 names;
`create`, `mkdir`, and `symlink` reject invalid UTF-8 with
`TRONA_INVALID_ARGUMENT` so that the casefold index stays well-defined.

### Regenerating the table

```
python3 tools/gen_casefold.py
```

The script is deterministic. Both the Unicode source
(`tools/data/CaseFolding-15.1.txt`) and the generated
`casefold_table.rs` are committed so builds do not need network access.

## Multi-user inbound protocol (V2)

`BACKEND_CREATE`, `BACKEND_MKDIR`, and `BACKEND_SYMLINK` understand two
register layouts distinguished by **bit 63 of `regs[0]`**
(`SALTYFS_PROTO_V2`):

- **V1 (legacy)**: uid/gid are implicitly zero. This is the layout that
  today's VFS still drives; it remains accepted for compatibility until
  the forthcoming VFS redesign migrates to V2.

- **V2**: `regs[0] |= SALTYFS_PROTO_V2`, and uid/gid follow in
  subsequent registers. See `handlers.rs` module comment for the exact
  layout per handler. Name capacity shrinks slightly (136 → 120 for
  create/mkdir, 72 → 56 for symlink link name) to make room for uid/gid
  in the same 32-register IPC slot.

No real inode number ever reaches 2^63, so the sentinel is
collision-free.

### Stat-merged lookup / readdir

`BACKEND_LOOKUP` and `BACKEND_READDIR` replies now carry inode metadata
inline, eliminating the "one extra STAT per directory entry" round-trip
pattern:

- `handle_lookup` returns `{ino, mode, size, nlink, mtime, uid, gid,
  dir_type, blocks}` in 9 registers.
- `handle_readdir` streams fixed 96-byte records into VFS shared memory
  (`VFS_SHM_VADDR`), one record per entry, carrying the same stat
  metadata plus a 44-byte NUL-padded name. See `READDIR_ENTRY_BYTES` /
  `READDIR_NAME_MAX` in `handlers.rs` for the byte layout.

## Backend callback contract

`handle_mount` (IPC label `BACKEND_OPEN_SESSION = 1`) requests carry exactly
one extra capability transfer — `extra_caps[0] = VFS backend_callback EP`.
SaltyFS captures this slot unconditionally at dispatch time into
`BACKEND_CALLBACK_EP`; any previously stored cap is `cnode_delete`-ed before
replacement so a VFS restart cannot leave SaltyFS holding a dead endpoint.
The captured slot is produced by the substrate helper
`trona::recv_slot::capture_transferred_cap` after the per-saltyfs receive
arena delivers the cap to `CURRENT_RECV_SLOT`.

Every correlated async completion path (`emit_server_reply` in `main.rs`,
`build_open_session_completion` / `build_read_blocks_completion` in
`worker.rs`) routes replies through this EP. `emit_server_reply` checks
the `ipc::send_ctx` return value and loud-logs on failure; a missing cap
at completion time is an invariant violation that indicates a VFS-side
protocol bug. The full wire contract lives in
`lib/trona/uapi/protocol/fs_backend.rs`.

## Read-only mount

A mount is read-only when any of the following is true:

- `handle_mount` request carries the `SALTYFS_MOUNT_RO` bit in
  `regs[0]`.
- `Superblock.compat_ro_flags` has unknown bits set (automatic safe
  fallback — mount still succeeds).

While read-only, every mutating handler short-circuits with
`TRONA_READONLY`. `write_superblock`, `write_block`, `alloc_block`,
`free_block`, and `bitmap_flush` carry defensive guards as well, so a
misbehaving code path can never actually touch the device in RO mode.
The bitmap consistency correction that normally runs at mount time is
also skipped with a warning.

Lookup, stat, read, readdir, xattr read, and listxattr continue to work
normally.

## Future Enhancements

1. **RAID support**: Built-in mirroring and striping
2. **Encryption**: Per-file and full-disk encryption
3. **Deduplication**: Block-level dedup with reflinks
4. **Send/Receive**: Efficient snapshot streaming
5. **Quotas**: Per-user and per-project quotas
6. **Scrubbing**: Background integrity checking
