// SPDX-License-Identifier: GPL-2.0-only
//! VFS protocol constants and configuration values.

// Cap layout — VFS is init-spawned (pre-procmgr). System roles flow through
// the substrate `trona_runtime::client::caps::*` getters (populated by init's cap-table
// builder via provider-name resolution for `.socket` attachments and
// `init_slot_to_role` for `.cap` source-slot attachments). Service-local
// caps that do not correspond to a system role remain as file-local
// constants.

// Service-local peer endpoints. These are lowered `.socket` attachments
// resolved by local role, not fixed child-cspace slots.
trona_runtime::local_cap!(pub(crate) posix_ttysrv_ep = "vfs:posix_ttysrv");
trona_runtime::local_cap!(pub(crate) netsrv_ep = "vfs:netsrv_ep");
pub(crate) const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;
/// Internal owner-loop wake message posted by VFS worker threads when a
/// completion ring transitions from empty to non-empty.
pub(crate) const VFS_OWNER_WORKER_KICK: u64 = 0x5657_4B01;

// ObjectEntry.rights bitmask (set at open time, capability-based access control)
pub(crate) const OBJ_RIGHT_READ: u8 = 1 << 0;
pub(crate) const OBJ_RIGHT_WRITE: u8 = 1 << 1;

// ObjectEntry.flags internal bits. Status flags remain in the low POSIX range.
pub(crate) const OBJ_FLAG_CLOEXEC: u32 = 1 << 31;

// VFS protocol labels — canonical definitions in trona_posix::consts (uapi/protocol/vfs.rs)

/// Per-client bulk SHM size (1MB = 256 pages).
pub(crate) const CLIENT_BULK_SHM_PAGES: u64 = 256;
pub(crate) const VFS_INLINE_READ_MAX: usize = 152;
pub(crate) const VFS_INLINE_WRITE_MAX: usize = 152;
pub(crate) const VFS_INLINE_PWRITE_MAX: usize = 136;

// Initial capacities (growable pools)
pub(crate) const INITIAL_DIRENTS: usize = 32;
pub(crate) const INITIAL_WRITABLE: usize = 32;
pub(crate) const WRITABLE_SIZE: usize = 8192;
pub(crate) const INVALID_WRITABLE_SLOT: u32 = u32::MAX;
pub(crate) const INITIAL_CLIENTS: usize = 16;
pub(crate) const INITIAL_FDS: usize = 32;
// Semantic limits (not pool sizes)
pub(crate) const MAX_PATH_LEN: usize = 128;
pub(crate) const MAX_NAME_LEN: usize = 255;

// Cap slot range for deferred replies.
// Keep this strictly below 64 so it never collides with service-attachment
// caps (validated to use slots >= 64) or rtld runtime slot pool.
pub(crate) const CAP_REPLY_BASE: u64 = 32;
pub(crate) const CAP_REPLY_LIMIT: u64 = 62;

// Root inode
pub(crate) const ROOT_INO: u32 = 1;

pub(crate) const INITIAL_SYMLINKS: usize = 32;

/// VFS-SaltyFS shared memory for bulk data transport
pub(crate) const VFS_SALTYFS_SHM_VADDR: u64 = 0x0000_0000_5000_0000;
pub(crate) const VFS_SALTYFS_SHM_PAGES: u64 = 256; // 1MB
pub(crate) const VFS_SALTYFS_SHM_ID: u64 = 0x56534653; // "VSFS"
pub(crate) const VFS_FILE_MMAP_SCRATCH_VADDR: u64 = 0x0000_0000_7000_0000;
