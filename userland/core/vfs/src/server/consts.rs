// SPDX-License-Identifier: GPL-2.0-only
//! VFS protocol constants and configuration values.

// Cap layout — VFS is init-spawned (pre-procmgr). System roles flow through
// the substrate `trona::caps::*` getters (populated by init's cap_table
// builder via `system_role_for_bare_name` for NeedEP= providers and
// `init_slot_to_role` for CopyCap= sources). Service-local caps that do
// not correspond to a system role remain as file-local constants.

// Service-local / spawner-private slots — no trona::caps::* getter exists.
// posix_ttysrv and netsrv are post-procmgr services whose EPs reach vfs
// via runtime registration (not at spawn time). The notification slots
// are delivered via init's `CopyCap=` mechanism from init-private objects.
pub(crate) const VFS_CAP_POSIX_TTYSRV_EP: u64 = 67; // NeedEP posix_ttysrv:67
pub(crate) const VFS_CAP_PTY_NTFN: u64 = 68; // CopyCap 138:68 (PTY data-ready)
pub(crate) const VFS_CAP_NETSRV_EP: u64 = 71; // NeedEP netsrv:71
pub(crate) const VFS_CAP_ROOTFS_READY_NTFN: u64 = 72; // CopyCap 137:72 (rootfs milestone)
pub(crate) const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;

// ObjectEntry.rights bitmask (set at open time, capability-based access control)
pub(crate) const OBJ_RIGHT_READ: u8 = 1 << 0;
pub(crate) const OBJ_RIGHT_WRITE: u8 = 1 << 1;

// ObjectEntry.flags internal bits. Status flags remain in the low POSIX range.
pub(crate) const OBJ_FLAG_CLOEXEC: u32 = 1 << 31;

// VFS protocol labels — canonical definitions in trona::consts (uapi/protocol/vfs.rs)

/// Per-client bulk SHM size (1MB = 256 pages).
pub(crate) const CLIENT_BULK_SHM_PAGES: u64 = 256;


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
// Keep this strictly below 64 so it never collides with service-injected caps
// (NeedEP/CopyCap are validated to use slots >= 64) or rtld runtime slot pool.
pub(crate) const CAP_REPLY_BASE: u64 = 32;
pub(crate) const CAP_REPLY_LIMIT: u64 = 62;
pub(crate) const VFS_CAP_BACKEND_CALLBACK_EP: u64 = 63; // bootstrap-private backend callback EP injected by init

// Root inode
pub(crate) const ROOT_INO: u32 = 1;


pub(crate) const INITIAL_SYMLINKS: usize = 32;

/// VFS-SaltyFS shared memory for bulk data transport
pub(crate) const VFS_SALTYFS_SHM_VADDR: u64 = 0x0000_0000_5000_0000;
pub(crate) const VFS_SALTYFS_SHM_PAGES: u64 = 256; // 1MB
pub(crate) const VFS_SALTYFS_SHM_ID: u64 = 0x56534653; // "VSFS"
pub(crate) const VFS_FILE_MMAP_SCRATCH_VADDR: u64 = 0x0000_0000_7000_0000;
