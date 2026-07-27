// SPDX-License-Identifier: GPL-2.0-only
//
//! Wire-level constants for mmsrv's per-client request MP and the
//! init-only master service-EP. The block is 0x400..=0x4FF; init-only
//! tier sits at 0x40x, self-only tier starts at 0x41x.

use trona_protocol::mm::{
    MM_ALLOC_RANGE, MM_BRK, MM_FILE_MMAP, MM_GET_CLIENT_VM_STATS, MM_GET_COMMIT_AS,
    MM_GET_SYSTEM_MEMINFO, MM_LIST_RESERVATIONS, MM_LIST_VMAS, MM_MMAP, MM_MO_CREATE, MM_MPROTECT,
    MM_MSYNC, MM_MUNMAP, MM_PREFAULT_RANGE, MM_REGISTER_VFS_PAGER, MM_RESERVE_IMAGE,
    MM_RESERVE_RANGE, MM_SBRK, MM_SHM_CREATE, MM_SHM_DESTROY, MM_SHM_MAP, MM_SHM_UNMAP,
    MM_UNMAP_IMAGE, MM_UNRESERVE_RANGE, MM_VFS_WRITEBACK_DONE,
};

/// init-only tier (master service-EP, INIT_PRIV_BADGE gate).
pub const LABEL_REGISTER_CLIENT: u64 = 0x400;
pub const LABEL_DEREGISTER_CLIENT: u64 = 0x401;
pub const LABEL_FORK_VSPACE: u64 = 0x402;
pub const LABEL_REGISTER_FAULT_PIPE: u64 = 0x403;
pub const LABEL_STAGE_IMAGE_REGION: u64 = 0x404;
/// Explicit exec transaction (Q2): allocate a pending VSpace,
/// stage the new image into it (with `STAGE_FLAG_EXEC_TXN` set on
/// `MM_STAGE_IMAGE_REGION`), then either commit (atomic VSpace
/// swap + old-region decommit) or abort (tear down the staged
/// VSpace).
pub const LABEL_BEGIN_EXEC_REPLACE: u64 = 0x405;
pub const LABEL_COMMIT_EXEC_REPLACE: u64 = 0x406;
pub const LABEL_ABORT_EXEC_REPLACE: u64 = 0x407;

/// Two-step admin verb step 1 (secondary operand). The secondary's own
/// control cap is invoked with one of these so the server records it as
/// the pending partner; the operate step (`FORK_VSPACE` / `STAGE_IMAGE_
/// REGION`) on the primary's control cap then consumes it. Shared with
/// `trona_protocol::mm`.
pub const LABEL_FORK_SET_PARTNER: u64 = trona_protocol::mm::MM_FORK_SET_PARTNER;
pub const LABEL_STAGE_SET_SOURCE: u64 = trona_protocol::mm::MM_STAGE_SET_SOURCE;

/// Bootstrap-bind exception within the 0x40x admin range. The
/// dispatcher accepts a non-`INIT_PRIV_BADGE` caller iff the badge's
/// `client_id` matches a registered `ClientState`. Used by lazy
/// resolution: child issues `NAMESRV_LOOKUP("mmsrv")` (gets a
/// caller-badged copy of the master service-EP send), then issues
/// `MM_BIND_CLIENT_SELF` to receive a copy of its per-client request
/// MP send (`ClientState.request_mp_send`).
pub const LABEL_BIND_CLIENT_SELF: u64 = 0x408;

/// `MM_STAGE_IMAGE_REGION` `flags` argument bits shared with
/// `trona_protocol::mm`.
pub const STAGE_FLAG_EXEC_TXN: u64 = trona_protocol::mm::STAGE_FLAG_EXEC_TXN;
/// Preserve the destination VMA as a stack mapping. The kernel's
/// `TCB_SET_STACK_BOUNDS` validation accepts only
/// `KERNITE_REGION_KIND_STACK`, so init sets this when staging the
/// initial user stack through mmsrv.
pub const STAGE_FLAG_STACK: u64 = trona_protocol::mm::STAGE_FLAG_STACK;
/// The staged region's source is the forwarded exec MO held in the
/// pending exec transaction (no `src_region_id`). Shared with
/// `trona_protocol::mm`.
pub const STAGE_FLAG_EXEC_MO_SRC: u64 = trona_protocol::mm::STAGE_FLAG_EXEC_MO_SRC;
/// Stage the exec-MO run as a private COW copy (clone the file pages out of
/// the exec MO + zero the tail) instead of a shared zero-copy sub-range.
/// Shared with `trona_protocol::mm`.
pub const STAGE_FLAG_EXEC_MATERIALIZE: u64 = trona_protocol::mm::STAGE_FLAG_EXEC_MATERIALIZE;
/// The staged region's source is a caller-provided code MO transferred as
/// `caps[0]`, mapped into the destination client's live VSpace. Used to stage a
/// service's interpreter / library closure from a `READ|EXECUTE` code MO (no
/// anon copy). Shared with `trona_protocol::mm`.
pub const STAGE_FLAG_PROVIDED_MO: u64 = trona_protocol::mm::STAGE_FLAG_PROVIDED_MO;
pub const STAGE_FLAG_TXN_ID_SHIFT: u32 = trona_protocol::mm::STAGE_FLAG_TXN_ID_SHIFT;
/// Stack guard width (pages) packed into the `MM_STAGE_IMAGE_REGION`
/// flags word, bits `[15:8]`. Shared with `trona_protocol::mm`.
pub const STAGE_GUARD_PAGES_SHIFT: u32 = trona_protocol::mm::STAGE_GUARD_PAGES_SHIFT;
pub const STAGE_GUARD_PAGES_MASK: u64 = trona_protocol::mm::STAGE_GUARD_PAGES_MASK;

/// `MM_STAGE_IMAGE_REGION` `regs[9]` image-segment classification,
/// shared with `trona_protocol::mm`.
pub const STAGE_IMAGE_KIND_NONE: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_NONE;
pub const STAGE_IMAGE_KIND_TEXT: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_TEXT;
pub const STAGE_IMAGE_KIND_DATA: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_DATA;
pub const STAGE_IMAGE_KIND_RODATA: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_RODATA;
pub const STAGE_IMAGE_KIND_BSS: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_BSS;

/// self-only tier (per-client request MP).
pub const LABEL_MMAP: u64 = MM_MMAP;
pub const LABEL_MUNMAP: u64 = MM_MUNMAP;
pub const LABEL_MPROTECT: u64 = MM_MPROTECT;
pub const LABEL_BRK: u64 = MM_BRK;
pub const LABEL_SBRK: u64 = MM_SBRK;
pub const LABEL_MSYNC: u64 = MM_MSYNC;
pub const LABEL_VFS_WRITEBACK_DONE: u64 = MM_VFS_WRITEBACK_DONE;
pub const LABEL_MO_CREATE: u64 = MM_MO_CREATE;
pub const LABEL_RESERVE_IMAGE: u64 = MM_RESERVE_IMAGE;
pub const LABEL_UNMAP_IMAGE: u64 = MM_UNMAP_IMAGE;
pub const LABEL_SHM_CREATE: u64 = MM_SHM_CREATE;
pub const LABEL_SHM_MAP: u64 = MM_SHM_MAP;
pub const LABEL_SHM_DESTROY: u64 = MM_SHM_DESTROY;
pub const LABEL_FILE_MMAP: u64 = MM_FILE_MMAP;
pub const LABEL_PREFAULT_RANGE: u64 = MM_PREFAULT_RANGE;
/// vfs-only registration of its pager EP. Self-tier label routed
/// through whichever per-client request MP vfs holds; the
/// dispatcher accepts only the first call (later calls return
/// `KERNITE_ERR_ALREADY_EXISTS`).
pub const LABEL_REGISTER_VFS_PAGER: u64 = MM_REGISTER_VFS_PAGER;
pub const LABEL_GET_SYSTEM_MEMINFO: u64 = MM_GET_SYSTEM_MEMINFO;

/// Reserve a VA range in the **caller's own** VM (self-tier). Args:
/// `regs[0]=base, regs[1]=length, regs[2]=kind` (a `ReservationKind`
/// discriminant). Reply: `regs[0]=idx, regs[1]=generation`.
pub const LABEL_RESERVE_RANGE: u64 = MM_RESERVE_RANGE;
pub const LABEL_ALLOC_RANGE: u64 = MM_ALLOC_RANGE;
/// Drop the reservation covering `regs[0]=base` in the caller's own VM.
pub const LABEL_UNRESERVE_RANGE: u64 = MM_UNRESERVE_RANGE;
/// Unmap a SHM mapping the caller holds. Args matching the
/// console / posix_ttysrv senders: `regs[0]=shm_id, regs[2]=vaddr`.
pub const LABEL_SHM_UNMAP: u64 = MM_SHM_UNMAP;
/// Cross-client VMA listing for procfs (gated to the vfs pager owner).
/// `regs[0]=pid`; reply `regs[0]=count`, records in the IPC buffer's
/// `reserved[]` area as `MmsrvVmaEntry`.
pub const LABEL_LIST_VMAS: u64 = MM_LIST_VMAS;
/// Cross-client reservation listing for procfs (gated to the vfs pager
/// owner). `regs[0]=pid`; reply `regs[0]=count`, records in the IPC
/// buffer's `reserved[]` area as `MmsrvReservationEntry`.
pub const LABEL_LIST_RESERVATIONS: u64 = MM_LIST_RESERVATIONS;
/// System-wide committed-AS aggregate (no args). Reply
/// `regs[0]=committed_bytes`.
pub const LABEL_GET_COMMIT_AS: u64 = MM_GET_COMMIT_AS;
/// Per-process memory snapshot for procfs (gated to the vfs pager
/// owner). `regs[0]=pid`; reply packs `TronaProcMemSnapshot` into
/// `regs[0..20]`.
pub const LABEL_GET_CLIENT_VM_STATS: u64 = MM_GET_CLIENT_VM_STATS;
