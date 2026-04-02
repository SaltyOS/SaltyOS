//! SaltyOS Memory Server (mmsrv)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Central pager service: all user frame allocation and VSpace mapping
//! is routed through this server. Eliminates per-service allocators and
//! hardcoded `MAX_*` limits.
//!
//! IPC protocol:
//!   MM_REGISTER    — init/procmgr registers a new client + VSpace cap transfer
//!   MM_DEREGISTER  — procmgr removes a client on exit
//!   MM_BRK         — client sets program break
//!   MM_SBRK        — client increments break
//!   MM_MMAP        — client anonymous mmap
//!   MM_MUNMAP      — client unmaps region
//!   MM_MPROTECT    — client changes protection
//!   MM_MAP_BATCH   — procmgr batch-maps frames for spawn
//!   MM_MAP_WINDOW  — procmgr opens write window for an existing client region
//!   MM_ALLOC_PRIVATE_WINDOW — materialize region + open first write window
//!   MM_ALLOC_INITRD_COPY — materialize region + populate it from initrd
//!   MM_ALLOC_BOOTINFO_COPY — materialize region + populate it from bootinfo
//!   MM_COPY_FROM_CLIENT_REGION — copy caller-owned region pages into client region
//!   MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION — allocate region + copy caller pages
//!   MM_UNMAP_WINDOW — procmgr removes write window
//!   MM_SHM_CREATE  — VFS creates SHM object
//!   MM_SHM_MAP     — VFS maps SHM into client
//!   MM_SHM_UNMAP   — VFS unmaps SHM from client
//!   MM_FORK_REGIONS — procmgr clones parent regions to child
//!
//! Cap layout (set by init):
//!   0 = self TCB
//!   1 = self VSpace
//!   2 = self CSpace
//!   3 = server endpoint
//!   7 = child untyped
//!   12 = initrd untyped
//!   14 = readiness notification
//!   16+ = mirrored parent untyped caps
//!   64 = namesrv endpoint (via NeedEP)

#![no_std]
#![no_main]

mod types;
mod client;
mod mmap;
mod pool;
mod shm;

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona_posix::consts::*;

use types::*;

// ---------------------------------------------------------------------------
// Cap slot layout
// ---------------------------------------------------------------------------

const CAP_SERVER_EP: u64 = 3;
const CAP_UNTYPED: u64 = 7;
const CAP_INITRD_UNTYPED: u64 = 12;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_UNTYPED_START: u64 = 16;
const CAP_NAMESERV: u64 = 64;
const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

/// VFS pager callback EP: when set (non-zero), mmsrv routes VFS_PAGER_READ /
/// VFS_PAGER_WRITE requests through this EP instead of the VFS service EP.
/// This breaks the VFS↔MMSRV cycle by allowing VFS to receive pager requests
/// on a dedicated callback EP while it's blocked on mmsrv's service EP.
///
/// The cap is transferred by VFS during registration (via a new label) or
/// injected by init. Zero means not registered (use VFS service EP directly).
static mut VFS_PAGER_CALLBACK_EP: Cap = 0;

/// Receive slot pool: top of CSpace to avoid conflicts with slot_alloc.
/// CNodeBits=16 → 65536 total slots. Reserve last 1024 for cap receives.
const RECV_SLOT_BASE: Cap = 0xFC00; // 64512
const RECV_SLOT_END: Cap = 0x10000; // 65536

// ---------------------------------------------------------------------------
// Self-mmap: internal memory allocation for mmsrv's own data structures.
// Cannot use posix_mmap (would be recursive IPC). Direct retype + vspace_map.
// ---------------------------------------------------------------------------

const SELF_MMAP_BASE: u64 = 0x2000_0000;
static mut SELF_MMAP_NEXT: u64 = SELF_MMAP_BASE;

const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;

unsafe fn self_mmap(num_pages: usize) -> *mut u8 {
    unsafe {
        let base = *(&raw const SELF_MMAP_NEXT);
        for i in 0..num_pages {
            let slot = match trona::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => return core::ptr::null_mut(),
            };
            if retype_any(OBJ_FRAME, 0, slot) != 0 {
                return core::ptr::null_mut();
            }
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                slot,
                base + i as u64 * 4096,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                return core::ptr::null_mut();
            }
        }
        *(&raw mut SELF_MMAP_NEXT) = base + num_pages as u64 * 4096;
        core::ptr::write_bytes(base as *mut u8, 0, num_pages * 4096);
        base as *mut u8
    }
}

/// Map an existing Frame cap into mmsrv's own VSpace (no new frame allocation).
/// Used for pool/ring pages where both mmsrv and the kernel must access the
/// SAME physical frame. Does NOT zero the page — caller is responsible.
///
/// # Safety
///
/// `frame_cap` must be a valid Frame capability.
unsafe fn self_map_frame(frame_cap: Cap) -> *mut u8 {
    unsafe {
        let va = *(&raw const SELF_MMAP_NEXT);
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            frame_cap,
            va,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            return core::ptr::null_mut();
        }
        *(&raw mut SELF_MMAP_NEXT) = va + 4096;
        va as *mut u8
    }
}

/// Create a MemoryObject with at least `min_pages` capacity.
///
/// Returns `(mo_cap, actual_page_count)` on success, or `(0, 0)` on failure.
/// The actual page count is the next power-of-two >= `min_pages`.
///
/// # Safety
/// Must be called from the mmsrv main loop (single-threaded access to statics).
unsafe fn create_mo(min_pages: usize) -> (Cap, usize) {
    unsafe {
        if min_pages == 0 {
            return (0, 0);
        }
        let mut sb: u64 = 0;
        while (1u64 << sb) < min_pages as u64 {
            sb += 1;
        }
        let actual = 1usize << sb;
        let slot = match recycled_slot_alloc() {
            Some(s) => s,
            None => return (0, 0),
        };
        if retype_any(OBJ_MEMORY_OBJECT, sb, slot) != 0 {
            recycle_empty_slot(slot);
            return (0, 0);
        }
        (slot, actual)
    }
}

// ---------------------------------------------------------------------------
// Untyped source tracking
// ---------------------------------------------------------------------------

static mut UT_SOURCES: [UntypedSource; MAX_UT_SOURCES] = {
    const E: UntypedSource = UntypedSource::empty();
    [E; MAX_UT_SOURCES]
};
static mut UT_COUNT: usize = 0;
static mut UT_HINT: usize = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Allocate a Cap array of `cap` entries via self_mmap (used by SHM).
unsafe fn alloc_frame_cap_array(cap: usize) -> *mut Cap {
    unsafe {
        let bytes = cap * core::mem::size_of::<Cap>();
        let pages = (bytes + 4095) / 4096;
        let ptr = self_mmap(pages);
        if ptr.is_null() {
            return core::ptr::null_mut();
        }
        ptr as *mut Cap
    }
}

/// Convert POSIX prot flags to VSpace flags.
fn prot_to_vspace_flags(prot: u8) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    if prot & (PROT_WRITE as u8) != 0 {
        flags |= VSPACE_FLAG_WRITABLE;
    }
    if prot & (PROT_EXEC as u8) != 0 {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

fn vspace_flags_to_prot(flags: u64) -> u8 {
    let mut prot = PROT_READ as u8;
    if flags & VSPACE_FLAG_WRITABLE != 0 {
        prot |= PROT_WRITE as u8;
    }
    if flags & VSPACE_FLAG_EXECUTABLE != 0 {
        prot |= PROT_EXEC as u8;
    }
    prot
}

/// Commit `count` pages starting at `offset` in a MemoryObject, trying each
/// available untyped source (round-robin from UT_HINT). If an untyped is
/// partially exhausted, continues with the next untyped for the remaining
/// pages. Falls back to PMM (ut_cap=0) as a last resort.
///
/// Returns `(error, total_committed)`.
///
/// # Safety
///
/// Must be called from the mmsrv main loop (single-threaded access to statics).
unsafe fn commit_mo_pages(mo_cap: Cap, offset: u64, count: u64) -> (i32, u64) {
    unsafe {
        let ut_count = *(&raw const UT_COUNT);
        if ut_count == 0 {
            // No untyped sources — fall back to PMM directly
            return invoke::mo_commit(mo_cap, offset, count, 0);
        }

        let start = {
            let h = *(&raw const UT_HINT);
            if h < ut_count { h } else { 0 }
        };

        let sources = &*(&raw const UT_SOURCES);
        let mut remaining = count;
        let mut cur_offset = offset;
        let mut total_committed: u64 = 0;

        // First pass: from hint to end
        for i in start..ut_count {
            if remaining == 0 {
                break;
            }
            if !sources[i].active {
                continue;
            }
            let (err, committed) = invoke::mo_commit(mo_cap, cur_offset, remaining, sources[i].cap);
            if committed > 0 {
                total_committed += committed;
                cur_offset += committed;
                remaining -= committed;
                *(&raw mut UT_HINT) = i;
            }
            if err != 0 && committed == 0 {
                if err as u64 == TRONA_OUT_OF_MEMORY {
                    deactivate_ut_source(i);
                }
                continue;
            }
            if remaining == 0 {
                return (0, total_committed);
            }
        }

        // Second pass: wrap around (0..start)
        for i in 0..start {
            if remaining == 0 {
                break;
            }
            if !sources[i].active {
                continue;
            }
            let (err, committed) = invoke::mo_commit(mo_cap, cur_offset, remaining, sources[i].cap);
            if committed > 0 {
                total_committed += committed;
                cur_offset += committed;
                remaining -= committed;
                *(&raw mut UT_HINT) = i;
            }
            if err != 0 && committed == 0 {
                if err as u64 == TRONA_OUT_OF_MEMORY {
                    deactivate_ut_source(i);
                }
                continue;
            }
            if remaining == 0 {
                return (0, total_committed);
            }
        }

        if remaining == 0 {
            return (0, total_committed);
        }

        // Final fallback: PMM (ut_cap=0)
        let (err, committed) = invoke::mo_commit(mo_cap, cur_offset, remaining, 0);
        total_committed += committed;
        remaining -= committed;

        if remaining == 0 {
            (0, total_committed)
        } else {
            (err, total_committed)
        }
    }
}

// ---------------------------------------------------------------------------
// Client tracking (growable, pointer-based)
// ---------------------------------------------------------------------------

static mut CLIENTS_PTR: *mut MmClient = core::ptr::null_mut();
static mut CLIENTS_CAP: usize = 0;
static mut CLIENT_COUNT: usize = 0;

/// Receive slot tracking: NEXT_RECV_SLOT is the bump allocator pointer,
/// CURRENT_RECV_SLOT is the slot configured for the current recv operation,
/// RECV_SLOT_KEPT indicates if the handler permanently kept the cap.
static mut NEXT_RECV_SLOT: Cap = RECV_SLOT_BASE;
static mut CURRENT_RECV_SLOT: Cap = 0;
static mut RECV_SLOT_KEPT: bool = false;

/// Deferred cap cleanup: slots to delete at the start of the next server loop
/// iteration (after reply_recv has completed the cap transfer to the client).
static mut PENDING_CLEANUP_SLOTS: [u64; 4] = [0; 4];
static mut PENDING_CLEANUP_COUNT: usize = 0;

// ---------------------------------------------------------------------------
// CNode slot recycling
// ---------------------------------------------------------------------------

/// Free-slot stack: dynamically allocated based on system memory.
static mut FREE_SLOTS_PTR: *mut u32 = core::ptr::null_mut();
static mut FREE_SLOTS_CAP: usize = 0;
static mut FREE_SLOT_COUNT: usize = 0;

// ---------------------------------------------------------------------------
// Frame cap recycling pool
// ---------------------------------------------------------------------------

/// Frame pool: dynamically allocated based on system memory.
static mut FRAME_POOL_PTR: *mut u64 = core::ptr::null_mut();
static mut FRAME_POOL_CAP: usize = 0;
static mut FRAME_POOL_COUNT: usize = 0;

/// Zeroing window: used by frame_pool_push for zeroing before pool push.
/// Located just below SELF_MMAP_BASE to avoid VA conflicts.
const ZERO_WINDOW_BASE: u64 = 0x1FFF_8000;

/// Statistics: total frames recycled into pool and reused from pool.
static mut FRAME_POOL_TOTAL_RECYCLED: u64 = 0;
static mut FRAME_POOL_TOTAL_REUSED: u64 = 0;

/// Initialize dynamically-sized FREE_SLOTS and FRAME_POOL arrays.
/// Size is based on total_usable_bytes from the bootinfo page (mapped at
/// 0x1FF000 by init). Formula: total_mb * 64, clamped to [4096, 131072].
///
/// # Safety
///
/// Must be called after self_mmap is functional (slot allocator initialized,
/// untyped pool available).
unsafe fn init_dynamic_pools() {
    unsafe {
        // SAFETY: bootinfo page is mapped at 0x1FF000 by init; offset 56
        // contains total_usable_bytes (u64).
        let bootinfo_ptr = 0x1FF000u64 as *const u8;
        let total_usable = (bootinfo_ptr.add(56) as *const u64).read();
        let total_mb = (total_usable / (1024 * 1024)) as usize;

        let cap = if total_mb * 64 < 4096 {
            4096
        } else if total_mb * 64 > 131072 {
            131072
        } else {
            total_mb * 64
        };

        // Allocate FREE_SLOTS array (cap * 4 bytes)
        let slot_bytes = cap * core::mem::size_of::<u32>();
        let slot_pages = (slot_bytes + 4095) / 4096;
        let slot_ptr = self_mmap(slot_pages);
        if !slot_ptr.is_null() {
            *(&raw mut FREE_SLOTS_PTR) = slot_ptr as *mut u32;
            *(&raw mut FREE_SLOTS_CAP) = cap;
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[MMSRV] WARN: FREE_SLOTS alloc failed, using fallback\n");
            });
        }

        // Allocate FRAME_POOL array (cap * 8 bytes)
        let pool_bytes = cap * core::mem::size_of::<u64>();
        let pool_pages = (pool_bytes + 4095) / 4096;
        let pool_ptr = self_mmap(pool_pages);
        if !pool_ptr.is_null() {
            *(&raw mut FRAME_POOL_PTR) = pool_ptr as *mut u64;
            *(&raw mut FRAME_POOL_CAP) = cap;
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[MMSRV] WARN: FRAME_POOL alloc failed, using fallback\n");
            });
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[MMSRV] dynamic pools: cap=");
            _lb.hex(cap as u64);
            _lb.str(b" (");
            _lb.hex(total_mb as u64);
            _lb.str(b" MB RAM)\n");
        });
    }
}

// ---------------------------------------------------------------------------
// SHM object tracking (growable, pointer-based)
// ---------------------------------------------------------------------------

static mut SHM_PTR: *mut ShmObject = core::ptr::null_mut();
static mut SHM_CAP: usize = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// Lazy procmgr EP acquisition (for sub-untyped provisioning)
// ---------------------------------------------------------------------------

/// Cached VFS endpoint cap (resolved lazily via namesrv lookup).
static mut VFS_EP: Cap = 0;

/// Look up the VFS endpoint via namesrv and cache it.
/// Returns the cap slot, or 0 on failure.
pub(crate) unsafe fn resolve_vfs_ep() -> Cap {
    unsafe {
        let cached = *(&raw const VFS_EP);
        if cached != 0 {
            return cached;
        }

        let ep_slot = match recycled_slot_alloc() {
            Some(s) => s,
            None => return 0,
        };

        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, ep_slot, 0);

        let name = b"vfs";
        let mut msg = TronaMsg::zeroed();
        msg.label = NS_LOOKUP;
        msg.regs[0] = name.len() as u64;
        msg.length = 1 + (name.len() as u64 + 7) / 8;
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            core::ptr::write(dst.add(i), name[i]);
        }

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            recycle_empty_slot(ep_slot);
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] vfs lookup via namesrv failed\n");
            });
            return 0;
        }

        *(&raw mut VFS_EP) = ep_slot;
        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] Resolved vfs EP via namesrv\n");
        });
        ep_slot
    }
}

/// Register a sub-untyped provisioned by procmgr via MM_PROVISION_UNTYPED.
/// Returns true on success.
unsafe fn register_provisioned_untyped(cap: Cap) -> bool {
    unsafe {
        let count = *(&raw const UT_COUNT);
        if count >= MAX_UT_SOURCES {
            return false;
        }
        let sources_ptr = &raw mut UT_SOURCES;
        (*sources_ptr)[count] = UntypedSource {
            cap,
            active: true,
        };
        *(&raw mut UT_COUNT) = count + 1;
        *(&raw mut UT_HINT) = count;
        trona::uinfo!(|_lb| {
            _lb.str(b"[MMSRV] provisioned untyped slot=");
            _lb.hex(cap);
            _lb.str(b" total=");
            _lb.dec((count + 1) as u64);
            _lb.str(b"\n");
        });
        true
    }
}

unsafe fn deactivate_ut_source(index: usize) {
    unsafe {
        let count = *(&raw const UT_COUNT);
        if index >= count {
            return;
        }
        let sources_ptr = &raw mut UT_SOURCES;
        if !(*sources_ptr)[index].active {
            return;
        }
        (*sources_ptr)[index].active = false;
        trona::uwarn!(|_lb| {
            _lb.str(b"[MMSRV] deactivating exhausted UT source idx=");
            _lb.dec(index as u64);
            _lb.str(b" cap=");
            _lb.hex((*sources_ptr)[index].cap);
            _lb.str(b"\n");
        });
    }
}

/// Estimate remaining retype capacity (number of active UT sources).
unsafe fn estimate_capacity() -> u64 {
    unsafe {
        let count = *(&raw const UT_COUNT);
        let sources = &*(&raw const UT_SOURCES);
        let mut active = 0u64;
        for i in 0..count {
            if sources[i].active {
                active += 1;
            }
        }
        active
    }
}

/// Retype an object from any available untyped source (round-robin scan).
unsafe fn retype_any(obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
    unsafe {
        let ut_count = *(&raw const UT_COUNT);
        if ut_count == 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }

        let start = {
            let h = *(&raw const UT_HINT);
            if h < ut_count { h } else { 0 }
        };

        let sources = &*(&raw const UT_SOURCES);

        // First pass: from hint to end
        for i in start..ut_count {
            if !sources[i].active {
                continue;
            }
            let err = invoke::untyped_retype(sources[i].cap, obj_type, size_bits, dest_slot);
            if err == 0 {
                *(&raw mut UT_HINT) = i;
                return 0;
            }
            if err as u64 == TRONA_OUT_OF_MEMORY {
                deactivate_ut_source(i);
            }
        }

        // Second pass: wrap around
        for i in 0..start {
            if !sources[i].active {
                continue;
            }
            let err = invoke::untyped_retype(sources[i].cap, obj_type, size_bits, dest_slot);
            if err == 0 {
                *(&raw mut UT_HINT) = i;
                return 0;
            }
            if err as u64 == TRONA_OUT_OF_MEMORY {
                deactivate_ut_source(i);
            }
        }

        // All sources exhausted — log per-source diagnostics
        trona::uerror!(|_lb| {
            _lb.str(b"[MMSRV] retype_any: all ");
            _lb.hex(ut_count as u64);
            _lb.str(b" sources failed, type=");
            _lb.hex(obj_type);
            _lb.str(b"\n");
        });
        for i in 0..ut_count {
            if !sources[i].active {
                continue;
            }
            let err = invoke::untyped_retype(sources[i].cap, obj_type, size_bits, dest_slot);
            trona::uerror!(|_lb| {
                _lb.str(b"  src[");
                _lb.hex(i as u64);
                _lb.str(b"] cap=");
                _lb.hex(sources[i].cap);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            if err == 0 {
                *(&raw mut UT_HINT) = i;
                return 0;
            }
            if err as u64 == TRONA_OUT_OF_MEMORY {
                deactivate_ut_source(i);
            }
        }

        TRONA_OUT_OF_MEMORY as i32
    }
}

/// Initialize the untyped source pool from well-known cap slots.
unsafe fn init_untyped_pool() {
    unsafe {
        let sources = &raw mut UT_SOURCES;
        let mut count: usize = 0;

        // Primary child untyped at slot 7
        (*sources)[count] = UntypedSource {
            cap: CAP_UNTYPED,
            active: true,
        };
        count += 1;

        // Mirrored parent untyped caps at slots 16+
        for slot in CAP_UNTYPED_START..CAP_UNTYPED_START + 16 {
            if count >= MAX_UT_SOURCES {
                break;
            }
            // Probe: try to retype a frame. If it succeeds, this untyped exists.
            // We don't actually want the frame, so just record the source.
            // Simpler: just add it and let retype_any skip on failure.
            (*sources)[count] = UntypedSource {
                cap: slot,
                active: true,
            };
            count += 1;
        }

        *(&raw mut UT_COUNT) = count;
        *(&raw mut UT_HINT) = 0;

        trona::uinfo!(|_lb| {
            _lb.str(b"[MMSRV] untyped pool: ");
            _lb.hex(count as u64);
            _lb.str(b" sources\n");
        });
    }
}

// ---------------------------------------------------------------------------
// Nameserv registration
// ---------------------------------------------------------------------------

unsafe fn register_with_namesrv() -> bool {
    unsafe {
        let name = b"mmsrv";
        let mut msg = TronaMsg::zeroed();
        msg.label = NS_REGISTER;
        msg.length = 1 + ((name.len() + 7) / 8) as u64;
        msg.regs[0] = name.len() as u64;
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            core::ptr::write(dst.add(i), name[i]);
        }

        // Send our server EP cap
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] namesrv register failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return false;
        }
        true
    }
}

/// Allocate a receive slot for the next incoming cap transfer.
/// Returns 0 if the pool is exhausted.
unsafe fn alloc_recv_slot() -> Cap {
    unsafe {
        let slot = *(&raw const NEXT_RECV_SLOT);
        if slot >= RECV_SLOT_END {
            return 0;
        }
        *(&raw mut NEXT_RECV_SLOT) = slot + 1;
        slot
    }
}

/// Mark that the current receive slot was permanently kept by a handler.
unsafe fn mark_recv_slot_kept() {
    unsafe {
        *(&raw mut RECV_SLOT_KEPT) = true;
    }
}

/// Allocate a CNode slot, preferring recycled slots over the bump allocator.
/// Never performs blocking IPC to procmgr — returns None instead of expanding
/// the CSpace, preventing the procmgr→mmsrv→procmgr deadlock on slot exhaustion.
pub(crate) fn recycled_slot_alloc() -> Option<u64> {
    // SAFETY: mmsrv is single-threaded; no concurrent access to FREE_SLOTS.
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        if count > 0 {
            let ptr = *(&raw const FREE_SLOTS_PTR);
            if !ptr.is_null() {
                let idx = count - 1;
                // SAFETY: idx < count <= FREE_SLOTS_CAP, ptr is valid.
                let slot = *ptr.add(idx);
                *(&raw mut FREE_SLOT_COUNT) = idx;
                return Some(slot as u64);
            }
        }
    }
    trona::slot_alloc::slot_alloc()
}

/// Delete a capability and return its CNode slot to the free pool for reuse.
/// Only recycles the slot if cnode_delete succeeds — prevents recycling
/// slots the kernel still considers occupied.
pub(crate) fn recycled_cnode_delete(slot: u64) {
    let err = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
    if err != 0 {
        return; // Slot still occupied in kernel; don't add to free pool
    }
    // SAFETY: mmsrv is single-threaded; no concurrent access to FREE_SLOTS.
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        let cap = *(&raw const FREE_SLOTS_CAP);
        let ptr = *(&raw const FREE_SLOTS_PTR);
        if count < cap && !ptr.is_null() {
            // SAFETY: count < cap, ptr is a valid allocation of cap entries.
            *ptr.add(count) = slot as u32;
            *(&raw mut FREE_SLOT_COUNT) = count + 1;
        }
        // If pool is full or not initialized, slot is permanently leaked (bounded degradation)
    }
}

/// Return an unused (empty) CNode slot to the free pool without calling
/// cnode_delete. Used when retype fails and the slot was never populated.
fn recycle_empty_slot(slot: u64) {
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        let cap = *(&raw const FREE_SLOTS_CAP);
        let ptr = *(&raw const FREE_SLOTS_PTR);
        if count < cap && !ptr.is_null() {
            // SAFETY: count < cap, ptr is a valid allocation of cap entries.
            *ptr.add(count) = slot as u32;
            *(&raw mut FREE_SLOT_COUNT) = count + 1;
        }
    }
}

/// Push a frame cap into the recycling pool after zeroing it.
/// Falls back to recycled_cnode_delete if pool is full or zeroing fails.
pub(crate) fn frame_pool_push(frame_cap: Cap) {
    unsafe {
        let count = *(&raw const FRAME_POOL_COUNT);
        let cap = *(&raw const FRAME_POOL_CAP);
        let ptr = *(&raw const FRAME_POOL_PTR);
        if count >= cap || ptr.is_null() {
            recycled_cnode_delete(frame_cap);
            return;
        }
        let va = ZERO_WINDOW_BASE;
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE, frame_cap, va,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            recycled_cnode_delete(frame_cap);
            return;
        }
        core::ptr::write_bytes(va as *mut u8, 0, 4096);
        invoke::vspace_unmap(CAP_SELF_VSPACE, va);
        // SAFETY: count < cap, ptr is a valid allocation of cap entries.
        *ptr.add(count) = frame_cap;
        *(&raw mut FRAME_POOL_COUNT) = count + 1;
        *(&raw mut FRAME_POOL_TOTAL_RECYCLED) += 1;
    }
}

/// Pop a pre-zeroed frame cap from the recycling pool.
pub(crate) fn frame_pool_pop() -> Option<Cap> {
    unsafe {
        let count = *(&raw const FRAME_POOL_COUNT);
        if count == 0 {
            return None;
        }
        let ptr = *(&raw const FRAME_POOL_PTR);
        if ptr.is_null() {
            return None;
        }
        let idx = count - 1;
        // SAFETY: idx < count <= FRAME_POOL_CAP, ptr is valid.
        let cap = *ptr.add(idx);
        *(&raw mut FRAME_POOL_COUNT) = idx;
        *(&raw mut FRAME_POOL_TOTAL_REUSED) += 1;
        Some(cap)
    }
}

/// Allocate a frame cap: tries the recycled frame pool first, then falls
/// back to slot_alloc + retype_any. Returns the CNode slot holding a valid
/// frame cap, or None on OOM.
pub(crate) fn alloc_frame() -> Option<Cap> {
    // Tier 1: recycled frame (already zeroed)
    if let Some(cap) = frame_pool_pop() {
        return Some(cap);
    }
    // Tier 2: fresh retype
    let slot = recycled_slot_alloc()?;
    // SAFETY: retype_any accesses static state; mmsrv is single-threaded.
    if unsafe { retype_any(OBJ_FRAME, 0, slot) } != 0 {
        recycle_empty_slot(slot);
        return None;
    }
    Some(slot)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] SaltyOS memory server starting\n");
    });

    // Set up IPC buffer
    let err = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[MMSRV] FAIL: set IPC buffer err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        idle();
    }
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    trona::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] IPC buffer ready\n");
    });

    // Initialize per-process slot allocator from RTLD-exported globals.
    // self_mmap() depends on slot_alloc for temporary frame-cap slots.
    unsafe {
        let base = *(&raw const trona::__trona_slot_base);
        let count = *(&raw const trona::__trona_slot_count);
        let cspace_ntfn = *(&raw const trona::__trona_cspace_ntfn);
        // Clamp count so the bump allocator cannot reach the receive-slot pool.
        let max_count = RECV_SLOT_BASE.saturating_sub(base);
        let count = if count > max_count { max_count } else { count };
        if base != 0 {
            trona::slot_alloc::slot_alloc_init(base, count, cspace_ntfn);
        } else {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: slot pool not provided by RTLD/auxv\n");
            });
            idle();
        }
    }

    // Initialize untyped pool
    unsafe {
        init_untyped_pool();
    }

    // Initialize dynamically-sized free-slot and frame pools
    unsafe {
        init_dynamic_pools();
    }

    // Initialize growable client table
    unsafe {
        let ptr = self_mmap(1);
        if ptr.is_null() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: client table alloc failed\n");
            });
            idle();
        }
        *(&raw mut CLIENTS_PTR) = ptr as *mut MmClient;
        *(&raw mut CLIENTS_CAP) = 4096 / core::mem::size_of::<MmClient>();
    }

    // Initialize growable SHM table
    unsafe {
        let ptr = self_mmap(1);
        if ptr.is_null() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: SHM table alloc failed\n");
            });
            idle();
        }
        *(&raw mut SHM_PTR) = ptr as *mut ShmObject;
        *(&raw mut SHM_CAP) = 4096 / core::mem::size_of::<ShmObject>();
    }

    // Set up initial receive slot for cap transfers
    unsafe {
        let slot = alloc_recv_slot();
        if slot == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: no receive slots\n");
            });
            idle();
        }
        *(&raw mut CURRENT_RECV_SLOT) = slot;
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);
    }

    // Register with namesrv
    if !unsafe { register_with_namesrv() } {
        trona::uerror!(|_lb| {
            _lb.str(b"[MMSRV] FATAL: namesrv registration failed\n");
        });
        idle();
    }
    trona::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] registered with namesrv\n");
    });

    // Signal readiness to init
    signal_ready();
    trona::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] ready\n");
    });

    // Initial recv
    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[MMSRV] initial recv failed\n");
        });
        idle();
    }

    // Server loop
    loop {
        let mut reply = TronaMsg::zeroed();
        // Set to true for unrecoverable faults: use recv() instead of reply_recv()
        // so the faulting thread stays permanently blocked rather than re-faulting.
        let mut skip_reply = false;

        // Drain deferred slot cleanup from previous iteration
        unsafe {
            let count = *(&raw const PENDING_CLEANUP_COUNT);
            for i in 0..count {
                let slot = (*(&raw const PENDING_CLEANUP_SLOTS))[i];
                if slot != 0 {
                    recycled_cnode_delete(slot);
                }
            }
            *(&raw mut PENDING_CLEANUP_COUNT) = 0;
        }

        unsafe {
            match msg.label {
                MM_REGISTER => client::handle_mm_register(&raw const msg, badge, &raw mut reply),
                MM_DEREGISTER => client::handle_mm_deregister(&raw const msg, badge, &raw mut reply),
                MM_BRK => mmap::handle_mm_brk(&raw const msg, badge, &raw mut reply),
                MM_SBRK => mmap::handle_mm_sbrk(&raw const msg, badge, &raw mut reply),
                MM_MMAP => mmap::handle_mm_mmap(&raw const msg, badge, &raw mut reply),
                MM_MUNMAP => mmap::handle_mm_munmap(&raw const msg, badge, &raw mut reply),
                MM_MPROTECT => mmap::handle_mm_mprotect(&raw const msg, badge, &raw mut reply),
                MM_MAP_BATCH => mmap::handle_mm_map_batch(&raw const msg, badge, &raw mut reply),
                MM_MAP_WINDOW => mmap::handle_mm_map_window(&raw const msg, badge, &raw mut reply),
                MM_UNMAP_WINDOW => mmap::handle_mm_unmap_window(&raw const msg, badge, &raw mut reply),
                MM_FORK_REGIONS => mmap::handle_mm_fork_regions(&raw const msg, badge, &raw mut reply),
                MM_ALLOC_THREAD_OBJECTS => mmap::handle_mm_alloc_thread_objects(&raw const msg, badge, &raw mut reply),
                MM_SHM_CREATE => shm::handle_mm_shm_create(&raw const msg, badge, &raw mut reply),
                MM_SHM_MAP => shm::handle_mm_shm_map(&raw const msg, badge, &raw mut reply),
                MM_SHM_UNMAP => shm::handle_mm_shm_unmap(&raw const msg, badge, &raw mut reply),
                MM_GET_CLIENT_STATS => client::handle_mm_get_client_stats(&raw const msg, badge, &raw mut reply),
                MM_ALLOC_OBJECT => mmap::handle_mm_alloc_object(&raw const msg, badge, &raw mut reply),
                MM_REGISTER_SHARED_REGION => mmap::handle_mm_register_shared_region(&raw const msg, badge, &raw mut reply),
                MM_MAP_OBJECT_REGION => mmap::handle_mm_map_object_region(&raw const msg, badge, &raw mut reply),
                MM_SYNC_FILE_BACKING => mmap::handle_mm_sync_file_backing(&raw const msg, badge, &raw mut reply),
                MM_FILE_MMAP => mmap::handle_mm_file_mmap(&raw const msg, badge, &raw mut reply),
                MM_SYNC_MMAP_WRITE => mmap::handle_mm_sync_mmap_write(&raw const msg, badge, &raw mut reply),
                MM_PROVISION_UNTYPED => {
                    // Procmgr pushes a sub-untyped to replenish our pool.
                    // The cap arrives via IPC cap transfer at CURRENT_RECV_SLOT.
                    let recv_slot = *(&raw const CURRENT_RECV_SLOT);
                    if register_provisioned_untyped(recv_slot) {
                        mark_recv_slot_kept();
                        reply.label = TRONA_OK;
                    } else {
                        reply.label = TRONA_OUT_OF_MEMORY;
                    }
                }
                MM_QUERY_CAPACITY => {
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = estimate_capacity();
                }
                MM_ALLOC_PRIVATE_REGION => mmap::handle_mm_alloc_private_region(&raw const msg, badge, &raw mut reply),
                MM_ALLOC_PRIVATE_WINDOW => mmap::handle_mm_alloc_private_window(&raw const msg, badge, &raw mut reply),
                MM_ALLOC_INITRD_COPY => mmap::handle_mm_alloc_initrd_copy(&raw const msg, badge, &raw mut reply),
                MM_ALLOC_BOOTINFO_COPY => mmap::handle_mm_alloc_bootinfo_copy(&raw const msg, badge, &raw mut reply),
                MM_COPY_FROM_CLIENT_REGION => mmap::handle_mm_copy_from_client_region(&raw const msg, badge, &raw mut reply),
                MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION => mmap::handle_mm_alloc_private_copy_from_client_region(&raw const msg, badge, &raw mut reply),
                MM_REGISTER_PAGER_EP => {
                    // VFS registers a dedicated callback endpoint for pager requests.
                    // The EP cap arrives via IPC cap transfer at CURRENT_RECV_SLOT.
                    let recv_slot = *(&raw const CURRENT_RECV_SLOT);
                    *(&raw mut VFS_PAGER_CALLBACK_EP) = recv_slot;
                    mark_recv_slot_kept();
                    trona::uinfo!(|_lb| {
                        _lb.str(b"[MMSRV] VFS pager callback EP registered slot=");
                        _lb.hex(recv_slot);
                        _lb.str(b"\n");
                    });
                    reply.label = TRONA_OK;
                }
                MM_DUMP_PENDING => {
                    // Debug: dump UT source pool to serial
                    let count = *(&raw const UT_COUNT);
                    trona::uinfo!(|_lb| {
                        _lb.str(b"[MMSRV] UT sources: ");
                        _lb.dec(count as u64);
                        _lb.str(b"/");
                        _lb.dec(MAX_UT_SOURCES as u64);
                        _lb.str(b"\n");
                    });
                    let sources = &*(&raw const UT_SOURCES);
                    for i in 0..count {
                        if sources[i].active {
                            trona::uinfo!(|_lb| {
                                _lb.str(b"  src[");
                                _lb.dec(i as u64);
                                _lb.str(b"] cap=");
                                _lb.hex(sources[i].cap);
                                _lb.str(b" active\n");
                            });
                        }
                    }
                    reply.label = TRONA_OK;
                }
                // VMFault: label=2 from kernel FaultType::VMFault.
                // Badge identifies the faulting client. Replying resumes the faulting thread.
                //
                // All error paths break out of 'fault without using `continue` so that
                // reply_recv_ctx (or recv for unrecoverable faults) is always reached.
                2 => {
                    let fault_addr = msg.regs[0];
                    let error_code = msg.regs[1];
                    let fault_rip = msg.regs[2];
                    let is_instruction_fault = msg.regs[3] != 0;
                    let page_addr = fault_addr & !0xFFFu64;


                    'fault: {
                        // 1. Find client by badge
                        let client_ptr = client::find_client_by_badge(badge);
                        if client_ptr.is_null() {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[MMSRV] VMFault: unknown client badge=");
                                _lb.hex(badge);
                                _lb.str(b"\n");
                            });
                            reply.label = TRONA_INVALID_OPERATION;
                            break 'fault;
                        }

                        // 2. Find region containing fault_addr
                        let region = client::find_region_by_addr(client_ptr, page_addr);
                        if region.is_null() {
                            // No region covers this address — segfault.
                            // Don't reply: leave the faulting thread permanently
                            // FaultBlocked instead of re-faulting in a tight loop.
                            let rc = (*client_ptr).region_count;
                            trona::uerror!(|_lb| {
                                _lb.str(b"[MMSRV] Segfault: badge=");
                                _lb.hex(badge);
                                _lb.str(b" addr=");
                                _lb.hex(fault_addr);
                                _lb.str(b" (no region) rip=");
                                _lb.hex(fault_rip);
                                _lb.str(b" regions=");
                                _lb.hex(rc as u64);
                                if rc > 0 {
                                    let regs = (*client_ptr).regions;
                                    let r0 = &*regs.add(0);
                                    _lb.str(b" r0=[");
                                    _lb.hex(r0.base);
                                    _lb.str(b",");
                                    _lb.hex(r0.base + r0.length);
                                    _lb.str(b")");
                                    let rl = &*regs.add(rc - 1);
                                    _lb.str(b" rN=[");
                                    _lb.hex(rl.base);
                                    _lb.str(b",");
                                    _lb.hex(rl.base + rl.length);
                                    _lb.str(b")");
                                }
                                _lb.str(b" err=");
                                _lb.hex(error_code);
                                _lb.str(b"\n");
                            });
                            // Dump all regions for debugging
                            if rc > 0 && rc <= 80 {
                                let regs = (*client_ptr).regions;
                                for ri in 0..rc {
                                    let rd = &*regs.add(ri);
                                    if rd.active {
                                        trona::uerror!(|_lb| {
                                            _lb.str(b"  r");
                                            _lb.hex(ri as u64);
                                            _lb.str(b"=[");
                                            _lb.hex(rd.base);
                                            _lb.str(b",");
                                            _lb.hex(rd.base + rd.length);
                                            _lb.str(b") t=");
                                            _lb.hex(rd.region_type as u64);
                                            _lb.str(b"\n");
                                        });
                                    }
                                }
                            }
                            skip_reply = true;
                            break 'fault;
                        }

                        // 3. Protection fault on a present page.
                        // These are not demand faults. They indicate an access
                        // to an already-mapped page with insufficient rights.
                        // VMFault IPC error bits are arch-neutral:
                        // [0]=present [1]=write [2]=user, while instruction
                        // faults are reported separately in MR3.
                        if (error_code & 0x1) != 0 {
                            let write_fault = (error_code & 0x2) != 0;
                            trona::uerror!(|_lb| {
                                _lb.str(b"[MMSRV] protection fault: badge=");
                                _lb.hex(badge);
                                _lb.str(b" kind=");
                                if is_instruction_fault {
                                    _lb.str(b"exec");
                                } else if write_fault {
                                    _lb.str(b"write");
                                } else {
                                    _lb.str(b"read");
                                }
                                _lb.str(b" addr=");
                                _lb.hex(fault_addr);
                                _lb.str(b" rip=");
                                _lb.hex(fault_rip);
                                _lb.str(b" err=");
                                _lb.hex(error_code);
                                _lb.str(b" region=[");
                                _lb.hex((*region).base);
                                _lb.str(b",");
                                _lb.hex((*region).base + (*region).length);
                                _lb.str(b") prot=");
                                _lb.hex((*region).prot as u64);
                                _lb.str(b" type=");
                                _lb.hex((*region).region_type as u64);
                                _lb.str(b" mo=");
                                _lb.hex((*region).mo_cap);
                                _lb.str(b" mo_off=");
                                _lb.hex((*region).mo_offset as u64);
                                _lb.str(b"\n");
                            });
                            let rc = (*client_ptr).region_count;
                            if rc > 0 && rc <= 80 {
                                let regs = (*client_ptr).regions;
                                for ri in 0..rc {
                                    let rd = &*regs.add(ri);
                                    if rd.active {
                                        trona::uerror!(|_lb| {
                                            _lb.str(b"  r");
                                            _lb.hex(ri as u64);
                                            _lb.str(b"=[");
                                            _lb.hex(rd.base);
                                            _lb.str(b",");
                                            _lb.hex(rd.base + rd.length);
                                            _lb.str(b") prot=");
                                            _lb.hex(rd.prot as u64);
                                            _lb.str(b" t=");
                                            _lb.hex(rd.region_type as u64);
                                            _lb.str(b" mo=");
                                            _lb.hex(rd.mo_cap);
                                            _lb.str(b" mo_off=");
                                            _lb.hex(rd.mo_offset as u64);
                                            _lb.str(b"\n");
                                        });
                                    }
                                }
                            }
                            skip_reply = true;
                            break 'fault;
                        }

                        // 4. Demand-page path: all regions are MO-backed.
                        // Commit the page via mo_commit, then map into VSpace.
                        if (*region).mo_cap == 0 {
                            // No MO — region is corrupted or legacy. Segfault.
                            trona::uerror!(|_lb| {
                                _lb.str(b"[MMSRV] VMFault: region has no MO badge=");
                                _lb.hex(badge);
                                _lb.str(b" addr=");
                                _lb.hex(fault_addr);
                                _lb.str(b"\n");
                            });
                            skip_reply = true;
                            break 'fault;
                        }

                        let page_offset = page_addr - (*region).base;
                        let mo_page_idx = (*region).mo_offset as u64 + page_offset / 4096;
                        let flags = prot_to_vspace_flags((*region).prot);

                        if (*region).backing_kind != MMAP_BACKING_NONE as u8 {
                            let pager_err = mmap::pagein_backing_page(region, page_addr);
                            if pager_err != TRONA_OK as i32 {
                                trona::uerror!(|_lb| {
                                    _lb.str(b"[MMSRV] VMFault: backing page-in failed badge=");
                                    _lb.hex(badge);
                                    _lb.str(b" addr=");
                                    _lb.hex(fault_addr);
                                    _lb.str(b" kind=");
                                    _lb.hex((*region).backing_kind as u64);
                                    _lb.str(b"\n");
                                });
                                reply.label = pager_err as u64;
                                break 'fault;
                            }
                        } else {
                            let (err, committed) = commit_mo_pages(
                                (*region).mo_cap,
                                mo_page_idx,
                                1,
                            );
                            if err != 0 || committed != 1 {
                                trona::uerror!(|_lb| {
                                    _lb.str(b"[MMSRV] VMFault: mo_commit failed badge=");
                                    _lb.hex(badge);
                                    _lb.str(b" addr=");
                                    _lb.hex(fault_addr);
                                    _lb.str(b" err=");
                                    _lb.hex(err as u64);
                                    _lb.str(b"\n");
                                });
                                reply.label = TRONA_OUT_OF_MEMORY;
                                break 'fault;
                            }
                        }

                        // Map committed page into client's VSpace
                        let count_and_flags = (1u64 << 32) | flags;
                        let _ = invoke::vspace_map_mo(
                            (*client_ptr).vspace_cap,
                            (*region).mo_cap,
                            page_addr,
                            mo_page_idx,
                            count_and_flags,
                        );
                        // AlreadyMapped is OK (page was already present
                        // from the spawn-time vspace_map_mo).

                        reply.label = TRONA_OK;
                    } // end 'fault
                }
                _ => {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[MMSRV] unknown label=");
                        _lb.hex(msg.label);
                        _lb.str(b" badge=");
                        _lb.hex(badge);
                        if msg.label == 4 {
                            _lb.str(b" vec=");
                            _lb.hex(msg.regs[0]);
                            _lb.str(b" err=");
                            _lb.hex(msg.regs[1]);
                            _lb.str(b" rip=");
                            _lb.hex(msg.regs[2]);
                            _lb.str(b" rsp=");
                            _lb.hex(msg.regs[3]);
                        } else if msg.label == 2 {
                            _lb.str(b" fault_addr=");
                            _lb.hex(msg.regs[0]);
                            _lb.str(b" err=");
                            _lb.hex(msg.regs[1]);
                            _lb.str(b" rip=");
                            _lb.hex(msg.regs[2]);
                        }
                        _lb.str(b"\n");
                    });
                    // Fault labels (CapFault=1, UnknownSyscall=3, UserException=4)
                    // are unrecoverable — skip reply so the thread stays FaultBlocked
                    // instead of resuming and re-faulting in a tight loop.
                    // Regular IPC labels (MM_* = 0x80+) get an error reply.
                    if msg.label <= 4 {
                        skip_reply = true;
                    } else {
                        reply.label = TRONA_INVALID_OPERATION;
                    }
                }
            }
        }

        // Recycle or advance receive slot
        unsafe {
            if *(&raw const RECV_SLOT_KEPT) {
                // Handler permanently kept the cap — allocate fresh slot
                let slot = alloc_recv_slot();
                if slot != 0 {
                    *(&raw mut CURRENT_RECV_SLOT) = slot;
                }
                *(&raw mut RECV_SLOT_KEPT) = false;
            } else {
                // No cap kept — clear any stale cap and reuse same slot
                let slot = *(&raw const CURRENT_RECV_SLOT);
                invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            }
            let slot = *(&raw const CURRENT_RECV_SLOT);
            ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);
        }

        if skip_reply {
            // Unrecoverable fault (e.g. no region): leave faulting thread permanently
            // FaultBlocked and wait for the next incoming message without replying.
            let err = unsafe {
                ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            };
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[MMSRV] recv failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                break;
            }
        } else {
            let err = unsafe {
                ipc::reply_recv_ctx(
                    ipc_ctx(),
                    CAP_SERVER_EP,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                )
            };
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[MMSRV] reply_recv failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                break;
            }
        }
    }

    idle()
}

fn idle() -> ! {
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
