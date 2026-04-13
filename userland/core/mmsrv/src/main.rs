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

mod client;
mod mmap;
mod pool;
mod shm;
mod types;

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

// namesrv endpoint is delivered by init at the slot named in
// `mmsrv.service` NeedEP=namesrv:64. Init also pushes ROLE_NAMESRV_CLIENT
// into mmsrv's startup cap_table (see
// `ini::system_role_for_bare_name`), so the substrate getter returns the
// correct slot regardless of the specific NeedEP assignment.
const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// rsrcsrv / readiness / initrd slots are delivered by init via `AT_TRONA_*`
// auxv tags. The cursor places them at varying positions, so we read them at
// runtime through the substrate `caps::*` getters. The service endpoint
// remains the fixed child slot 3 for init-spawned bootstrap services.
/// VFS pager callback EP: when set (non-zero), mmsrv routes VFS_BACKEND_PAGER_READ /
/// VFS_BACKEND_PAGER_WRITE requests through this EP instead of the VFS service EP.
/// This breaks the VFS↔MMSRV cycle by allowing VFS to receive pager requests
/// on a dedicated callback EP while it's blocked on mmsrv's service EP.
///
/// The cap is transferred by VFS during registration (via a new label) or
/// injected by init. Zero means not registered (use VFS service EP directly).
static mut VFS_PAGER_CALLBACK_EP: Cap = 0;

// ---------------------------------------------------------------------------
// Internal metadata allocation for mmsrv's own data structures.
// Cannot use posix_mmap (would be recursive IPC), so metadata lives in
// private tracked MOs mapped into mmsrv's own VSpace.
// ---------------------------------------------------------------------------

const SELF_MMAP_BASE: u64 = 0x2000_0000;
static mut SELF_MMAP_NEXT: u64 = SELF_MMAP_BASE;

const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;

unsafe fn tracked_alloc_pages(num_pages: usize) -> TrackedBuffer {
    unsafe {
        if num_pages == 0 {
            return TrackedBuffer::zeroed();
        }

        let base = *(&raw const SELF_MMAP_NEXT);
        let (mo_cap, actual_pages) = create_mo(num_pages);
        if mo_cap == 0 || actual_pages < num_pages {
            if mo_cap != 0 {
                recycled_cnode_delete(mo_cap);
            }
            return TrackedBuffer::zeroed();
        }

        let (commit_err, committed) = commit_mo_pages(mo_cap, 0, num_pages as u64);
        if commit_err != 0 || committed != num_pages as u64 {
            recycled_cnode_delete(mo_cap);
            return TrackedBuffer::zeroed();
        }

        let count_and_flags = ((num_pages as u64) << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let (map_err, mapped) =
            invoke::vspace_map_mo_with_count(CAP_SELF_VSPACE, mo_cap, base, 0, count_and_flags);
        if map_err != 0 || mapped != num_pages as u64 {
            for page in 0..mapped {
                let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, base + page * 4096);
            }
            recycled_cnode_delete(mo_cap);
            return TrackedBuffer::zeroed();
        }

        *(&raw mut SELF_MMAP_NEXT) = base + num_pages as u64 * 4096;
        core::ptr::write_bytes(base as *mut u8, 0, num_pages * 4096);
        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] tracked_alloc pages=");
            _lb.hex(num_pages as u64);
            _lb.str(b" base=");
            _lb.hex(base);
            _lb.str(b" mo=");
            _lb.hex(mo_cap);
            _lb.str(b" self_next=");
            _lb.hex(*(&raw const SELF_MMAP_NEXT));
            _lb.str(b"\n");
        });
        TrackedBuffer {
            ptr: base as *mut u8,
            pages: num_pages,
            mo_cap,
        }
    }
}

unsafe fn tracked_free_pages(buf: TrackedBuffer) {
    unsafe {
        if buf.ptr.is_null() || buf.pages == 0 || buf.mo_cap == 0 {
            return;
        }

        for page in 0..buf.pages as u64 {
            let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, buf.ptr as u64 + page * 4096);
        }
        recycled_cnode_delete(buf.mo_cap);
        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] tracked_free pages=");
            _lb.hex(buf.pages as u64);
            _lb.str(b" base=");
            _lb.hex(buf.ptr as u64);
            _lb.str(b" mo=");
            _lb.hex(buf.mo_cap);
            _lb.str(b"\n");
        });
    }
}

/// Allocate a kernel object from rsrcsrv into `dest_slot`. mmsrv is its own
/// owner — `owner_id=0` makes rsrcsrv use mmsrv's caller badge automatically.
unsafe fn rsrcsrv_alloc_object(obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, dest_slot, 0);
        let mut req = TronaMsg::zeroed();
        req.label = RES_ALLOC_OBJECT;
        req.length = 4;
        req.regs[0] = 0;
        req.regs[1] = obj_type;
        req.regs[2] = size_bits;
        req.regs[3] = 0;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::rsrcsrv_ep(),
            &raw const req,
            &raw mut resp,
        );
        if err != 0 {
            return err;
        }
        if resp.label != TRONA_OK {
            return resp.label as i32;
        }
        0
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
        if rsrcsrv_alloc_object(OBJ_MEMORY_OBJECT, sb, slot) != 0 {
            recycle_empty_slot(slot);
            return (0, 0);
        }
        (slot, actual)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Commit `count` pages starting at `offset` in a MemoryObject. mmsrv no
/// longer owns any untyped of its own — every commit goes through the
/// kernel PMM path (`ut_cap=0`). The kernel handles physical-frame
/// allocation directly via the bitmap PMM.
unsafe fn commit_mo_pages(mo_cap: Cap, offset: u64, count: u64) -> (i32, u64) {
    unsafe { invoke::mo_commit(mo_cap, offset, count, 0) }
}

unsafe fn debug_total_region_count() -> usize {
    unsafe {
        let ptr = *(&raw const CLIENTS_PTR);
        let cap = *(&raw const CLIENTS_CAP);
        if ptr.is_null() || cap == 0 {
            return 0;
        }

        let mut total = 0usize;
        for i in 0..cap {
            let client = ptr.add(i);
            if (*client).active {
                total = total.saturating_add((*client).region_count);
            }
        }
        total
    }
}

unsafe fn debug_total_region_buf_pages() -> usize {
    unsafe {
        let ptr = *(&raw const CLIENTS_PTR);
        let cap = *(&raw const CLIENTS_CAP);
        if ptr.is_null() || cap == 0 {
            return 0;
        }

        let mut total = 0usize;
        for i in 0..cap {
            let client = ptr.add(i);
            if (*client).active {
                total = total.saturating_add((*client).regions_buf.pages);
            }
        }
        total
    }
}

pub(crate) unsafe fn debug_log_state(prefix: &[u8], client: *const MmClient) {
    unsafe {
        let total_regions = debug_total_region_count();
        let total_region_pages = debug_total_region_buf_pages();
        trona::udebug!(|_lb| {
            _lb.bytes(prefix);
            _lb.str(b" clients=");
            _lb.hex(*(&raw const CLIENT_COUNT) as u64);
            _lb.str(b" total_regions=");
            _lb.hex(total_regions as u64);
            _lb.str(b" total_region_pages=");
            _lb.hex(total_region_pages as u64);
            _lb.str(b" free_slots=");
            _lb.hex(*(&raw const FREE_SLOT_COUNT) as u64);
            _lb.str(b" frame_pool=");
            _lb.hex(*(&raw const FRAME_POOL_COUNT) as u64);
            _lb.str(b" self_next=");
            _lb.hex(*(&raw const SELF_MMAP_NEXT));
            if !client.is_null() {
                _lb.str(b" badge=");
                _lb.hex((*client).badge);
                _lb.str(b" pid=");
                _lb.hex((*client).pid as u64);
                _lb.str(b" rc=");
                _lb.hex((*client).region_count as u64);
                _lb.str(b" cap=");
                _lb.hex((*client).region_cap as u64);
                _lb.str(b" rpages=");
                _lb.hex((*client).regions_buf.pages as u64);
                _lb.str(b" heap=");
                _lb.hex((*client).heap_current);
                _lb.str(b" mmap=");
                _lb.hex((*client).mmap_next);
            }
            _lb.str(b"\n");
        });
    }
}

// ---------------------------------------------------------------------------
// Client tracking (growable, pointer-based)
// ---------------------------------------------------------------------------

static mut CLIENTS_PTR: *mut MmClient = core::ptr::null_mut();
static mut CLIENTS_CAP: usize = 0;
static mut CLIENT_COUNT: usize = 0;
static mut CLIENTS_BUF: TrackedBuffer = TrackedBuffer::zeroed();

/// Receive slot tracking: NEXT_RECV_SLOT is the bump allocator pointer,
/// CURRENT_RECV_SLOT is the slot configured for the current recv operation,
/// RECV_SLOT_KEPT indicates if the handler permanently kept the cap.
static mut RECV_SLOT_BASE_RUNTIME: Cap = 0;
static mut RECV_SLOT_END_RUNTIME: Cap = 0;
static mut NEXT_RECV_SLOT: Cap = 0;
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
static mut FREE_SLOTS_BUF: TrackedBuffer = TrackedBuffer::zeroed();

// ---------------------------------------------------------------------------
// Frame cap recycling pool
// ---------------------------------------------------------------------------

/// Frame pool: dynamically allocated based on system memory.
static mut FRAME_POOL_PTR: *mut u64 = core::ptr::null_mut();
static mut FRAME_POOL_CAP: usize = 0;
static mut FRAME_POOL_COUNT: usize = 0;
static mut FRAME_POOL_BUF: TrackedBuffer = TrackedBuffer::zeroed();

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
        let slot_buf = tracked_alloc_pages(slot_pages);
        if !slot_buf.ptr.is_null() {
            *(&raw mut FREE_SLOTS_BUF) = slot_buf;
            *(&raw mut FREE_SLOTS_PTR) = slot_buf.ptr as *mut u32;
            *(&raw mut FREE_SLOTS_CAP) = cap;
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[MMSRV] WARN: FREE_SLOTS alloc failed, using fallback\n");
            });
        }

        // Allocate FRAME_POOL array (cap * 8 bytes)
        let pool_bytes = cap * core::mem::size_of::<u64>();
        let pool_pages = (pool_bytes + 4095) / 4096;
        let pool_buf = tracked_alloc_pages(pool_pages);
        if !pool_buf.ptr.is_null() {
            *(&raw mut FRAME_POOL_BUF) = pool_buf;
            *(&raw mut FRAME_POOL_PTR) = pool_buf.ptr as *mut u64;
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
static mut SHM_BUF: TrackedBuffer = TrackedBuffer::zeroed();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, trona::caps::readiness_ntfn(), 1, 0, 0, 0, 0);
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
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::namesrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
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

// Untyped pool, MM_PROVISION_UNTYPED handler, MM_QUERY_CAPACITY estimator,
// retype_any round-robin scan, and init_untyped_pool — all gone. mmsrv now
// asks rsrcsrv for every kernel object via `rsrcsrv_alloc_object`.

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
        ipc::set_send_cap_ctx(ipc_ctx(), 0, 3);

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::namesrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
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
        if slot >= *(&raw const RECV_SLOT_END_RUNTIME) {
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
    trona::slot_alloc::slot_alloc_no_expand()
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
            CAP_SELF_VSPACE,
            frame_cap,
            va,
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

/// Allocate a frame cap: tries the recycled frame pool first, then asks
/// rsrcsrv for a fresh `OBJ_FRAME`. Returns the CNode slot holding a valid
/// frame cap, or None on OOM.
pub(crate) fn alloc_frame() -> Option<Cap> {
    // Tier 1: recycled frame (already zeroed)
    if let Some(cap) = frame_pool_pop() {
        return Some(cap);
    }
    // Tier 2: fresh allocation via rsrcsrv
    let slot = recycled_slot_alloc()?;
    // SAFETY: rsrcsrv_alloc_object touches static IPC state; mmsrv is single-threaded.
    if unsafe { rsrcsrv_alloc_object(OBJ_FRAME, 0, slot) } != 0 {
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

    // Ensure the startup CSpace contract is coherent before continuing.
    unsafe {
        let Some(cspace_layout) = trona::runtime_get_cspace_layout() else {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: missing startup CSpace layout\n");
            });
            idle();
        };

        if !cspace_layout.has_recv_range() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: pager receive-slot range missing from CSpace layout\n");
            });
            idle();
        }

        if !trona::slot_alloc::slot_alloc_is_initialized() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: slot allocator not initialized from CSpace layout\n");
            });
            idle();
        }

        let alloc_base = trona::slot_alloc::slot_alloc_base();
        let alloc_limit = alloc_base.saturating_add(trona::slot_alloc::slot_alloc_count());
        if alloc_base != cspace_layout.alloc_base || alloc_limit != cspace_layout.alloc_limit {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: allocator range does not match startup CSpace layout\n");
            });
            idle();
        }

        *(&raw mut RECV_SLOT_BASE_RUNTIME) = cspace_layout.recv_base;
        *(&raw mut RECV_SLOT_END_RUNTIME) = cspace_layout.recv_limit;
        *(&raw mut NEXT_RECV_SLOT) = cspace_layout.recv_base;
    }

    // Initialize dynamically-sized free-slot and frame pools
    unsafe {
        init_dynamic_pools();
    }

    // Initialize growable client table
    unsafe {
        let buf = tracked_alloc_pages(1);
        if buf.ptr.is_null() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: client table alloc failed\n");
            });
            idle();
        }
        *(&raw mut CLIENTS_BUF) = buf;
        *(&raw mut CLIENTS_PTR) = buf.ptr as *mut MmClient;
        *(&raw mut CLIENTS_CAP) = 4096 / core::mem::size_of::<MmClient>();
    }

    // Initialize growable SHM table
    unsafe {
        let buf = tracked_alloc_pages(1);
        if buf.ptr.is_null() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] FATAL: SHM table alloc failed\n");
            });
            idle();
        }
        *(&raw mut SHM_BUF) = buf;
        *(&raw mut SHM_PTR) = buf.ptr as *mut ShmObject;
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

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), 3, &raw mut msg, &raw mut badge) };
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
                MM_DEREGISTER => {
                    client::handle_mm_deregister(&raw const msg, badge, &raw mut reply)
                }
                MM_BRK => mmap::handle_mm_brk(&raw const msg, badge, &raw mut reply),
                MM_SBRK => mmap::handle_mm_sbrk(&raw const msg, badge, &raw mut reply),
                MM_MMAP => mmap::handle_mm_mmap(&raw const msg, badge, &raw mut reply),
                MM_MUNMAP => mmap::handle_mm_munmap(&raw const msg, badge, &raw mut reply),
                MM_MPROTECT => mmap::handle_mm_mprotect(&raw const msg, badge, &raw mut reply),
                MM_MPROTECT_TARGET => {
                    mmap::handle_mm_mprotect_target(&raw const msg, badge, &raw mut reply)
                }
                MM_MAP_BATCH => mmap::handle_mm_map_batch(&raw const msg, badge, &raw mut reply),
                MM_MAP_WINDOW => mmap::handle_mm_map_window(&raw const msg, badge, &raw mut reply),
                MM_UNMAP_WINDOW => {
                    mmap::handle_mm_unmap_window(&raw const msg, badge, &raw mut reply)
                }
                MM_FORK_REGIONS => {
                    mmap::handle_mm_fork_regions(&raw const msg, badge, &raw mut reply)
                }
                MM_SHM_CREATE => shm::handle_mm_shm_create(&raw const msg, badge, &raw mut reply),
                MM_SHM_MAP => shm::handle_mm_shm_map(&raw const msg, badge, &raw mut reply),
                MM_SHM_UNMAP => shm::handle_mm_shm_unmap(&raw const msg, badge, &raw mut reply),
                MM_SHM_DESTROY => shm::handle_mm_shm_destroy(&raw const msg, badge, &raw mut reply),
                MM_SHM_RESIZE => shm::handle_mm_shm_resize(&raw const msg, badge, &raw mut reply),
                MM_GET_CLIENT_STATS => {
                    client::handle_mm_get_client_stats(&raw const msg, badge, &raw mut reply)
                }
                MM_REGISTER_SHARED_REGION => {
                    mmap::handle_mm_register_shared_region(&raw const msg, badge, &raw mut reply)
                }
                MM_MAP_OBJECT_REGION => {
                    mmap::handle_mm_map_object_region(&raw const msg, badge, &raw mut reply)
                }
                MM_SYNC_FILE_BACKING => {
                    mmap::handle_mm_sync_file_backing(&raw const msg, badge, &raw mut reply)
                }
                MM_FILE_MMAP => mmap::handle_mm_file_mmap(&raw const msg, badge, &raw mut reply),
                MM_SYNC_MMAP_WRITE => {
                    mmap::handle_mm_sync_mmap_write(&raw const msg, badge, &raw mut reply)
                }
                // MM_PROVISION_UNTYPED / MM_QUERY_CAPACITY removed: mmsrv no
                // longer owns an untyped pool. Every kernel object goes
                // through rsrcsrv via `rsrcsrv_alloc_object`.
                MM_ALLOC_PRIVATE_REGION => {
                    mmap::handle_mm_alloc_private_region(&raw const msg, badge, &raw mut reply)
                }
                MM_ALLOC_PRIVATE_WINDOW => {
                    mmap::handle_mm_alloc_private_window(&raw const msg, badge, &raw mut reply)
                }
                MM_ALLOC_INITRD_COPY => {
                    mmap::handle_mm_alloc_initrd_copy(&raw const msg, badge, &raw mut reply)
                }
                MM_ALLOC_BOOTINFO_COPY => {
                    mmap::handle_mm_alloc_bootinfo_copy(&raw const msg, badge, &raw mut reply)
                }
                MM_COPY_FROM_CLIENT_REGION => {
                    mmap::handle_mm_copy_from_client_region(&raw const msg, badge, &raw mut reply)
                }
                MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION => {
                    mmap::handle_mm_alloc_private_copy_from_client_region(
                        &raw const msg,
                        badge,
                        &raw mut reply,
                    )
                }
                MM_ALLOC_TYPED_COPY_FROM_CLIENT_REGION => {
                    mmap::handle_mm_alloc_typed_copy_from_client_region(
                        &raw const msg,
                        badge,
                        &raw mut reply,
                    )
                }
                MM_PREFAULT_RANGE => {
                    mmap::handle_mm_prefault_range(&raw const msg, badge, &raw mut reply)
                }
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
                    // Debug: dump frame pool / client counts. mmsrv no
                    // longer owns untyped sources, so the legacy UT pool
                    // dump is gone.
                    trona::uinfo!(|_lb| {
                        _lb.str(b"[MMSRV] frame_pool count=");
                        _lb.dec(*(&raw const FRAME_POOL_COUNT) as u64);
                        _lb.str(b" cap=");
                        _lb.dec(*(&raw const FRAME_POOL_CAP) as u64);
                        _lb.str(b" recycled=");
                        _lb.dec(*(&raw const FRAME_POOL_TOTAL_RECYCLED));
                        _lb.str(b" reused=");
                        _lb.dec(*(&raw const FRAME_POOL_TOTAL_REUSED));
                        _lb.str(b"\n");
                    });
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
                            // The fault endpoint can still carry in-flight
                            // faults briefly after procmgr has torn the client
                            // down. Keep the dead thread FaultBlocked quietly
                            // instead of spamming logs and re-faulting.
                            skip_reply = true;
                            break 'fault;
                        }

                        if (*client_ptr).deregistering {
                            skip_reply = true;
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

                        // 4. Demand-page path: materialize the target page
                        // through the same helper used by explicit prefaults.
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

                        let prefault_err =
                            mmap::materialize_region_page(client_ptr, region, page_addr);
                        if prefault_err != TRONA_OK {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[MMSRV] VMFault: materialize failed badge=");
                                _lb.hex(badge);
                                _lb.str(b" addr=");
                                _lb.hex(fault_addr);
                                _lb.str(b" err=");
                                _lb.hex(prefault_err);
                                _lb.str(b"\n");
                            });
                            reply.label = prefault_err;
                            break 'fault;
                        }

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
            let err = unsafe { ipc::recv_ctx(ipc_ctx(), 3, &raw mut msg, &raw mut badge) };
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
                ipc::reply_recv_ctx(ipc_ctx(), 3, &raw const reply, &raw mut msg, &raw mut badge)
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
