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
//!   MM_MAP_WINDOW  — procmgr creates write window in caller's VSpace
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
//!   64 = nameserv endpoint (via NeedEP)

#![no_std]
#![no_main]

mod types;
mod client;
mod mmap;
mod pool;
mod shm;

use besalt::consts::*;
use besalt::invoke;
use besalt::ipc;
use besalt::serial;
use besalt::serial::LineBuf;
use besalt::types::*;

use types::*;

// ---------------------------------------------------------------------------
// Cap slot layout
// ---------------------------------------------------------------------------

const CAP_SERVER_EP: u64 = 3;
const CAP_UNTYPED: u64 = 7;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_UNTYPED_START: u64 = 16;
const CAP_NAMESERV: u64 = 64;
const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

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
            let slot = match besalt::slot_alloc::slot_alloc() {
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
// Per-page region tracking helpers
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

/// Allocate a frame_caps array of `cap` entries via self_mmap.
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

/// Grow a frame_caps array: allocate new, copy old, return new pointer.
unsafe fn grow_frame_cap_array(
    old: *mut Cap,
    old_count: usize,
    new_cap: usize,
) -> *mut Cap {
    unsafe {
        let new_ptr = alloc_frame_cap_array(new_cap);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }
        if !old.is_null() && old_count > 0 {
            for i in 0..old_count {
                *new_ptr.add(i) = *old.add(i);
            }
        }
        new_ptr
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

/// Shared COW aggregation notification — bound to mmsrv's TCB.
/// All per-VSpace pools share this notification so a single bound signal
/// wakes mmsrv from Recv when any pool is consumed.
static mut COW_AGG_NTFN: Cap = 0;

// ---------------------------------------------------------------------------
// CNode slot recycling
// ---------------------------------------------------------------------------

/// Free-slot stack capacity. 32K entries × 4 bytes = 128KB.
/// Handles worst-case deregister of a client with ~24K frame caps.
const FREE_SLOT_CAP: usize = 32768;
static mut FREE_SLOTS: [u32; FREE_SLOT_CAP] = [0u32; FREE_SLOT_CAP];
static mut FREE_SLOT_COUNT: usize = 0;

// ---------------------------------------------------------------------------
// Frame cap recycling pool
// ---------------------------------------------------------------------------

/// Frame pool capacity. 32K entries x 8 bytes = 256KB.
/// Handles worst-case recycling of ~24K frame caps from a large binary cycle.
const FRAME_POOL_CAP: usize = 32768;
static mut FRAME_POOL: [u64; FRAME_POOL_CAP] = [0u64; FRAME_POOL_CAP];
static mut FRAME_POOL_COUNT: usize = 0;

/// Zeroing window: 8 pages for batch frame zeroing before pool push.
/// Located just below SELF_MMAP_BASE to avoid VA conflicts.
const ZERO_WINDOW_BASE: u64 = 0x1FFF_8000;
const ZERO_WINDOW_PAGES: usize = 8;

/// Statistics: total frames recycled into pool and reused from pool.
static mut FRAME_POOL_TOTAL_RECYCLED: u64 = 0;
static mut FRAME_POOL_TOTAL_REUSED: u64 = 0;

// ---------------------------------------------------------------------------
// SHM object tracking (growable, pointer-based)
// ---------------------------------------------------------------------------

static mut SHM_PTR: *mut ShmObject = core::ptr::null_mut();
static mut SHM_CAP: usize = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    besalt::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = besalt::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Retype an object from any available untyped source (round-robin scan).
unsafe fn retype_any(obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
    unsafe {
        let ut_count = *(&raw const UT_COUNT);
        if ut_count == 0 {
            return BESALT_OUT_OF_MEMORY as i32;
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
        }

        // All sources exhausted — log per-source diagnostics
        let mut lb = LineBuf::new();
        lb.str(b"[MMSRV] retype_any: all ");
        lb.hex(ut_count as u64);
        lb.str(b" sources failed, type=");
        lb.hex(obj_type);
        lb.str(b"\n");
        lb.flush();
        for i in 0..ut_count {
            if !sources[i].active {
                continue;
            }
            let err = invoke::untyped_retype(sources[i].cap, obj_type, size_bits, dest_slot);
            let mut lb2 = LineBuf::new();
            lb2.str(b"  src[");
            lb2.hex(i as u64);
            lb2.str(b"] cap=");
            lb2.hex(sources[i].cap);
            lb2.str(b" err=");
            lb2.hex(err as u64);
            lb2.str(b"\n");
            lb2.flush();
            if err == 0 {
                *(&raw mut UT_HINT) = i;
                return 0;
            }
        }

        BESALT_OUT_OF_MEMORY as i32
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
        for slot in CAP_UNTYPED_START..CAP_UNTYPED_START + 8 {
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

        let mut lb = LineBuf::new();
        lb.str(b"[MMSRV] untyped pool: ");
        lb.hex(count as u64);
        lb.str(b" sources\n");
        lb.flush();
    }
}

// ---------------------------------------------------------------------------
// Nameserv registration
// ---------------------------------------------------------------------------

unsafe fn register_with_nameserv() -> bool {
    unsafe {
        let name = b"mmsrv";
        let mut msg = BesaltMsg::zeroed();
        msg.label = POSIX_NS_REGISTER;
        msg.length = 1 + ((name.len() + 7) / 8) as u64;
        msg.regs[0] = name.len() as u64;
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            core::ptr::write(dst.add(i), name[i]);
        }

        // Send our server EP cap
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);

        let mut reply = BesaltMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != BESALT_OK {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] nameserv register failed err=");
            lb.hex(err as u64);
            lb.str(b" label=");
            lb.hex(reply.label);
            lb.str(b"\n");
            lb.flush();
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

pub(crate) fn cow_agg_ntfn() -> Cap {
    unsafe { *(&raw const COW_AGG_NTFN) }
}

/// Allocate a CNode slot, preferring recycled slots over the bump allocator.
/// Never performs blocking IPC to procmgr — returns None instead of expanding
/// the CSpace, preventing the procmgr→mmsrv→procmgr deadlock on slot exhaustion.
pub(crate) fn recycled_slot_alloc() -> Option<u64> {
    // SAFETY: mmsrv is single-threaded; no concurrent access to FREE_SLOTS.
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        if count > 0 {
            let idx = count - 1;
            let slot = *(&raw const FREE_SLOTS as *const u32).add(idx);
            *(&raw mut FREE_SLOT_COUNT) = idx;
            return Some(slot as u64);
        }
    }
    besalt::slot_alloc::slot_alloc()
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
        if count < FREE_SLOT_CAP {
            *(&raw mut FREE_SLOTS as *mut u32).add(count) = slot as u32;
            *(&raw mut FREE_SLOT_COUNT) = count + 1;
        }
        // If pool is full, slot is permanently leaked (bounded degradation)
    }
}

/// Return an unused (empty) CNode slot to the free pool without calling
/// cnode_delete. Used when retype fails and the slot was never populated.
fn recycle_empty_slot(slot: u64) {
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        if count < FREE_SLOT_CAP {
            *(&raw mut FREE_SLOTS as *mut u32).add(count) = slot as u32;
            *(&raw mut FREE_SLOT_COUNT) = count + 1;
        }
    }
}

/// Push a frame cap into the recycling pool after zeroing it.
/// Falls back to recycled_cnode_delete if pool is full or zeroing fails.
pub(crate) fn frame_pool_push(frame_cap: Cap) {
    unsafe {
        let count = *(&raw const FRAME_POOL_COUNT);
        if count >= FRAME_POOL_CAP {
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
        *(&raw mut FRAME_POOL as *mut u64).add(count) = frame_cap;
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
        let idx = count - 1;
        let cap = *(&raw const FRAME_POOL as *const u64).add(idx);
        *(&raw mut FRAME_POOL_COUNT) = idx;
        *(&raw mut FRAME_POOL_TOTAL_REUSED) += 1;
        Some(cap)
    }
}

/// Batch push frame caps into the recycling pool with 8-page window zeroing.
/// Null (0) entries in `caps` are skipped. Falls back to recycled_cnode_delete
/// for caps that cannot be pooled (map failure or pool full).
///
/// # Safety
///
/// `caps` must point to a valid array of at least `count` Cap entries.
pub(crate) unsafe fn frame_pool_push_batch(caps: *const Cap, count: usize) {
    unsafe {
        let mut i = 0;
        while i < count {
            let chunk = core::cmp::min(count - i, ZERO_WINDOW_PAGES);
            let mut mapped_flags: [bool; 8] = [false; 8];

            for j in 0..chunk {
                let cap = *caps.add(i + j);
                if cap == 0 {
                    continue;
                }
                let va = ZERO_WINDOW_BASE + j as u64 * 4096;
                let err = invoke::vspace_map(
                    CAP_SELF_VSPACE, cap, va,
                    VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                );
                if err != 0 {
                    recycled_cnode_delete(cap);
                    continue;
                }
                mapped_flags[j] = true;
            }

            // Zero only mapped pages — skip holes where cap was 0 or map failed
            for j in 0..chunk {
                if mapped_flags[j] {
                    let va = ZERO_WINDOW_BASE + j as u64 * 4096;
                    core::ptr::write_bytes(va as *mut u8, 0, 4096);
                }
            }

            for j in 0..chunk {
                let cap = *caps.add(i + j);
                if cap == 0 || !mapped_flags[j] {
                    continue;
                }
                let va = ZERO_WINDOW_BASE + j as u64 * 4096;
                invoke::vspace_unmap(CAP_SELF_VSPACE, va);
                let pool_count = *(&raw const FRAME_POOL_COUNT);
                if pool_count < FRAME_POOL_CAP {
                    *(&raw mut FRAME_POOL as *mut u64).add(pool_count) = cap;
                    *(&raw mut FRAME_POOL_COUNT) = pool_count + 1;
                    *(&raw mut FRAME_POOL_TOTAL_RECYCLED) += 1;
                } else {
                    recycled_cnode_delete(cap);
                }
            }

            i += chunk;
        }
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

/// Drain COW notification rings for all active pools.
///
/// For each active VSpace pool, reads the notification ring to learn which
/// pool entries were consumed by the kernel fast-path, clears COW bits in
/// the corresponding regions, and replenishes the pool.
unsafe fn drain_all_cow_pools() {
    unsafe {
        let clients_ptr = *(&raw const CLIENTS_PTR);
        let clients_cap = *(&raw const CLIENTS_CAP);
        if clients_ptr.is_null() {
            return;
        }
        for ci in 0..clients_cap {
            let client = clients_ptr.add(ci);
            if !(*client).active {
                continue;
            }
            let pool_ptr = pool::find_pool_by_vspace((*client).vspace_cap);
            if pool_ptr.is_null() {
                continue;
            }
            let (drained, complete) = pool::drain_notifications(client, pool_ptr);
            if drained > 0 && complete {
                pool::replenish_pool(client, pool_ptr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[MMSRV] SaltyOS memory server starting\n");

    // Set up IPC buffer
    let err = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[MMSRV] FAIL: set IPC buffer err=");
        lb.hex(err as u64);
        lb.str(b"\n");
        lb.flush();
        idle();
    }
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    puts(b"[MMSRV] IPC buffer ready\n");

    // Initialize per-process slot allocator from RTLD-exported globals.
    // self_mmap() depends on slot_alloc for temporary frame-cap slots.
    unsafe {
        let base = *(&raw const besalt::__besalt_slot_base);
        let count = *(&raw const besalt::__besalt_slot_count);
        let cspace_ntfn = *(&raw const besalt::__besalt_cspace_ntfn);
        // Clamp count so the bump allocator cannot reach the receive-slot pool.
        let max_count = RECV_SLOT_BASE.saturating_sub(base);
        let count = if count > max_count { max_count } else { count };
        if base != 0 {
            besalt::slot_alloc::slot_alloc_init(base, count, cspace_ntfn);
        } else {
            puts(b"[MMSRV] FATAL: slot pool not provided by RTLD/auxv\n");
            idle();
        }
    }

    // Allocate shared COW aggregation notification and bind to our TCB.
    // When the kernel fast-path consumes pool entries and signals, the
    // bound notification wakes us from Recv without a real IPC message.
    unsafe {
        if let Some(ntfn_slot) = recycled_slot_alloc() {
            if retype_any(OBJ_NOTIFICATION, 0, ntfn_slot) == 0 {
                let err = invoke::tcb_bind_notification(CAP_SELF_TCB, ntfn_slot);
                if err == 0 {
                    *(&raw mut COW_AGG_NTFN) = ntfn_slot;
                    puts(b"[MMSRV] COW aggregation notification bound\n");
                } else {
                    let mut lb = LineBuf::new();
                    lb.str(b"[MMSRV] WARN: bind COW ntfn failed err=");
                    lb.hex(err as u64);
                    lb.str(b"\n");
                    lb.flush();
                    recycled_cnode_delete(ntfn_slot);
                }
            }
        }
    }

    // Initialize untyped pool
    unsafe {
        init_untyped_pool();
    }

    // Initialize growable client table
    unsafe {
        let ptr = self_mmap(1);
        if ptr.is_null() {
            puts(b"[MMSRV] FATAL: client table alloc failed\n");
            idle();
        }
        *(&raw mut CLIENTS_PTR) = ptr as *mut MmClient;
        *(&raw mut CLIENTS_CAP) = 4096 / core::mem::size_of::<MmClient>();
    }

    // Initialize growable SHM table
    unsafe {
        let ptr = self_mmap(1);
        if ptr.is_null() {
            puts(b"[MMSRV] FATAL: SHM table alloc failed\n");
            idle();
        }
        *(&raw mut SHM_PTR) = ptr as *mut ShmObject;
        *(&raw mut SHM_CAP) = 4096 / core::mem::size_of::<ShmObject>();
    }

    // Set up initial receive slot for cap transfers
    unsafe {
        let slot = alloc_recv_slot();
        if slot == 0 {
            puts(b"[MMSRV] FATAL: no receive slots\n");
            idle();
        }
        *(&raw mut CURRENT_RECV_SLOT) = slot;
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);
    }

    // Register with nameserv
    if !unsafe { register_with_nameserv() } {
        puts(b"[MMSRV] FATAL: nameserv registration failed\n");
        idle();
    }
    puts(b"[MMSRV] registered with nameserv\n");

    // Signal readiness to init
    signal_ready();
    puts(b"[MMSRV] ready\n");

    // Initial recv
    let mut msg = BesaltMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        puts(b"[MMSRV] initial recv failed\n");
        idle();
    }

    // Server loop
    loop {
        let mut reply = BesaltMsg::zeroed();
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

        // Phase 2: Drain COW notification rings for all active pools.
        // When the kernel fast-path resolves a COW fault, it writes to
        // the notification ring and signals. We drain on every loop
        // iteration (lightweight check: head != tail).
        unsafe {
            drain_all_cow_pools();
        }

        // Bound-notification wakeup: when the kernel signals a pool's
        // notification, mmsrv wakes from Recv with label=0 and badge
        // carrying the signal bits. Drain pools and re-enter recv
        // (no caller to reply to).
        if msg.label == 0 && badge != 0 {
            unsafe {
                drain_all_cow_pools();
            }
            let err = unsafe {
                ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            };
            if err != 0 {
                puts(b"[MMSRV] recv after ntfn drain failed\n");
                break;
            }
            continue;
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
                // VMFault: label=2 from kernel FaultType::VMFault.
                // Badge identifies the faulting client. Replying resumes the faulting thread.
                //
                // All error paths break out of 'fault without using `continue` so that
                // reply_recv_ctx (or recv for unrecoverable faults) is always reached.
                2 => {
                    let fault_addr = msg.regs[0];
                    let error_code = msg.regs[1];
                    let fault_rip = msg.regs[2];
                    let page_addr = fault_addr & !0xFFFu64;

                    'fault: {
                        // 1. Find client by badge
                        let client_ptr = client::find_client_by_badge(badge);
                        if client_ptr.is_null() {
                            let mut lb = LineBuf::new();
                            lb.str(b"[MMSRV] VMFault: unknown client badge=");
                            lb.hex(badge);
                            lb.str(b"\n");
                            lb.flush();
                            reply.label = BESALT_INVALID_OPERATION;
                            break 'fault;
                        }

                        // 2. Find region containing fault_addr
                        let region = client::find_region_by_addr(client_ptr, page_addr);
                        if region.is_null() {
                            // No region covers this address — segfault.
                            // Don't reply: leave the faulting thread permanently
                            // FaultBlocked instead of re-faulting in a tight loop.
                            let mut lb = LineBuf::new();
                            lb.str(b"[MMSRV] Segfault: badge=");
                            lb.hex(badge);
                            lb.str(b" addr=");
                            lb.hex(fault_addr);
                            lb.str(b" (no region) rip=");
                            lb.hex(fault_rip);
                            let rc = (*client_ptr).region_count;
                            lb.str(b" regions=");
                            lb.hex(rc as u64);
                            if rc > 0 {
                                let regs = (*client_ptr).regions;
                                let r0 = &*regs.add(0);
                                lb.str(b" r0=[");
                                lb.hex(r0.base);
                                lb.str(b",");
                                lb.hex(r0.base + r0.length);
                                lb.str(b")");
                                let rl = &*regs.add(rc - 1);
                                lb.str(b" rN=[");
                                lb.hex(rl.base);
                                lb.str(b",");
                                lb.hex(rl.base + rl.length);
                                lb.str(b")");
                            }
                            lb.str(b" err=");
                            lb.hex(error_code);
                            lb.str(b"\n");
                            lb.flush();
                            // Dump all regions for debugging
                            if rc > 0 && rc <= 80 {
                                let regs = (*client_ptr).regions;
                                for ri in 0..rc {
                                    let rd = &*regs.add(ri);
                                    if rd.active {
                                        let mut lb2 = LineBuf::new();
                                        lb2.str(b"  r");
                                        lb2.hex(ri as u64);
                                        lb2.str(b"=[");
                                        lb2.hex(rd.base);
                                        lb2.str(b",");
                                        lb2.hex(rd.base + rd.length);
                                        lb2.str(b") t=");
                                        lb2.hex(rd.region_type as u64);
                                        lb2.str(b"\n");
                                        lb2.flush();
                                    }
                                }
                            }
                            skip_reply = true;
                            break 'fault;
                        }

                        let page_idx = ((page_addr - (*region).base) / 4096) as usize;

                        // 3. COW fault detection: write to present page
                        // error_code bits: [0]=Present, [1]=Write, [2]=User
                        // 0x7 = present + write + user = COW write fault
                        // Guard: only enter COW path if the page is actually
                        // COW-inherited. Non-COW write-to-present faults (e.g.
                        // mprotect(PROT_READ) violations) are access violations.
                        //
                        // Implicit COW fallback: if the bitmap is missing
                        // (OOM during fork) but the region is writable, the
                        // fault MUST be COW — SaltyOS has no other mechanism
                        // that downgrades writable PTEs to read-only.
                        let bitmap_cow = client::is_cow_page(region, page_idx);
                        let implicit_cow = !bitmap_cow && (*region).cow_inherited;
                        if (error_code & 0x7) == 0x7 && (bitmap_cow || implicit_cow) {
                            // COW resolution path: allocate a new frame and
                            // let the kernel copy + replace the COW mapping.
                            // Use fresh retype (not recycled pool) to avoid
                            // issues with frame lifecycle during COW.
                            let slot = match recycled_slot_alloc() {
                                Some(s) => s,
                                None => {
                                    reply.label = BESALT_OUT_OF_MEMORY;
                                    break 'fault;
                                }
                            };

                            if retype_any(OBJ_FRAME, 0, slot) != 0 {
                                reply.label = BESALT_OUT_OF_MEMORY;
                                break 'fault;
                            }

                            let flags = prot_to_vspace_flags((*region).prot);

                            let err = invoke::vspace_cow_resolve(
                                (*client_ptr).vspace_cap,
                                page_addr,
                                slot,
                                flags,
                            );

                            if err == BESALT_ALREADY_EXISTS as i32 {
                                // Race: another CPU already resolved this COW page.
                                // Kernel confirmed PTE is writable (not COW).
                                // Safe for both bitmap_cow and implicit_cow paths.
                                recycled_cnode_delete(slot);
                                if bitmap_cow {
                                    client::clear_cow_bit(region, page_idx);
                                }
                                reply.label = BESALT_OK;
                                break 'fault;
                            }
                            if err == BESALT_INVALID_OPERATION as i32 {
                                // Kernel says page is present, not COW, not writable.
                                // Genuine access violation (e.g. mprotect PROT_READ).
                                recycled_cnode_delete(slot);
                                let mut lb = LineBuf::new();
                                lb.str(b"[MMSRV] access violation (not COW): badge=");
                                lb.hex(badge);
                                lb.str(b" addr=");
                                lb.hex(fault_addr);
                                lb.str(b"\n");
                                lb.flush();
                                skip_reply = true;
                                break 'fault;
                            }
                            if err != 0 {
                                recycled_cnode_delete(slot);
                                reply.label = BESALT_BAD_ADDRESS;
                                break 'fault;
                            }

                            // Success — ensure frame_caps array is large enough
                            if page_idx >= (*region).frame_cap_capacity as usize {
                                let old_cap = (*region).frame_cap_capacity as usize;
                                let required = page_idx + 1;
                                let growth = if old_cap < 128 {
                                    if old_cap == 0 { 8 } else { old_cap }
                                } else if old_cap < 1024 {
                                    old_cap / 2
                                } else {
                                    256
                                };
                                let new_cap = core::cmp::max(required, old_cap + growth);
                                let new_fcaps = grow_frame_cap_array(
                                    (*region).frame_caps,
                                    old_cap,
                                    new_cap,
                                );
                                if new_fcaps.is_null() {
                                    // Frame is already resolved in kernel; just
                                    // lose tracking rather than fail the fault.
                                    reply.label = BESALT_OK;
                                    break 'fault;
                                }
                                (*region).frame_caps = new_fcaps;
                                (*region).frame_cap_capacity = new_cap as u16;
                            }

                            // Replace stale frame cap if parent had one
                            if !(*region).frame_caps.is_null() && page_idx < (*region).frame_cap_capacity as usize {
                                let old_cap = *(*region).frame_caps.add(page_idx);
                                if old_cap != 0 {
                                    recycled_cnode_delete(old_cap);
                                }
                                *(*region).frame_caps.add(page_idx) = slot;
                            }

                            // Clear COW bit — this page now has its own frame
                            client::clear_cow_bit(region, page_idx);

                            // High-water-mark update: after fork, sparse COW
                            // resolution at high page_idx must not leave
                            // frame_count below the resolved index.
                            let needed = (page_idx + 1) as u16;
                            if needed > (*region).frame_count {
                                (*region).frame_count = needed;
                            }
                            reply.label = BESALT_OK;
                            break 'fault;
                        }

                        // Non-COW write to present page = access violation
                        // (e.g. mprotect(PROT_READ) page). Leave faulting
                        // thread permanently FaultBlocked.
                        if (error_code & 0x7) == 0x7 {
                            let mut lb = LineBuf::new();
                            lb.str(b"[MMSRV] access violation: badge=");
                            lb.hex(badge);
                            lb.str(b" addr=");
                            lb.hex(fault_addr);
                            lb.str(b"\n");
                            lb.flush();
                            skip_reply = true;
                            break 'fault;
                        }

                        // 4. Non-COW fault: demand-page path
                        // Grow frame_caps array if needed
                        if page_idx >= (*region).frame_cap_capacity as usize {
                            // Index out of bounds — grow frame_caps array to fit
                            let old_cap = (*region).frame_cap_capacity as usize;
                            let required = page_idx + 1;
                            // Hybrid growth: small 2x, medium 1.5x, large +256
                            let growth = if old_cap < 128 {
                                if old_cap == 0 { 8 } else { old_cap }
                            } else if old_cap < 1024 {
                                old_cap / 2
                            } else {
                                256
                            };
                            let new_cap = core::cmp::max(required, old_cap + growth);
                            let new_fcaps = grow_frame_cap_array(
                                (*region).frame_caps,
                                old_cap,
                                new_cap,
                            );
                            if new_fcaps.is_null() {
                                reply.label = BESALT_OUT_OF_MEMORY;
                                break 'fault;
                            }
                            (*region).frame_caps = new_fcaps;
                            (*region).frame_cap_capacity = new_cap as u16;
                        }
                        if !(*region).frame_caps.is_null() && *(*region).frame_caps.add(page_idx) != 0 {
                            // Already mapped (race)
                            reply.label = BESALT_OK;
                            break 'fault;
                        }

                        // 5. Allocate frame: fresh retype (not recycled pool)
                        let slot = match recycled_slot_alloc() {
                            Some(s) => s,
                            None => {
                                reply.label = BESALT_OUT_OF_MEMORY;
                                break 'fault;
                            }
                        };
                        if retype_any(OBJ_FRAME, 0, slot) != 0 {
                            reply.label = BESALT_OUT_OF_MEMORY;
                            break 'fault;
                        }

                        // 6. Map into client's VSpace
                        let flags = prot_to_vspace_flags((*region).prot);
                        let err = invoke::vspace_map((*client_ptr).vspace_cap, slot, page_addr, flags);
                        if err != 0 {
                            recycled_cnode_delete(slot);
                            reply.label = BESALT_BAD_ADDRESS;
                            break 'fault;
                        }

                        // 7. Track frame cap
                        if !(*region).frame_caps.is_null() {
                            *(*region).frame_caps.add(page_idx) = slot;
                        }
                        // High-water-mark update
                        let needed = (page_idx + 1) as u16;
                        if needed > (*region).frame_count {
                            (*region).frame_count = needed;
                        }

                        // 8. Reply OK — kernel resumes faulting thread
                        reply.label = BESALT_OK;
                    } // end 'fault
                }
                _ => {
                    let mut lb = LineBuf::new();
                    lb.str(b"[MMSRV] unknown label=");
                    lb.hex(msg.label);
                    lb.str(b" badge=");
                    lb.hex(badge);
                    lb.str(b"\n");
                    lb.flush();
                    reply.label = BESALT_INVALID_OPERATION;
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
                let mut lb = LineBuf::new();
                lb.str(b"[MMSRV] recv failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
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
                let mut lb = LineBuf::new();
                lb.str(b"[MMSRV] reply_recv failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                break;
            }
        }
    }

    idle();
}

fn idle() -> ! {
    loop {
        besalt::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
