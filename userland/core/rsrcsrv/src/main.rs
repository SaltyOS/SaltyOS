//! SaltyOS Resource Server (rsrcsrv)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Sole runtime authority for kernel object allocation, quota accounting,
//! and owner-based reclaim.
//!
//! IPC protocol (lib/trona/uapi/protocol/rsrcsrv.rs):
//!   RES_ALLOC_OBJECT (0xE0) — single object alloc, returns (cap, handle)
//!   RES_ALLOC_BATCH  (0xE1) — heterogeneous batch alloc
//!   RES_FREE_HANDLE  (0xE2) — free a single handle
//!   RES_RECLAIM_OWNER(0xE3) — bulk-free everything an owner holds
//!   RES_QUERY_USAGE  (0xE4) — query usage stats
//!   RES_SET_QUOTA    (0xE5) — set per-owner quota; high-bit flag promotes privileged
//!   RES_ADOPT_UNTYPED(0xE6) — accept an untyped cap into the pool
//!
//! Cap layout (set by init):
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   3  = server endpoint
//!   7  = boot-load child untyped (filled by init at spawn time)
//!   14 = readiness notification
//!   15 = receive scratch slot
//!   16..32 = root untypeds (cnode_move'd from init at spawn time)
//!   64 = namesrv endpoint (unused — rsrcsrv lives at well-known slot CAP_RSRCSRV_EP=6)
//!
//! Owner / handle / quota model:
//!   Each successful alloc records `HandleEntry { owner_id, obj_type, size_bits,
//!   rsrcsrv_slot, epoch, active }` in a dynamic table. The cap is transferred
//!   to the caller via cap_transfer of `rsrcsrv_slot`, which makes the caller's
//!   copy a CDT child of rsrcsrv's slot. RES_FREE_HANDLE and RES_RECLAIM_OWNER
//!   both use `cnode_revoke` on rsrcsrv's slot, which invalidates every derived
//!   cap including the caller's.
//!
//!   Handles are 64-bit opaque values: `(epoch: u32) << 32 | (index: u32)`.
//!   Epoch prevents ABA reuse after a slot is freed and reallocated.
//!
//!   `owner_table` tracks `bytes_in_use`, `handle_count`, `max_bytes`, and
//!   `max_handles` per owner_id. Quota is enforced before alloc.
//!
//! Privileged caller model:
//!   Only callers in `privileged_owners` may set `owner_id != caller_badge`.
//!   The privileged set is populated via RES_SET_QUOTA with the high bit of
//!   MR2 set (RES_QUOTA_FLAG_PROMOTE_PRIVILEGED). Promotion is only accepted
//!   when the caller's badge matches `INIT_BADGE`. Init promotes procmgr
//!   right after spawning rsrcsrv.

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_posix;

use trona::consts::kernel::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

// ---------------------------------------------------------------------------
// Cap slot layout
// ---------------------------------------------------------------------------

const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;

const CAP_UNTYPED: Cap = 7;
const CAP_UNTYPED_START: Cap = 16;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

/// Well-known badge value for init. Init mints CAP_RSRCSRV_EP with this
/// badge when spawning rsrcsrv, so rsrcsrv can recognize init's IPCs and
/// accept privileged operations (FLAG_PROMOTE_PRIVILEGED, RES_ADOPT_UNTYPED).
const INIT_BADGE: u64 = 1;

// ---------------------------------------------------------------------------
// Untyped source pool
// ---------------------------------------------------------------------------

const MAX_UT_SOURCES: usize = 32;

#[derive(Clone, Copy)]
struct UntypedSource {
    cap: Cap,
    active: bool,
}

impl UntypedSource {
    const fn empty() -> Self {
        UntypedSource { cap: 0, active: false }
    }
}

static mut UT_SOURCES: [UntypedSource; MAX_UT_SOURCES] = {
    const E: UntypedSource = UntypedSource::empty();
    [E; MAX_UT_SOURCES]
};
static mut UT_COUNT: usize = 0;
static mut UT_HINT: usize = 0;

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
            _lb.str(b"[RSRCSRV] deactivating exhausted UT source idx=");
            _lb.dec(index as u64);
            _lb.str(b" cap=");
            _lb.hex((*sources_ptr)[index].cap);
            _lb.str(b"\n");
        });
    }
}

unsafe fn try_reset_ut_source(index: usize) -> bool {
    unsafe {
        let count = *(&raw const UT_COUNT);
        if index >= count {
            return false;
        }

        let sources_ptr = &raw mut UT_SOURCES;
        let cap = (*sources_ptr)[index].cap;
        if cap == 0 {
            return false;
        }

        let err = invoke::untyped_reset(cap);
        if err != 0 {
            return false;
        }

        (*sources_ptr)[index].active = true;
        trona::uinfo!(|_lb| {
            _lb.str(b"[RSRCSRV] reactivated UT source idx=");
            _lb.dec(index as u64);
            _lb.str(b" cap=");
            _lb.hex(cap);
            _lb.str(b"\n");
        });
        true
    }
}

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

        for i in start..ut_count {
            let source = (*(&raw const UT_SOURCES))[i];
            if !source.active {
                continue;
            }
            let mut err = invoke::untyped_retype(source.cap, obj_type, size_bits, dest_slot);
            if err == 0 {
                *(&raw mut UT_HINT) = i;
                return 0;
            }
            if err as u64 == TRONA_OUT_OF_MEMORY {
                if try_reset_ut_source(i) {
                    let reset_source = (*(&raw const UT_SOURCES))[i];
                    err = invoke::untyped_retype(reset_source.cap, obj_type, size_bits, dest_slot);
                    if err == 0 {
                        *(&raw mut UT_HINT) = i;
                        return 0;
                    }
                }
                if err as u64 == TRONA_OUT_OF_MEMORY {
                    deactivate_ut_source(i);
                }
            }
        }

        for i in 0..start {
            let source = (*(&raw const UT_SOURCES))[i];
            if !source.active {
                continue;
            }
            let mut err = invoke::untyped_retype(source.cap, obj_type, size_bits, dest_slot);
            if err == 0 {
                *(&raw mut UT_HINT) = i;
                return 0;
            }
            if err as u64 == TRONA_OUT_OF_MEMORY {
                if try_reset_ut_source(i) {
                    let reset_source = (*(&raw const UT_SOURCES))[i];
                    err = invoke::untyped_retype(reset_source.cap, obj_type, size_bits, dest_slot);
                    if err == 0 {
                        *(&raw mut UT_HINT) = i;
                        return 0;
                    }
                }
                if err as u64 == TRONA_OUT_OF_MEMORY {
                    deactivate_ut_source(i);
                }
            }
        }

        for i in 0..ut_count {
            let source = (*(&raw const UT_SOURCES))[i];
            if source.active || !try_reset_ut_source(i) {
                continue;
            }
            let reset_source = (*(&raw const UT_SOURCES))[i];
            let err = invoke::untyped_retype(reset_source.cap, obj_type, size_bits, dest_slot);
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

unsafe fn init_untyped_pool() {
    unsafe {
        let sources = &raw mut UT_SOURCES;
        let mut count: usize = 0;

        // slot 7 = boot-load untyped (init mints at spawn time)
        (*sources)[count] = UntypedSource { cap: CAP_UNTYPED, active: true };
        count += 1;

        // slots 16..32 = root untypeds (init cnode_move's at spawn time)
        for slot in CAP_UNTYPED_START..CAP_UNTYPED_START + 16 {
            if count >= MAX_UT_SOURCES {
                break;
            }
            (*sources)[count] = UntypedSource { cap: slot, active: true };
            count += 1;
        }

        *(&raw mut UT_COUNT) = count;
        *(&raw mut UT_HINT) = 0;

        trona::uinfo!(|_lb| {
            _lb.str(b"[RSRCSRV] untyped pool registered: ");
            _lb.dec(count as u64);
            _lb.str(b" sources (probe-on-demand)\n");
        });
    }
}

unsafe fn adopt_untyped_source(cap: Cap) -> bool {
    unsafe {
        let count = *(&raw const UT_COUNT);
        if count >= MAX_UT_SOURCES {
            return false;
        }
        let sources_ptr = &raw mut UT_SOURCES;
        (*sources_ptr)[count] = UntypedSource { cap, active: true };
        *(&raw mut UT_COUNT) = count + 1;
        *(&raw mut UT_HINT) = count;
        trona::uinfo!(|_lb| {
            _lb.str(b"[RSRCSRV] adopted untyped slot=");
            _lb.hex(cap);
            _lb.str(b" total=");
            _lb.dec((count + 1) as u64);
            _lb.str(b"\n");
        });
        true
    }
}

// ---------------------------------------------------------------------------
// Tracked internal mappings for handle/owner tables
// ---------------------------------------------------------------------------

const SELF_MMAP_BASE: u64 = 0x2000_0000;
static mut SELF_MMAP_NEXT: u64 = SELF_MMAP_BASE;

#[derive(Clone, Copy)]
struct TrackedBuffer {
    ptr: *mut u8,
    pages: usize,
    mo_cap: Cap,
}

impl TrackedBuffer {
    const fn zeroed() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            pages: 0,
            mo_cap: 0,
        }
    }
}

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

        let (commit_err, committed) = invoke::mo_commit(mo_cap, 0, num_pages as u64, 0);
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
    }
}

// ---------------------------------------------------------------------------
// Free-slot stack: recycled CSpace slots inside rsrcsrv's own CNode
// ---------------------------------------------------------------------------

static mut FREE_SLOTS_PTR: *mut u32 = core::ptr::null_mut();
static mut FREE_SLOTS_CAP: usize = 0;
static mut FREE_SLOT_COUNT: usize = 0;
static mut FREE_SLOTS_BUF: TrackedBuffer = TrackedBuffer::zeroed();

unsafe fn init_free_slot_pool() {
    unsafe {
        let cap: usize = 4096;
        let slot_bytes = cap * core::mem::size_of::<u32>();
        let slot_pages = (slot_bytes + 4095) / 4096;
        let buf = tracked_alloc_pages(slot_pages);
        if !buf.ptr.is_null() {
            *(&raw mut FREE_SLOTS_BUF) = buf;
            *(&raw mut FREE_SLOTS_PTR) = buf.ptr as *mut u32;
            *(&raw mut FREE_SLOTS_CAP) = cap;
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[RSRCSRV] WARN: FREE_SLOTS alloc failed (no untyped yet)\n");
            });
        }
    }
}

fn recycled_slot_alloc() -> Option<u64> {
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        if count > 0 {
            let ptr = *(&raw const FREE_SLOTS_PTR);
            if !ptr.is_null() {
                let idx = count - 1;
                let slot = *ptr.add(idx);
                *(&raw mut FREE_SLOT_COUNT) = idx;
                return Some(slot as u64);
            }
        }
    }
    trona::slot_alloc::slot_alloc_no_expand()
}

fn recycle_empty_slot(slot: u64) {
    unsafe {
        let count = *(&raw const FREE_SLOT_COUNT);
        let cap = *(&raw const FREE_SLOTS_CAP);
        let ptr = *(&raw const FREE_SLOTS_PTR);
        if count < cap && !ptr.is_null() {
            *ptr.add(count) = slot as u32;
            *(&raw mut FREE_SLOT_COUNT) = count + 1;
        }
    }
}

fn recycled_cnode_delete(slot: u64) {
    let err = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
    if err != 0 {
        return;
    }
    recycle_empty_slot(slot);
}

// ---------------------------------------------------------------------------
// Handle table — primary alloc bookkeeping
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct HandleEntry {
    owner_id: u64,
    obj_type: u32,
    size_bits: u32,
    rsrcsrv_slot: Cap,
    epoch: u32,
    active: u8,
    _pad: [u8; 3],
}

impl HandleEntry {
    const fn empty() -> Self {
        HandleEntry {
            owner_id: 0,
            obj_type: 0,
            size_bits: 0,
            rsrcsrv_slot: 0,
            epoch: 0,
            active: 0,
            _pad: [0; 3],
        }
    }
}

const HANDLE_INITIAL_CAPACITY: usize = 256;
const HANDLE_MAX_CAPACITY: usize = 65536;

static mut HANDLES_PTR: *mut HandleEntry = core::ptr::null_mut();
static mut HANDLES_CAP: usize = 0;
static mut HANDLES_COUNT: usize = 0;
static mut HANDLES_NEXT_FREE_HINT: usize = 0;
static mut HANDLES_BUF: TrackedBuffer = TrackedBuffer::zeroed();

/// Pack (epoch, index) into a 64-bit handle.
fn make_handle(epoch: u32, index: u32) -> u64 {
    ((epoch as u64) << 32) | (index as u64)
}

fn split_handle(handle: u64) -> (u32, u32) {
    ((handle >> 32) as u32, (handle & 0xFFFF_FFFF) as u32)
}

unsafe fn handles_grow(min_capacity: usize) -> bool {
    unsafe {
        let current_cap = *(&raw const HANDLES_CAP);
        if min_capacity <= current_cap {
            return true;
        }
        if min_capacity > HANDLE_MAX_CAPACITY {
            return false;
        }
        let mut new_cap = if current_cap == 0 {
            HANDLE_INITIAL_CAPACITY
        } else {
            current_cap * 2
        };
        while new_cap < min_capacity {
            new_cap *= 2;
        }
        if new_cap > HANDLE_MAX_CAPACITY {
            new_cap = HANDLE_MAX_CAPACITY;
        }

        let bytes = new_cap * core::mem::size_of::<HandleEntry>();
        let pages = (bytes + 4095) / 4096;
        let new_buf = tracked_alloc_pages(pages);
        if new_buf.ptr.is_null() {
            return false;
        }
        let new_ptr = new_buf.ptr as *mut HandleEntry;

        // Initialize new entries to empty
        for i in 0..new_cap {
            *new_ptr.add(i) = HandleEntry::empty();
        }

        // Copy existing entries
        let old_ptr = *(&raw const HANDLES_PTR);
        if !old_ptr.is_null() {
            for i in 0..current_cap {
                *new_ptr.add(i) = *old_ptr.add(i);
            }
        }

        let old_buf = *(&raw const HANDLES_BUF);
        *(&raw mut HANDLES_BUF) = new_buf;
        *(&raw mut HANDLES_PTR) = new_ptr;
        *(&raw mut HANDLES_CAP) = new_cap;
        tracked_free_pages(old_buf);
        true
    }
}

unsafe fn handles_alloc_slot() -> Option<u32> {
    unsafe {
        let cap = *(&raw const HANDLES_CAP);
        let hint = *(&raw const HANDLES_NEXT_FREE_HINT);
        let ptr = *(&raw const HANDLES_PTR);

        if cap == 0 || ptr.is_null() {
            if !handles_grow(HANDLE_INITIAL_CAPACITY) {
                return None;
            }
            return handles_alloc_slot_inner();
        }

        // Try hint forward
        for i in hint..cap {
            if (*ptr.add(i)).active == 0 {
                *(&raw mut HANDLES_NEXT_FREE_HINT) = i;
                return Some(i as u32);
            }
        }
        // Try from start
        for i in 0..hint {
            if (*ptr.add(i)).active == 0 {
                *(&raw mut HANDLES_NEXT_FREE_HINT) = i;
                return Some(i as u32);
            }
        }

        // Full — try to grow
        if !handles_grow(cap + HANDLE_INITIAL_CAPACITY) {
            return None;
        }
        Some(cap as u32)
    }
}

unsafe fn handles_alloc_slot_inner() -> Option<u32> {
    unsafe {
        let ptr = *(&raw const HANDLES_PTR);
        if ptr.is_null() {
            return None;
        }
        Some(0)
    }
}

unsafe fn handle_get(index: u32) -> Option<&'static mut HandleEntry> {
    unsafe {
        let cap = *(&raw const HANDLES_CAP);
        let ptr = *(&raw const HANDLES_PTR);
        if ptr.is_null() || index as usize >= cap {
            return None;
        }
        Some(&mut *ptr.add(index as usize))
    }
}

// ---------------------------------------------------------------------------
// Owner table — quota / accounting
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct OwnerEntry {
    owner_id: u64,
    bytes_in_use: u64,
    handle_count: u64,
    max_bytes: u64,
    max_handles: u64,
    active: u8,
    _pad: [u8; 7],
}

impl OwnerEntry {
    const fn empty() -> Self {
        OwnerEntry {
            owner_id: 0,
            bytes_in_use: 0,
            handle_count: 0,
            max_bytes: 0,
            max_handles: 0,
            active: 0,
            _pad: [0; 7],
        }
    }
}

const OWNER_INITIAL_CAPACITY: usize = 64;
const OWNER_MAX_CAPACITY: usize = 4096;

static mut OWNERS_PTR: *mut OwnerEntry = core::ptr::null_mut();
static mut OWNERS_CAP: usize = 0;
static mut OWNERS_BUF: TrackedBuffer = TrackedBuffer::zeroed();

unsafe fn owners_grow(min_capacity: usize) -> bool {
    unsafe {
        let current_cap = *(&raw const OWNERS_CAP);
        if min_capacity <= current_cap {
            return true;
        }
        if min_capacity > OWNER_MAX_CAPACITY {
            return false;
        }
        let mut new_cap = if current_cap == 0 {
            OWNER_INITIAL_CAPACITY
        } else {
            current_cap * 2
        };
        while new_cap < min_capacity {
            new_cap *= 2;
        }
        if new_cap > OWNER_MAX_CAPACITY {
            new_cap = OWNER_MAX_CAPACITY;
        }

        let bytes = new_cap * core::mem::size_of::<OwnerEntry>();
        let pages = (bytes + 4095) / 4096;
        let new_buf = tracked_alloc_pages(pages);
        if new_buf.ptr.is_null() {
            return false;
        }
        let new_ptr = new_buf.ptr as *mut OwnerEntry;

        for i in 0..new_cap {
            *new_ptr.add(i) = OwnerEntry::empty();
        }

        let old_ptr = *(&raw const OWNERS_PTR);
        if !old_ptr.is_null() {
            for i in 0..current_cap {
                *new_ptr.add(i) = *old_ptr.add(i);
            }
        }

        let old_buf = *(&raw const OWNERS_BUF);
        *(&raw mut OWNERS_BUF) = new_buf;
        *(&raw mut OWNERS_PTR) = new_ptr;
        *(&raw mut OWNERS_CAP) = new_cap;
        tracked_free_pages(old_buf);
        true
    }
}

unsafe fn owner_lookup(owner_id: u64) -> Option<&'static mut OwnerEntry> {
    unsafe {
        let cap = *(&raw const OWNERS_CAP);
        let ptr = *(&raw const OWNERS_PTR);
        if ptr.is_null() {
            return None;
        }
        for i in 0..cap {
            let entry = &mut *ptr.add(i);
            if entry.active != 0 && entry.owner_id == owner_id {
                return Some(entry);
            }
        }
        None
    }
}

unsafe fn owner_lookup_or_create(owner_id: u64) -> Option<&'static mut OwnerEntry> {
    unsafe {
        if let Some(entry) = owner_lookup(owner_id) {
            return Some(entry);
        }
        // Create
        let cap = *(&raw const OWNERS_CAP);
        let ptr = *(&raw const OWNERS_PTR);
        if cap == 0 || ptr.is_null() {
            if !owners_grow(OWNER_INITIAL_CAPACITY) {
                return None;
            }
        }
        let cap = *(&raw const OWNERS_CAP);
        let ptr = *(&raw const OWNERS_PTR);
        for i in 0..cap {
            let entry = &mut *ptr.add(i);
            if entry.active == 0 {
                *entry = OwnerEntry::empty();
                entry.owner_id = owner_id;
                entry.active = 1;
                return Some(entry);
            }
        }
        // Full — try to grow
        if !owners_grow(cap + OWNER_INITIAL_CAPACITY) {
            return None;
        }
        let new_ptr = *(&raw const OWNERS_PTR);
        let entry = &mut *new_ptr.add(cap);
        entry.owner_id = owner_id;
        entry.active = 1;
        Some(entry)
    }
}

// ---------------------------------------------------------------------------
// Privileged caller set
// ---------------------------------------------------------------------------

const MAX_PRIVILEGED: usize = 8;
static mut PRIVILEGED_OWNERS: [u64; MAX_PRIVILEGED] = [0; MAX_PRIVILEGED];
static mut PRIVILEGED_COUNT: usize = 0;

fn is_privileged(badge: u64) -> bool {
    unsafe {
        if badge == INIT_BADGE {
            return true;
        }
        let count = *(&raw const PRIVILEGED_COUNT);
        let table = &*(&raw const PRIVILEGED_OWNERS);
        for i in 0..count {
            if table[i] == badge {
                return true;
            }
        }
        false
    }
}

unsafe fn add_privileged(owner_id: u64) -> bool {
    unsafe {
        let count = *(&raw const PRIVILEGED_COUNT);
        if count >= MAX_PRIVILEGED {
            return false;
        }
        let table = &mut *(&raw mut PRIVILEGED_OWNERS);
        // Dedupe
        for i in 0..count {
            if table[i] == owner_id {
                return true;
            }
        }
        table[count] = owner_id;
        *(&raw mut PRIVILEGED_COUNT) = count + 1;
        trona::uinfo!(|_lb| {
            _lb.str(b"[RSRCSRV] promoted privileged owner_id=");
            _lb.hex(owner_id);
            _lb.str(b"\n");
        });
        true
    }
}

// ---------------------------------------------------------------------------
// Object byte cost (for quota accounting)
// ---------------------------------------------------------------------------

fn obj_byte_cost(obj_type: u64, size_bits: u64) -> u64 {
    match obj_type {
        OBJ_TCB => 1024,
        OBJ_NOTIFICATION => 64,
        OBJ_ENDPOINT => 64,
        OBJ_SCHED_CONTEXT => 256,
        OBJ_VSPACE => 4096,
        OBJ_CNODE => 32u64 << size_bits,
        OBJ_FRAME => 1u64 << size_bits.max(12),
        OBJ_MEMORY_OBJECT => 256,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Core alloc / free / reclaim primitives
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct AllocResult {
    rsrcsrv_slot: Cap,
    handle: u64,
}

/// Allocate a single object on behalf of `owner_id`. Returns the rsrcsrv-side
/// cap slot (caller will receive it via cap_transfer) and the new handle.
unsafe fn alloc_single(
    owner_id: u64,
    obj_type: u64,
    size_bits: u64,
) -> Result<AllocResult, u64> {
    unsafe {
        // Quota check
        let cost = obj_byte_cost(obj_type, size_bits);
        let owner = match owner_lookup_or_create(owner_id) {
            Some(o) => o,
            None => return Err(TRONA_OUT_OF_MEMORY),
        };
        if owner.max_bytes != 0 && owner.bytes_in_use.saturating_add(cost) > owner.max_bytes {
            return Err(TRONA_OUT_OF_MEMORY);
        }
        if owner.max_handles != 0 && owner.handle_count.saturating_add(1) > owner.max_handles {
            return Err(TRONA_OUT_OF_MEMORY);
        }

        // Reserve a CSpace slot inside rsrcsrv's own CNode
        let rsrcsrv_slot = match recycled_slot_alloc() {
            Some(s) => s,
            None => return Err(TRONA_OUT_OF_MEMORY),
        };

        // Retype the object into our slot
        let err = retype_any(obj_type, size_bits, rsrcsrv_slot);
        if err != 0 {
            recycle_empty_slot(rsrcsrv_slot);
            return Err(TRONA_OUT_OF_MEMORY);
        }

        // Reserve a handle table slot
        let handle_index = match handles_alloc_slot() {
            Some(i) => i,
            None => {
                recycled_cnode_delete(rsrcsrv_slot);
                return Err(TRONA_OUT_OF_MEMORY);
            }
        };

        // Epoch: bump existing epoch (or start at 1) to invalidate stale handles
        let entry = match handle_get(handle_index) {
            Some(e) => e,
            None => {
                recycled_cnode_delete(rsrcsrv_slot);
                return Err(TRONA_OUT_OF_MEMORY);
            }
        };
        let new_epoch = entry.epoch.wrapping_add(1).max(1);

        entry.owner_id = owner_id;
        entry.obj_type = obj_type as u32;
        entry.size_bits = size_bits as u32;
        entry.rsrcsrv_slot = rsrcsrv_slot;
        entry.epoch = new_epoch;
        entry.active = 1;

        owner.bytes_in_use = owner.bytes_in_use.saturating_add(cost);
        owner.handle_count = owner.handle_count.saturating_add(1);

        let count = *(&raw const HANDLES_COUNT);
        *(&raw mut HANDLES_COUNT) = count + 1;
        *(&raw mut HANDLES_NEXT_FREE_HINT) = (handle_index as usize) + 1;

        Ok(AllocResult {
            rsrcsrv_slot,
            handle: make_handle(new_epoch, handle_index),
        })
    }
}

/// Free a single handle. Verifies owner_id and epoch. Revokes the internal
/// back-reference cap (which invalidates all derived caps including the
/// caller's copy), then deletes and recycles the slot.
unsafe fn free_handle_internal(owner_id: u64, handle: u64) -> u64 {
    unsafe {
        let (epoch, index) = split_handle(handle);
        let entry = match handle_get(index) {
            Some(e) => e,
            None => return TRONA_NOT_FOUND,
        };
        if entry.active == 0 || entry.epoch != epoch {
            return TRONA_NOT_FOUND;
        }
        if entry.owner_id != owner_id {
            return TRONA_INSUFFICIENT_RIGHTS;
        }

        let slot = entry.rsrcsrv_slot;
        let entry_owner = entry.owner_id;
        let cost = obj_byte_cost(entry.obj_type as u64, entry.size_bits as u64);

        // Revoke + delete + recycle
        let _ = invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
        recycled_cnode_delete(slot);

        entry.active = 0;
        entry.rsrcsrv_slot = 0;

        let count = *(&raw const HANDLES_COUNT);
        if count > 0 {
            *(&raw mut HANDLES_COUNT) = count - 1;
        }
        if (index as usize) < *(&raw const HANDLES_NEXT_FREE_HINT) {
            *(&raw mut HANDLES_NEXT_FREE_HINT) = index as usize;
        }

        if let Some(o) = owner_lookup(entry_owner) {
            o.bytes_in_use = o.bytes_in_use.saturating_sub(cost);
            if o.handle_count > 0 {
                o.handle_count -= 1;
            }
        }

        TRONA_OK
    }
}

/// Reclaim every handle owned by `owner_id`. Returns the count freed.
unsafe fn reclaim_owner_internal(owner_id: u64) -> u64 {
    unsafe {
        let cap = *(&raw const HANDLES_CAP);
        let ptr = *(&raw const HANDLES_PTR);
        if ptr.is_null() {
            return 0;
        }
        let mut freed: u64 = 0;
        for i in 0..cap {
            let entry = &mut *ptr.add(i);
            if entry.active == 0 || entry.owner_id != owner_id {
                continue;
            }
            let slot = entry.rsrcsrv_slot;
            let cost = obj_byte_cost(entry.obj_type as u64, entry.size_bits as u64);
            let _ = invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
            recycled_cnode_delete(slot);
            entry.active = 0;
            entry.rsrcsrv_slot = 0;
            freed += 1;

            let hcount = *(&raw const HANDLES_COUNT);
            if hcount > 0 {
                *(&raw mut HANDLES_COUNT) = hcount - 1;
            }
            if let Some(o) = owner_lookup(owner_id) {
                o.bytes_in_use = o.bytes_in_use.saturating_sub(cost);
                if o.handle_count > 0 {
                    o.handle_count -= 1;
                }
            }
        }
        // Reset hint to start
        *(&raw mut HANDLES_NEXT_FREE_HINT) = 0;
        // Optionally clear the owner entry if drained
        if let Some(o) = owner_lookup(owner_id) {
            if o.handle_count == 0 && o.bytes_in_use == 0 {
                o.active = 0;
            }
        }
        freed
    }
}

// ---------------------------------------------------------------------------
// Receive slot pool for incoming cap transfers (RES_ADOPT_UNTYPED only)
// ---------------------------------------------------------------------------

const CAP_RECV_SCRATCH: Cap = 15;

unsafe fn arm_recv_scratch() {
    unsafe {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, trona::caps::readiness_ntfn(), 1, 0, 0, 0, 0);
}

fn idle() -> ! {
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

/// Resolve the effective owner_id for a request. Caller may pass 0 to mean
/// "use my own badge", or any other value if they are privileged.
fn resolve_owner(caller_badge: u64, requested: u64) -> Result<u64, u64> {
    if requested == 0 {
        return Ok(caller_badge);
    }
    if requested == caller_badge {
        return Ok(caller_badge);
    }
    if is_privileged(caller_badge) {
        return Ok(requested);
    }
    Err(TRONA_INSUFFICIENT_RIGHTS)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

unsafe fn handle_alloc_object(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let owner_req = (*msg).regs[0];
        let obj_type = (*msg).regs[1];
        let size_bits = (*msg).regs[2];
        let _flags = (*msg).regs[3];

        let owner_id = match resolve_owner(badge, owner_req) {
            Ok(o) => o,
            Err(e) => {
                (*reply).label = e;
                return;
            }
        };

        match alloc_single(owner_id, obj_type, size_bits) {
            Ok(res) => {
                ipc::set_send_cap_ctx(ipc_ctx(), 0, res.rsrcsrv_slot);
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[0] = res.handle;
                (*reply).regs[1] = TRONA_OK;
            }
            Err(e) => {
                (*reply).label = e;
            }
        }
    }
}

const MAX_BATCH: usize = 8;

unsafe fn handle_alloc_batch(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let owner_req = (*msg).regs[0];
        let count = (*msg).regs[1] as usize;

        if count == 0 || count > MAX_BATCH {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let owner_id = match resolve_owner(badge, owner_req) {
            Ok(o) => o,
            Err(e) => {
                (*reply).label = e;
                return;
            }
        };

        let mut allocated: [AllocResult; MAX_BATCH] = [AllocResult { rsrcsrv_slot: 0, handle: 0 }; MAX_BATCH];
        let mut allocated_count = 0;

        for i in 0..count {
            let packed = (*msg).regs[2 + i];
            let obj_type = (packed >> 8) & 0xFF;
            let size_bits = packed & 0xFF;

            match alloc_single(owner_id, obj_type, size_bits) {
                Ok(res) => {
                    allocated[allocated_count] = res;
                    allocated_count += 1;
                }
                Err(e) => {
                    // Rollback all previous allocations in this batch
                    for j in 0..allocated_count {
                        let _ = free_handle_internal(owner_id, allocated[j].handle);
                    }
                    (*reply).label = e;
                    return;
                }
            }
        }

        // Cap transfer all allocated objects
        for i in 0..allocated_count {
            ipc::set_send_cap_ctx(ipc_ctx(), i as i32, allocated[i].rsrcsrv_slot);
        }

        (*reply).label = TRONA_OK;
        (*reply).length = (allocated_count + 1) as u64;
        for i in 0..allocated_count {
            (*reply).regs[i] = allocated[i].handle;
        }
        (*reply).regs[allocated_count] = TRONA_OK;
    }
}

unsafe fn handle_free_handle(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let owner_req = (*msg).regs[0];
        let handle = (*msg).regs[1];

        let owner_id = match resolve_owner(badge, owner_req) {
            Ok(o) => o,
            Err(e) => {
                (*reply).label = e;
                return;
            }
        };

        let status = free_handle_internal(owner_id, handle);
        (*reply).label = status;
    }
}

unsafe fn handle_reclaim_owner(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let owner_req = (*msg).regs[0];
        let owner_id = match resolve_owner(badge, owner_req) {
            Ok(o) => o,
            Err(e) => {
                (*reply).label = e;
                return;
            }
        };

        let freed = reclaim_owner_internal(owner_id);
        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = TRONA_OK;
        (*reply).regs[1] = freed;
    }
}

unsafe fn handle_query_usage(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let owner_req = (*msg).regs[0];
        let owner_id = match resolve_owner(badge, owner_req) {
            Ok(o) => o,
            Err(e) => {
                (*reply).label = e;
                return;
            }
        };

        let (bytes, handles) = match owner_lookup(owner_id) {
            Some(o) => (o.bytes_in_use, o.handle_count),
            None => (0, 0),
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 3;
        (*reply).regs[0] = TRONA_OK;
        (*reply).regs[1] = bytes;
        (*reply).regs[2] = handles;
    }
}

unsafe fn handle_set_quota(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let owner_id = (*msg).regs[0];
        let max_bytes = (*msg).regs[1];
        let mr2 = (*msg).regs[2];
        let promote = (mr2 & RES_QUOTA_FLAG_PROMOTE_PRIVILEGED) != 0;
        let max_handles = mr2 & !RES_QUOTA_FLAG_PROMOTE_PRIVILEGED;

        // Quota changes themselves require privileged caller (init or procmgr)
        // for owners other than self.
        if owner_id != badge && !is_privileged(badge) {
            (*reply).label = TRONA_INSUFFICIENT_RIGHTS;
            return;
        }

        // PROMOTE_PRIVILEGED requires the caller to be init.
        if promote && badge != INIT_BADGE {
            (*reply).label = TRONA_INSUFFICIENT_RIGHTS;
            return;
        }

        let entry = match owner_lookup_or_create(owner_id) {
            Some(e) => e,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        entry.max_bytes = max_bytes;
        entry.max_handles = max_handles;

        if promote {
            if !add_privileged(owner_id) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        (*reply).label = TRONA_OK;
    }
}

unsafe fn handle_adopt_untyped(reply: *mut TronaMsg, badge: u64) {
    unsafe {
        if badge != INIT_BADGE {
            (*reply).label = TRONA_INSUFFICIENT_RIGHTS;
            return;
        }

        // The cap was transferred into CAP_RECV_SCRATCH. Move it to a permanent
        // slot and add it as a UT source.
        let perm_slot = match recycled_slot_alloc() {
            Some(s) => s,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        let err = invoke::cnode_move(
            CAP_SELF_CSPACE,
            perm_slot,
            CAP_SELF_CSPACE,
            CAP_RECV_SCRATCH,
        );
        if err != 0 {
            recycle_empty_slot(perm_slot);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if !adopt_untyped_source(perm_slot) {
            // Pool full — delete the cap
            recycled_cnode_delete(perm_slot);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*reply).label = TRONA_OK;
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[RSRCSRV] SaltyOS resource server starting\n");
    });

    // Set up IPC buffer
    let err = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] FAIL: set IPC buffer err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        idle();
    }
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    // Register the well-known untyped slot positions (slot 7 + 16..31).
    // The kernel resolves caps by slot at retype time, so these can be
    // registered before init has actually filled them; the first
    // RES_ALLOC_OBJECT after init's cnode_move sees a populated source.
    unsafe { init_untyped_pool(); }

    // Bring up MO-backed tracked structures lazily on first use; init the
    // free-slot stack here so handle/owner table grows can recycle slots.
    unsafe { init_free_slot_pool(); }

    // Set up receive slot for incoming cap transfers (RES_ADOPT_UNTYPED).
    unsafe { arm_recv_scratch(); }

    // Signal readiness to init
    signal_ready();
    trona::uinfo!(|_lb| {
        _lb.str(b"[RSRCSRV] ready\n");
    });

    // Initial recv
    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe {
        ipc::recv_ctx(
            ipc_ctx(),
            trona::caps::service_ep(),
            &raw mut msg,
            &raw mut badge,
        )
    };
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] initial recv failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        idle();
    }

    // Server loop
    loop {
        let mut reply = TronaMsg::zeroed();

        unsafe {
            match msg.label {
                RES_ALLOC_OBJECT => handle_alloc_object(&raw const msg, &raw mut reply, badge),
                RES_ALLOC_BATCH => handle_alloc_batch(&raw const msg, &raw mut reply, badge),
                RES_FREE_HANDLE => handle_free_handle(&raw const msg, &raw mut reply, badge),
                RES_RECLAIM_OWNER => handle_reclaim_owner(&raw const msg, &raw mut reply, badge),
                RES_QUERY_USAGE => handle_query_usage(&raw const msg, &raw mut reply, badge),
                RES_SET_QUOTA => handle_set_quota(&raw const msg, &raw mut reply, badge),
                RES_ADOPT_UNTYPED => handle_adopt_untyped(&raw mut reply, badge),
                _ => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[RSRCSRV] unknown label=");
                        _lb.hex(msg.label);
                        _lb.str(b" badge=");
                        _lb.hex(badge);
                        _lb.str(b"\n");
                    });
                    reply.label = TRONA_INVALID_OPERATION;
                }
            }
        }

        unsafe { arm_recv_scratch(); }

        let err = unsafe {
            ipc::reply_recv_ctx(
                ipc_ctx(),
                trona::caps::service_ep(),
                &raw const reply,
                &raw mut msg,
                &raw mut badge,
            )
        };
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[RSRCSRV] reply_recv failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            break;
        }
    }

    idle();
}
