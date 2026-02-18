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

extern crate salty;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

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
/// CNodeBits=14 → 16384 total slots. Reserve last 1024 for cap receives.
const RECV_SLOT_BASE: Cap = 0x3C00; // 15360
const RECV_SLOT_END: Cap = 0x4000; // 16384

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
            let slot = match salty::slot_alloc::slot_alloc() {
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

// ---------------------------------------------------------------------------
// Untyped source tracking
// ---------------------------------------------------------------------------

const MAX_UT_SOURCES: usize = 12;

#[derive(Clone, Copy)]
struct UntypedSource {
    cap: Cap,
    active: bool,
}

impl UntypedSource {
    const fn empty() -> Self {
        UntypedSource {
            cap: 0,
            active: false,
        }
    }
}

static mut UT_SOURCES: [UntypedSource; MAX_UT_SOURCES] = {
    const E: UntypedSource = UntypedSource::empty();
    [E; MAX_UT_SOURCES]
};
static mut UT_COUNT: usize = 0;
static mut UT_HINT: usize = 0;

// ---------------------------------------------------------------------------
// Per-page region tracking
// ---------------------------------------------------------------------------

const REGION_HEAP: u8 = 0;
const REGION_MMAP: u8 = 1;
const REGION_SPAWN: u8 = 2;
const REGION_INITIAL_CAP: usize = 8;

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

unsafe fn register_tracked_region(
    client: *mut MmClient,
    base: u64,
    page_count: usize,
    flags: u64,
    region_type: u8,
    frame_caps: *mut Cap,
    frame_count: usize,
) -> bool {
    unsafe {
        if page_count == 0 || frame_caps.is_null() {
            return false;
        }
        if page_count > u16::MAX as usize || frame_count > u16::MAX as usize {
            return false;
        }

        let region = client_add_region(client);
        if region.is_null() {
            return false;
        }

        (*region).base = base;
        (*region).length = page_count as u64 * 4096;
        (*region).prot = vspace_flags_to_prot(flags);
        (*region).region_type = region_type;
        (*region).active = true;
        (*region).lazy = false;
        (*region).frame_caps = frame_caps;
        (*region).frame_count = frame_count as u16;
        (*region).frame_cap_capacity = page_count as u16;
        true
    }
}
const HEAP_INITIAL_FRAME_CAP: usize = 64;

#[derive(Clone, Copy)]
struct MmRegion {
    base: u64,
    length: u64,
    prot: u8,
    region_type: u8,
    active: bool,
    lazy: bool,  // true = demand-paged, frames allocated on fault
    frame_caps: *mut Cap,
    frame_count: u16,
    frame_cap_capacity: u16,
}

impl MmRegion {
    const fn zeroed() -> Self {
        MmRegion {
            base: 0,
            length: 0,
            prot: 0,
            region_type: 0,
            active: false,
            lazy: false,
            frame_caps: core::ptr::null_mut(),
            frame_count: 0,
            frame_cap_capacity: 0,
        }
    }
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

#[derive(Clone, Copy)]
struct MmClient {
    badge: u64,
    pid: u32,
    active: bool,
    /// Cap slot in mmsrv's CSpace holding the client's VSpace cap.
    vspace_cap: Cap,
    heap_base: u64,
    heap_current: u64,
    mmap_next: u64,
    regions: *mut MmRegion,
    region_count: usize,
    region_cap: usize,
}

impl MmClient {
    const fn zeroed() -> Self {
        MmClient {
            badge: 0,
            pid: 0,
            active: false,
            vspace_cap: 0,
            heap_base: 0,
            heap_current: 0,
            mmap_next: 0,
            regions: core::ptr::null_mut(),
            region_count: 0,
            region_cap: 0,
        }
    }
}

static mut CLIENTS_PTR: *mut MmClient = core::ptr::null_mut();
static mut CLIENTS_CAP: usize = 0;
static mut CLIENT_COUNT: usize = 0;

/// Receive slot tracking: NEXT_RECV_SLOT is the bump allocator pointer,
/// CURRENT_RECV_SLOT is the slot configured for the current recv operation,
/// RECV_SLOT_KEPT indicates if the handler permanently kept the cap.
static mut NEXT_RECV_SLOT: Cap = RECV_SLOT_BASE;
static mut CURRENT_RECV_SLOT: Cap = 0;
static mut RECV_SLOT_KEPT: bool = false;

// ---------------------------------------------------------------------------
// SHM object tracking (growable, pointer-based)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct ShmObject {
    id: u64,
    active: bool,
    page_count: u16,
    frame_caps: *mut Cap,
    frame_cap_capacity: u16,
}

impl ShmObject {
    const fn zeroed() -> Self {
        ShmObject {
            id: 0,
            active: false,
            page_count: 0,
            frame_caps: core::ptr::null_mut(),
            frame_cap_capacity: 0,
        }
    }
}

static mut SHM_PTR: *mut ShmObject = core::ptr::null_mut();
static mut SHM_CAP: usize = 0;

unsafe fn find_shm_by_id(id: u64) -> *mut ShmObject {
    unsafe {
        let ptr = *(&raw const SHM_PTR);
        let cap = *(&raw const SHM_CAP);
        for i in 0..cap {
            let obj = ptr.add(i);
            if (*obj).active && (*obj).id == id {
                return obj;
            }
        }
        core::ptr::null_mut()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Retype an object from any available untyped source (round-robin scan).
unsafe fn retype_any(obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
    unsafe {
        let ut_count = *(&raw const UT_COUNT);
        if ut_count == 0 {
            return SALTY_OUT_OF_MEMORY as i32;
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

        SALTY_OUT_OF_MEMORY as i32
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
        let mut msg = SaltyMsg::zeroed();
        msg.label = POSIX_NS_REGISTER;
        msg.length = 1 + ((name.len() + 7) / 8) as u64;
        msg.regs[0] = name.len() as u64;
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            core::ptr::write(dst.add(i), name[i]);
        }

        // Send our server EP cap
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);

        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
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

// ---------------------------------------------------------------------------
// Client lookup
// ---------------------------------------------------------------------------

unsafe fn find_client_by_badge(badge: u64) -> *mut MmClient {
    unsafe {
        let ptr = *(&raw const CLIENTS_PTR);
        let cap = *(&raw const CLIENTS_CAP);
        for i in 0..cap {
            let c = ptr.add(i);
            if (*c).active && (*c).badge == badge {
                return c;
            }
        }
        core::ptr::null_mut()
    }
}

/// Find or grow a free client slot. Returns pointer to free slot or null.
unsafe fn find_free_client_slot() -> *mut MmClient {
    unsafe {
        let mut ptr = *(&raw const CLIENTS_PTR);
        let mut cap = *(&raw const CLIENTS_CAP);
        for i in 0..cap {
            let c = ptr.add(i);
            if !(*c).active {
                return c;
            }
        }
        // Grow: double capacity
        let new_cap = cap * 2;
        let new_bytes = new_cap * core::mem::size_of::<MmClient>();
        let new_pages = (new_bytes + 4095) / 4096;
        let new_ptr = self_mmap(new_pages);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }
        let new_ptr = new_ptr as *mut MmClient;
        // Copy old entries
        for i in 0..cap {
            *new_ptr.add(i) = *ptr.add(i);
        }
        // First free slot is at old cap
        let free = new_ptr.add(cap);
        *(&raw mut CLIENTS_PTR) = new_ptr;
        *(&raw mut CLIENTS_CAP) = new_cap;
        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] clients grown to ");
            lb.hex(new_cap as u64);
            lb.str(b"\n");
            lb.flush();
        }
        free
    }
}

/// Add a region to a client. Returns pointer to the new region or null.
unsafe fn client_add_region(client: *mut MmClient) -> *mut MmRegion {
    unsafe {
        let count = (*client).region_count;
        let cap = (*client).region_cap;

        if count >= cap {
            // Grow regions array
            let new_cap = if cap == 0 { REGION_INITIAL_CAP } else { cap * 2 };
            let new_bytes = new_cap * core::mem::size_of::<MmRegion>();
            let new_pages = (new_bytes + 4095) / 4096;
            let new_pages = if new_pages == 0 { 1 } else { new_pages };
            let new_ptr = self_mmap(new_pages);
            if new_ptr.is_null() {
                return core::ptr::null_mut();
            }
            let new_ptr = new_ptr as *mut MmRegion;
            // Copy old regions
            let old_ptr = (*client).regions;
            if !old_ptr.is_null() {
                for i in 0..count {
                    *new_ptr.add(i) = *old_ptr.add(i);
                }
            }
            (*client).regions = new_ptr;
            (*client).region_cap = new_cap;
        }

        let region = (*client).regions.add(count);
        *region = MmRegion::zeroed();
        (*client).region_count = count + 1;
        region
    }
}

/// Find the region containing `addr` in a client's region list.
unsafe fn find_region_by_addr(client: *mut MmClient, addr: u64) -> *mut MmRegion {
    unsafe {
        let count = (*client).region_count;
        let regions = (*client).regions;
        if regions.is_null() {
            return core::ptr::null_mut();
        }
        for i in 0..count {
            let r = regions.add(i);
            if (*r).active && addr >= (*r).base && addr < (*r).base + (*r).length {
                return r;
            }
        }
        core::ptr::null_mut()
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

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

/// MM_REGISTER: init/procmgr registers a new client.
///   MR0 = client badge
///   MR1 = heap_base
///   MR2 = mmap_base
///   MR3 = pid
///   + cap transfer: client's VSpace cap
unsafe fn handle_mm_register(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let heap_base = (*msg).regs[1];
        let mmap_base = (*msg).regs[2];
        let pid = (*msg).regs[3] as u32;

        if client_badge == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        if !find_client_by_badge(client_badge).is_null() {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] REGISTER: duplicate badge=");
            lb.hex(client_badge);
            lb.str(b"\n");
            lb.flush();
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Find free slot in client table (grows if needed)
        let slot = find_free_client_slot();
        if slot.is_null() {
            puts(b"[MMSRV] REGISTER: client table full, grow failed\n");
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // The VSpace cap was transferred into the current receive slot.
        let vspace_cap = *(&raw const CURRENT_RECV_SLOT);

        *slot = MmClient {
            badge: client_badge,
            pid,
            active: true,
            vspace_cap,
            heap_base,
            heap_current: heap_base,
            mmap_next: mmap_base,
            regions: core::ptr::null_mut(),
            region_count: 0,
            region_cap: 0,
        };
        *(&raw mut CLIENT_COUNT) += 1;

        // This handler permanently keeps the VSpace cap
        mark_recv_slot_kept();

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] registered client badge=");
            lb.hex(client_badge);
            lb.str(b" pid=");
            lb.hex(pid as u64);
            lb.str(b" heap=");
            lb.hex(heap_base);
            lb.str(b" mmap=");
            lb.hex(mmap_base);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_DEREGISTER: procmgr removes a client on exit.
///   MR0 = client badge
unsafe fn handle_mm_deregister(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let pid = (*client).pid;
        let vspace_cap = (*client).vspace_cap;

        // Clean up all frame caps tracked in client regions
        let region_count = (*client).region_count;
        let regions = (*client).regions;
        if !regions.is_null() {
            for ri in 0..region_count {
                let r = regions.add(ri);
                if (*r).active {
                    let fcaps = (*r).frame_caps;
                    if !fcaps.is_null() {
                        for fi in 0..(*r).frame_count as usize {
                            let fc = *fcaps.add(fi);
                            if fc != 0 {
                                invoke::cnode_delete(CAP_SELF_CSPACE, fc);
                            }
                        }
                    }
                    (*r).active = false;
                }
            }
        }

        // Clean up the VSpace cap we hold
        if vspace_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, vspace_cap);
        }

        (*client).active = false;
        (*client).badge = 0;
        *(&raw mut CLIENT_COUNT) -= 1;

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] deregistered client badge=");
            lb.hex(client_badge);
            lb.str(b" pid=");
            lb.hex(pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_MMAP: client requests anonymous mmap.
///   MR0 = addr hint (0=auto)
///   MR1 = length
///   MR2 = prot
///   MR3 = flags
///   Badge identifies the client.
///   Reply: MR0 = mapped base address
unsafe fn handle_mm_mmap(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let _addr_hint = (*msg).regs[0];
        let length = (*msg).regs[1];
        let _prot = (*msg).regs[2] as i32;
        let _flags = (*msg).regs[3] as i32;

        if length == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };
        let num_pages = (len / 4096) as usize;
        let vspace_cap = (*client).vspace_cap;
        let base = (*client).mmap_next;

        // Map flags
        let mut map_flags = VSPACE_FLAG_USER;
        if _prot & PROT_WRITE != 0 {
            map_flags |= VSPACE_FLAG_WRITABLE;
        }
        if _prot & PROT_EXEC != 0 {
            map_flags |= VSPACE_FLAG_EXECUTABLE;
        }

        // Create region to track frame caps
        let region = client_add_region(client);
        if region.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let fcaps = alloc_frame_cap_array(num_pages);
        if fcaps.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }
        (*region).base = base;
        (*region).length = len;
        (*region).prot = _prot as u8;
        (*region).region_type = REGION_MMAP;
        (*region).active = true;
        (*region).frame_caps = fcaps;
        (*region).frame_count = 0;
        (*region).frame_cap_capacity = num_pages as u16;

        // Check for MAP_LAZY flag
        let is_lazy = (_flags & MAP_LAZY) != 0;
        (*region).lazy = is_lazy;

        if is_lazy {
            // Lazy path: VA reservation only, no frame allocation
            // All frame_caps entries are 0 (unallocated sentinel)
            // First access triggers VMFault → mmsrv maps one page → resume
            (*client).mmap_next = base + len;
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = base;
            return;
        }

        // Eager path: Allocate and map each page immediately
        for i in 0..num_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => {
                    for j in 0..i {
                        invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                    }
                    (*region).active = false;
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            };

            let err = retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                }
                (*region).active = false;
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }

            let err = invoke::vspace_map(vspace_cap, frame_slot, base + i as u64 * 4096, map_flags);
            if err != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                }
                (*region).active = false;
                (*reply).label = SALTY_BAD_ADDRESS;
                return;
            }

            *fcaps.add(i) = frame_slot;
            (*region).frame_count = (i + 1) as u16;
        }

        (*client).mmap_next = base + len;

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = base;
    }
}

/// MM_BRK: client sets program break.
///   MR0 = new break address
///   Badge identifies the client.
unsafe fn handle_mm_brk(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let new_brk = (*msg).regs[0];
        if new_brk < (*client).heap_base {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let old_page = ((*client).heap_current + 4095) & !4095u64;
        let new_page = (new_brk + 4095) & !4095u64;
        let vspace_cap = (*client).vspace_cap;

        // Find or create heap region
        let mut heap_region = core::ptr::null_mut::<MmRegion>();
        {
            let count = (*client).region_count;
            let regions = (*client).regions;
            if !regions.is_null() {
                for ri in 0..count {
                    let r = regions.add(ri);
                    if (*r).active && (*r).region_type == REGION_HEAP {
                        heap_region = r;
                        break;
                    }
                }
            }
        }
        if heap_region.is_null() {
            heap_region = client_add_region(client);
            if heap_region.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let fcaps = alloc_frame_cap_array(HEAP_INITIAL_FRAME_CAP);
            if fcaps.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            (*heap_region).base = (*client).heap_base;
            (*heap_region).length = 0;
            (*heap_region).prot = (PROT_READ | PROT_WRITE) as u8;
            (*heap_region).region_type = REGION_HEAP;
            (*heap_region).active = true;
            (*heap_region).frame_caps = fcaps;
            (*heap_region).frame_count = 0;
            (*heap_region).frame_cap_capacity = HEAP_INITIAL_FRAME_CAP as u16;
        }

        if new_page > old_page {
            let grow_pages = ((new_page - old_page) / 4096) as usize;
            let new_total = (*heap_region).frame_count as usize + grow_pages;

            // Grow frame_caps array if needed
            if new_total > (*heap_region).frame_cap_capacity as usize {
                let mut new_fcap = (*heap_region).frame_cap_capacity as usize * 2;
                while new_fcap < new_total {
                    new_fcap *= 2;
                }
                let new_ptr = grow_frame_cap_array(
                    (*heap_region).frame_caps,
                    (*heap_region).frame_count as usize,
                    new_fcap,
                );
                if new_ptr.is_null() {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                (*heap_region).frame_caps = new_ptr;
                (*heap_region).frame_cap_capacity = new_fcap as u16;
            }

            // Grow: allocate and map new pages
            let mut va = old_page;
            let mut page_idx = (*heap_region).frame_count as usize;
            while va < new_page {
                let frame_slot = match salty::slot_alloc::slot_alloc() {
                    Some(s) => s,
                    None => {
                        let mut rva = old_page;
                        while rva < va {
                            invoke::vspace_unmap(vspace_cap, rva);
                            rva += 4096;
                        }
                        (*heap_region).frame_count = ((old_page - (*heap_region).base) / 4096) as u16;
                        (*reply).label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                };

                let err = retype_any(OBJ_FRAME, 0, frame_slot);
                if err != 0 {
                    let mut rva = old_page;
                    while rva < va {
                        invoke::vspace_unmap(vspace_cap, rva);
                        rva += 4096;
                    }
                    (*heap_region).frame_count = ((old_page - (*heap_region).base) / 4096) as u16;
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                let err = invoke::vspace_map(
                    vspace_cap,
                    frame_slot,
                    va,
                    VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                );
                if err != 0 {
                    invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                    let mut rva = old_page;
                    while rva < va {
                        invoke::vspace_unmap(vspace_cap, rva);
                        rva += 4096;
                    }
                    (*heap_region).frame_count = ((old_page - (*heap_region).base) / 4096) as u16;
                    (*reply).label = SALTY_BAD_ADDRESS;
                    return;
                }
                *(*heap_region).frame_caps.add(page_idx) = frame_slot;
                page_idx += 1;
                va += 4096;
            }
            (*heap_region).frame_count = page_idx as u16;
            (*heap_region).length = new_page - (*heap_region).base;
        } else if new_page < old_page {
            // Shrink: unmap freed pages and clean up frame caps
            let shrink_pages = ((old_page - new_page) / 4096) as usize;
            let old_count = (*heap_region).frame_count as usize;
            let new_count = if old_count >= shrink_pages { old_count - shrink_pages } else { 0 };

            let mut va = new_page;
            let mut idx = new_count;
            while va < old_page && idx < old_count {
                let fcap = *(*heap_region).frame_caps.add(idx);
                invoke::vspace_unmap(vspace_cap, va);
                if fcap != 0 {
                    invoke::cnode_delete(CAP_SELF_CSPACE, fcap);
                }
                va += 4096;
                idx += 1;
            }
            (*heap_region).frame_count = new_count as u16;
            (*heap_region).length = new_page - (*heap_region).base;
        }

        (*client).heap_current = new_brk;
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_brk;
    }
}

/// MM_SBRK: client increments break.
///   MR0 = increment (signed as u64)
///   Badge identifies the client.
///   Reply: MR0 = old break address
unsafe fn handle_mm_sbrk(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let increment = (*msg).regs[0] as i64;
        let old_break = (*client).heap_current;

        if increment == 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = old_break;
            return;
        }

        let new_break = if increment > 0 {
            old_break + increment as u64
        } else {
            let dec = (-increment) as u64;
            if dec > old_break - (*client).heap_base {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            old_break - dec
        };

        // Delegate to brk handler
        let mut brk_msg = SaltyMsg::zeroed();
        brk_msg.regs[0] = new_break;
        handle_mm_brk(&raw const brk_msg, badge, reply);

        // On success, return old break in MR0
        if (*reply).label == SALTY_OK {
            (*reply).regs[0] = old_break;
        }
    }
}

/// MM_MUNMAP: client unmaps a region.
///   MR0 = base address
///   MR1 = length
///   Badge identifies the client.
unsafe fn handle_mm_munmap(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let base = (*msg).regs[0];
        let length = (*msg).regs[1];
        let vspace_cap = (*client).vspace_cap;

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };
        let num_pages = (len / 4096) as usize;

        // Look up region for frame cap cleanup
        let region = find_region_by_addr(client, base);
        if !region.is_null() && (*region).active {
            // Unmap with frame cap cleanup
            let region_start_page = ((base - (*region).base) / 4096) as usize;
            for i in 0..num_pages {
                let page_idx = region_start_page + i;
                invoke::vspace_unmap(vspace_cap, base + i as u64 * 4096);
                if page_idx < (*region).frame_count as usize {
                    let fcap = *(*region).frame_caps.add(page_idx);
                    if fcap != 0 {
                        invoke::cnode_delete(CAP_SELF_CSPACE, fcap);
                        *(*region).frame_caps.add(page_idx) = 0;
                    }
                }
            }
            // If entire region unmapped, mark inactive
            if base == (*region).base && len >= (*region).length {
                (*region).active = false;
            }
        } else {
            // No region tracking — just unmap
            for i in 0..num_pages {
                invoke::vspace_unmap(vspace_cap, base + i as u64 * 4096);
            }
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_MPROTECT: client changes protection on a mapped region.
///   MR0 = base address
///   MR1 = length
///   MR2 = prot (PROT_READ/WRITE/EXEC)
///   Badge identifies the client.
///
/// Uses per-page frame cap tracking: unmap each page and remap with new flags.
unsafe fn handle_mm_mprotect(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let addr = (*msg).regs[0];
        let length = (*msg).regs[1];
        let prot = (*msg).regs[2] as u8;

        let region = find_region_by_addr(client, addr);
        if region.is_null() || !(*region).active {
            // No region tracking for this address — accept silently
            (*reply).label = SALTY_OK;
            return;
        }

        // Convert PROT_* → VSPACE_FLAG_*
        let mut flags = VSPACE_FLAG_USER;
        if prot & PROT_WRITE as u8 != 0 {
            flags |= VSPACE_FLAG_WRITABLE;
        }
        if prot & PROT_EXEC as u8 != 0 {
            flags |= VSPACE_FLAG_EXECUTABLE;
        }

        let vspace_cap = (*client).vspace_cap;
        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };
        let start_page = ((addr - (*region).base) / 4096) as usize;
        let page_count = (len / 4096) as usize;

        for i in 0..page_count {
            let page_idx = start_page + i;
            if page_idx >= (*region).frame_count as usize {
                break;
            }
            let frame_cap = *(*region).frame_caps.add(page_idx);
            if frame_cap == 0 {
                continue;
            }
            let page_va = (*region).base + page_idx as u64 * 4096;
            invoke::vspace_unmap(vspace_cap, page_va);
            invoke::vspace_map(vspace_cap, frame_cap, page_va, flags);
        }

        (*region).prot = prot;
        (*reply).label = SALTY_OK;
    }
}

/// MM_MAP_WINDOW: procmgr creates dual-mapped write window.
///   MR0 = target client badge
///   MR1 = target start vaddr
///   MR2 = window vaddr in caller's VSpace
///   MR3 = num_pages
///   MR4 = vspace flags for target mapping
///   + cap transfer: caller's VSpace cap
///   Reply: MR0 = pages_mapped
unsafe fn handle_mm_map_window(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let target_vaddr = (*msg).regs[1];
        let window_vaddr = (*msg).regs[2];
        let num_pages = (*msg).regs[3] as usize;
        let target_flags = (*msg).regs[4];

        let caller_vspace_cap = *(&raw const CURRENT_RECV_SLOT);

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            invoke::cnode_delete(CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let target_vspace_cap = (*client).vspace_cap;
        let mut mapped: usize = 0;

        // Track frame caps for rollback/region registration.
        const MAX_WINDOW_PAGES: usize = 512;
        let mut frame_caps: [Cap; MAX_WINDOW_PAGES] = [0; MAX_WINDOW_PAGES];
        let effective_pages = if num_pages > MAX_WINDOW_PAGES { MAX_WINDOW_PAGES } else { num_pages };

        for i in 0..effective_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };

            let err = retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                break;
            }

            let err = invoke::vspace_map(
                target_vspace_cap, frame_slot,
                target_vaddr + i as u64 * 4096, target_flags,
            );
            if err != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                break;
            }

            let err = invoke::vspace_map(
                caller_vspace_cap, frame_slot,
                window_vaddr + i as u64 * 4096,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                break;
            }

            frame_caps[i] = frame_slot;
            mapped += 1;
        }

        // On partial failure (mapped < requested), roll back all mappings
        // to avoid leaking frames that aren't tracked anywhere
        if mapped > 0 && mapped < effective_pages {
            for i in 0..mapped {
                invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
                if frame_caps[i] != 0 {
                    invoke::cnode_delete(CAP_SELF_CSPACE, frame_caps[i]);
                }
            }
            mapped = 0;
        }

        if mapped > 0 {
            let tracked_caps = alloc_frame_cap_array(mapped);
            if tracked_caps.is_null() {
                for i in 0..mapped {
                    invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                    invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
                    if frame_caps[i] != 0 {
                        invoke::cnode_delete(CAP_SELF_CSPACE, frame_caps[i]);
                    }
                }
                invoke::cnode_delete(CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }

            for i in 0..mapped {
                *tracked_caps.add(i) = frame_caps[i];
            }

            if !register_tracked_region(
                client,
                target_vaddr,
                mapped,
                target_flags,
                REGION_SPAWN,
                tracked_caps,
                mapped,
            ) {
                for i in 0..mapped {
                    invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                    invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
                    let frame = *tracked_caps.add(i);
                    if frame != 0 {
                        invoke::cnode_delete(CAP_SELF_CSPACE, frame);
                    }
                }
                invoke::cnode_delete(CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        invoke::cnode_delete(CAP_SELF_CSPACE, caller_vspace_cap);

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = mapped as u64;
    }
}

/// MM_UNMAP_WINDOW: procmgr removes write window from caller's VSpace.
///   MR0 = window vaddr in caller
///   MR1 = num_pages
///   + cap transfer: caller's VSpace cap
///   Reply: label = SALTY_OK
///
/// Frame caps stay in mmsrv's CSpace; target mapping persists after
/// window removal.
unsafe fn handle_mm_unmap_window(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let window_vaddr = (*msg).regs[0];
        let num_pages = (*msg).regs[1] as usize;

        // The caller's VSpace cap was transferred into the current receive slot.
        let caller_vspace_cap = *(&raw const CURRENT_RECV_SLOT);

        for i in 0..num_pages {
            invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
        }

        // Delete transient caller VSpace cap
        invoke::cnode_delete(CAP_SELF_CSPACE, caller_vspace_cap);

        (*reply).label = SALTY_OK;
    }
}

/// MM_FORK_REGIONS: procmgr clones parent's region state to child.
///   MR0 = parent client badge
///   MR1 = child client badge
///
/// Copies parent's heap_base, heap_current, and mmap_next to the child
/// client entry (which must already exist via MM_REGISTER).
unsafe fn handle_mm_fork_regions(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];

        let parent = find_client_by_badge(parent_badge);
        if parent.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let child = find_client_by_badge(child_badge);
        if child.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // Clone parent's memory layout
        (*child).heap_base = (*parent).heap_base;
        (*child).heap_current = (*parent).heap_current;
        (*child).mmap_next = (*parent).mmap_next;

        // Deep-copy parent's region list (without frame caps — COW-managed)
        let parent_rc = (*parent).region_count;
        let parent_regions = (*parent).regions;
        if !parent_regions.is_null() && parent_rc > 0 {
            let child_region_cap = if parent_rc > REGION_INITIAL_CAP {
                parent_rc
            } else {
                REGION_INITIAL_CAP
            };
            let bytes = child_region_cap * core::mem::size_of::<MmRegion>();
            let pages = if bytes == 0 { 1 } else { (bytes + 4095) / 4096 };
            let ptr = self_mmap(pages);
            if !ptr.is_null() {
                let child_regions = ptr as *mut MmRegion;
                for ri in 0..parent_rc {
                    let pr = &*parent_regions.add(ri);
                    let mut cr = MmRegion::zeroed();
                    cr.base = pr.base;
                    cr.length = pr.length;
                    cr.prot = pr.prot;
                    cr.region_type = pr.region_type;
                    cr.active = pr.active;
                    // frame_caps left null — inherited via kernel COW
                    *child_regions.add(ri) = cr;
                }
                (*child).regions = child_regions;
                (*child).region_count = parent_rc;
                (*child).region_cap = child_region_cap;
            }
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] fork-regions parent=");
            lb.hex(parent_badge);
            lb.str(b" child=");
            lb.hex(child_badge);
            lb.str(b" heap=");
            lb.hex((*parent).heap_current);
            lb.str(b" mmap=");
            lb.hex((*parent).mmap_next);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_SHM_CREATE: allocate frames for a SHM object.
///   MR0 = shm_id
///   MR1 = num_pages
///   Reply: label = SALTY_OK or error
unsafe fn handle_mm_shm_create(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let num_pages = (*msg).regs[1] as usize;

        if num_pages == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        if !find_shm_by_id(shm_id).is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Find free slot in SHM table (grow if needed)
        let mut shm_ptr = *(&raw const SHM_PTR);
        let mut shm_cap = *(&raw const SHM_CAP);
        let mut free_slot: *mut ShmObject = core::ptr::null_mut();
        for i in 0..shm_cap {
            let obj = shm_ptr.add(i);
            if !(*obj).active {
                free_slot = obj;
                break;
            }
        }
        if free_slot.is_null() {
            // Grow
            let new_cap = shm_cap * 2;
            let new_bytes = new_cap * core::mem::size_of::<ShmObject>();
            let new_pages = (new_bytes + 4095) / 4096;
            let new_pages = if new_pages == 0 { 1 } else { new_pages };
            let new_ptr = self_mmap(new_pages);
            if new_ptr.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let new_ptr = new_ptr as *mut ShmObject;
            for i in 0..shm_cap {
                *new_ptr.add(i) = *shm_ptr.add(i);
            }
            free_slot = new_ptr.add(shm_cap);
            *(&raw mut SHM_PTR) = new_ptr;
            *(&raw mut SHM_CAP) = new_cap;
        }

        // Allocate frame_caps array
        let fcaps = alloc_frame_cap_array(num_pages);
        if fcaps.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Allocate frames
        for i in 0..num_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => {
                    for j in 0..i {
                        invoke::cnode_delete(CAP_SELF_CSPACE, *fcaps.add(j));
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            };
            let err = retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                for j in 0..i {
                    invoke::cnode_delete(CAP_SELF_CSPACE, *fcaps.add(j));
                }
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            *fcaps.add(i) = frame_slot;
        }

        *free_slot = ShmObject {
            id: shm_id,
            active: true,
            page_count: num_pages as u16,
            frame_caps: fcaps,
            frame_cap_capacity: num_pages as u16,
        };

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] SHM create id=");
            lb.hex(shm_id);
            lb.str(b" pages=");
            lb.hex(num_pages as u64);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_SHM_MAP: map SHM frames into a client's VSpace.
///   MR0 = shm_id
///   MR1 = client badge
///   MR2 = vaddr
///   MR3 = prot (vspace flags)
///   Reply: label = SALTY_OK, MR0 = mapped_base
unsafe fn handle_mm_shm_map(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_badge = (*msg).regs[1];
        let requested_vaddr = (*msg).regs[2];
        let flags = (*msg).regs[3];

        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // Auto-pick vaddr from client's mmap region when caller passes 0
        let actual_vaddr = if requested_vaddr == 0 {
            (*client).mmap_next
        } else {
            requested_vaddr
        };

        let vspace_cap = (*client).vspace_cap;
        let page_count = (*shm).page_count as usize;

        for i in 0..page_count {
            let err = invoke::vspace_map(
                vspace_cap,
                *(*shm).frame_caps.add(i),
                actual_vaddr + i as u64 * 4096,
                flags,
            );
            if err != 0 {
                // Rollback mapped pages
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, actual_vaddr + j as u64 * 4096);
                }
                (*reply).label = SALTY_BAD_ADDRESS;
                return;
            }
        }

        // Advance mmap_next if auto-placed
        if requested_vaddr == 0 {
            (*client).mmap_next = actual_vaddr + page_count as u64 * 4096;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual_vaddr;
    }
}

/// MM_SHM_UNMAP: unmap SHM frames from a client's VSpace.
///   MR0 = shm_id
///   MR1 = client badge
///   MR2 = vaddr (base address of the mapping)
///   Reply: label = SALTY_OK
unsafe fn handle_mm_shm_unmap(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_badge = (*msg).regs[1];
        let vaddr = (*msg).regs[2];

        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // Unmap each SHM page from the client's VSpace
        if vaddr != 0 {
            let vspace_cap = (*client).vspace_cap;
            for i in 0..(*shm).page_count as usize {
                invoke::vspace_unmap(vspace_cap, vaddr + i as u64 * 4096);
            }
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_MAP_BATCH: procmgr batch-maps N frames for spawn.
///   MR0 = target client badge
///   MR1 = start vaddr
///   MR2 = num_pages
///   MR3 = vspace flags
///   Reply: MR0 = pages_mapped
unsafe fn handle_mm_map_batch(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let start_vaddr = (*msg).regs[1];
        let num_pages = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let vspace_cap = (*client).vspace_cap;
        let mut mapped: usize = 0;

        if num_pages == 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let tracked_caps = alloc_frame_cap_array(num_pages);
        if tracked_caps.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for i in 0..num_pages {
            *tracked_caps.add(i) = 0;
        }

        for i in 0..num_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };

            let err = retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                break;
            }

            let err = invoke::vspace_map(
                vspace_cap,
                frame_slot,
                start_vaddr + i as u64 * 4096,
                flags,
            );
            if err != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                break;
            }
            *tracked_caps.add(i) = frame_slot;
            mapped += 1;
        }

        if mapped > 0 {
            if !register_tracked_region(
                client,
                start_vaddr,
                mapped,
                flags,
                REGION_SPAWN,
                tracked_caps,
                mapped,
            ) {
                for i in 0..mapped {
                    invoke::vspace_unmap(vspace_cap, start_vaddr + i as u64 * 4096);
                    let frame = *tracked_caps.add(i);
                    if frame != 0 {
                        invoke::cnode_delete(CAP_SELF_CSPACE, frame);
                        *tracked_caps.add(i) = 0;
                    }
                }
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = mapped as u64;
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
        let base = *(&raw const salty::__salty_slot_base);
        let count = *(&raw const salty::__salty_slot_count);
        let cspace_ntfn = *(&raw const salty::__salty_cspace_ntfn);
        if base != 0 {
            salty::slot_alloc::slot_alloc_init(base, count, cspace_ntfn);
        } else {
            puts(b"[MMSRV] FATAL: slot pool not provided by RTLD/auxv\n");
            idle();
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
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        puts(b"[MMSRV] initial recv failed\n");
        idle();
    }

    // Server loop
    loop {
        let mut reply = SaltyMsg::zeroed();
        // Set to true for unrecoverable faults: use recv() instead of reply_recv()
        // so the faulting thread stays permanently blocked rather than re-faulting.
        let mut skip_reply = false;

        unsafe {
            match msg.label {
                MM_REGISTER => handle_mm_register(&raw const msg, badge, &raw mut reply),
                MM_DEREGISTER => handle_mm_deregister(&raw const msg, badge, &raw mut reply),
                MM_BRK => handle_mm_brk(&raw const msg, badge, &raw mut reply),
                MM_SBRK => handle_mm_sbrk(&raw const msg, badge, &raw mut reply),
                MM_MMAP => handle_mm_mmap(&raw const msg, badge, &raw mut reply),
                MM_MUNMAP => handle_mm_munmap(&raw const msg, badge, &raw mut reply),
                MM_MPROTECT => handle_mm_mprotect(&raw const msg, badge, &raw mut reply),
                MM_MAP_BATCH => handle_mm_map_batch(&raw const msg, badge, &raw mut reply),
                MM_MAP_WINDOW => handle_mm_map_window(&raw const msg, badge, &raw mut reply),
                MM_UNMAP_WINDOW => handle_mm_unmap_window(&raw const msg, badge, &raw mut reply),
                MM_FORK_REGIONS => handle_mm_fork_regions(&raw const msg, badge, &raw mut reply),
                MM_SHM_CREATE => handle_mm_shm_create(&raw const msg, badge, &raw mut reply),
                MM_SHM_MAP => handle_mm_shm_map(&raw const msg, badge, &raw mut reply),
                MM_SHM_UNMAP => handle_mm_shm_unmap(&raw const msg, badge, &raw mut reply),
                // VMFault: label=2 from kernel FaultType::VMFault.
                // Badge identifies the faulting client. Replying resumes the faulting thread.
                //
                // All error paths break out of 'fault without using `continue` so that
                // reply_recv_ctx (or recv for unrecoverable faults) is always reached.
                2 => {
                    let fault_addr = msg.regs[0];
                    let _error_code = msg.regs[1];
                    let _fault_rip = msg.regs[2];
                    let page_addr = fault_addr & !0xFFFu64;

                    'fault: {
                        // 1. Find client by badge
                        let client = find_client_by_badge(badge);
                        if client.is_null() {
                            let mut lb = LineBuf::new();
                            lb.str(b"[MMSRV] VMFault: unknown client badge=");
                            lb.hex(badge);
                            lb.str(b"\n");
                            lb.flush();
                            reply.label = SALTY_INVALID_OPERATION;
                            break 'fault;
                        }

                        // 2. Find region containing fault_addr
                        let region = find_region_by_addr(client, page_addr);
                        if region.is_null() {
                            // No region covers this address — segfault.
                            // Don't reply: leave the faulting thread permanently
                            // FaultBlocked instead of re-faulting in a tight loop.
                            let mut lb = LineBuf::new();
                            lb.str(b"[MMSRV] Segfault: badge=");
                            lb.hex(badge);
                            lb.str(b" addr=");
                            lb.hex(fault_addr);
                            lb.str(b" (no region)\n");
                            lb.flush();
                            skip_reply = true;
                            break 'fault;
                        }

                        // 3. Check if page already mapped (race / double fault / COW)
                        let page_idx = ((page_addr - (*region).base) / 4096) as usize;
                        if page_idx >= (*region).frame_cap_capacity as usize {
                            // Index out of bounds — grow frame_caps array to fit
                            let old_cap = (*region).frame_cap_capacity as usize;
                            let required = page_idx + 1;
                            // Hybrid growth: small 2x, medium 1.5x, large +256
                            let growth = if old_cap < 128 {
                                old_cap
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
                                reply.label = SALTY_OUT_OF_MEMORY;
                                break 'fault;
                            }
                            (*region).frame_caps = new_fcaps;
                            (*region).frame_cap_capacity = new_cap as u16;
                        }
                        if *(*region).frame_caps.add(page_idx) != 0 {
                            // Already mapped (COW handled by kernel, or race)
                            reply.label = SALTY_OK;
                            break 'fault;
                        }

                        // 4. Allocate frame: slot_alloc + retype_any
                        let slot = match salty::slot_alloc::slot_alloc() {
                            Some(s) => s,
                            None => {
                                reply.label = SALTY_OUT_OF_MEMORY;
                                break 'fault;
                            }
                        };
                        if retype_any(OBJ_FRAME, 0, slot) != 0 {
                            reply.label = SALTY_OUT_OF_MEMORY;
                            break 'fault;
                        }

                        // 5. Map into client's VSpace
                        let flags = prot_to_vspace_flags((*region).prot);
                        let err = invoke::vspace_map((*client).vspace_cap, slot, page_addr, flags);
                        if err != 0 {
                            invoke::cnode_delete(CAP_SELF_CSPACE, slot);
                            reply.label = SALTY_BAD_ADDRESS;
                            break 'fault;
                        }

                        // 6. Track frame cap
                        *(*region).frame_caps.add(page_idx) = slot;
                        (*region).frame_count += 1;

                        // 7. Reply OK — kernel resumes faulting thread
                        reply.label = SALTY_OK;
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
                    reply.label = SALTY_INVALID_OPERATION;
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
        salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
