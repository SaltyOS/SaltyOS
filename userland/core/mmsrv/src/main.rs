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
mod shm;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

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
    salty::tls::current_ipc_ctx()
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

        // Drain deferred slot cleanup from previous iteration
        unsafe {
            let count = *(&raw const PENDING_CLEANUP_COUNT);
            for i in 0..count {
                let slot = (*(&raw const PENDING_CLEANUP_SLOTS))[i];
                if slot != 0 {
                    invoke::cnode_delete(CAP_SELF_CSPACE, slot);
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
                        let client_ptr = client::find_client_by_badge(badge);
                        if client_ptr.is_null() {
                            let mut lb = LineBuf::new();
                            lb.str(b"[MMSRV] VMFault: unknown client badge=");
                            lb.hex(badge);
                            lb.str(b"\n");
                            lb.flush();
                            reply.label = SALTY_INVALID_OPERATION;
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
                        let err = invoke::vspace_map((*client_ptr).vspace_cap, slot, page_addr, flags);
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
