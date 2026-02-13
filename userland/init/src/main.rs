//! SaltyOS Init Process - Service Manager
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! First userspace process. Receives initial capabilities from kernel
//! and bootstraps the system using service definitions from .service files
//! in the initrd CPIO archive.
//!
//! Boot sequence:
//!   1. IPC buffer setup
//!   2. (Optional) Self-tests: IPC + fault handling
//!   3. Load .service files from CPIO, build dependency graph
//!   4. Topological sort, boot services in order
//!   5. Service monitor loop

#![no_std]
#![no_main]

extern crate salty;

mod ini;
mod selftest;
mod spawn;
mod svc_mgr;

use salty::consts::*;
use salty::cpio;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::syscall::syscall;
use salty::types::*;

use spawn::ExtraCapCopy;

// ======================================================================
// Constants
// ======================================================================

const CAP_IPC_BUF_FRAME: u64 = 131;
const CAP_UNTYPED_PROBE_TMP: u64 = 132;
const EP_POOL_BASE: u64 = 140;

const CAP_CHILD_BASE: u64 = 200;
const CAP_CHILD_STRIDE: u64 = 128;

pub const COFF_TCB: u64 = 0;
pub const COFF_VSPACE: u64 = 1;
pub const COFF_CNODE: u64 = 2;
pub const COFF_SC: u64 = 3;
pub const COFF_STACK_FR: u64 = 4;
pub const COFF_EP: u64 = 5;
pub const COFF_IPC_FR: u64 = 6;
pub const COFF_READY_NTFN: u64 = 8;
pub const COFF_FRAME_START: u64 = 16;

pub const CAP_CHILD_UNTYPED_OFFSET: u64 = 7;
pub const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;

pub const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

const PM_WAIT_ANY_CHILD: u64 = u32::MAX as u64;

pub const AT_SALTY_SHARED_LIB_BASE: u64 = 0x1006;

// Keep init's transient frame/cap allocations above per-service child slots
// while staying inside init CSpace (0..4095).
const INIT_DYN_FRAME_MIN: u64 = 1024;

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_SALTY_UNTYPED: u64 = 0x1000;
pub const AT_SALTY_VSPACE: u64 = 0x1001;
pub const AT_SALTY_SCRATCH: u64 = 0x1002;
pub const AT_SALTY_INITRD: u64 = 0x1003;
pub const AT_SALTY_INITRD_SZ: u64 = 0x1004;
pub const AT_SALTY_FRAME_SLOT: u64 = 0x1005;

// ======================================================================
// Statics
// ======================================================================

static mut INIT_DYN_FRAME_NEXT: u64 = INIT_DYN_FRAME_MIN;
static mut INITRD_SIZE: usize = 0;

// ======================================================================
// Helpers
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

pub unsafe extern "C" fn init_alloc_frame_slot(_opaque: *mut u8) -> Cap {
    unsafe {
        let slot = INIT_DYN_FRAME_NEXT;
        INIT_DYN_FRAME_NEXT += 1;
        slot
    }
}

unsafe fn restore_init_ipc_context() {
    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }
}

fn idle() -> ! {
    loop {
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

fn select_init_work_untyped() -> Cap {
    let candidate = CAP_UNTYPED_START + 1;
    let err = invoke::cnode_copy(
        CAP_SELF_CSPACE,
        candidate,
        CAP_SELF_CSPACE,
        CAP_UNTYPED_PROBE_TMP,
        CAP_RIGHTS_ALL,
    );
    if err == 0 {
        invoke::cnode_delete(CAP_SELF_CSPACE, CAP_UNTYPED_PROBE_TMP);
        return candidate;
    }
    CAP_UNTYPED_START
}

/// Read the kernel boot info page at BOOTINFO_VADDR.
/// Returns (initrd_vaddr, initrd_size).
unsafe fn read_boot_info() -> (u64, usize) {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            puts(b"[INIT] WARN: boot info magic mismatch\n");
            return (INITRD_VADDR, 0);
        }
        let vaddr = core::ptr::read_volatile(page.add(1));
        let size = core::ptr::read_volatile(page.add(2)) as usize;
        (vaddr, size)
    }
}

/// Read total usable RAM bytes from boot info page (offset 56).
unsafe fn read_total_usable_bytes() -> u64 {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(7))
    }
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn memory_kb_to_ut_bits(kb: u16) -> u8 {
    let bytes = (kb as u32) * 1024;
    let mut bits: u8 = 12;
    while (1u32 << bits) < bytes && bits < 28 {
        bits += 1;
    }
    bits
}

fn log2_floor(n: u64) -> u8 {
    if n == 0 { return 0; }
    63 - n.leading_zeros() as u8
}

/// Compute per-service memory budget dynamically from total usable RAM.
/// Each service gets an equal share of 2/3 available RAM.
/// MapInitrd services (process managers) get 4x boost.
/// MemoryKB in .service overrides the formula.
fn compute_service_budget(total_usable: u64, num_services: usize, memory_kb: u16, map_initrd: bool) -> u8 {
    if memory_kb > 0 {
        return memory_kb_to_ut_bits(memory_kb);
    }

    let svc_count = if num_services == 0 { 1 } else { num_services } as u64;
    let per_svc = total_usable / (svc_count * 16);
    let mut bits = log2_floor(per_svc);

    if bits < 14 { bits = 14; }
    if bits > 20 { bits = 20; }

    if map_initrd {
        bits = if bits + 2 > 21 { 21 } else { bits + 2 };
    }

    bits
}

// ======================================================================
// Service loading from CPIO
// ======================================================================

unsafe fn load_service_defs(mgr: &mut svc_mgr::ServiceManager) {
    puts(b"[INIT] Loading service definitions...\n");

    unsafe {
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = INITRD_SIZE;

        let mut offset: usize = 0;
        let mut entry = CpioEntry::zeroed();

        while cpio::cpio_next(initrd, initrd_size, &raw mut offset, &raw mut entry) != 0 {
            // Check if file path starts with "services/" and ends with ".service"
            let name = core::slice::from_raw_parts(entry.name, entry.name_len);

            if !starts_with(name, b"services/") || !ends_with(name, b".service") {
                continue;
            }

            { let mut lb = LineBuf::new(); lb.str(b"[INIT] Found service file: "); lb.bytes(name); lb.str(b"\n"); lb.flush(); }

            let data = core::slice::from_raw_parts(entry.data, entry.data_len);
            let mut def = ini::ServiceDef::zeroed();
            if ini::parse_service(data, &mut def) {
                { let mut lb = LineBuf::new(); lb.str(b"[INIT] Parsed service: "); lb.bytes(def.name_bytes()); lb.str(b" binary="); lb.bytes(def.binary_bytes()); lb.str(b"\n"); lb.flush(); }
                mgr.add_service(&def);
            } else {
                puts(b"[INIT] WARN: failed to parse service file\n");
            }
        }

        { let mut lb = LineBuf::new(); lb.str(b"[INIT] Found "); lb.hex(mgr.count as u64); lb.str(b" services\n"); lb.flush(); }
    }
}

fn starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    if haystack.len() < prefix.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if haystack[i] != prefix[i] {
            return false;
        }
    }
    true
}

fn ends_with(haystack: &[u8], suffix: &[u8]) -> bool {
    if haystack.len() < suffix.len() {
        return false;
    }
    let start = haystack.len() - suffix.len();
    for i in 0..suffix.len() {
        if haystack[start + i] != suffix[i] {
            return false;
        }
    }
    true
}

// ======================================================================
// Pre-create service endpoints (socket activation)
// ======================================================================

unsafe fn pre_create_endpoints(mgr: &mut svc_mgr::ServiceManager, ut: Cap) {
    puts(b"[INIT] Pre-creating service endpoints...\n");
    for i in 0..mgr.count {
        let ep_slot = EP_POOL_BASE + i as u64;
        let err = invoke::untyped_retype(ut, salty::OBJ_ENDPOINT, 0, ep_slot);
        if err == 0 {
            mgr.services[i].pre_ep = ep_slot;
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"[INIT] WARN: pre-create EP for ");
            lb.bytes(mgr.services[i].def.name_bytes());
            lb.str(b" failed\n");
            lb.flush();
        }
    }
}

// ======================================================================
// Boot services
// ======================================================================

/// Get the cap base slot for the Nth pre-procmgr service (0-indexed by spawn order)
fn get_cap_base(spawn_idx: u64) -> u64 {
    CAP_CHILD_BASE + CAP_CHILD_STRIDE * spawn_idx
}

/// Check whether procmgr's Requires= dependencies reference a given service name.
/// Services that procmgr blocks on during startup must be init-spawned.
fn is_procmgr_requires(mgr: &svc_mgr::ServiceManager, pm_idx: i32, name: &[u8]) -> bool {
    if pm_idx < 0 {
        return false;
    }
    let pm = &mgr.services[pm_idx as usize];
    for i in 0..pm.def.ep_need_count as usize {
        let dep_name = &pm.def.ep_needs[i].service[..pm.def.ep_needs[i].service_len as usize];
        if bytes_eq(dep_name, name) {
            return true;
        }
    }
    false
}

unsafe fn boot_services(mgr: &mut svc_mgr::ServiceManager, ut: Cap, total_usable: u64) -> Cap {
    let mut pre_spawn_idx: u64 = 0;
    let mut procmgr_ep: Cap = 0;
    let pm_svc_idx = mgr.find_service(b"procmgr");

    for order_idx in 0..mgr.boot_order_len {
        let svc_idx = mgr.boot_order[order_idx] as usize;

        if mgr.services[svc_idx].state == svc_mgr::ServiceState::Failed {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] Skipping failed service: "); lb.bytes(mgr.services[svc_idx].def.name_bytes()); lb.str(b"\n"); lb.flush(); }
            continue;
        }

        if !mgr.deps_satisfied(svc_idx) {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] Dependencies not met for "); lb.bytes(mgr.services[svc_idx].def.name_bytes()); lb.str(b", marking Failed\n"); lb.flush(); }
            mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
            continue;
        }

        // Copy name and binary to stack buffers to avoid borrow conflict
        let mut name_buf = [0u8; 32];
        let name_len = mgr.services[svc_idx].def.name_len as usize;
        name_buf[..name_len].copy_from_slice(&mgr.services[svc_idx].def.name[..name_len]);
        let name = &name_buf[..name_len];

        let mut bin_buf = [0u8; 48];
        let bin_len = mgr.services[svc_idx].def.binary_len as usize;
        bin_buf[..bin_len].copy_from_slice(&mgr.services[svc_idx].def.binary[..bin_len]);
        let elf_name = &bin_buf[..bin_len];

        mgr.set_state(svc_idx, svc_mgr::ServiceState::Starting);
        // Determine whether this service must be init-spawned (pre-procmgr) or
        // can go through procmgr's PM_SPAWN path. Init-spawned services don't
        // get procmgr/vfs/nameserv EPs, so only services that truly need to
        // boot before procmgr is ready should be init-spawned.
        let is_pre_procmgr = bytes_eq(name, b"procmgr")
            || mgr.services[svc_idx].def.cap_count > 0
            || mgr.services[svc_idx].def.ep_need_count > 0
            || mgr.services[svc_idx].def.ep_inject_count > 0
            || is_procmgr_requires(mgr, pm_svc_idx, name);

        if is_pre_procmgr {
            let cap_base = get_cap_base(pre_spawn_idx);

            // Copy capability-related fields to stack to avoid borrow conflicts
            let cap_count = mgr.services[svc_idx].def.cap_count;
            let caps = mgr.services[svc_idx].def.caps;
            let ep_need_count = mgr.services[svc_idx].def.ep_need_count;
            let ep_needs = mgr.services[svc_idx].def.ep_needs;
            let ep_inject_count = mgr.services[svc_idx].def.ep_inject_count;
            let ep_injects = mgr.services[svc_idx].def.ep_injects;
            let cnode_bits = mgr.services[svc_idx].def.cnode_bits as u64;
            let do_map_initrd = mgr.services[svc_idx].def.map_initrd;
            let memory_kb = mgr.services[svc_idx].def.memory_kb;
            let ready_timeout_ns = mgr.services[svc_idx].def.timeout_start_ns;
            let svc_pre_ep = mgr.services[svc_idx].pre_ep;

            // Build extras from [Capabilities] declarations
            let mut extras = [ExtraCapCopy { src: 0, dst: 0 }; 10];
            let mut n: usize = 0;

            for i in 0..cap_count as usize {
                if n < extras.len() {
                    extras[n] = ExtraCapCopy {
                        src: caps[i].src_slot,
                        dst: caps[i].dst_slot,
                    };
                    n += 1;
                }
            }

            for i in 0..ep_need_count as usize {
                let svc_name = &ep_needs[i].service[..ep_needs[i].service_len as usize];
                let provider_idx = mgr.find_service(svc_name);
                if provider_idx >= 0 && n < extras.len() {
                    let pre_ep = mgr.services[provider_idx as usize].pre_ep;
                    if pre_ep != 0 {
                        extras[n] = ExtraCapCopy {
                            src: pre_ep,
                            dst: ep_needs[i].dst_slot,
                        };
                        n += 1;
                    }
                }
            }

            let ut_bits = compute_service_budget(total_usable, mgr.count, memory_kb, do_map_initrd);

            { let mut lb = LineBuf::new(); lb.str(b"[INIT] "); lb.bytes(name); lb.str(b" budget=2^"); lb.hex(ut_bits as u64); lb.str(b"\n"); lb.flush(); }

            let err = unsafe {
                spawn::spawn_server(
                    ut,
                    cap_base,
                    elf_name,
                    name,
                    &extras[..n],
                    do_map_initrd,
                    cnode_bits,
                    ut_bits,
                    do_map_initrd,
                    ready_timeout_ns,
                    svc_pre_ep,
                )
            };

            if err != 0 {
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
                pre_spawn_idx += 1;
                continue;
            }

            mgr.services[svc_idx].cap_base = cap_base;

            // Post-spawn EP injection from [Capabilities] InjectEP
            for i in 0..ep_inject_count as usize {
                let tgt_name = &ep_injects[i].target[..ep_injects[i].target_len as usize];
                let tgt_idx = mgr.find_service(tgt_name);
                if tgt_idx >= 0 && mgr.services[tgt_idx as usize].cap_base != 0 {
                    let tgt_cnode = mgr.services[tgt_idx as usize].cap_base + COFF_CNODE;
                    let err = invoke::cnode_copy(
                        CAP_SELF_CSPACE,
                        cap_base + COFF_EP,
                        tgt_cnode,
                        ep_injects[i].target_slot,
                        CAP_RIGHTS_ALL,
                    );
                    if err == 0 {
                        let mut lb = LineBuf::new();
                        lb.str(b"[INIT] Injected EP into ");
                        lb.bytes(tgt_name);
                        lb.str(b" slot ");
                        lb.hex(ep_injects[i].target_slot);
                        lb.str(b"\n");
                        lb.flush();
                    }
                }
            }

            // Mint badged procmgr EP for init's monitor loop
            if bytes_eq(name, b"procmgr") {
                let ep = cap_base + COFF_EP;
                unsafe {
                    let pm_badged_slot = INIT_DYN_FRAME_NEXT;
                    INIT_DYN_FRAME_NEXT += 1;
                    let merr = invoke::cnode_mint(CAP_SELF_CSPACE, ep, CAP_SELF_CSPACE, pm_badged_slot, 1);
                    if merr == 0 {
                        procmgr_ep = pm_badged_slot;
                        puts(b"[INIT] Minted badged PM EP (badge=1)\n");
                    } else {
                        procmgr_ep = ep;
                        puts(b"[INIT] WARN: mint badged PM EP failed\n");
                    }
                }
            }

            pre_spawn_idx += 1;
            mgr.set_state(svc_idx, svc_mgr::ServiceState::Running);

            syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        } else {
            // Post-procmgr: spawn via procmgr IPC
            if procmgr_ep == 0 {
                { let mut lb = LineBuf::new(); lb.str(b"[INIT] Cannot spawn "); lb.bytes(name); lb.str(b" - procmgr not available\n"); lb.flush(); }
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
                continue;
            }

            for _ in 0..5 {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }

            let spawn_name = if ends_with(elf_name, b".elf") {
                &elf_name[..elf_name.len() - 4]
            } else {
                elf_name
            };

            let pid = unsafe { spawn::pm_spawn(procmgr_ep, spawn_name, &mgr.services[svc_idx].def) };
            if pid < 0 {
                { let mut lb = LineBuf::new(); lb.str(b"[INIT] Failed to spawn "); lb.bytes(name); lb.str(b" via procmgr\n"); lb.flush(); }
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
                continue;
            }

            mgr.services[svc_idx].pid = pid as u32;
            mgr.set_state(svc_idx, svc_mgr::ServiceState::Running);
        }
    }

    procmgr_ep
}

// ======================================================================
// Service monitor loop
// ======================================================================

/// Find service index by PID (post-procmgr services only).
fn find_service_by_pid(mgr: &svc_mgr::ServiceManager, pid: u32) -> i32 {
    for i in 0..mgr.count {
        if mgr.services[i].active
            && mgr.services[i].pid == pid
            && mgr.services[i].state == svc_mgr::ServiceState::Running
        {
            return i as i32;
        }
    }
    -1
}

/// Send a blocking PM_WAIT(-1, 0) to procmgr. Init sleeps until a child exits.
/// Returns (exit_status, child_pid), or (0, 0) on error / no children.
unsafe fn blocking_wait_child(pm_ep: Cap) -> (i32, u32) {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        msg.label = POSIX_PM_WAIT;
        msg.length = 2;
        msg.regs[0] = PM_WAIT_ANY_CHILD;
        msg.regs[1] = 0; // blocking (no WNOHANG)

        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), pm_ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return (0, 0);
        }

        let exit_status = reply.regs[0] as i32;
        let child_pid = reply.regs[1] as u32;
        (exit_status, child_pid)
    }
}

/// Process a single child exit: log, record in service manager, restart if needed.
unsafe fn handle_child_exit(
    mgr: &mut svc_mgr::ServiceManager,
    pm_ep: Cap,
    child_pid: u32,
    exit_status: i32,
) {
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] Child exited: pid="); lb.hex(child_pid as u64); lb.str(b" status="); lb.hex(exit_status as u64); lb.str(b"\n"); lb.flush(); }

    let idx = find_service_by_pid(mgr, child_pid);
    if idx < 0 {
        puts(b"[INIT] Unknown child pid, ignoring\n");
        return;
    }

    let svc_idx = idx as usize;

    let exit_code = if (exit_status & 0x7f) == 0 {
        (exit_status >> 8) & 0xff
    } else {
        exit_status
    };

    mgr.record_exit(svc_idx, exit_code);

    if mgr.should_restart(svc_idx) {
        unsafe {
            let mut bin_buf = [0u8; 48];
            let bin_len = mgr.services[svc_idx].def.binary_len as usize;
            bin_buf[..bin_len].copy_from_slice(&mgr.services[svc_idx].def.binary[..bin_len]);
            let elf_name = &bin_buf[..bin_len];

            let spawn_name = if ends_with(elf_name, b".elf") {
                &elf_name[..elf_name.len() - 4]
            } else {
                elf_name
            };

            let new_pid = spawn::pm_spawn(pm_ep, spawn_name, &mgr.services[svc_idx].def);
            if new_pid < 0 {
                puts(b"[INIT] Failed to restart service\n");
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
            } else {
                mgr.services[svc_idx].pid = new_pid as u32;
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Running);
            }
        }
    }
}

/// Drain remaining zombie children using WNOHANG (non-blocking).
unsafe fn drain_zombies(mgr: &mut svc_mgr::ServiceManager, pm_ep: Cap) {
    unsafe {
        loop {
            let mut msg = SaltyMsg::zeroed();
            msg.label = POSIX_PM_WAIT;
            msg.length = 2;
            msg.regs[0] = PM_WAIT_ANY_CHILD;
            msg.regs[1] = WNOHANG;

            let mut reply = SaltyMsg::zeroed();
            let err = ipc::call_ctx(ipc_ctx(), pm_ep, &raw const msg, &raw mut reply);
            if err != 0 || reply.label != SALTY_OK {
                break;
            }

            let child_pid = reply.regs[1] as u32;
            if child_pid == 0 {
                break;
            }

            let exit_status = reply.regs[0] as i32;
            handle_child_exit(mgr, pm_ep, child_pid, exit_status);
        }
    }
}

/// Main service monitor loop. Blocks in procmgr until a child exits, then
/// handles restart and drains additional zombies before blocking again.
/// This avoids WNOHANG polling that starves other procmgr clients on SMP.
unsafe fn service_monitor(mgr: &mut svc_mgr::ServiceManager, pm_ep: Cap) -> ! {
    if pm_ep == 0 {
        idle();
    }

    loop {
        let (exit_status, child_pid) = unsafe { blocking_wait_child(pm_ep) };

        if child_pid == 0 {
            // No children in procmgr yet — yield and retry
            for _ in 0..50 {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
            continue;
        }

        unsafe { handle_child_exit(mgr, pm_ep, child_pid, exit_status) };
        unsafe { drain_zombies(mgr, pm_ep) };
    }
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[INIT] SaltyOS init process starting\n");

    let ut: Cap = select_init_work_untyped();
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] Bootstrap untyped slot="); lb.hex(ut); lb.str(b"\n"); lb.flush(); }

    // Set up IPC buffer for init
    let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, CAP_IPC_BUF_FRAME);
    if err != 0 {
        puts(b"[INIT] FAIL: IPC buf frame retype\n");
        idle();
    }
    let err = invoke::vspace_map(
        CAP_SELF_VSPACE,
        CAP_IPC_BUF_FRAME,
        IPC_BUF_VADDR,
        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
    );
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[INIT] FAIL: IPC buf map err=");
        lb.hex(err as u64);
        lb.str(b"\n");
        lb.flush();
        idle();
    }
    invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] IPC buffer mapped at "); lb.hex(IPC_BUF_VADDR); lb.str(b"\n"); lb.flush(); }

    // Read initrd size from kernel boot info page (once, at startup)
    let (_, initrd_size) = unsafe { read_boot_info() };
    unsafe { INITRD_SIZE = initrd_size; }
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] Initrd size from boot info: "); lb.hex(initrd_size as u64); lb.str(b" bytes\n"); lb.flush(); }

    let total_usable = unsafe { read_total_usable_bytes() };
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] Total usable RAM: "); lb.hex(total_usable); lb.str(b" bytes\n"); lb.flush(); }

    // Optional self-tests (IPC + fault handling)
    // Check if selftest is enabled by looking for "selftest.enable" in CPIO
    let run_selftest = unsafe {
        let initrd = INITRD_VADDR as *const u8;
        let mut entry = CpioEntry::zeroed();
        let name = b"selftest.enable";
        cpio::cpio_find_file(initrd, initrd_size, name.as_ptr(), name.len(), &raw mut entry) != 0
    };

    if run_selftest {
        puts(b"[INIT] Self-test mode enabled\n");

        if unsafe { selftest::phase1_ipc_test(ut) } != 0 {
            idle();
        }
        unsafe { restore_init_ipc_context() };

        if unsafe { selftest::phase2_fault_test(ut) } != 0 {
            idle();
        }
        unsafe { restore_init_ipc_context() };
    }

    // Load service definitions from CPIO
    let mut mgr = svc_mgr::ServiceManager::new();
    unsafe { load_service_defs(&mut mgr) };

    if mgr.count == 0 {
        puts(b"[INIT] No service definitions found in initrd\n");
        idle();
    }

    // Pre-load shared library RO pages into a cache so all children share
    // the same physical frames (saves ~120 frames per additional process).
    unsafe { spawn::init_shared_lib_cache(ut) };

    // Build dependency graph and topological sort
    mgr.build_deps();
    let sort_ok = mgr.topological_sort();
    if !sort_ok {
        puts(b"[INIT] WARNING: dependency cycle detected, some services may not start\n");
    }
    mgr.log_boot_order();

    // Pre-create endpoints for socket activation (before any service spawns)
    unsafe { pre_create_endpoints(&mut mgr, ut) };

    // Boot services in topological order
    let pm_ep = unsafe { boot_services(&mut mgr, ut, total_usable) };

    // Service monitor loop
    puts(b"[INIT] Entering service monitor loop\n");
    unsafe { service_monitor(&mut mgr, pm_ep) };
}
