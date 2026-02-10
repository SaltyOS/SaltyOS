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

const CAP_CHILD_BASE: u64 = 200;
const CAP_CHILD_STRIDE: u64 = 128;

pub const COFF_TCB: u64 = 0;
pub const COFF_VSPACE: u64 = 1;
pub const COFF_CNODE: u64 = 2;
pub const COFF_SC: u64 = 3;
pub const COFF_STACK_FR: u64 = 4;
pub const COFF_EP: u64 = 5;
pub const COFF_IPC_FR: u64 = 6;
pub const COFF_FRAME_START: u64 = 16;

pub const CAP_CHILD_UNTYPED_OFFSET: u64 = 7;
pub const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;

pub const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

pub const CHILD_CODE_VADDR: u64 = 0x0000_0000_0040_0000;
pub const CHILD_STACK_VADDR: u64 = 0x0000_0000_0080_0000;
pub const CHILD_RTLD_VADDR: u64 = 0x0000_0000_0200_0000;
pub const CHILD_INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
pub const CHILD_SCRATCH_VADDR: u64 = 0x0000_0000_0400_0000;
pub const CHILD_IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

pub const SRV_STACK_PAGES: usize = 4;
pub const SRV_STACK_SIZE: u64 = SRV_STACK_PAGES as u64 * 4096;
pub const SRV_STACK_TOP: u64 = CHILD_STACK_VADDR + SRV_STACK_SIZE;

const PROCMGR_CNODE_SIZE_BITS: u64 = 15;
const CHILD_UT_BITS_DEFAULT: u8 = 20;  // 1MB per child
const CHILD_UT_BITS_PROCMGR: u8 = 25;  // 32MB for procmgr (spawns children)
const PM_WAIT_ANY_CHILD: u64 = u32::MAX as u64;

const INIT_DYN_FRAME_MIN: u64 = 720;

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

// ======================================================================
// Service loading from CPIO
// ======================================================================

unsafe fn load_service_defs(mgr: &mut svc_mgr::ServiceManager) {
    puts(b"[INIT] Loading service definitions...\n");

    unsafe {
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = cpio::cpio_archive_size(initrd, 1024 * 1024);

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
// Boot services
// ======================================================================

/// Get the cap base slot for the Nth pre-procmgr service (0-indexed by spawn order)
fn get_cap_base(spawn_idx: u64) -> u64 {
    CAP_CHILD_BASE + CAP_CHILD_STRIDE * spawn_idx
}

unsafe fn boot_services(mgr: &mut svc_mgr::ServiceManager, ut: Cap) -> Cap {
    // Track which pre-procmgr slot we're on
    let mut pre_spawn_idx: u64 = 0;

    // First, track the EPs for inter-service wiring
    let mut console_ep: Cap = 0;
    let mut nameserv_ep: Cap = 0;
    let mut vfs_ep: Cap = 0;
    let mut procmgr_ep: Cap = 0;

    for order_idx in 0..mgr.boot_order_len {
        let svc_idx = mgr.boot_order[order_idx] as usize;

        if mgr.services[svc_idx].state == svc_mgr::ServiceState::Failed {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] Skipping failed service: "); lb.bytes(mgr.services[svc_idx].def.name_bytes()); lb.str(b"\n"); lb.flush(); }
            continue;
        }

        // Check deps satisfied
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

        if mgr.is_pre_procmgr(svc_idx) {
            // Direct spawn via spawn_server
            let cap_base = get_cap_base(pre_spawn_idx);

            let extras = build_extras(name, console_ep, nameserv_ep, vfs_ep);
            let is_procmgr = bytes_eq(name, b"procmgr");
            let cnode_bits = if is_procmgr { PROCMGR_CNODE_SIZE_BITS } else { 0 };
            let map_initrd = is_procmgr;
            let ut_bits = if is_procmgr { CHILD_UT_BITS_PROCMGR } else { CHILD_UT_BITS_DEFAULT };

            let err = unsafe {
                spawn::spawn_server(
                    ut,
                    cap_base,
                    elf_name,
                    name,
                    &extras,
                    map_initrd,
                    cnode_bits,
                    ut_bits,
                )
            };

            if err != 0 {
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
                pre_spawn_idx += 1;
                continue;
            }

            mgr.services[svc_idx].cap_base = cap_base;

            // Record the EP for this service
            let ep = cap_base + COFF_EP;
            if bytes_eq(name, b"console") {
                console_ep = ep;
            } else if bytes_eq(name, b"nameserv") {
                nameserv_ep = ep;
            } else if bytes_eq(name, b"vfs") {
                vfs_ep = ep;
            } else if bytes_eq(name, b"procmgr") {
                // Mint a badged EP (badge=1 -> PID 1)
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

            // Yield to let the service start
            syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        } else {
            // Post-procmgr: spawn via procmgr IPC
            if procmgr_ep == 0 {
                { let mut lb = LineBuf::new(); lb.str(b"[INIT] Cannot spawn "); lb.bytes(name); lb.str(b" - procmgr not available\n"); lb.flush(); }
                mgr.set_state(svc_idx, svc_mgr::ServiceState::Failed);
                continue;
            }

            // Give procmgr a few yields to be ready
            for _ in 0..5 {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }

            // Strip .elf suffix for procmgr spawn name
            let spawn_name = if ends_with(elf_name, b".elf") {
                &elf_name[..elf_name.len() - 4]
            } else {
                elf_name
            };

            let pid = unsafe { spawn::pm_spawn(procmgr_ep, spawn_name) };
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

fn build_extras(name: &[u8], console_ep: Cap, ns_ep: Cap, vfs_ep: Cap) -> [ExtraCapCopy; 4] {
    let mut extras: [ExtraCapCopy; 4] = [
        ExtraCapCopy { src: 0, dst: 0 },
        ExtraCapCopy { src: 0, dst: 0 },
        ExtraCapCopy { src: 0, dst: 0 },
        ExtraCapCopy { src: 0, dst: 0 },
    ];

    // Console gets IoPort, IRQ, Notification
    if bytes_eq(name, b"console") {
        extras[0] = ExtraCapCopy { src: CAP_COM1_IOPORT, dst: 4 };
        extras[1] = ExtraCapCopy { src: CAP_COM1_IRQ, dst: 5 };
        extras[2] = ExtraCapCopy { src: CAP_COM1_NTFN, dst: 6 };
    }
    // VFS gets console EP + nameserv EP
    if bytes_eq(name, b"vfs") {
        if console_ep != 0 {
            extras[0] = ExtraCapCopy { src: console_ep, dst: 4 };
        }
        if ns_ep != 0 {
            extras[1] = ExtraCapCopy { src: ns_ep, dst: 8 };
        }
    }
    // procmgr gets nameserv EP + VFS EP
    if bytes_eq(name, b"procmgr") {
        if ns_ep != 0 {
            extras[0] = ExtraCapCopy { src: ns_ep, dst: 8 };
        }
        if vfs_ep != 0 {
            extras[1] = ExtraCapCopy { src: vfs_ep, dst: 9 };
        }
    }

    extras
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
            && !mgr.is_pre_procmgr(i)
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

            let new_pid = spawn::pm_spawn(pm_ep, spawn_name);
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

    let ut: Cap = CAP_UNTYPED_START;

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
        puts(b"[INIT] FAIL: IPC buf map\n");
        idle();
    }
    invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] IPC buffer mapped at "); lb.hex(IPC_BUF_VADDR); lb.str(b"\n"); lb.flush(); }

    // Optional self-tests (IPC + fault handling)
    // Check if selftest is enabled by looking for "selftest.enable" in CPIO
    let run_selftest = unsafe {
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = cpio::cpio_archive_size(initrd, 1024 * 1024);
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
        puts(b"[INIT] No service definitions found, falling back to legacy boot\n");
        // Fallback: legacy boot (direct spawn console + servers + run tests)
        unsafe { legacy_boot(ut) };
        idle();
    }

    // Build dependency graph and topological sort
    mgr.build_deps();
    let sort_ok = mgr.topological_sort();
    if !sort_ok {
        puts(b"[INIT] WARNING: dependency cycle detected, some services may not start\n");
    }
    mgr.log_boot_order();

    // Boot services in topological order
    let pm_ep = unsafe { boot_services(&mut mgr, ut) };

    // Service monitor loop
    puts(b"[INIT] Entering service monitor loop\n");
    unsafe { service_monitor(&mut mgr, pm_ep) };
}

// ======================================================================
// Legacy boot (fallback when no .service files found)
// ======================================================================

const LEGACY_CAP_NS_BASE: u64 = CAP_CHILD_BASE + CAP_CHILD_STRIDE * 1;
const LEGACY_CAP_PM_BASE: u64 = CAP_CHILD_BASE + CAP_CHILD_STRIDE * 2;
const LEGACY_CAP_VFS_BASE: u64 = CAP_CHILD_BASE + CAP_CHILD_STRIDE * 3;

unsafe fn legacy_boot(ut: Cap) {
    puts(b"\n[INIT] Legacy boot: Spawning console server\n");

    unsafe {
        // Phase 3: Spawn console
        if spawn::spawn_server(ut, CAP_CHILD_BASE, b"console.elf", b"console",
            &[
                ExtraCapCopy { src: CAP_COM1_IOPORT, dst: 4 },
                ExtraCapCopy { src: CAP_COM1_IRQ, dst: 5 },
                ExtraCapCopy { src: CAP_COM1_NTFN, dst: 6 },
            ], false, 0, CHILD_UT_BITS_DEFAULT) != 0 {
            puts(b"[INIT] FAIL: console spawn failed\n");
            return;
        }
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);

        let console_ep = CAP_CHILD_BASE + COFF_EP;
        let ns_ep = LEGACY_CAP_NS_BASE + COFF_EP;
        let vfs_ep = LEGACY_CAP_VFS_BASE + COFF_EP;
        let mut pm_ep = LEGACY_CAP_PM_BASE + COFF_EP;

        // Spawn nameserv
        if spawn::spawn_server(ut, LEGACY_CAP_NS_BASE, b"nameserv.elf", b"nameserv", &[], false, 0, CHILD_UT_BITS_DEFAULT) != 0 {
            puts(b"[INIT] FAIL: nameserv spawn failed\n");
            return;
        }
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);

        // Spawn VFS
        let vfs_extras = [
            ExtraCapCopy { src: console_ep, dst: 4 },
            ExtraCapCopy { src: ns_ep, dst: 8 },
        ];
        if spawn::spawn_server(ut, LEGACY_CAP_VFS_BASE, b"vfs.elf", b"vfs", &vfs_extras, false, 0, CHILD_UT_BITS_DEFAULT) != 0 {
            puts(b"[INIT] FAIL: vfs spawn failed\n");
            return;
        }
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);

        // Spawn procmgr
        let pm_extras = [
            ExtraCapCopy { src: ns_ep, dst: 8 },
            ExtraCapCopy { src: vfs_ep, dst: 9 },
        ];
        if spawn::spawn_server(ut, LEGACY_CAP_PM_BASE, b"procmgr.elf", b"procmgr", &pm_extras, true, PROCMGR_CNODE_SIZE_BITS, CHILD_UT_BITS_PROCMGR) != 0 {
            puts(b"[INIT] FAIL: procmgr spawn failed\n");
            return;
        }

        // Mint badged PM EP
        let pm_badged_slot = INIT_DYN_FRAME_NEXT;
        INIT_DYN_FRAME_NEXT += 1;
        let merr = invoke::cnode_mint(CAP_SELF_CSPACE, pm_ep, CAP_SELF_CSPACE, pm_badged_slot, 1);
        if merr == 0 {
            pm_ep = pm_badged_slot;
        }

        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);

        for _ in 0..5 {
            syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }

        // Phase 5: Runtime tests via procmgr
        puts(b"\n[INIT] Running userland runtime tests\n");

        // Spawn test_runner via procmgr
        puts(b"[INIT] spawn test_runner\n");
        let pid = spawn::pm_spawn(pm_ep, b"test_runner");
        if pid < 0 {
            puts(b"[INIT] FAIL: spawn failed for test_runner\n");
            return;
        }

        // Wait for test_runner to complete
        let mut wait_msg = SaltyMsg::zeroed();
        wait_msg.label = POSIX_PM_WAIT;
        wait_msg.length = 1;
        wait_msg.regs[0] = pid as u64;

        let mut wait_reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), pm_ep, &raw const wait_msg, &raw mut wait_reply);
        if err != 0 || wait_reply.label != SALTY_OK {
            puts(b"[INIT] FAIL: wait failed for test_runner\n");
            return;
        }
        let status = wait_reply.regs[0] as i32;

        { let mut lb = LineBuf::new(); lb.str(b"[INIT] test_runner exited with code "); lb.hex(status as u64); lb.str(b"\n"); lb.flush(); }

        if (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 42 {
            puts(b"[INIT] All tests PASSED\n");
        } else {
            puts(b"[INIT] FAIL: test_runner did not pass\n");
        }

    }
}
