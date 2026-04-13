//! SaltyOS Process Manager
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Panic handler provided by libtrona.so (dynamic linking).

#![no_std]
#![no_main]

mod base;
mod bootstrap;
mod dispatch;
mod lifecycle;
mod loader;
mod personality;
mod reply_path;
mod server;
mod service;

use trona::protocol::*;
use trona::types::core::*;

use base::proc_table::MAX_NAME_LEN;

// ---- Cap layout (set by init for this process) ----
//
// The first three slots are kernel ABI. Every additional startup capability is
// resolved at runtime through `trona::caps::*()` or `procmgr_caps::*()`.
const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;
const CAP_UNTYPED: Cap = 7;
const CAP_RECV_SCRATCH: Cap = 15; // Scratch slot for receiving transferred caps
const CAP_REPLY_TEMP: Cap = 86; // Temporary reply cap for timed receive path
const CAP_UNTYPED_START: Cap = 16;

const VSPACE_WALK_BATCH: u64 = 48;

const TRONA_PENDING: u64 = 0x80;

const PROCMGR_SCRATCH_VADDR: u64 = 0x0000_0000_0500_0000;

// Child CSpace layout is per-spawn and lives in `child_layout.rs`; spawn_tx
// and fork_exec build a `ChildCapLayout` from a `ChildSlotAlloc` cursor and
// hand the slot positions to the child via `AT_TRONA_*` auxv tags.

pub(crate) const READY_TIMEOUT_NS_DEFAULT: u64 = 10_000_000_000; // 10s

// ---- Auxiliary vector types ----
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_TRONA_VSPACE: u64 = 0x1001;
const AT_TRONA_SCRATCH: u64 = 0x1002;
const AT_TRONA_INITRD: u64 = 0x1003;
const AT_TRONA_INITRD_SZ: u64 = 0x1004;
const AT_TRONA_CSPACE_LAYOUT: u64 = 0x1005;
const AT_TRONA_SHARED_LIB_BASE: u64 = 0x1006;
const AT_TRONA_CSPACE_NTFN: u64 = 0x100A;
const AT_TRONA_IPC_BUFFER: u64 = 0x100C;
const AT_TRONA_SC_CAP: u64 = 0x100E;
const AT_SALTYOS_PE_BASE: u64 = 0x2000;
const AT_SALTYOS_PE_SIZE: u64 = 0x2001;
const AT_SALTYOS_WIN32SRV: u64 = 0x2002;
const AT_SALTYOS_KERNEL32_BASE: u64 = 0x2003;
const AT_SALTYOS_KERNEL32_SIZE: u64 = 0x2004;
// AT_TRONA_CAP_TABLE carries the role-based startup capability table used
// by every spawned child. All role-bearing cap slots (PROCMGR_CONTROL,
// VFS_CLIENT, NAMESRV_CLIENT, SIGNAL_NTFN, MMSRV_CLIENT, RSRCSRV_CLIENT,
// SERVICE_EP, CONSOLE_CLIENT, READINESS_NTFN, INITRD_UNTYPED, FB_UNTYPED,
// PCI_IOPORT, COM1_IOPORT) are delivered exclusively through that table —
// no individual AT_TRONA_*_EP / _NTFN / _UNTYPED / _IOPORT tag is emitted.
pub use trona::consts::kernel::AT_TRONA_CAP_TABLE;

// ---- Shorthand re-exports ----
const OBJ_TCB: u64 = trona::OBJ_TCB;
const OBJ_UNTYPED: u64 = trona::OBJ_UNTYPED;
const OBJ_VSPACE: u64 = trona::OBJ_VSPACE;
const OBJ_CNODE: u64 = trona::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = trona::OBJ_SCHED_CONTEXT;
const OBJ_NOTIFICATION: u64 = trona::OBJ_NOTIFICATION;
const TRONA_OK: u64 = trona::TRONA_OK;
const TRONA_OUT_OF_MEMORY: u64 = trona::TRONA_OUT_OF_MEMORY;
const TRONA_NOT_FOUND: u64 = trona::TRONA_NOT_FOUND;
const TRONA_OUT_OF_RANGE: u64 = trona::TRONA_OUT_OF_RANGE;
const TRONA_INVALID_ARGUMENT: u64 = trona::TRONA_INVALID_ARGUMENT;
const TRONA_INVALID_OPERATION: u64 = trona::TRONA_INVALID_OPERATION;
const TRONA_WOULD_BLOCK: u64 = trona::TRONA_WOULD_BLOCK;
const TRONA_CANCELLED: u64 = trona::TRONA_CANCELLED;
const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;
const CAP_RIGHTS_ALL: u64 = trona::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const UT_MIRROR_COUNT: Cap = 16;
const INITRD_VADDR: u64 = trona::INITRD_VADDR;
const BOOTINFO_VADDR: u64 = trona::BOOTINFO_VADDR;
const BOOTINFO_MAGIC: u64 = trona::BOOTINFO_MAGIC;

// ---- CSpace expansion via bound notification ----
/// rsrcsrv handle for procmgr's bound notification cap. Set during main()
/// startup and used by `cspace::register_client` to mint per-child badged
/// copies into children's CNodes.
pub(crate) static mut BOUND_NTFN: Cap = 0;
/// TCBs to resume after the current caller has been replied to.
const POST_REPLY_RESUME_QUEUE_CAP: usize = 16;
static mut POST_REPLY_RESUME_QUEUE: [Cap; POST_REPLY_RESUME_QUEUE_CAP] =
    [0; POST_REPLY_RESUME_QUEUE_CAP];
static mut POST_REPLY_RESUME_COUNT: usize = 0;

static mut ALLOCATOR: base::alloc::Allocator = base::alloc::Allocator::new();
fn read_boot_info_initrd_size() -> usize {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(2)) as usize
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(
        trona::SYS_SIGNAL,
        trona::caps::readiness_ntfn(),
        1,
        0,
        0,
        0,
        0,
    );
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

fn basename_of(name: &[u8], len: usize) -> usize {
    let mut last = 0usize;
    let mut i = 0usize;
    while i < len {
        if name[i] == b'/' && i + 1 < len {
            last = i + 1;
        }
        i += 1;
    }
    last
}

fn strip_elf_suffix(name: &mut [u8], mut len: usize) -> usize {
    if len >= 4
        && name[len - 4] == b'.'
        && name[len - 3] == b'e'
        && name[len - 2] == b'l'
        && name[len - 1] == b'f'
    {
        len -= 4;
    }
    len
}

/// Extract process path/name from message regs and normalize by stripping
/// an optional trailing ".elf" suffix.
/// Returns the name buffer and its length.
fn extract_name(msg: &TronaMsg, name_reg_idx: usize) -> ([u8; MAX_NAME_LEN + 5], usize) {
    let mut name = [0u8; MAX_NAME_LEN + 5];
    let mut name_len = msg.regs[0] as usize;
    if name_len > MAX_NAME_LEN {
        name_len = MAX_NAME_LEN;
    }

    for i in 0..name_len {
        unsafe {
            let src = msg.regs.as_ptr().add(name_reg_idx) as *const u8;
            name[i] = *src.add(i);
        }
    }

    name_len = strip_elf_suffix(&mut name, name_len);
    name[name_len] = 0;
    (name, name_len)
}

// ===========================================================================
// handle_getpid / handle_getppid
// ===========================================================================

// ===========================================================================
// Entry point
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[PROCMGR] SaltyOS process manager starting\n");
    });

    unsafe {
        bootstrap::initialize();
        server::run();
    }
}

fn idle() -> ! {
    loop {
        trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
