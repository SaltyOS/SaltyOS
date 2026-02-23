//! POSIX memory management — thin IPC client to mmsrv
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All anonymous page allocation (brk/sbrk/mmap/munmap/mprotect) is delegated
//! to the centralized memory server (mmsrv) via IPC.  fd-backed mmap (e.g.
//! /dev/fb0) still delegates to VFS for device cap transfer, then maps the
//! device pages locally.

use crate::consts::*;
use crate::invoke;
use crate::ipc;
use crate::types::*;

// Standard child CSpace layout
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_VFS_EP: u64 = 4;

/// mmsrv endpoint cap. Set by `posix_mm_init`.
static mut MMSRV_EP: Cap = 0;

/// Whether the memory manager has been initialized.
static mut MM_INITIALIZED: bool = false;

/// Bump allocator for fd-backed (device) mappings. Separate address range
/// from the mmsrv-managed heap/mmap space so they never collide.
const DEVICE_MMAP_BASE: u64 = 0x0000_0000_8000_0000; // 2 GB
const DEVICE_MMAP_LIMIT: u64 = 0x0000_0001_0000_0000; // 4 GB (2 GB range)
static mut DEVICE_MMAP_NEXT: u64 = DEVICE_MMAP_BASE;

/// Minimal tracking for device-mapped regions (needed for munmap cleanup).
const MAX_DEVICE_REGIONS: usize = 4;

/// Spinlock protecting DEVICE_MMAP_NEXT and DEVICE_REGIONS for thread safety.
static DEVICE_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[inline]
fn device_lock_acquire() {
    use core::sync::atomic::Ordering;
    while DEVICE_LOCK.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        while DEVICE_LOCK.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

#[inline]
fn device_lock_release() {
    DEVICE_LOCK.store(0, core::sync::atomic::Ordering::Release);
}

struct DeviceRegion {
    base: u64,
    length: u64,
    device_cap: Cap,
    active: bool,
}

impl DeviceRegion {
    const fn empty() -> Self {
        DeviceRegion { base: 0, length: 0, device_cap: 0, active: false }
    }
}

static mut DEVICE_REGIONS: [DeviceRegion; MAX_DEVICE_REGIONS] = {
    const E: DeviceRegion = DeviceRegion::empty();
    [E; MAX_DEVICE_REGIONS]
};

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Initialize the memory manager with the mmsrv endpoint capability.
///
/// # Safety
/// Must be called exactly once during process startup.
pub unsafe fn posix_mm_init(mmsrv_ep: Cap) {
    unsafe {
        *(&raw mut MMSRV_EP) = mmsrv_ep;
        *(&raw mut MM_INITIALIZED) = mmsrv_ep != 0;
        let mut lb = crate::serial::LineBuf::new();
        lb.str(b"[MM] init ep=");
        lb.hex(mmsrv_ep);
        if mmsrv_ep != 0 { lb.str(b" OK\n"); } else { lb.str(b" FAIL\n"); }
        lb.flush();
    }
}

// ---------------------------------------------------------------------------
// brk / sbrk
// ---------------------------------------------------------------------------

/// Set the program break (end of heap) to `addr`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_brk(addr: u64) -> i32 {
    unsafe {
        if !*(&raw const MM_INITIALIZED) {
            return -1;
        }
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_BRK;
        msg.length = 1;
        msg.regs[0] = addr;
        let err = ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            *(&raw const MMSRV_EP),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK { -1 } else { 0 }
    }
}

/// Increment the program break by `increment` bytes.
/// Returns the previous break address on success, or `u64::MAX` on error.
pub unsafe fn posix_sbrk(increment: i64) -> u64 {
    unsafe {
        if !*(&raw const MM_INITIALIZED) {
            return u64::MAX;
        }
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_SBRK;
        msg.length = 1;
        msg.regs[0] = increment as u64;
        let err = ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            *(&raw const MMSRV_EP),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            let mut lb = crate::serial::LineBuf::new();
            lb.str(b"[MM] sbrk FAIL inc=");
            lb.hex(increment as u64);
            lb.str(b" err=");
            lb.hex(err as u64);
            lb.str(b" label=");
            lb.hex(reply.label);
            lb.str(b"\n");
            lb.flush();
            u64::MAX
        } else {
            reply.regs[0]
        }
    }
}

// ---------------------------------------------------------------------------
// mmap / munmap / mprotect
// ---------------------------------------------------------------------------

/// fd-backed mmap: sends POSIX_VFS_MMAP to VFS, receives device untyped cap,
/// then maps it locally with write-combining flags.
unsafe fn posix_mmap_fd(
    _addr: *mut u8,
    length: u64,
    _prot: i32,
    _flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    unsafe {
        if offset < 0 {
            return usize::MAX as *mut u8;
        }

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => return usize::MAX as *mut u8,
        };
        let num_pages = len / 4096;
        if num_pages > u16::MAX as u64 {
            return usize::MAX as *mut u8;
        }

        // Allocate a free cap slot to receive the transferred capability
        let recv_slot = match crate::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => return usize::MAX as *mut u8,
        };

        // Prepare receive slot for IPC cap transfer
        ipc::set_receive_slot_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_SELF_CSPACE,
            recv_slot,
            0,
        );

        // Send POSIX_VFS_MMAP to VFS
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MMAP;
        msg.length = 5;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = len;
        msg.regs[3] = _prot as u64;
        msg.regs[4] = _flags as u64;

        let err = ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
            return usize::MAX as *mut u8;
        }

        // Server-side mapped (e.g. SHM via mmsrv): frames already in our VSpace
        if reply.regs[2] == 1 {
            // No cap was transferred — clean up the unused recv slot
            invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
            return reply.regs[0] as *mut u8;
        }

        // Pick a mapping base from the device-mmap bump allocator (locked)
        device_lock_acquire();
        let base = *(&raw const DEVICE_MMAP_NEXT);
        let new_next = match base.checked_add(len) {
            Some(n) if n <= DEVICE_MMAP_LIMIT => n,
            _ => {
                device_lock_release();
                invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
                return usize::MAX as *mut u8;
            }
        };
        *(&raw mut DEVICE_MMAP_NEXT) = new_next;
        device_lock_release();

        // Map using batch device range syscall with WC flags
        let map_flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER | VSPACE_FLAG_WRITE_THROUGH;
        let (map_err, mapped) = invoke::vspace_map_device_range(
            CAP_SELF_VSPACE,
            recv_slot,
            offset as u64,
            base,
            num_pages,
            map_flags,
        );
        if map_err != 0 || mapped != num_pages {
            for i in 0..mapped {
                invoke::vspace_unmap(CAP_SELF_VSPACE, base + i * 4096);
            }
            invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
            // Conditional rollback: only if no one else has bumped past us
            device_lock_acquire();
            if *(&raw const DEVICE_MMAP_NEXT) == new_next {
                *(&raw mut DEVICE_MMAP_NEXT) = base;
            }
            device_lock_release();
            return usize::MAX as *mut u8;
        }

        // Track for munmap cleanup (locked)
        device_lock_acquire();
        let regions = &raw mut DEVICE_REGIONS;
        let mut tracked = false;
        for i in 0..MAX_DEVICE_REGIONS {
            if !(*regions)[i].active {
                (*regions)[i] = DeviceRegion {
                    base,
                    length: len,
                    device_cap: recv_slot,
                    active: true,
                };
                tracked = true;
                break;
            }
        }
        device_lock_release();

        if !tracked {
            // No tracking slot available — unmap everything and fail
            for i in 0..num_pages {
                invoke::vspace_unmap(CAP_SELF_VSPACE, base + i * 4096);
            }
            invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
            // Conditional rollback
            device_lock_acquire();
            if *(&raw const DEVICE_MMAP_NEXT) == new_next {
                *(&raw mut DEVICE_MMAP_NEXT) = base;
            }
            device_lock_release();
            return usize::MAX as *mut u8;
        }

        base as *mut u8
    }
}

/// Map pages into the process address space.
///
/// - **Anonymous** (`MAP_ANONYMOUS`): delegates to mmsrv via `MM_MMAP`.
/// - **fd-backed** (`fd >= 0`): delegates to VFS for device cap transfer.
///
/// Returns the mapped base address, or `MAP_FAILED` (usize::MAX) on error.
pub unsafe fn posix_mmap(
    addr: *mut u8,
    length: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    unsafe {
        if !*(&raw const MM_INITIALIZED) || length == 0 {
            return usize::MAX as *mut u8;
        }

        // fd-backed mmap (e.g. /dev/fb0): delegate to VFS for cap transfer
        if fd >= 0 && (flags & MAP_ANONYMOUS) == 0 {
            return posix_mmap_fd(addr, length, prot, flags, fd, offset);
        }

        if (flags & MAP_ANONYMOUS) == 0 {
            return usize::MAX as *mut u8;
        }

        // Anonymous mmap → mmsrv IPC
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 4;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        msg.regs[2] = prot as u64;
        msg.regs[3] = flags as u64;
        let err = ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            *(&raw const MMSRV_EP),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            usize::MAX as *mut u8
        } else {
            reply.regs[0] as *mut u8
        }
    }
}

/// Unmap a previously mmap'd region.
///
/// Device-backed regions are handled locally; anonymous regions are
/// forwarded to mmsrv via `MM_MUNMAP`.
pub unsafe fn posix_munmap(addr: *mut u8, length: u64) -> i32 {
    unsafe {
        if !*(&raw const MM_INITIALIZED) {
            return -1;
        }

        let base = addr as u64;

        // Check if this is a device-backed region (local tracking)
        device_lock_acquire();
        let regions = &raw mut DEVICE_REGIONS;
        for i in 0..MAX_DEVICE_REGIONS {
            if (*regions)[i].active && (*regions)[i].base == base {
                let r = &mut (*regions)[i];
                let pages = r.length / 4096;
                for j in 0..pages {
                    invoke::vspace_unmap(CAP_SELF_VSPACE, r.base + j * 4096);
                }
                if r.device_cap != 0 {
                    invoke::cnode_delete(CAP_SELF_CSPACE, r.device_cap);
                }
                r.active = false;
                device_lock_release();
                return 0;
            }
        }
        device_lock_release();

        // Anonymous region → mmsrv IPC
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_MUNMAP;
        msg.length = 2;
        msg.regs[0] = base;
        msg.regs[1] = length;
        let err = ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            *(&raw const MMSRV_EP),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK { -1 } else { 0 }
    }
}

/// Change protection flags on a mapped region.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_mprotect(addr: *mut u8, length: u64, prot: i32) -> i32 {
    unsafe {
        if !*(&raw const MM_INITIALIZED) {
            return -1;
        }
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_MPROTECT;
        msg.length = 3;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        msg.regs[2] = prot as u64;
        let err = ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            *(&raw const MMSRV_EP),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK { -1 } else { 0 }
    }
}
