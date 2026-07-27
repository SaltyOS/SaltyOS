// SPDX-License-Identifier: GPL-2.0-only
//
//! Anonymous memory helpers for vfs-owned state. Every dynamic-grow
//! data structure (Arena segments, BadgeMap, SegmentedSlotTable
//! segments, page-cache index buckets) backs onto these by way of an
//! `mmsrv MM_MMAP MAP_ANONYMOUS` round-trip.
//!
//! The mmsrv EP is resolved lazily through
//! [`trona_runtime::client::caps::mmsrv_ep`]: vfs is itself an mmsrv client, and on
//! the first call substrate runs `NAMESRV_LOOKUP("mmsrv")` +
//! `MM_BIND_CLIENT_SELF` to populate the cached cap. Subsequent
//! calls hit the cached weak symbol without re-resolving.
//!
//! Both helpers return `usize::MAX as *mut u8` on failure (caller
//! converts to `None`). `null_mut` is reserved for "0-byte request
//! is a no-op" semantics inside `map_anon_rw`.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;
use trona_protocol::mm::{MM_MMAP, MM_MUNMAP, MMAP_KIND_ANON};
use trona_protocol::posix_abi::mm::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};

unsafe fn mmsrv_call(msg: *const TronaMsg, reply: *mut TronaMsg) -> i32 {
    unsafe {
        loop {
            let err = trona_kernel::ipc::mp_call_ctx(
                trona_posix::tls::current_ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep().addr(),
                msg,
                reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err == uapi::KERNITE_ERR_RESTART as i32
                || err == uapi::KERNITE_ERR_INTERRUPTED as i32
            {
                continue;
            }
            return err;
        }
    }
}

/// Map `bytes` of zeroed anonymous memory into vfs's own VSpace and
/// return the resulting base VA. Falls back to `usize::MAX` on
/// failure so callers can branch with a single sentinel check.
///
/// # Safety
///
/// The returned pointer is valid only inside vfs (never share-map
/// across server boundaries). Callers must pair every successful
/// `map_anon` with a matching [`unmap`] when releasing the region.
pub(crate) unsafe fn map_anon(bytes: u64) -> *mut u8 {
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 5;
    msg.regs[0] = MMAP_KIND_ANON;
    msg.regs[1] = 0;
    msg.regs[2] = bytes;
    msg.regs[3] = (PROT_READ | PROT_WRITE) as u64;
    msg.regs[4] = (MAP_PRIVATE | MAP_ANONYMOUS) as u64;
    let err = unsafe { mmsrv_call(&raw const msg, &raw mut reply) };
    if err != 0 || reply.label != TRONA_OK {
        usize::MAX as *mut u8
    } else {
        reply.regs[0] as *mut u8
    }
}

/// Release `bytes` of anonymous memory previously returned by
/// [`map_anon`]. Returns 0 on success, -1 on failure (the caller
/// generally treats failure as a fatal teardown signal — a successful
/// `map_anon` paired with a failing `unmap` indicates mmsrv state
/// drift).
///
/// # Safety
///
/// `addr` must come from a prior `map_anon` call against this vfs
/// process and `bytes` must equal the corresponding mapped length.
pub(crate) unsafe fn unmap(addr: *mut u8, bytes: u64) -> i32 {
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_MUNMAP;
    msg.length = 2;
    msg.regs[0] = addr as u64;
    msg.regs[1] = bytes;
    let err = unsafe { mmsrv_call(&raw const msg, &raw mut reply) };
    if err != 0 || reply.label != TRONA_OK {
        -1
    } else {
        0
    }
}
