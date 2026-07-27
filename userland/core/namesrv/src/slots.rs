// SPDX-License-Identifier: GPL-2.0-only
//
//! namesrv-internal CSpace slot zones, populated at startup from the
//! cap_table delivered by init.

use trona_kernel::core_types::{CapRef, IpcContext};
use uapi::KERNITE_CAP_SELF_CSPACE;

/// Snapshot of the namesrv-private cap_table entries.
#[derive(Clone, Copy, Debug)]
pub struct StartupSlots {
    pub master_eq: u64,
    pub master_mp: u64,
    pub watch_base: u64,
    pub park_timer: u64,
    /// init control MP — admin commands and `OWNER_EXITED` echo back.
    pub init_ep: u64,
    /// MessagePipe send-side that namesrv pushes
    /// `NAMESRV_REGISTER_EVENT` onto every time a publisher's
    /// REGISTER succeeds. Set by `NAMESRV_SUBSCRIBE_REGISTER`; zero
    /// before that admin call lands. unit_mgr (in init) is the only
    /// authorised subscriber.
    pub unit_mgr_subscriber: u64,
    /// Spawner-private untyped chunk delivered via
    /// `ROLE_NAMESRV_BOOT_UNTYPED`. The namesrv `SegmentAllocator`
    /// retypes pages out of this for `EventLoop`
    /// cookie-table backing — boot order puts namesrv ahead of
    /// mmsrv, so `mm::mmap_anon` isn't an option, and rsrcsrv's
    /// vending object set excludes `OBJ_FRAME`.
    pub boot_untyped: u64,
}

impl StartupSlots {
    pub const fn zeroed() -> Self {
        Self {
            master_eq: 0,
            master_mp: 0,
            watch_base: 0,
            park_timer: 0,
            init_ep: 0,
            unit_mgr_subscriber: 0,
            boot_untyped: 0,
        }
    }
}

pub const CAP_SELF_CSPACE: CapRef = CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64);

/// Per-call receive scratch slot. Caller-supplied caps (publisher cap
/// transferred during REGISTER, unit_mgr subscriber MP send during
/// SUBSCRIBE_REGISTER) land here and namesrv either moves them to a
/// permanent slot or drops them after handling.
pub static mut CAP_RECV_SCRATCH_SLOT: u64 = 0;

/// CSpace slot range reserved for stashing publishers' registered cap
/// objects. Allocated as a contiguous block at startup; `entry.cap_slot`
/// points into it. Size is `MAX_NAMES`.
pub static mut REGISTERED_CAP_BASE: u64 = 0;

/// Set by `boot::reserve_internal_slots` once. Treat as read-only after
/// that point.
pub fn cap_recv_scratch() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const CAP_RECV_SCRATCH_SLOT) }
}

pub fn registered_cap_base() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const REGISTERED_CAP_BASE) }
}

/// Clear and arm the IPC receive window so inbound cap-transfer
/// carriers land in `CAP_RECV_SCRATCH_SLOT..CAP_RECV_SCRATCH_SLOT+2`.
pub fn arm_recv_scratch(ctx: *mut IpcContext) {
    let window = trona_server::recv_slot::FixedRecvWindow::new(
        cap_recv_scratch(),
        2,
        trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
    );
    unsafe {
        window.arm(ctx, CAP_SELF_CSPACE.addr());
    }
}
