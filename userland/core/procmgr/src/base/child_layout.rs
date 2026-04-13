//! Child cspace layout — spawner-internal.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! procmgr's view of where well-known capabilities live in a child's CSpace.
//! Built per-spawn from a `ChildSlotAlloc` cursor by `spawn_tx.rs` and
//! `fork_exec.rs`.
//!
//! The slot positions chosen here are then communicated to the child via
//! `AT_TRONA_*` auxv tags so that lib code (libtrona, libposix, ...) can
//! reach the caps via the substrate `caps::*` getters without ever
//! hard-coding a slot number.
//!
//! `ChildSlotAlloc::new(0, ...)` deliberately starts at zero so that the
//! first three allocations land on slots 0/1/2, which are the kernel ABI
//! positions for `CAP_SELF_TCB`, `CAP_SELF_VSPACE`, and `CAP_SELF_CSPACE`.
//! Everything past that is spawner-private and may move freely.

/// procmgr-side per-child offsets into its own CSpace slot allocator. These
/// are the positions where `spawn_tx` temporarily realizes newly allocated
/// kernel objects before copying/minting them into the child's CNode. They
/// are spawner-private and have nothing to do with where the child sees the
/// caps in *its* CSpace.
pub const COFF_TCB: usize = 0;
pub const COFF_VSPACE: usize = 1;
pub const COFF_CNODE: usize = 2;
pub const COFF_SC: usize = 3;
pub const COFF_SIGNAL_NTFN: usize = 6;
pub const COFF_READY_NTFN: usize = 7;

/// First child CNode slot reserved for RTLD-driven runtime frame allocation.
/// Cursor-allocated well-known caps are kept strictly below this value so
/// that RTLD's frame slot pool never collides with them.
pub const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;

/// Sequential allocator that hands out child CNode slots one at a time.
/// Used by `spawn_tx` and `fork_exec` to choose where each well-known
/// capability lives in the child's CSpace.
pub struct ChildSlotAlloc {
    next: u64,
    limit: u64,
}

impl ChildSlotAlloc {
    /// Create a new allocator that hands out slots in `[start, limit)`.
    pub fn new(start: u64, limit: u64) -> Self {
        Self { next: start, limit }
    }

    /// Allocate the next free slot, or return `None` if the cursor would
    /// cross `limit`.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.next >= self.limit {
            return None;
        }
        let s = self.next;
        self.next += 1;
        Some(s)
    }

    /// Peek at the next slot the cursor will return without consuming it.
    pub fn next_free(&self) -> u64 {
        self.next
    }
}

/// Layout of well-known capabilities in a child's CSpace, as chosen by
/// procmgr for one specific spawn.
///
/// A field that is `0` means the corresponding capability was not minted
/// for this child — not every process gets every cap (for example, only
/// display-class processes receive an `fb_untyped`, and only PE processes
/// receive a `win32srv_ep`).
#[derive(Clone, Copy)]
pub struct ChildCapLayout {
    pub self_tcb: u64,
    pub self_vspace: u64,
    pub self_cspace: u64,
    pub procmgr_ep: u64,
    pub vfs_ep: u64,
    pub namesrv_ep: u64,
    pub signal_ntfn: u64,
    pub mmsrv_ep: u64,
    pub sc: u64,
    pub ready_ntfn: u64,
    pub cspace_ntfn: u64,
    pub console_ep: u64,
    pub service_ep: u64,
    pub win32srv_ep: u64,
    pub rsrcsrv_ep: u64,
    pub initrd_untyped: u64,
    pub fb_untyped: u64,
    pub frame_slot_start: u64,
    /// Cursor position right after the well-known fields above were
    /// allocated. The cap_table builder uses this as the starting slot
    /// for service-local `Require=` entries — those slots live in
    /// `[extras_base, frame_slot_start)`.
    pub extras_base: u64,
}

impl ChildCapLayout {
    /// All-zero layout used to initialize `ProcessState::Free` proctab entries. The
    /// fields are meaningless until the spawn/fork path rewrites them, which
    /// happens before the process becomes observable.
    pub const fn zeroed() -> Self {
        Self {
            self_tcb: 0,
            self_vspace: 0,
            self_cspace: 0,
            procmgr_ep: 0,
            vfs_ep: 0,
            namesrv_ep: 0,
            signal_ntfn: 0,
            mmsrv_ep: 0,
            sc: 0,
            ready_ntfn: 0,
            cspace_ntfn: 0,
            console_ep: 0,
            service_ep: 0,
            win32srv_ep: 0,
            rsrcsrv_ep: 0,
            initrd_untyped: 0,
            fb_untyped: 0,
            frame_slot_start: 0,
            extras_base: 0,
        }
    }

    /// Build a layout by drawing slot positions from `alloc`.
    ///
    /// The first three allocations are pinned to 0/1/2 (kernel ABI for
    /// `CAP_SELF_TCB`/`VSPACE`/`CSPACE`). Everything else is whatever the
    /// cursor returns next — procmgr is free to rearrange the child cspace
    /// without any lib code noticing, because every well-known cap is
    /// communicated to the child via an `AT_TRONA_*` auxv tag.
    ///
    /// Returns `None` if the cursor runs out of slots, which would mean
    /// the child CNode is too small for the well-known cap set.
    pub fn from_alloc(alloc: &mut ChildSlotAlloc) -> Option<Self> {
        let layout = Self {
            self_tcb: alloc.alloc()?,
            self_vspace: alloc.alloc()?,
            self_cspace: alloc.alloc()?,
            procmgr_ep: alloc.alloc()?,
            vfs_ep: alloc.alloc()?,
            namesrv_ep: alloc.alloc()?,
            signal_ntfn: alloc.alloc()?,
            mmsrv_ep: alloc.alloc()?,
            sc: alloc.alloc()?,
            ready_ntfn: alloc.alloc()?,
            cspace_ntfn: alloc.alloc()?,
            console_ep: alloc.alloc()?,
            service_ep: alloc.alloc()?,
            win32srv_ep: alloc.alloc()?,
            rsrcsrv_ep: alloc.alloc()?,
            initrd_untyped: alloc.alloc()?,
            fb_untyped: alloc.alloc()?,
            frame_slot_start: CHILD_RTLD_FRAME_SLOT_START,
            extras_base: 0,
        };
        // Snapshot the cursor *after* the well-known fields are placed.
        // This is the starting slot for any service-local `Require=` cap
        // entries the cap_table builder needs to add later.
        let mut layout = layout;
        layout.extras_base = alloc.next_free();
        Some(layout)
    }

    /// Emit one cap_table entry per system role this layout carries.
    /// Zero-valued fields are silently skipped by `CapTableBuilder::push`,
    /// so services that do not receive a given cap (e.g. `fb_untyped` on
    /// non-display services) never produce an entry for it.
    ///
    /// procmgr maps its layout to the following system roles:
    ///
    /// | field          | role                       |
    /// |----------------|----------------------------|
    /// | `procmgr_ep`   | `ROLE_PROCMGR_CONTROL`     |
    /// | `vfs_ep`       | `ROLE_VFS_CLIENT`          |
    /// | `namesrv_ep`   | `ROLE_NAMESRV_CLIENT`      |
    /// | `signal_ntfn`  | `ROLE_SIGNAL_NTFN`         |
    /// | `mmsrv_ep`     | `ROLE_MMSRV_CLIENT`        |
    /// | `sc`           | `ROLE_SC_CAP`              |
    /// | `ready_ntfn`   | `ROLE_READINESS_NTFN`      |
    /// | `cspace_ntfn`  | `ROLE_CSPACE_NTFN`         |
    /// | `console_ep`   | `ROLE_CONSOLE_CLIENT`      |
    /// | `service_ep`   | `ROLE_SERVICE_EP`          |
    /// | `win32srv_ep`  | `ROLE_WIN32SRV_CLIENT`     |
    /// | `rsrcsrv_ep`   | `ROLE_RSRCSRV_CLIENT`      |
    /// | `initrd_untyped` | `ROLE_INITRD_UNTYPED`    |
    /// | `fb_untyped`   | `ROLE_FB_UNTYPED`          |
    ///
    /// `self_tcb/vspace/cspace` are kernel-ABI fixed (slots 0/1/2) and
    /// deliberately do not appear here.
    pub fn populate_cap_table(
        &self,
        builder: &mut trona::cap_table::CapTableBuilder,
    ) -> Result<(), trona::cap_table::CapTableErr> {
        use trona::consts::kernel::{
            CAP_TBL_FLAG_BADGED, CAP_TBL_FLAG_DEVICE_UT, CAP_TBL_FLAG_NOTIFICATION,
            CAP_TBL_FLAG_UNTYPED, ROLE_CONSOLE_CLIENT, ROLE_CSPACE_NTFN, ROLE_FB_UNTYPED,
            ROLE_INITRD_UNTYPED, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT, ROLE_PROCMGR_CONTROL,
            ROLE_READINESS_NTFN, ROLE_RSRCSRV_CLIENT, ROLE_SC_CAP, ROLE_SERVICE_EP,
            ROLE_SIGNAL_NTFN, ROLE_VFS_CLIENT, ROLE_WIN32SRV_CLIENT,
        };
        builder.push(
            ROLE_PROCMGR_CONTROL,
            self.procmgr_ep,
            0,
            CAP_TBL_FLAG_BADGED,
        )?;
        builder.push(ROLE_VFS_CLIENT, self.vfs_ep, 0, 0)?;
        builder.push(ROLE_NAMESRV_CLIENT, self.namesrv_ep, 0, 0)?;
        builder.push(
            ROLE_SIGNAL_NTFN,
            self.signal_ntfn,
            0,
            CAP_TBL_FLAG_NOTIFICATION,
        )?;
        builder.push(ROLE_MMSRV_CLIENT, self.mmsrv_ep, 0, CAP_TBL_FLAG_BADGED)?;
        builder.push(ROLE_SC_CAP, self.sc, 0, 0)?;
        builder.push(
            ROLE_READINESS_NTFN,
            self.ready_ntfn,
            0,
            CAP_TBL_FLAG_NOTIFICATION,
        )?;
        builder.push(
            ROLE_CSPACE_NTFN,
            self.cspace_ntfn,
            0,
            CAP_TBL_FLAG_NOTIFICATION,
        )?;
        builder.push(ROLE_CONSOLE_CLIENT, self.console_ep, 0, 0)?;
        builder.push(ROLE_SERVICE_EP, self.service_ep, 0, 0)?;
        builder.push(ROLE_WIN32SRV_CLIENT, self.win32srv_ep, 0, 0)?;
        builder.push(ROLE_RSRCSRV_CLIENT, self.rsrcsrv_ep, 0, CAP_TBL_FLAG_BADGED)?;
        builder.push(
            ROLE_INITRD_UNTYPED,
            self.initrd_untyped,
            0,
            CAP_TBL_FLAG_UNTYPED | CAP_TBL_FLAG_DEVICE_UT,
        )?;
        builder.push(
            ROLE_FB_UNTYPED,
            self.fb_untyped,
            0,
            CAP_TBL_FLAG_UNTYPED | CAP_TBL_FLAG_DEVICE_UT,
        )?;
        Ok(())
    }
}
