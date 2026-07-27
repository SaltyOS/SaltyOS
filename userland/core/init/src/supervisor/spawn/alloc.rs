// SPDX-License-Identifier: GPL-2.0-only
//
//! `SpawnAllocator` — backend-neutral kernel-object retype interface
//! the spawn pipeline calls into. Two implementations exist:
//!
//! * [`DirectUntypedAllocator`] — invokes `KERNITE_INV_UNTYPED_RETYPE`
//!   directly against a private untyped seed. Used by Stage C/D/E
//!   while bringing up namesrv / rsrcsrv / mmsrv themselves (rsrcsrv
//!   is not alive yet, so the broker route is not available).
//! * [`RsrcsrvAllocator`] — low-level wrapper around rsrcsrv's
//!   `RSRC_ALLOC` / `RSRC_ALLOC_MP_PAIR` for call sites that already
//!   hold the correctly-badged rsrcsrv endpoint. The normal service
//!   lifecycle uses the recorded helpers directly so partial spawns can
//!   roll back with `RSRC_FREE`.
//!
//! Boot-only code still uses the trait to share direct-untyped MP-pair
//! construction; post-rsrcsrv lifecycle code needs record ids and uses
//! the rsrc IPC helpers directly.

use trona_kernel::core_types::{CapRef, IpcContext};
use trona_kernel::invoke;
use uapi::KERNITE_OBJ_MESSAGE_PIPE;

use crate::supervisor::retype::RetypeClass;
use crate::supervisor::rsrc_ipc::{rsrc_alloc, rsrc_alloc_mp_pair};

/// Backend-neutral kernel-object retype interface used by the spawn
/// pipeline. Every helper here writes a freshly-retyped cap into the
/// caller's CSpace at the requested `dest_slot`. Backends are
/// responsible for arming the IPC receive window when the retype
/// crosses a server boundary; for direct retype the kernel writes
/// the cap inline.
pub trait SpawnAllocator {
    fn alloc(&mut self, class: RetypeClass, size_bits: u64, dest_slot: u64) -> Result<u64, i32>;

    /// Allocate a connected MessagePipe pair (core + 2 sides + bind).
    /// Returns `(send_slot, recv_slot)` consecutive in the caller's
    /// CSpace. Direct backend retypes core + send + recv from the
    /// private untyped, then issues `KERNITE_INV_MP_CORE_PAIR`. The
    /// rsrcsrv backend routes through `RSRC_ALLOC_MP_PAIR` which does
    /// the same work server-side.
    fn alloc_mp_pair(&mut self, recv_base: u64) -> Result<(u64, u64), i32>;
}

/// Allocate from a private untyped seed. Used at boot before rsrcsrv
/// is alive — Stage A retypes init-private supports out of the boot
/// untyped, and Stage C/D/E retype core service plumbing out of the
/// chunk dedicated to that server.
pub struct DirectUntypedAllocator {
    pub untyped: CapRef,
    /// Optional spare slot in init's CSpace used by `alloc_mp_pair`'s
    /// transient MP_CORE retype. The backend writes the core slot
    /// here, issues the bind invoke against `recv_base`/`recv_base+1`,
    /// then drops the core cap so it is reclaimable. Caller must
    /// reserve a free slot before invoking `alloc_mp_pair`.
    pub mp_core_temp_slot: u64,
}

impl SpawnAllocator for DirectUntypedAllocator {
    fn alloc(&mut self, class: RetypeClass, size_bits: u64, dest_slot: u64) -> Result<u64, i32> {
        let r = invoke::untyped_retype(self.untyped, class.obj_type(), size_bits, dest_slot);
        if r != 0 {
            return Err(r);
        }
        Ok(dest_slot)
    }

    fn alloc_mp_pair(&mut self, recv_base: u64) -> Result<(u64, u64), i32> {
        use crate::internal_slots::SLOT_SELF_CSPACE;
        let self_cspace = CapRef::flat(SLOT_SELF_CSPACE);

        // Kernel `syscall_mp_pair` validates side_a and side_b are
        // already-retyped MessagePipes; retype core + 2 sides first.
        let r = invoke::untyped_retype(
            self.untyped,
            RetypeClass::MpPair.obj_type(),
            0,
            self.mp_core_temp_slot,
        );
        if r != 0 {
            return Err(r);
        }
        let r = invoke::untyped_retype(self.untyped, KERNITE_OBJ_MESSAGE_PIPE as u64, 0, recv_base);
        if r != 0 {
            let _ = invoke::cnode_delete(self_cspace, self.mp_core_temp_slot);
            return Err(r);
        }
        let r = invoke::untyped_retype(
            self.untyped,
            KERNITE_OBJ_MESSAGE_PIPE as u64,
            0,
            recv_base + 1,
        );
        if r != 0 {
            let _ = invoke::cnode_delete(self_cspace, self.mp_core_temp_slot);
            let _ = invoke::cnode_delete(self_cspace, recv_base);
            return Err(r);
        }
        let r = invoke::mp_core_pair(
            CapRef::flat(self.mp_core_temp_slot),
            CapRef::flat(recv_base),
            CapRef::flat(recv_base + 1),
        );
        // Drop the transient core cap unconditionally — the bind has
        // either succeeded (the pair holds the only live core
        // reference now via its internal back-pointer) or failed
        // (we reclaim the slot anyway). Without this delete the boot
        // path leaks one slot per MP pair every retype call.
        let _ = invoke::cnode_delete(self_cspace, self.mp_core_temp_slot);
        if r != 0 {
            let _ = invoke::cnode_delete(self_cspace, recv_base);
            let _ = invoke::cnode_delete(self_cspace, recv_base + 1);
            return Err(r);
        }
        Ok((recv_base, recv_base + 1))
    }
}

/// Allocate via rsrcsrv. Carries the rsrcsrv master MP send and the
/// per-thread IPC context so receive-window arming is automatic.
pub struct RsrcsrvAllocator {
    pub rsrcsrv_mp: u64,
    pub ipc_ctx: *mut IpcContext,
}

impl SpawnAllocator for RsrcsrvAllocator {
    fn alloc(&mut self, class: RetypeClass, size_bits: u64, dest_slot: u64) -> Result<u64, i32> {
        rsrc_alloc(self.rsrcsrv_mp, class, size_bits, dest_slot, self.ipc_ctx)
    }

    fn alloc_mp_pair(&mut self, recv_base: u64) -> Result<(u64, u64), i32> {
        rsrc_alloc_mp_pair(self.rsrcsrv_mp, recv_base, self.ipc_ctx)
    }
}
