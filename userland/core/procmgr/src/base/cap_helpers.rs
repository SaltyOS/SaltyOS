// SPDX-License-Identifier: GPL-2.0-only
//! procmgr-private helpers for raw authority capabilities that are
//! intentionally excluded from the public `trona_runtime::client::caps::*` surface.
//!
//! procmgr holds **two** variants of the mmsrv and rsrcsrv endpoints:
//!
//! - a **badged client** copy at the slot named by
//!   `trona_runtime::client::caps::mmsrv_ep()` / `trona_runtime::client::caps::rsrcsrv_ep()`, used for
//!   procmgr's own IPC to those services.
//! - an **unbadged raw-authority** copy that preserves the `GRANT`
//!   right, used by procmgr when minting per-child badged copies into
//!   children's CSpaces during spawn.
//!
//! The raw-authority slots must not appear on any `trona_runtime::client::caps::*`
//! public getter — exposing unbadged authority caps to arbitrary
//! services would let them mint badged copies and impersonate other
//! clients. Instead, init publishes them through the startup cap_table
//! under the deliberately-private `ROLE_MMSRV_AUTHORITY_RAW` /
//! `ROLE_RSRCSRV_AUTHORITY_RAW` role ids, which the substrate's
//! `system_role_target` match deliberately does **not** handle. Only
//! procmgr links against this module and looks the slots up from the
//! cap_table directly via [`cap_table::lookup`].
//!
//! If a future procmgr reshuffles its bootstrap layout, update both
//! `userland/services/procmgr.service` (the `Requires=` lines) and this
//! module together.

use trona_kernel::core_types::Cap;
use trona_runtime::spawn::cap_table;
use uapi::{ROLE_MMSRV_AUTHORITY_RAW, ROLE_RSRCSRV_AUTHORITY_RAW};

pub(crate) const PROCMGR_VFS_CLIENT_BADGE: u64 = 0xFFFF_FFFF_FF50_434D; // "...PROCM"

static mut VFS_PROVIDER_EP: Cap = 0;
static mut VFS_SELF_CLIENT_EP: Cap = 0;

/// Look up a raw-authority role in the startup cap_table. Returns the
/// cap slot number the spawner placed the cap at, or 0 if the table is
/// missing or the role is absent (which indicates a procmgr.service
/// misconfiguration).
unsafe fn lookup_raw_role(role: u32) -> Cap {
    // SAFETY: `__trona_saved_auxv` is populated by `runtime_set_auxv`
    // early in procmgr startup; `find_in_auxv` handles null gracefully.
    unsafe {
        let auxv = *(&raw const trona_runtime::__trona_saved_auxv);
        let table = cap_table::find_in_auxv(auxv);
        match cap_table::lookup(table, role) {
            Some(entry) => entry.slot as Cap,
            None => 0,
        }
    }
}

/// Unbadged mmsrv endpoint cap (the raw authority variant). procmgr
/// uses this during child spawn to mint badged per-child copies of the
/// mmsrv client cap into children's CSpaces while preserving the
/// `GRANT` right. Reads from the cap_table entry for
/// `ROLE_MMSRV_AUTHORITY_RAW`.
#[inline]
pub(crate) fn mmsrv_authority_raw() -> Cap {
    // SAFETY: `lookup_raw_role` validates the table header before use.
    unsafe { lookup_raw_role(ROLE_MMSRV_AUTHORITY_RAW) }
}

/// Unbadged rsrcsrv endpoint cap. Same semantics as
/// [`mmsrv_authority_raw`], but for rsrcsrv.
#[inline]
pub(crate) fn rsrcsrv_authority_raw() -> Cap {
    // SAFETY: `lookup_raw_role` validates the table header before use.
    unsafe { lookup_raw_role(ROLE_RSRCSRV_AUTHORITY_RAW) }
}

/// Unbadged VFS provider endpoint used only for privileged mint/copy paths
/// inside procmgr.
#[inline]
pub(crate) fn vfs_provider_ep() -> Cap {
    unsafe {
        let slot = *(&raw const VFS_PROVIDER_EP);
        if slot != 0 {
            slot
        } else {
            trona_runtime::client::caps::vfs_ep()
        }
    }
}

#[inline]
pub(crate) fn vfs_self_client_ep() -> Cap {
    unsafe { *(&raw const VFS_SELF_CLIENT_EP) }
}

#[inline]
pub(crate) unsafe fn refresh_vfs_caps(provider_slot: Cap) -> bool {
    unsafe {
        *(&raw mut VFS_PROVIDER_EP) = provider_slot;
        if provider_slot == 0 {
            return false;
        }

        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        let mut self_slot = *(&raw const VFS_SELF_CLIENT_EP);
        let newly_allocated = self_slot == 0;
        if newly_allocated {
            let Some(slot) = alloc.alloc_single_slot() else {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] WARN: no slot for self VFS client cap\n");
                });
                return false;
            };
            self_slot = slot;
            *(&raw mut VFS_SELF_CLIENT_EP) = slot;
        } else {
            let _ = trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, self_slot);
        }

        let err = trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            provider_slot,
            crate::CAP_SELF_CSPACE,
            self_slot,
            PROCMGR_VFS_CLIENT_BADGE,
        );
        if err != 0 {
            if newly_allocated {
                alloc.free_single_slot(self_slot);
                *(&raw mut VFS_SELF_CLIENT_EP) = 0;
            }
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: self VFS client cap mint failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return false;
        }

        core::ptr::write_volatile(&raw mut trona_runtime::__trona_cap_vfs_ep, self_slot);
        true
    }
}
