// SPDX-License-Identifier: GPL-2.0-only
//! procmgr-private helpers for raw authority capabilities that are
//! intentionally excluded from the public `trona::caps::*` surface.
//!
//! procmgr holds **two** variants of the mmsrv and rsrcsrv endpoints:
//!
//! - a **badged client** copy at the slot named by
//!   `trona::caps::mmsrv_ep()` / `trona::caps::rsrcsrv_ep()`, used for
//!   procmgr's own IPC to those services.
//! - an **unbadged raw-authority** copy that preserves the `GRANT`
//!   right, used by procmgr when minting per-child badged copies into
//!   children's CSpaces during spawn.
//!
//! The raw-authority slots must not appear on any `trona::caps::*`
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
//! `userland/services/procmgr.service` (the `NeedEP=` / `Require=`
//! lines) and this module together.

use trona::cap_table;
use trona::consts::kernel::{ROLE_MMSRV_AUTHORITY_RAW, ROLE_RSRCSRV_AUTHORITY_RAW};
use trona::types::core::Cap;

/// Look up a raw-authority role in the startup cap_table. Returns the
/// cap slot number the spawner placed the cap at, or 0 if the table is
/// missing or the role is absent (which indicates a procmgr.service
/// misconfiguration).
unsafe fn lookup_raw_role(role: u32) -> Cap {
    // SAFETY: `__trona_saved_auxv` is populated by `runtime_set_auxv`
    // early in procmgr startup; `find_in_auxv` handles null gracefully.
    unsafe {
        let auxv = *(&raw const trona::__trona_saved_auxv);
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
