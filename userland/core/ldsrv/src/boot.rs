// SPDX-License-Identifier: GPL-2.0-only
//
//! ldsrv startup: resolve the private adopt-MP recv cap from the startup
//! cap table. Init holds the send end and never publishes this MP to the
//! name service, so the adopt handshake — the boot code-MO set plus the
//! moved exec-authority — cannot be forged by a public `resolve_library`
//! client.

use trona_runtime::spawn::cap_table::{find_in_auxv, lookup};
use trona_runtime::spawn::role_consts::{
    ROLE_LDSRV_ADOPT_RECV, ROLE_LDSRV_EXEC_CONTROL_RECV, ROLE_LDSRV_PLUMBING_UNTYPED,
};

/// CSpace slot init installed for `role` in ldsrv's startup cap table, or `0`
/// when absent.
fn role_slot(role: u32) -> u64 {
    let auxv = unsafe { core::ptr::read_volatile(&raw const trona_runtime::__trona_saved_auxv) };
    let table = unsafe { find_in_auxv(auxv) };
    if table.is_null() {
        return 0;
    }
    lookup(table, role).map(|e| e.slot as u64).unwrap_or(0)
}

/// Recv end of the private adopt MP (boot handoff). `0` ⇒ ldsrv idles — it
/// cannot become the code authority without the handoff channel.
pub fn adopt_recv_slot() -> u64 {
    role_slot(ROLE_LDSRV_ADOPT_RECV)
}

/// Recv end of the dedicated exec-control MP over which init issues
/// `resolve_main`. `0` ⇒ ldsrv serves only `resolve_library`.
pub fn exec_control_recv_slot() -> u64 {
    role_slot(ROLE_LDSRV_EXEC_CONTROL_RECV)
}

/// Plumbing untyped ldsrv retypes its reactor objects (EventQueue + Watches)
/// from. `0` ⇒ ldsrv cannot build its multiplexed reactor.
pub fn plumbing_untyped_slot() -> u64 {
    role_slot(ROLE_LDSRV_PLUMBING_UNTYPED)
}
