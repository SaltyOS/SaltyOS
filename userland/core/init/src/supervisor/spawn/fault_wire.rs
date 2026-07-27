// SPDX-License-Identifier: GPL-2.0-only
//
//! Fault-pipe wiring — connect a TCB's fault MP send side to the
//! kernel, and register the recv side with mmsrv.
//!
//! Order matters. Codex's review of the wiring flow established
//! the canonical sequence:
//!
//! 1. Allocate fault MP pair via `RSRC_ALLOC_MP_PAIR`.
//! 2. Register the recv side with mmsrv via `MM_REGISTER_FAULT_PIPE`.
//! 3. Bind the fault MP send side to the TCB (`TCB_SET_FAULT_PIPE`).

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::supervisor::SupervisorState;
use crate::supervisor::mm_ipc::mm_register_fault_pipe;

/// Forward to mmsrv: register a per-TCB fault MP recv side. mmsrv
/// arms a Watch with cookie = `(client_id<<32 | tcb_id)` so the
/// fault dispatcher resolves victim identity from the EventRecord.
pub fn register_fault_pipe(
    state: &SupervisorState,
    client_id: u32,
    tcb_id: u32,
    fault_mp_recv: OwnedCap,
) -> Result<(), i32> {
    mm_register_fault_pipe(state, client_id, tcb_id, fault_mp_recv)
}

/// Bind the per-TCB fault MP send side to a child TCB. The kernel
/// uses this on every page-fault / signal-fault delivery on this TCB.
pub fn bind_fault_caps(tcb: CapRef, fault_mp_send: CapRef) -> Result<(), i32> {
    let r = invoke::tcb_set_fault_pipe(tcb, fault_mp_send);
    if r != 0 {
        return Err(r);
    }
    Ok(())
}
