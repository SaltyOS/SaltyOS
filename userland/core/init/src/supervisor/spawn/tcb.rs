// SPDX-License-Identifier: GPL-2.0-only
//
//! TCB and SchedContext invoke wrappers used by the spawn pipeline.
//!
//! `configure_and_start_tcb` is the single bring-up entry point —
//! callers compose a [`crate::supervisor::spawn::plan::ChildBundle`],
//! a per-spawn [`SchedParams`], and the entry point + stack bounds
//! into one call. The wrapper issues every kernel-side bind in order:
//!
//! 1. `TCB_SET_SPACE(cspace, vspace)` — bind address space.
//! 2. `TCB_SET_STACK_BOUNDS(stack_top, stack_min, guard_bottom)` —
//!    optional; enables the stack-overflow guard and lets `setrlimit
//!    (RLIMIT_STACK)` reason about user stack growth.
//! 3. `TCB_CONFIGURE(rip, rsp, ipc_va)` — allocate/install the
//!    kernel + trampoline stacks, record the IPC buffer VA, and seed
//!    the initial user register state.
//! 4. `SC_CONFIGURE(budget_ns, period_ns)` — fair-class default if
//!    `params.is_default()`.
//! 5. `SC_BIND(tcb)` — atomically attach the SC to the TCB.
//! 6. `TCB_START` — schedule.

use crate::supervisor::spawn::plan::ChildBundle;
use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;

/// SchedContext parameters. The `is_default()` factory yields the
/// fair-class budget the userland uses for every freshly
/// spawned service (1 ms budget, 0 period = best-effort fair).
#[derive(Clone, Copy, Debug)]
pub struct SchedParams {
    pub budget_ns: u64,
    pub period_ns: u64,
}

impl SchedParams {
    pub const fn fair_default() -> Self {
        // 1 ms budget, no period = best-effort fair scheduling. Real-
        // time / deadline policies override after the TCB is up.
        Self {
            budget_ns: 1_000_000,
            period_ns: 0,
        }
    }
}

/// `TCB_SET_SPACE(cspace_cap, vspace_cap, cspace_depth)`.
pub fn tcb_set_space(
    tcb: CapRef,
    cspace: CapRef,
    vspace: CapRef,
    cspace_depth: u64,
) -> Result<(), i32> {
    let err = invoke::tcb_set_space_with_depth(tcb, cspace, vspace, cspace_depth);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// `TCB_CONFIGURE(rip, rsp, ipc_buffer_va)` — install per-TCB kernel
/// stacks, record the IPC buffer VA, and seed the initial user-mode
/// entry state. Freshly retyped TCBs must pass through this before
/// they can be started on x86_64.
pub fn tcb_configure(tcb: CapRef, rip: u64, rsp: u64, ipc_buffer_va: u64) -> Result<(), i32> {
    let err = invoke::tcb_configure(tcb, rip, rsp, ipc_buffer_va);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// `TCB_SET_TLS_BASE(tls_base)` — sets the initial user thread pointer
/// for a TCB before it is started.
pub fn tcb_set_tls_base(tcb: CapRef, tls_base: u64) -> Result<(), i32> {
    let err = invoke::tcb_set_tls_base(tcb, tls_base);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// `TCB_SET_STACK_BOUNDS(stack_top, stack_min, guard_bottom)` — sets
/// the user stack's high / low VAs and the guard-page bottom. Enables
/// stack-overflow detection and lets the kernel reject `setrlimit
/// (RLIMIT_STACK)` calls below the current commitment.
pub fn tcb_set_stack_bounds(
    tcb: CapRef,
    stack_top: u64,
    stack_min: u64,
    guard_bottom: u64,
) -> Result<(), i32> {
    let err = invoke::tcb_set_stack_bounds(tcb, stack_top, stack_min, guard_bottom);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// `TCB_START` — transition the TCB to Runnable and enqueue.
pub fn tcb_start(tcb: CapRef) -> Result<(), i32> {
    let err = invoke::tcb_start(tcb);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// `SC_CONFIGURE(budget_ns, period_ns)` — set the SchedContext's
/// budget and period.
pub fn sc_configure(sc: CapRef, params: SchedParams) -> Result<(), i32> {
    let err = invoke::sc_configure(sc, params.budget_ns, params.period_ns);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// `SC_BIND(tcb_cap)` — atomically attach the SchedContext to the
/// TCB. After this call the TCB has a non-null `sched_context` field
/// and may be started.
pub fn sc_bind(sc: CapRef, tcb: CapRef) -> Result<(), i32> {
    let err = invoke::sc_bind(sc, tcb);
    if err != 0 {
        return Err(err);
    }
    Ok(())
}

/// Configure a freshly-retyped TCB: bind address space, apply optional
/// stack bounds, run `TCB_CONFIGURE`, then configure + bind the
/// SchedContext. The TCB is left configured but not running on return.
///
/// `initial_rsp` is the user-space stack pointer the kernel writes
/// into RSP — typically `LoadedImage::child_sp`, which points at
/// `argc` inside the SysV-composed stack page so the child's
/// `_start` reads the argv/envp/auxv blob correctly. `stack_high`
/// is the high VA of the stack VMA (`DEFAULT_CHILD_STACK_TOP`); it
/// goes to `TCB_SET_STACK_BOUNDS` as the upper bound and bears no
/// relation to `initial_rsp`.
///
/// `stack_min == 0` skips `TCB_SET_STACK_BOUNDS` — the kernel
/// validates the stack VMA exists before accepting bounds, so the
/// caller must only supply a non-zero `stack_min` once the loader
/// has actually mapped the stack region.
///
/// `ipc_buffer_va == 0` is passed through to `TCB_CONFIGURE`; the
/// kernel accepts that as "no fastpath IPC buffer".
#[allow(clippy::too_many_arguments)]
pub fn configure_tcb(
    bundle: &ChildBundle,
    ipc_buffer_va: u64,
    entry_pc: u64,
    initial_rsp: u64,
    initial_tls_base: u64,
    stack_high: u64,
    stack_min: u64,
    guard_bottom: u64,
    sched_params: SchedParams,
) -> Result<(), i32> {
    let tcb = bundle
        .tcb
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let cspace = bundle
        .cspace
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let vspace = bundle
        .vspace
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let sc = bundle
        .sched_context
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    tcb_set_space(tcb, cspace, vspace, 0)?;
    if stack_min != 0 {
        tcb_set_stack_bounds(tcb, stack_high, stack_min, guard_bottom)?;
    }
    tcb_configure(tcb, entry_pc, initial_rsp, ipc_buffer_va)?;
    if initial_tls_base != 0 {
        tcb_set_tls_base(tcb, initial_tls_base)?;
    }
    sc_configure(sc, sched_params)?;
    sc_bind(sc, tcb)?;
    Ok(())
}

/// Bring up a freshly-retyped TCB end-to-end. The TCB is left running
/// on return.
#[allow(clippy::too_many_arguments)]
pub fn configure_and_start_tcb(
    bundle: &ChildBundle,
    ipc_buffer_va: u64,
    entry_pc: u64,
    initial_rsp: u64,
    initial_tls_base: u64,
    stack_high: u64,
    stack_min: u64,
    guard_bottom: u64,
    sched_params: SchedParams,
) -> Result<(), i32> {
    configure_tcb(
        bundle,
        ipc_buffer_va,
        entry_pc,
        initial_rsp,
        initial_tls_base,
        stack_high,
        stack_min,
        guard_bottom,
        sched_params,
    )?;
    let tcb = bundle
        .tcb
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    tcb_start(tcb)?;
    Ok(())
}
