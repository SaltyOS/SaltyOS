// SPDX-License-Identifier: GPL-2.0-only
//! Structural TCB mutations.
//!
//! `task::control` only carries the configuration / capability /
//! priority mutations that flip TCB structural state under the
//! per-TCB lock. Wait/wake transitions live in `task::wait`,
//! TCB_STOP/RESUME in `task::stop`, kill/exit in `task::quiesce`,
//! and the fault MessagePipe binding.

use super::state::can_mutate_thread_structure;
use crate::cap::{CNode, KernelObject, ObjectType};
use crate::ipc::message_pipe::MessagePipe;
use crate::mm::{VSpace, VSpaceTracking};
use crate::sched::class::fair::FAIR_DEFAULT_WEIGHT;
use crate::sched::class::rt::RT_FIFO_MAX_PRIORITY;
use crate::sched::class::{SCHED_CLASS_FAIR, SCHED_CLASS_IDLE, SCHED_CLASS_RT_FIFO};
use crate::sched::thread::Tcb;
use crate::syscall::SyscallError;
use crate::task::state::ThreadState;

pub(crate) const TCB_CONFIGURE_KSTACK_PAGES: usize = 4;

pub(crate) struct ConfigureCleanup {
    pub(crate) kernel_stack_top: u64,
    pub(crate) trampoline_stack_top: u64,
    pub(crate) tracking: *mut VSpaceTracking,
}

pub(crate) struct SpaceRootsToRelease {
    pub(crate) cspace: *mut CNode,
    pub(crate) vspace: *mut VSpace,
}

pub(crate) struct WriteRegistersAction {
    pub(crate) enqueue: bool,
}

pub(crate) struct PriorityAction {
    pub(crate) fair_reweight: Option<u16>,
    pub(crate) requeue_ready: bool,
}

pub(crate) struct SchedClassAction {
    pub(crate) requeue_ready: bool,
}

pub(crate) struct TlsBaseAction {
    pub(crate) apply_now: bool,
}

pub(crate) struct AbiTpAction {
    pub(crate) apply_now: bool,
}

pub(crate) unsafe fn free_tcb_configure_stacks(
    kernel_stack_top: u64,
    trampoline_stack_top: u64,
    tracking: *mut VSpaceTracking,
) {
    let owner = crate::mm::frame::FrameOwner::KernelPrivate {
        subkind: crate::mm::frame::KernelMetaKind::KernelStack,
    };

    if kernel_stack_top != 0 {
        let base =
            kernel_stack_top - (TCB_CONFIGURE_KSTACK_PAGES as u64 * crate::mm::PAGE_SIZE as u64);
        let phys = crate::mm::virt_to_phys(base);
        for i in 0..TCB_CONFIGURE_KSTACK_PAGES {
            crate::mm::pmm_free(phys + (i * crate::mm::PAGE_SIZE) as u64, &owner);
        }
        if !tracking.is_null() {
            unsafe {
                (*tracking).vm_kstack_pages.fetch_sub(
                    TCB_CONFIGURE_KSTACK_PAGES as u64,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    }

    if trampoline_stack_top != 0 {
        let phys = crate::mm::virt_to_phys(trampoline_stack_top - crate::mm::PAGE_SIZE as u64);
        crate::mm::pmm_free(phys, &owner);
        if !tracking.is_null() {
            unsafe {
                (*tracking)
                    .vm_kstack_pages
                    .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

pub(crate) unsafe fn configure_thread_locked(
    tcb: &mut Tcb,
    entry_rip: u64,
    entry_rsp: u64,
    ipc_buffer: u64,
    kernel_stack_top: u64,
    #[cfg_attr(target_arch = "aarch64", allow(unused_variables))] trampoline_stack_top: u64,
) -> Result<ConfigureCleanup, SyscallError> {
    if !can_mutate_thread_structure(tcb) {
        return Err(SyscallError::Busy);
    }
    if tcb.vspace_root.is_null() {
        return Err(SyscallError::InvalidOperation);
    }

    let cleanup = ConfigureCleanup {
        kernel_stack_top: tcb.kernel_stack_top,
        trampoline_stack_top: tcb.trampoline_stack_top,
        tracking: unsafe { (*tcb.vspace_root).tracking },
    };
    tcb.debug_user_entry = entry_rip;

    #[cfg(target_arch = "x86_64")]
    {
        let vspace = unsafe { &*tcb.vspace_root };
        tcb.kernel_stack_top = kernel_stack_top;
        tcb.trampoline_stack_top = trampoline_stack_top;
        tcb.stack_canary = crate::arch::generate_stack_canary();
        tcb.context.rip = crate::arch::usermode_trampoline as *const () as u64;
        tcb.context.rsp = trampoline_stack_top;
        tcb.context.r12 = entry_rip;
        tcb.context.r13 = entry_rsp;
        tcb.context.r14 = vspace.root();
        tcb.context.r15 = 0x0202;
        tcb.context.rflags = 0x202;
        if !cleanup.tracking.is_null() {
            unsafe {
                (*cleanup.tracking).vm_kstack_pages.fetch_add(
                    (TCB_CONFIGURE_KSTACK_PAGES + 1) as u64,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        tcb.kernel_stack_top = kernel_stack_top;
        tcb.trampoline_stack_top = 0;
        tcb.stack_canary = crate::arch::generate_stack_canary();
        unsafe {
            crate::arch::aarch64::context::init_user_thread_context(
                &mut tcb.context,
                kernel_stack_top,
                entry_rip,
                entry_rsp,
                0x0,
            );
        }
        if !cleanup.tracking.is_null() {
            unsafe {
                (*cleanup.tracking).vm_kstack_pages.fetch_add(
                    TCB_CONFIGURE_KSTACK_PAGES as u64,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    }

    tcb.ipc_buffer = ipc_buffer;
    if tcb.user_stack_top == 0 {
        tcb.user_stack_top = entry_rsp;
        tcb.user_stack_min = 0;
        tcb.user_stack_guard_bottom = 0;
    }
    crate::arch::fpu::init_thread(tcb);
    unsafe { crate::task::state::mark_configured_locked(tcb as *mut Tcb) };
    Ok(cleanup)
}

pub(crate) unsafe fn set_space_roots_locked(
    tcb: &mut Tcb,
    cspace: *mut CNode,
    vspace: *mut VSpace,
    cspace_depth: u8,
) -> Result<SpaceRootsToRelease, SyscallError> {
    if !can_mutate_thread_structure(tcb) {
        return Err(SyscallError::Busy);
    }

    let old = SpaceRootsToRelease {
        cspace: tcb.cspace_root,
        vspace: tcb.vspace_root,
    };
    tcb.cspace_root = cspace;
    tcb.vspace_root = vspace;
    tcb.cspace_depth = cspace_depth;
    Ok(old)
}

pub(crate) fn set_ipc_buffer_locked(tcb: &mut Tcb, addr: u64) {
    tcb.ipc_buffer = addr;
}

pub(crate) fn set_fault_pipe_locked(tcb: &mut Tcb, pipe: *mut MessagePipe) -> *mut MessagePipe {
    let old_pipe = tcb.fault_pipe;
    tcb.fault_pipe = pipe;
    old_pipe
}

pub(crate) fn release_fault_pipe_ref(pipe: *mut MessagePipe) {
    if pipe.is_null() {
        return;
    }

    unsafe {
        crate::cap::release_object(pipe as *mut KernelObject, ObjectType::MessagePipe);
    }
}

pub(crate) fn set_tls_base_locked(
    tcb: &mut Tcb,
    current: *mut Tcb,
    tls_base: u64,
) -> Result<TlsBaseAction, SyscallError> {
    if !core::ptr::eq(tcb as *mut Tcb, current) && tcb.state == ThreadState::Runnable {
        return Err(SyscallError::InvalidOperation);
    }

    tcb.tls_base = tls_base;
    Ok(TlsBaseAction {
        apply_now: core::ptr::eq(tcb as *mut Tcb, current),
    })
}

pub(crate) fn set_abi_tp_locked(
    tcb: &mut Tcb,
    current: *mut Tcb,
    abi_tp: u64,
) -> Result<AbiTpAction, SyscallError> {
    if !core::ptr::eq(tcb as *mut Tcb, current) && tcb.state == ThreadState::Runnable {
        return Err(SyscallError::InvalidOperation);
    }

    tcb.abi_tp_base = abi_tp;
    #[cfg(target_arch = "aarch64")]
    {
        tcb.context.x[18] = abi_tp;
    }
    Ok(AbiTpAction {
        apply_now: core::ptr::eq(tcb as *mut Tcb, current),
    })
}

pub(crate) fn set_stack_bounds_locked(
    tcb: &mut Tcb,
    stack_top: u64,
    stack_min: u64,
    guard_bottom: u64,
) -> Result<(), SyscallError> {
    if !can_mutate_thread_structure(tcb) {
        return Err(SyscallError::Busy);
    }
    tcb.user_stack_top = stack_top;
    tcb.user_stack_min = stack_min;
    tcb.user_stack_guard_bottom = guard_bottom;
    Ok(())
}

pub(crate) unsafe fn write_registers_locked(
    tcb: &mut Tcb,
    flags: u64,
    rip: u64,
    rsp: u64,
) -> Result<WriteRegistersAction, SyscallError> {
    if !can_mutate_thread_structure(tcb) {
        return Err(SyscallError::Busy);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if tcb.vspace_root.is_null() || tcb.trampoline_stack_top == 0 {
            return Err(SyscallError::InvalidOperation);
        }
        let vspace = unsafe { &*tcb.vspace_root };
        tcb.context.rip = crate::arch::usermode_trampoline as *const () as u64;
        tcb.context.rsp = tcb.trampoline_stack_top;
        tcb.context.r12 = rip;
        tcb.context.r13 = rsp;
        tcb.context.r14 = vspace.root();
        tcb.context.r15 = 0x0202;
        tcb.context.rflags = 0x202;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if !tcb.vspace_root.is_null() {
            tcb.context.return_elr = rip;
            tcb.context.user_sp = rsp;
            tcb.context.return_spsr = 0x0;
        } else {
            unsafe {
                crate::arch::aarch64::context::init_kernel_thread_context(
                    &mut tcb.context,
                    rsp,
                    rip,
                );
            }
        }
    }

    Ok(WriteRegistersAction {
        enqueue: (flags & 1) != 0,
    })
}

pub(crate) unsafe fn set_priority_locked(
    tcb: &mut Tcb,
    priority: u64,
) -> Result<PriorityAction, SyscallError> {
    match tcb.sched_class {
        crate::sched::class::SCHED_CLASS_DEADLINE => {
            if !tcb.sched_context.is_null() {
                unsafe {
                    (*tcb.sched_context).deadline = priority;
                }
            } else {
                tcb.base_priority = Tcb::encode_deadline_priority(priority);
                if tcb.pip_donation_count == 0 {
                    tcb.priority = tcb.base_priority;
                }
            }
            unsafe {
                tcb.recompute_sched_key();
            }
            Ok(PriorityAction {
                fair_reweight: None,
                requeue_ready: tcb.state == ThreadState::Runnable,
            })
        }
        SCHED_CLASS_RT_FIFO => {
            if priority == 0 || priority > RT_FIFO_MAX_PRIORITY as u64 {
                return Err(SyscallError::InvalidArgument);
            }
            tcb.rt_priority = priority as u8;
            unsafe {
                tcb.recompute_sched_key();
            }
            Ok(PriorityAction {
                fair_reweight: None,
                requeue_ready: tcb.state == ThreadState::Runnable,
            })
        }
        SCHED_CLASS_FAIR => {
            if priority == 0 || priority > u16::MAX as u64 {
                return Err(SyscallError::InvalidArgument);
            }
            Ok(PriorityAction {
                fair_reweight: Some(priority as u16),
                requeue_ready: false,
            })
        }
        SCHED_CLASS_IDLE => Err(SyscallError::InvalidOperation),
        _ => Ok(PriorityAction {
            fair_reweight: None,
            requeue_ready: false,
        }),
    }
}

pub(crate) unsafe fn set_sched_class_locked(
    tcb: &mut Tcb,
    class: u8,
) -> Result<SchedClassAction, SyscallError> {
    if class == SCHED_CLASS_IDLE {
        return Err(SyscallError::InvalidOperation);
    }

    let old_class = tcb.sched_class;
    tcb.sched_class = class;
    if class == SCHED_CLASS_RT_FIFO && old_class != SCHED_CLASS_RT_FIFO {
        tcb.rt_priority = RT_FIFO_MAX_PRIORITY;
    }
    if class == SCHED_CLASS_FAIR {
        if old_class != SCHED_CLASS_FAIR {
            tcb.set_fair_weight(FAIR_DEFAULT_WEIGHT);
            tcb.fair_vruntime = 0;
            tcb.clear_fair_saved_lag();
        }
        unsafe { tcb.prepare_fair_sched_context_for_enqueue() };
    }
    unsafe {
        tcb.recompute_sched_key();
    }

    Ok(SchedClassAction {
        requeue_ready: tcb.state == ThreadState::Runnable,
    })
}
