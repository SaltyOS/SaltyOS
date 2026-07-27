// SPDX-License-Identifier: GPL-2.0-only
//! TCB-related syscall handlers.

use super::cspace::resolve_tcb_request;
use super::{
    CNode, CapRights, Capability, DeferredReleaseList, ObjectType, SCHED_CLASS_DEADLINE,
    SCHED_CLASS_FAIR, SCHED_CLASS_IDLE, SCHED_CLASS_RT_FIFO, SyscallError, SyscallResult, Tcb,
    ThreadState, lookup_cnode_root, lookup_typed_cap_locked, restore_irq, save_irq_disable,
    validate_capability, write_current_ipc_word,
};
use crate::mm::VSpace;
use core::sync::atomic::Ordering;

pub(super) fn syscall_tcb_start(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::RESUME) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        tcb.tcb_lock();
        let action = crate::task::stop::prepare_resume_locked(tcb);
        crate::sched::control::apply_resume_locked(
            scheduler,
            tcb as *mut Tcb,
            &action,
            &mut releases,
        );
        tcb.tcb_unlock();
        crate::sched::control::finish_resume(scheduler, tcb as *mut Tcb, &action, &mut releases);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_stop(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let target_tcb = cap.object as *mut Tcb;

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *target_tcb;
        let scheduler = crate::sched::scheduler::scheduler();
        tcb.tcb_lock();
        let running_cpu = if tcb.state() == ThreadState::Runnable {
            scheduler.lock();
            let cpu = scheduler.find_running_cpu(tcb as *mut Tcb);
            scheduler.unlock();
            cpu
        } else {
            None
        };
        let action = crate::task::stop::prepare_suspend_locked(
            tcb,
            crate::arch::current_cpu() as usize,
            running_cpu,
        );
        if matches!(
            action.kind,
            crate::task::stop::SuspendActionKind::RescheduleSelf
        ) {
            tcb.tcb_unlock();
            scheduler.reschedule();
            restore_irq(irq);
            return SyscallResult::ok(0);
        }
        tcb.tcb_unlock();
        crate::task::quiesce::release_suspended_waiter(scheduler, target_tcb, &action);
        restore_irq(irq);

        if matches!(
            action.kind,
            crate::task::stop::SuspendActionKind::WaitForQuiesce
        ) {
            crate::task::quiesce::wait_for_tcb_quiesced_blocking(target_tcb, action.cpu_hint);
            crate::task::quiesce::cleanup_quiesced_thread(scheduler, target_tcb);
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_affinity(cap: &Capability, cpu_id: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let affinity = cpu_id as u32;
    let online_cpus = crate::sched::scheduler::scheduler().online_cpus as usize;
    if affinity != 0xFFFF_FFFF && (affinity as usize) >= online_cpus {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        tcb.tcb_lock();
        let action = crate::task::stop::set_affinity_locked(tcb, affinity);
        let resched_cpu = crate::sched::control::apply_affinity_locked(
            scheduler,
            tcb as *mut Tcb,
            &action,
            &mut releases,
        );
        tcb.tcb_unlock();
        crate::sched::control::finish_locked_mutation(scheduler, &mut releases);
        restore_irq(irq);
        crate::sched::control::dispatch_reschedule(scheduler, resched_cpu);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_read_registers(cap: &Capability, _flags: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &*(cap.object as *const Tcb);
        tcb.tcb_lock();
        let result = if tcb.state() != ThreadState::Stopped {
            SyscallResult::err(SyscallError::Busy)
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                SyscallResult::ok(tcb.context.rip)
            }
            #[cfg(target_arch = "aarch64")]
            {
                SyscallResult::ok(tcb.context.return_elr)
            }
        };
        tcb.tcb_unlock();
        restore_irq(irq);
        result
    }
}

pub(super) fn syscall_tcb_write_registers(
    cap: &Capability,
    flags: u64,
    rip: u64,
    rsp: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        tcb.tcb_lock();
        let action = match crate::task::control::write_registers_locked(tcb, flags, rip, rsp) {
            Ok(action) => action,
            Err(err) => {
                tcb.tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };

        crate::sched::control::apply_write_registers_locked(
            scheduler,
            tcb as *mut Tcb,
            &action,
            &mut releases,
        );
        tcb.tcb_unlock();
        crate::sched::control::finish_locked_mutation(scheduler, &mut releases);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_priority(cap: &Capability, priority: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        tcb.tcb_lock();
        let action = match crate::task::control::set_priority_locked(tcb, priority) {
            Ok(action) => action,
            Err(err) => {
                tcb.tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        crate::sched::control::apply_priority_locked(
            scheduler,
            tcb as *mut Tcb,
            &action,
            &mut releases,
        );
        tcb.tcb_unlock();
        crate::sched::control::finish_locked_mutation(scheduler, &mut releases);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_sched_class(cap: &Capability, class: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let class_u8 = class as u8;
    let class = match class_u8 {
        SCHED_CLASS_DEADLINE | SCHED_CLASS_RT_FIFO | SCHED_CLASS_FAIR => class_u8,
        SCHED_CLASS_IDLE => return SyscallResult::err(SyscallError::InvalidOperation),
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    };

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        tcb.tcb_lock();
        let action = match crate::task::control::set_sched_class_locked(tcb, class) {
            Ok(action) => action,
            Err(err) => {
                tcb.tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };

        crate::sched::control::apply_sched_class_locked(
            scheduler,
            tcb as *mut Tcb,
            &action,
            &mut releases,
        );
        tcb.tcb_unlock();
        crate::sched::control::finish_locked_mutation(scheduler, &mut releases);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn validate_ipc_buffer_addr(addr: u64) -> Result<(), SyscallError> {
    if addr == 0 {
        return Ok(());
    }
    if addr & 0xFFF != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if addr >= 0x0000_8000_0000_0000 {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(())
}

pub(super) fn syscall_tcb_set_ipc_buffer(cap: &Capability, addr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if let Err(e) = validate_ipc_buffer_addr(addr) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        crate::task::control::set_ipc_buffer_locked(tcb, addr);
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_fault_pipe(
    cap: &Capability,
    fault_pipe_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let pipe = if fault_pipe_cap_ptr == 0 {
        core::ptr::null_mut::<crate::ipc::message_pipe::MessagePipe>()
    } else {
        // Resolve / validate / refcount-bump must run inside a
        // single CAP_LOCK section. Without this, a sibling thread's
        // `delete_capability` could drive the pipe's refcount to
        // zero between our lookup and our `increment_refcount`,
        // and our +1 on a reaper-enqueued object would smuggle a
        // dangling pointer into the TCB.
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let cspace_root = unsafe { (*current).cspace_root };
        if cspace_root.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let result: Result<*mut crate::ipc::message_pipe::MessagePipe, SyscallError> = unsafe {
            let irq = save_irq_disable();
            crate::mm::CAP_LOCK.lock();
            let r = (|| -> Result<_, SyscallError> {
                let cref =
                    crate::cap::cnode::resolve_root_cspace_slot(&*cspace_root, fault_pipe_cap_ptr)
                        .map_err(|_| SyscallError::InvalidCapability)?;
                // Reject a stale CNode entry (slot freed + reused since
                // written) instead of dereferencing whatever cap now
                // occupies the slot.
                let (_, pipe_cap) = cref.get_live().ok_or(SyscallError::InvalidCapability)?;
                validate_capability(&pipe_cap, ObjectType::MessagePipe, CapRights::WRITE)?;
                crate::cap::increment_refcount(pipe_cap.object);
                Ok(pipe_cap.object as *mut crate::ipc::message_pipe::MessagePipe)
            })();
            crate::mm::CAP_LOCK.unlock();
            restore_irq(irq);
            r
        };
        match result {
            Ok(p) => p,
            Err(e) => return SyscallResult::err(e),
        }
    };

    let old_pipe;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        old_pipe = crate::task::control::set_fault_pipe_locked(tcb, pipe);
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    crate::task::control::release_fault_pipe_ref(old_pipe);

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_copy_fpu(dest_cap: &Capability, src_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(dest_cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let src_req = match resolve_tcb_request(src_cap_ptr, CapRights::READ) {
        Ok(request) => request,
        Err(e) => return SyscallResult::err(e),
    };

    unsafe {
        let dest_tcb = dest_cap.object as *mut Tcb;
        let src_tcb = src_req.tcb();
        crate::arch::fpu::flush_current(src_tcb);
        core::ptr::copy_nonoverlapping(
            (*src_tcb).fpu_state.data.as_ptr(),
            (*dest_tcb).fpu_state.data.as_mut_ptr(),
            (*src_tcb).fpu_state.data.len(),
        );
        crate::arch::fpu::reload_current(dest_tcb);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_tls_base(cap: &Capability, tls_base: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    if tls_base != 0 && tls_base >= 0x0000_8000_0000_0000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let action;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        let current = crate::sched::scheduler::scheduler().current();
        action = match crate::task::control::set_tls_base_locked(tcb, current, tls_base) {
            Ok(action) => action,
            Err(err) => {
                tcb.tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    if action.apply_now {
        unsafe {
            crate::arch::write_fs_base(tls_base);
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_abi_tp(cap: &Capability, abi_tp: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    if abi_tp != 0 && abi_tp >= 0x0000_8000_0000_0000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let action;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        let current = crate::sched::scheduler::scheduler().current();
        action = match crate::task::control::set_abi_tp_locked(tcb, current, abi_tp) {
            Ok(action) => action,
            Err(err) => {
                tcb.tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    if action.apply_now {
        crate::arch::write_abi_tp_base(abi_tp);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_get_space_info(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let depth;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &*(cap.object as *const Tcb);
        tcb.tcb_lock();
        depth = tcb.cspace_depth as u64;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    unsafe {
        if let Err(err) = write_current_ipc_word(0, depth) {
            return SyscallResult::err(err);
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_configure(
    cap: &Capability,
    entry_rip: u64,
    entry_rsp: u64,
    ipc_buffer: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if let Err(e) = validate_ipc_buffer_addr(ipc_buffer) {
        return SyscallResult::err(e);
    }

    crate::kernel::printk::kdebug!(syscall, |_g| {
        _g.puts("[TCB_CONFIGURE] begin tcb=");
        _g.hex(cap.object as u64);
        _g.puts(" entry=");
        _g.hex(entry_rip);
        _g.puts(" rsp=");
        _g.hex(entry_rsp);
        _g.puts(" ipc=");
        _g.hex(ipc_buffer);
        _g.puts(" free=");
        _g.dec(crate::mm::pmm_free_count() as u64);
        _g.puts("\n");
    });

    let kstack_owner = crate::mm::frame::FrameOwner::KernelPrivate {
        subkind: crate::mm::frame::KernelMetaKind::KernelStack,
    };

    let kstack_phys = match crate::mm::pmm_alloc_contiguous_owned(
        crate::task::control::TCB_CONFIGURE_KSTACK_PAGES,
        &kstack_owner,
    ) {
        Some(f) => f,
        None => {
            crate::kernel::printk::kdebug!(syscall, |_g| {
                _g.puts("[TCB_CONFIGURE] kernel-stack alloc failed tcb=");
                _g.hex(cap.object as u64);
                _g.puts(" need_pages=");
                _g.dec(crate::task::control::TCB_CONFIGURE_KSTACK_PAGES as u64);
                _g.puts(" free=");
                _g.dec(crate::mm::pmm_free_count() as u64);
                _g.puts("\n");
            });
            return SyscallResult::err(SyscallError::OutOfMemory);
        }
    };
    let kstack_virt = crate::mm::phys_to_virt(kstack_phys);
    let kstack_top = kstack_virt
        + (crate::task::control::TCB_CONFIGURE_KSTACK_PAGES * crate::mm::PAGE_SIZE) as u64;
    unsafe {
        core::ptr::write_bytes(
            kstack_virt as *mut u8,
            0,
            crate::task::control::TCB_CONFIGURE_KSTACK_PAGES * crate::mm::PAGE_SIZE,
        );
    }

    #[cfg(target_arch = "x86_64")]
    let tramp_stack_top = {
        let tramp_stack_phys = match crate::mm::pmm_alloc(&kstack_owner) {
            Some(f) => f,
            None => {
                unsafe {
                    crate::task::control::free_tcb_configure_stacks(
                        kstack_top,
                        0,
                        core::ptr::null_mut(),
                    )
                };
                crate::kernel::printk::kdebug!(syscall, |_g| {
                    _g.puts("[TCB_CONFIGURE] trampoline alloc failed tcb=");
                    _g.hex(cap.object as u64);
                    _g.puts(" free=");
                    _g.dec(crate::mm::pmm_free_count() as u64);
                    _g.puts("\n");
                });
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
        };
        let tramp_stack_virt = crate::mm::phys_to_virt(tramp_stack_phys);
        let tramp_stack_top = tramp_stack_virt + crate::mm::PAGE_SIZE as u64;
        unsafe {
            core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, crate::mm::PAGE_SIZE);
        }
        tramp_stack_top
    };

    #[cfg(target_arch = "aarch64")]
    let tramp_stack_top = 0;

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        let cleanup = match crate::task::control::configure_thread_locked(
            tcb,
            entry_rip,
            entry_rsp,
            ipc_buffer,
            kstack_top,
            tramp_stack_top,
        ) {
            Ok(cleanup) => cleanup,
            Err(err) => {
                let _state = tcb.state() as u64;
                tcb.tcb_unlock();
                restore_irq(irq);
                crate::task::control::free_tcb_configure_stacks(
                    kstack_top,
                    tramp_stack_top,
                    core::ptr::null_mut(),
                );
                crate::kernel::printk::kdebug!(syscall, |_g| {
                    _g.puts("[TCB_CONFIGURE] rejected tcb=");
                    _g.hex(cap.object as u64);
                    _g.puts(" err=");
                    _g.dec(err as u64);
                    _g.puts(" state=");
                    _g.dec(_state);
                    _g.puts(" free=");
                    _g.dec(crate::mm::pmm_free_count() as u64);
                    _g.puts("\n");
                });
                return SyscallResult::err(err);
            }
        };
        tcb.tcb_unlock();
        restore_irq(irq);

        crate::task::control::free_tcb_configure_stacks(
            cleanup.kernel_stack_top,
            cleanup.trampoline_stack_top,
            cleanup.tracking,
        );
    }

    crate::kernel::printk::kdebug!(syscall, |_g| {
        _g.puts("[TCB_CONFIGURE] success tcb=");
        _g.hex(cap.object as u64);
        _g.puts(" kstack_phys=");
        _g.hex(kstack_phys);
        _g.puts(" free=");
        _g.dec(crate::mm::pmm_free_count() as u64);
        _g.puts("\n");
    });

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_stack_bounds(
    cap: &Capability,
    stack_top: u64,
    stack_min: u64,
    guard_bottom: u64,
    reserved: u64,
) -> SyscallResult {
    const USER_VA_TOP: u64 = (crate::mm::PAGE_SIZE as u64) * 512 * 512 * 512 * 256;
    const PAGE_SIZE_U64: u64 = crate::mm::PAGE_SIZE as u64;
    const PAGE_MASK: u64 = PAGE_SIZE_U64 - 1;

    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if reserved != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if stack_top == 0 || stack_min == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if stack_top & PAGE_MASK != 0 || stack_min & PAGE_MASK != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if stack_top <= stack_min {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if stack_top > USER_VA_TOP || stack_min >= USER_VA_TOP {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if guard_bottom != 0 && (guard_bottom & PAGE_MASK != 0 || guard_bottom >= stack_min) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let expected_pages = ((stack_top - stack_min) / PAGE_SIZE_U64) as u32;
    if expected_pages == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let tcb = &mut *(cap.object as *mut Tcb);
        let vspace_root = tcb.vspace_root;
        if vspace_root.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let tracking = (*vspace_root).tracking;
        if tracking.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let vspace = &*vspace_root;
        let irq = save_irq_disable();
        vspace.lock.lock();
        let probe = (*tracking).mappings.lookup(stack_top - PAGE_SIZE_U64);
        let looked_up = match probe {
            Some((vma_start, vma)) => {
                if vma_start == stack_min
                    && vma.page_count == expected_pages
                    && vma.region_kind == uapi::KERNITE_REGION_KIND_STACK as u8
                {
                    if vma.mo().is_null() {
                        None
                    } else {
                        let mo = &*vma.mo();
                        if mo.page_count >= expected_pages {
                            Some(())
                        } else {
                            None
                        }
                    }
                } else {
                    None
                }
            }
            None => None,
        };
        vspace.lock.unlock();

        if looked_up.is_none() {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        tcb.tcb_lock();
        if let Err(err) =
            crate::task::control::set_stack_bounds_locked(tcb, stack_top, stack_min, guard_bottom)
        {
            tcb.tcb_unlock();
            restore_irq(irq);
            return SyscallResult::err(err);
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_set_space(
    cap: &Capability,
    cspace_cap_ptr: u64,
    vspace_cap_ptr: u64,
    cspace_depth: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let cspace_cap = match lookup_cnode_root(cspace_cap_ptr, CapRights::READ) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };

    let vspace_cap =
        match lookup_typed_cap_locked(vspace_cap_ptr, ObjectType::VSpace, CapRights::READ) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    if cspace_depth > 64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        crate::cap::increment_refcount(cspace_cap as *mut crate::cap::KernelObject);
        crate::cap::increment_refcount(vspace_cap.object as *mut crate::cap::KernelObject);
    }

    let mut old_cspace: *mut CNode = core::ptr::null_mut();
    let mut old_vspace: *mut VSpace = core::ptr::null_mut();
    let mut busy = false;

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        match crate::task::control::set_space_roots_locked(
            tcb,
            cspace_cap,
            vspace_cap.object as *mut VSpace,
            cspace_depth as u8,
        ) {
            Ok(old) => {
                old_cspace = old.cspace;
                old_vspace = old.vspace;
            }
            Err(SyscallError::Busy) => {
                busy = true;
            }
            Err(err) => {
                tcb.tcb_unlock();
                restore_irq(irq);
                crate::cap::release_object(
                    cspace_cap as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::CNode,
                );
                crate::cap::release_object(
                    vspace_cap.object as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::VSpace,
                );
                return SyscallResult::err(err);
            }
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    if busy {
        unsafe {
            crate::cap::release_object(
                cspace_cap as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::CNode,
            );
            crate::cap::release_object(
                vspace_cap.object as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::VSpace,
            );
        }
        return SyscallResult::err(SyscallError::Busy);
    }

    unsafe {
        if !old_cspace.is_null() {
            crate::cap::release_object(
                old_cspace as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::CNode,
            );
        }
        if !old_vspace.is_null() {
            crate::cap::release_object(
                old_vspace as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::VSpace,
            );
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_get_cpu_times(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let (user_runtime_ns, system_runtime_ns) = unsafe {
        let tcb = &*(cap.object as *const Tcb);
        (
            tcb.user_runtime_ns.load(Ordering::Acquire),
            tcb.system_runtime_ns.load(Ordering::Acquire),
        )
    };

    unsafe {
        if let Err(err) = super::copy_to_current_ipc_words(0, &[user_runtime_ns, system_runtime_ns])
        {
            return SyscallResult::err(err);
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_get_trace_id(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &*(cap.object as *const Tcb);
        let trace_id = tcb.trace_id();
        restore_irq(irq);
        SyscallResult::ok(trace_id)
    }
}

pub(super) fn syscall_tcb_kill(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    unsafe {
        crate::task::quiesce::begin_destroy(cap.object as *mut Tcb);
    }

    SyscallResult::ok(0)
}

/// Begin destroying the *calling* thread — the one currently running on
/// this CPU — regardless of which TCB `cap` names. `thread_exit` uses this
/// so an auxiliary thread that shares its process's CSpace terminates
/// itself instead of `CAP_SELF_TCB` (slot 0), which always names the
/// process main thread in a shared CSpace. `cap` is the authority token:
/// a thread may only exit itself, and it always holds a CONFIGURE-rights
/// TCB cap (`CAP_SELF_TCB`). For the main thread `current` already equals
/// that cap's object, so this matches the existing self-kill path.
pub(super) fn syscall_tcb_exit_self(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let current = crate::sched::scheduler::scheduler().current();
    // SAFETY: `current` is this CPU's running TCB, valid for the duration of
    // the syscall; begin_destroy tolerates self-destruction (the same path
    // the main thread takes today via CAP_SELF_TCB + TCB_KILL).
    unsafe {
        crate::task::quiesce::begin_destroy(current);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_yield(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let target = cap.object as *mut Tcb;
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if !core::ptr::eq(target as *const Tcb, current as *const Tcb) {
        return SyscallResult::err(SyscallError::InvalidOperation);
    }
    scheduler.yield_current();

    SyscallResult::ok(0)
}

pub(super) fn syscall_tcb_get_state(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let state;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &*(cap.object as *const Tcb);
        tcb.tcb_lock();
        state = tcb.state() as u64;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(state)
}

pub(super) fn syscall_tcb_get_abi_version(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    SyscallResult::ok(uapi::KERNITE_ABI_VERSION as u64)
}

pub(super) fn syscall_tcb_set_invoke_depths(
    cap: &Capability,
    depth0: u64,
    depth1: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if depth0 > 64 || depth1 > 64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        tcb.invoke_depth0 = depth0 as u8;
        tcb.invoke_depth1 = depth1 as u8;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}
