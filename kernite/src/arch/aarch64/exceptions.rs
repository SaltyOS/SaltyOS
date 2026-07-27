// SPDX-License-Identifier: GPL-2.0-only
//! AArch64 exception vector table and dispatch handlers.
//!
//! Provides the active host vector table (via `exceptions.S`) and Rust-side
//! handlers for synchronous exceptions (SVC, data/instruction aborts) and
//! IRQs from both EL1 and EL0.

unsafe extern "C" {
    fn aarch64_exceptions_read_esr_el1() -> u64;
    fn aarch64_exceptions_read_far_el1() -> u64;
    fn aarch64_exceptions_read_daif() -> u64;
    fn aarch64_exceptions_write_vbar_el1(vbar: u64);
}

// ---------------------------------------------------------------------------
// Exception frame
// ---------------------------------------------------------------------------

/// Saved register state pushed onto the kernel stack by the exception entry
/// macro.  Layout must match the `SAVE_REGS` / `RESTORE_REGS` assembly below.
///
/// Total size: 34 saved values (x0-x30 + SP_EL0 + ELR_EL1 + SPSR_EL1) =
/// 272 bytes, padded to 288 for 16-byte stack alignment.
#[repr(C)]
pub struct ExceptionFrame {
    /// General-purpose registers x0-x30.
    pub regs: [u64; 31],
    /// Saved user stack pointer (SP_EL0).
    pub sp_el0: u64,
    /// Exception return address (ELR_EL1).
    pub elr_el1: u64,
    /// Saved processor state (SPSR_EL1).
    pub spsr_el1: u64,
    /// Padding to 288 bytes (16-byte aligned).
    pub _pad: [u64; 2],
}

// ---------------------------------------------------------------------------
// ESR_EL1 exception class constants
// ---------------------------------------------------------------------------

/// SVC instruction execution in AArch64 state.
const EC_SVC_AARCH64: u64 = 0x15;
/// Instruction abort from a lower Exception Level.
const EC_IABT_LOWER: u64 = 0x20;
/// Instruction abort from the current Exception Level.
const EC_IABT_CURRENT: u64 = 0x21;
/// PC alignment fault.
const EC_PCALIGN: u64 = 0x22;
/// Data abort from a lower Exception Level.
const EC_DABT_LOWER: u64 = 0x24;
/// Data abort from the current Exception Level.
const EC_DABT_CURRENT: u64 = 0x25;
/// SP alignment fault.
const EC_SPALIGN: u64 = 0x26;
/// Access to SVE, Advanced SIMD, or floating-point (trapped).
const EC_FP_TRAP: u64 = 0x07;

#[inline(always)]
fn is_access_flag_fault(fsc: u64) -> bool {
    (0x08..=0x0B).contains(&fsc)
}

#[inline(always)]
fn is_permission_fault(fsc: u64) -> bool {
    (0x0C..=0x0F).contains(&fsc)
}

#[inline(always)]
fn read_exception_esr() -> u64 {
    unsafe { aarch64_exceptions_read_esr_el1() }
}

#[inline(always)]
fn read_exception_far() -> u64 {
    unsafe { aarch64_exceptions_read_far_el1() }
}

/// Spurious interrupt ID (no pending interrupt).
const INTID_SPURIOUS: u32 = 1023;
/// Maximum SGI interrupt ID (inclusive).
const INTID_SGI_MAX: u32 = 15;

unsafe fn save_el0_frame_to_current_tcb(frame: *const ExceptionFrame) {
    unsafe {
        let current = crate::sched::scheduler::scheduler().current();
        if current.is_null() {
            return;
        }
        let ctx = &mut (*current).context;
        let mut i = 0usize;
        while i < 31 {
            ctx.x[i] = (*frame).regs[i];
            i += 1;
        }
        ctx.x[18] = (*current).abi_tp_base;
        ctx.user_sp = (*frame).sp_el0;
        ctx.return_elr = (*frame).elr_el1;
        ctx.return_spsr = (*frame).spsr_el1;
    }
}

unsafe fn restore_el0_frame_from_current_tcb(frame: *mut ExceptionFrame, x0: u64, x1: u64) {
    unsafe {
        let current = crate::sched::scheduler::scheduler().current();
        if current.is_null() {
            (*frame).regs[0] = x0;
            (*frame).regs[1] = x1;
            return;
        }
        let ctx = &(*current).context;
        let mut i = 0usize;
        while i < 31 {
            (*frame).regs[i] = ctx.x[i];
            i += 1;
        }
        (*frame).regs[18] = (*current).abi_tp_base;
        (*frame).sp_el0 = ctx.user_sp;
        (*frame).elr_el1 = ctx.return_elr;
        (*frame).spsr_el1 = ctx.return_spsr;
        (*frame).regs[0] = x0;
        (*frame).regs[1] = x1;
    }
}

unsafe fn sync_el0_ttbr0_from_current_tcb(frame: *const ExceptionFrame) {
    unsafe {
        let current = crate::sched::scheduler::scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            return;
        }

        let vspace = &*(*current).vspace_root;
        let expected = vspace.host_ttbr0();
        let active = crate::arch::paging::read_cr3();
        if active != expected {
            let f = &*frame;
            let s = crate::kernel::printk::SerialGuard::acquire();
            s.puts("[A64] TTBR0 mismatch on EL0 resume: active=");
            s.hex(active);
            s.puts(" expected=");
            s.hex(expected);
            s.puts(" elr=");
            s.hex(f.elr_el1);
            s.puts("\n");
        }
        crate::arch::paging::write_cr3(expected);
    }
}

// The vector table and register save/restore stubs live in `exceptions.S`.

// ---------------------------------------------------------------------------
// Rust exception handlers
// ---------------------------------------------------------------------------

/// Handle synchronous exceptions taken from EL1 (kernel context).
///
/// Reads ESR_EL1 to determine the exception class and dispatches accordingly.
#[unsafe(no_mangle)]
extern "C" fn el1_sync_handler(frame: *const ExceptionFrame) {
    let esr = read_exception_esr();
    let ec = (esr >> 26) & 0x3F;

    match ec {
        EC_DABT_CURRENT => {
            // Data abort from EL1 (kernel page fault).
            let far = read_exception_far();
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };

            // Check if this is a write permission fault on a user VA.
            // This happens when the kernel writes to a COW page (e.g. IPC
            // buffer after fork). Resolve the COW fault so the faulting
            // instruction can be retried via ERET.
            let dfsc = esr & 0x3F;
            let is_write = esr & (1 << 6) != 0;
            let is_user_va = far < 0x0001_0000_0000_0000;

            if is_user_va && is_access_flag_fault(dfsc) {
                let fault = crate::mm::PageFaultInfo {
                    present: true,
                    write: is_write,
                    user: true,
                };
                let handled = unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        vspace.handle_accessed_fault(far, &fault).unwrap_or(false)
                    } else {
                        false
                    }
                };
                if handled {
                    return;
                }
            }

            if is_user_va && is_permission_fault(dfsc) && is_write {
                let fault = crate::mm::PageFaultInfo {
                    present: true,
                    write: true,
                    // Treat as user-page fault: FAR is a user VA in the
                    // current thread's VSpace, handle_cow_fault gates on this.
                    user: true,
                };
                let handled = unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        vspace.handle_cow_fault_pooled(far, &fault).unwrap_or(false)
                            || vspace.handle_cow_fault(far, &fault).unwrap_or(false)
                    } else {
                        false
                    }
                };
                if handled {
                    return;
                }
                // SMP race: another CPU may have already resolved the COW.
                // Re-read the PTE — if now writable, flush TLB and retry.
                let resolved_race = unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &*(*current).vspace_root;
                        if let Some(entry) = vspace.read_entry(far, 1) {
                            let writable = entry & crate::mm::vspace::ENTRY_WRITABLE != 0;
                            let cow = entry & crate::mm::vspace::ENTRY_COW != 0;
                            writable && !cow
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };
                if resolved_race {
                    crate::arch::paging::invlpg(far);
                    return;
                }
            }

            crate::kernel::panic::fatal_exception_context(
                "aarch64 EL1 data abort",
                format_args!("FAR={:#018x} ESR={:#010x} ELR={:#018x}", far, esr, elr),
                aarch64_panic_context(frame, esr, Some(far)),
                || dump_aarch64_exception(frame, esr, Some(far)),
            );
        }
        EC_IABT_CURRENT => {
            // Instruction abort from EL1.
            let far = read_exception_far();
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            crate::kernel::panic::fatal_exception_context(
                "aarch64 EL1 instruction abort",
                format_args!("FAR={:#018x} ESR={:#010x} ELR={:#018x}", far, esr, elr),
                aarch64_panic_context(frame, esr, Some(far)),
                || dump_aarch64_exception(frame, esr, Some(far)),
            );
        }
        EC_FP_TRAP => {
            // EL1 hit a trapped FP/SIMD instruction.
            let elr = unsafe { (*frame).elr_el1 };
            crate::kernel::panic::fatal_exception_context(
                "aarch64 EL1 FP/ASIMD trap",
                format_args!("ESR={:#010x} ELR={:#018x}", esr, elr),
                aarch64_panic_context(frame, esr, None),
                || dump_aarch64_exception(frame, esr, None),
            );
        }
        _ => {
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            crate::kernel::panic::fatal_exception_context(
                "aarch64 EL1 sync exception",
                format_args!("EC={:#04x} ESR={:#010x} ELR={:#018x}", ec, esr, elr),
                aarch64_panic_context(frame, esr, None),
                || dump_aarch64_exception(frame, esr, None),
            );
        }
    }
}

/// Handle IRQs taken from EL1 (kernel context).
///
/// Acknowledges the interrupt via the GIC, dispatches based on INTID,
/// and sends EOI. `frame.spsr_el1` still provides the interrupted-mode hint
/// for the scheduler's timer API shape; precise user/kernel runtime
/// attribution itself happens in the common entry/exit hooks.
#[unsafe(no_mangle)]
extern "C" fn el1_irq_handler(frame: *const ExceptionFrame) {
    // SPSR_EL1.M[3:0] == 0 → EL0t (user). Any other value is an EL1 mode.
    let interrupted_user_mode = unsafe { ((*frame).spsr_el1 & 0xF) == 0 };
    let intid = super::gic::acknowledge_irq();

    match intid {
        intid if intid == super::timer::irq_intid() => {
            // Active timer PPI — re-arm before EOI to clear ISTATUS, then EOI
            // before timer_tick (which may context-switch).
            super::timer::rearm();
            super::gic::eoi(intid);
            crate::event::timer::dispatch_tick(interrupted_user_mode);
        }
        0..=INTID_SGI_MAX => {
            // Software Generated Interrupt (IPI).
            // EOI before dispatch — the handler may context-switch (reschedule)
            // and we must not block further SGI delivery on this CPU.
            super::gic::eoi(intid);
            dispatch_sgi(intid);
        }
        INTID_SPURIOUS => {
            // Spurious interrupt — no EOI needed.
        }
        _ => {
            // SPI or other peripheral interrupt.
            // EOI before dispatch — consistent with timer (line 332) and SGI
            // (line 339). For level-triggered SPIs the line stays asserted
            // after EOI, but dispatch_irq runs with IRQs disabled so the
            // re-trigger is deferred until after the handler completes.
            super::gic::eoi(intid);
            crate::event::irq::dispatch_irq(intid as usize);
        }
    }
}

// ---------------------------------------------------------------------------
// SGI (IPI) dispatch
// ---------------------------------------------------------------------------

/// Dispatch a Software Generated Interrupt based on its INTID.
///
/// SGI allocation (must match `mod.rs` constants):
///   0 = Reschedule
///   1 = TLB shootdown (single page)
///   2 = TLB shootdown all
///   3 = VSpace teardown
fn dispatch_sgi(intid: u32) {
    match intid {
        super::SGI_RESCHEDULE => {
            crate::sched::handle_reschedule_ipi();
        }
        super::SGI_TLB_SHOOTDOWN => {
            let cpu_id = super::current_cpu();
            let addr = super::take_tlb_shootdown_addr(cpu_id);
            if addr != 0 {
                super::paging::invlpg(addr);
            }
        }
        super::SGI_TLB_SHOOTDOWN_ALL => {
            super::paging::flush_tlb_all();
        }
        super::SGI_VSPACE_TEARDOWN => {
            handle_vspace_teardown_ipi();
        }
        _ => {
            // Other SGIs unused.
        }
    }
}

/// Handle VSpace teardown IPI.
///
/// Switch away from a dying user VSpace on this CPU, then drive the scheduler
/// epilogue so the remote active-count decrement is observed promptly.
fn handle_vspace_teardown_ipi() {
    let cpu_id = super::current_cpu();
    let current_tracking = crate::mm::vspace::current_vspace_tracking();
    let kernel_tracking = crate::mm::vspace::kernel_vspace_tracking();

    if current_tracking.is_null() || current_tracking == kernel_tracking {
        return;
    }

    // SAFETY: current_tracking is this CPU's current VSpace tracking pointer
    // and was checked for null above.
    unsafe {
        if (*current_tracking).state() == crate::mm::vspace::VSpaceState::Active {
            return;
        }
    }

    let kernel_root = crate::mm::vspace::kernel_vspace_root();
    // SAFETY: kernel_root is the kernel VSpace root and is valid to install in
    // TTBR0 while handling the teardown IPI.
    unsafe {
        crate::arch::paging::write_cr3(kernel_root);
    }

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    crate::mm::vspace::set_current_vspace_tracking(kernel_tracking);

    // SAFETY: this runs on cpu_id in an interrupt handler with IRQs disabled;
    // current_vspace_tracking has already been moved to the kernel VSpace.
    unsafe {
        crate::mm::vspace::set_pending_deactivate(cpu_id, current_tracking);
    }

    // Process the pending deactivate through the scheduler epilogue. This was
    // the original aarch64 path; the missing piece was recording the pending
    // VSpace before entering it.
    crate::sched::scheduler::scheduler().with_lock(|_| {});
}

/// Deliver an EL0 fault to the bound fault `MessagePipe` via the
/// reply-to-resume protocol. `deliver_fault` parks the thread on the
/// bound fault pipe and reschedules; on wake we return here with
/// `true` (handler replied `KERNITE_OK` — return to user mode at the
/// faulting ELR for instruction retry) or `false` (no handler, fault
/// pipe full / closed, or non-OK reply — destroy the thread so the
/// exception does not loop).
fn finish_el0_fault(record: crate::ipc::message_pipe::MpRecord) {
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();

        if !current.is_null() {
            if crate::ipc::fault::deliver_fault(current, record) {
                return; // handler consumed → retry instruction
            }
            crate::task::quiesce::begin_destroy_on_fault(current);
            return;
        }

        scheduler.reschedule();
    }

    loop {
        core::hint::spin_loop();
    }
}

fn log_el0_sync_state(
    prefix: &'static str,
    frame: *const ExceptionFrame,
    ec: Option<u64>,
    esr: u64,
    far: Option<u64>,
) {
    crate::kernel::printk::serial_puts(prefix);
    unsafe {
        let f = &*frame;
        let s = crate::kernel::printk::SerialGuard::acquire();
        if let Some(ec) = ec {
            s.puts(" EC=");
            s.hex(ec);
        }
        if let Some(far) = far {
            s.puts(" FAR=");
            s.hex(far);
        }
        s.puts(" ESR=");
        s.hex(esr);
        s.puts(" ELR=");
        s.hex(f.elr_el1);
        s.puts(" SP_EL0=");
        s.hex(f.sp_el0);
        s.puts(" TTBR0=");
        s.hex(crate::arch::paging::read_cr3());
        s.puts(" X29=");
        s.hex(f.regs[29]);
        s.puts(" X30=");
        s.hex(f.regs[30]);
        s.puts("\n");
    }
}

/// Handle synchronous exceptions taken from EL0 (user context).
///
/// Dispatches SVC (syscall), data aborts (user page fault), instruction
/// aborts, and FP/NEON traps.
#[unsafe(no_mangle)]
extern "C" fn el0_sync_handler(frame: *mut ExceptionFrame) {
    let esr = read_exception_esr();
    let ec = (esr >> 26) & 0x3F;

    match ec {
        EC_SVC_AARCH64 => {
            // SVC from AArch64 — system call.
            // AArch64 SVC convention:
            //   x8  = syscall number
            //   x0  = cap_ptr
            //   x1  = invoke label
            //   x2-x5 = arg0-arg3
            // SAFETY: frame was set up by SAVE_REGS and is a valid pointer
            // to a fully-initialized ExceptionFrame on the kernel stack.
            // syscall_handle_rust and the fastpath functions are unsafe
            // because they perform privileged kernel operations.
            unsafe {
                save_el0_frame_to_current_tcb(frame);
                let f = &*frame;
                let syscall_num = f.regs[8];

                // Try the inline fastpath first; on a miss the helper
                // returns 0 with no observable side effect and we fall
                // through to the full dispatch. Mirror of the x86_64
                // dispatch in `arch/x86_64/syscall.S`.
                let mut fast_out = crate::syscall::SyscallResult::ok(0);
                let handled = crate::syscall::fastpath::kernite_try_sys_invoke_fastpath(
                    syscall_num,
                    f.regs[0], // cap_ptr (x0)
                    f.regs[1], // invoke label (x1)
                    f.regs[2], // arg0 (x2)
                    f.regs[3], // arg1 (x3)
                    f.regs[4], // arg2 (x4)
                    f.regs[5], // arg3 (x5)
                    &mut fast_out as *mut _,
                );
                let result = if handled != 0 {
                    fast_out
                } else {
                    // Slowpath: full syscall dispatch.
                    crate::syscall::syscall_handle_rust(
                        syscall_num,
                        f.regs[0],
                        f.regs[1],
                        f.regs[2],
                        f.regs[3],
                        f.regs[4],
                        f.regs[5],
                    )
                };
                // Write return values back into the saved frame so RESTORE_REGS
                // delivers them to userspace.
                restore_el0_frame_from_current_tcb(frame, result.error, result.value);
                sync_el0_ttbr0_from_current_tcb(frame);
            }
        }
        EC_DABT_LOWER => {
            // Data abort from EL0 (user page fault or device access error).
            let far = read_exception_far();

            let dfsc = esr & 0x3F;

            // Synchronous External Abort from device MMIO read (e.g., PCI
            // ECAM probe to non-existent device). Fixup the load instruction
            // to return all-ones, mimicking x86 PCI behavior.
            if dfsc == DFSC_SYNC_EXTERNAL_ABORT {
                if try_fixup_device_load(frame) {
                    return;
                }
            }

            // Kernel fast-path fault handling: COW, demand paging, stack growth.
            // Construct arch-neutral PageFaultInfo from AArch64 ESR_EL1:
            //   - Translation Fault (DFSC 0x04..0x07): page not present
            //   - Access Flag Fault (DFSC 0x08..0x0B): first touch on AF=0 page
            //   - Permission Fault (DFSC 0x0C..0x0F): page present, wrong perms
            //   - WnR (bit 6): write access
            //   - Always user mode (EL0 data abort)
            let is_write = esr & (1 << 6) != 0;
            if is_access_flag_fault(dfsc) {
                let access_fault = crate::mm::PageFaultInfo {
                    present: true,
                    write: is_write,
                    user: true,
                };
                let handled = unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        vspace
                            .handle_accessed_fault(far, &access_fault)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };
                if handled {
                    return;
                }
            }
            let fault = crate::mm::PageFaultInfo {
                present: is_permission_fault(dfsc),
                write: is_write,
                user: true,
            };
            let elr = unsafe { (*frame).elr_el1 };
            let handled = unsafe {
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() && !(*current).vspace_root.is_null() {
                    let vspace = &mut *(*current).vspace_root;

                    let cow_pooled_result = vspace.handle_cow_fault_pooled(far, &fault);
                    if let Ok(true) = cow_pooled_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    let cow_result = vspace.handle_cow_fault(far, &fault);
                    if let Ok(true) = cow_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }

                    let demand_result = vspace.handle_demand_fault(far, &fault);
                    if let Ok(true) = demand_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    // Stack growth is handled by the demand fault path —
                    // the full-span stack reserve carries a single
                    // REGION_KIND_STACK VmArea + DEMAND PTEs, so any
                    // stack miss is just a demand fault. Guard-hole
                    // accesses have no VmArea and drop through to
                    // SIGSEGV below.
                    if matches!(
                        cow_pooled_result,
                        Err(crate::mm::vspace::VSpaceError::OutOfMemory)
                    ) || matches!(cow_result, Err(crate::mm::vspace::VSpaceError::OutOfMemory))
                        || matches!(
                            demand_result,
                            Err(crate::mm::vspace::VSpaceError::OutOfMemory)
                        )
                    {
                        finish_el0_fault(crate::ipc::fault::oom_record(far, elr, 0));
                        return;
                    }
                    false
                } else {
                    false
                }
            };
            if handled {
                return;
            }

            // Fast-path didn't resolve — deliver the recoverable VM fault to
            // userspace without logging it as a fatal-looking exception.
            if fault.present {
                unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        let _ = vspace.note_present_fault_activity(far);
                    }
                }
            }
            let ipc_ec = fault.to_ipc_error_code(false);
            finish_el0_fault(crate::ipc::fault::page_fault_record(
                far, ipc_ec, elr, false,
            ));
        }
        EC_IABT_LOWER => {
            // Instruction abort from EL0.
            let far = read_exception_far();

            let ifsc = esr & 0x3F;

            // Kernel fast-path fault handling (mirrors data abort path).
            // Instruction fetches are never writes; no stack growth check
            // needed since instruction faults don't hit the stack guard page.
            if is_access_flag_fault(ifsc) {
                let access_fault = crate::mm::PageFaultInfo {
                    present: true,
                    write: false,
                    user: true,
                };
                let handled = unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        vspace
                            .handle_accessed_fault(far, &access_fault)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };
                if handled {
                    return;
                }
            }
            let fault = crate::mm::PageFaultInfo {
                present: is_permission_fault(ifsc),
                write: false,
                user: true,
            };
            let elr = unsafe { (*frame).elr_el1 };
            let handled = unsafe {
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() && !(*current).vspace_root.is_null() {
                    let vspace = &mut *(*current).vspace_root;

                    let cow_pooled_result = vspace.handle_cow_fault_pooled(far, &fault);
                    if let Ok(true) = cow_pooled_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    let cow_result = vspace.handle_cow_fault(far, &fault);
                    if let Ok(true) = cow_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }

                    let demand_result = vspace.handle_demand_fault(far, &fault);
                    if let Ok(true) = demand_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    if matches!(
                        cow_pooled_result,
                        Err(crate::mm::vspace::VSpaceError::OutOfMemory)
                    ) || matches!(cow_result, Err(crate::mm::vspace::VSpaceError::OutOfMemory))
                        || matches!(
                            demand_result,
                            Err(crate::mm::vspace::VSpaceError::OutOfMemory)
                        )
                    {
                        finish_el0_fault(crate::ipc::fault::oom_record(far, elr, 0));
                        return;
                    }
                    false
                } else {
                    false
                }
            };
            if handled {
                return;
            }

            // Fast-path didn't resolve — deliver the recoverable VM fault to
            // userspace without logging it as a fatal-looking exception.
            if fault.present {
                unsafe {
                    let scheduler = crate::sched::scheduler::scheduler();
                    let current = scheduler.current();
                    if !current.is_null() && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        let _ = vspace.note_present_fault_activity(far);
                    }
                }
            }
            let ipc_ec = fault.to_ipc_error_code(true);
            finish_el0_fault(crate::ipc::fault::page_fault_record(far, ipc_ec, elr, true));
        }
        EC_PCALIGN => {
            log_el0_sync_state(
                "[EXCEPTION] EL0 PC alignment fault:",
                frame,
                Some(ec),
                esr,
                None,
            );
            let f = unsafe { &*frame };
            finish_el0_fault(crate::ipc::fault::user_exception_record(
                ec, esr, f.elr_el1, f.sp_el0,
            ));
        }
        EC_SPALIGN => {
            log_el0_sync_state(
                "[EXCEPTION] EL0 SP alignment fault:",
                frame,
                Some(ec),
                esr,
                None,
            );
            let f = unsafe { &*frame };
            finish_el0_fault(crate::ipc::fault::user_exception_record(
                ec, esr, f.elr_el1, f.sp_el0,
            ));
        }
        EC_FP_TRAP => {
            // FPU/NEON access trap must not occur in eager FPU mode —
            // CPACR_EL1.FPEN is held at 0b11 throughout, so any access
            // is allowed without trapping. Reaching here means CPACR_EL1
            // was clobbered after init or hardware misbehaved; treat as
            // a fatal regression.
            crate::kernel::panic::fatal_exception_context(
                "aarch64 EL0 FP/ASIMD trap",
                format_args!("unexpected FP/SIMD trap in eager FPU mode ESR={:#x}", esr),
                aarch64_panic_context(frame, esr, None),
                || dump_aarch64_exception(frame, esr, None),
            );
        }
        _ => {
            log_el0_sync_state("[EXCEPTION] Unknown EL0 sync:", frame, Some(ec), esr, None);
            let f = unsafe { &*frame };
            finish_el0_fault(crate::ipc::fault::user_exception_record(
                ec, esr, f.elr_el1, f.sp_el0,
            ));
        }
    }
}

/// Handle IRQs taken from EL0 (user context).
///
/// Delegates to the EL1 IRQ handler — the GIC interrupt handling is identical
/// regardless of which exception level was interrupted.
#[unsafe(no_mangle)]
extern "C" fn el0_irq_handler(frame: *const ExceptionFrame) {
    el1_irq_handler(frame);
}

/// Handle SError taken from EL1 (kernel context).
///
/// SErrors are asynchronous external aborts (e.g. uncorrectable bus errors,
/// ECC failures, or MMIO faults that arrive asynchronously). These indicate
/// unrecoverable hardware-level corruption so we dump state and panic.
#[unsafe(no_mangle)]
extern "C" fn el1_serror_handler(frame: *const ExceptionFrame) {
    let esr = read_exception_esr();
    let f = unsafe { &*frame };
    let iss = esr & 0x01FF_FFFF;
    let dfsc = iss & 0x3F;
    crate::kernel::panic::fatal_exception_context(
        "aarch64 EL1 SError",
        format_args!(
            "ESR={:#010x} ISS={:#09x} DFSC={:#04x} ELR={:#018x}",
            esr, iss, dfsc, f.elr_el1
        ),
        aarch64_panic_context(frame, esr, None),
        || dump_aarch64_exception(frame, esr, None),
    );
}

/// Handle SError taken from EL0 (user context).
///
/// An asynchronous external abort while running user code. Dump state and
/// retire the faulting thread via the fault handler path so the rest of
/// the system can continue.
#[unsafe(no_mangle)]
extern "C" fn el0_serror_handler(frame: *const ExceptionFrame) {
    let esr = read_exception_esr();
    let f = unsafe { &*frame };
    let iss = esr & 0x01FF_FFFF;
    let _dfsc = iss & 0x3F;
    crate::kernel::printk::serial_puts("[SERROR] SError from EL0\n");
    dump_serror_state(f, esr);
    finish_el0_fault(crate::ipc::fault::user_exception_record(
        0x2F, // EC for SError (synthetic — real EC field is zero for SError)
        esr, f.elr_el1, f.sp_el0,
    ));
}

/// Dump register state for SError diagnostics.
fn dump_serror_state(f: &ExceptionFrame, esr: u64) {
    let s = crate::kernel::printk::SerialGuard::acquire();
    s.puts("  ESR=");
    s.hex(esr);
    s.puts(" ELR=");
    s.hex(f.elr_el1);
    s.puts(" SPSR=");
    s.hex(f.spsr_el1);
    s.puts(" SP_EL0=");
    s.hex(f.sp_el0);
    s.puts("\n");
    s.puts("  x0=");
    s.hex(f.regs[0]);
    s.puts(" x1=");
    s.hex(f.regs[1]);
    s.puts(" x29=");
    s.hex(f.regs[29]);
    s.puts(" x30=");
    s.hex(f.regs[30]);
    s.puts("\n");
}

fn dump_aarch64_exception(frame: *const ExceptionFrame, esr: u64, far: Option<u64>) {
    use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};

    let f = unsafe { &*frame };
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x01FF_FFFF;
    let fsc = iss & 0x3F;
    serial_puts_raw("ESR: ");
    serial_hex_raw(esr);
    serial_puts_raw(" EC=");
    serial_hex_raw(ec);
    serial_puts_raw(" ISS=");
    serial_hex_raw(iss);
    serial_puts_raw(" FSC=");
    serial_hex_raw(fsc);
    serial_puts_raw(" WnR=");
    serial_dec_raw(((esr >> 6) & 1) as u64);
    serial_putc_hw(b'\n');
    if let Some(far) = far {
        serial_puts_raw("FAR: ");
        serial_hex_raw(far);
        serial_putc_hw(b'\n');
    }
    serial_puts_raw("ELR: ");
    serial_hex_raw(f.elr_el1);
    serial_puts_raw(" SPSR: ");
    serial_hex_raw(f.spsr_el1);
    serial_puts_raw(" SP_EL0: ");
    serial_hex_raw(f.sp_el0);
    serial_putc_hw(b'\n');

    let mut i = 0usize;
    while i < 31 {
        serial_puts_raw("x");
        serial_dec_raw(i as u64);
        serial_puts_raw("=");
        serial_hex_raw(f.regs[i]);
        if i % 4 == 3 || i == 30 {
            serial_putc_hw(b'\n');
        } else {
            serial_puts_raw(" ");
        }
        i += 1;
    }
}

fn aarch64_panic_context(
    frame: *const ExceptionFrame,
    esr: u64,
    far: Option<u64>,
) -> crate::kernel::stacktrace::ArchPanicContext {
    let f = unsafe { &*frame };
    crate::kernel::stacktrace::ArchPanicContext {
        kind: crate::kernel::stacktrace::ContextKind::Exception,
        elr: f.elr_el1,
        sp: frame as u64,
        x29: f.regs[29],
        x30: f.regs[30],
        daif: unsafe { aarch64_exceptions_read_daif() },
        esr_el1: esr,
        far_el1: far.unwrap_or_else(read_exception_far),
        ttbr0_el1: crate::arch::paging::read_cr3(),
    }
}

// ---------------------------------------------------------------------------
// VBAR installation
// ---------------------------------------------------------------------------

/// Install the exception vector table by writing its address to VBAR_EL1.
///
/// Must be called during early boot after the vector table is accessible
/// (identity-mapped or in the direct physical map).
pub fn init() {
    unsafe extern "C" {
        static exception_vectors: u8;
    }
    // SAFETY: exception_vectors is defined in exceptions.S
    // and is guaranteed to be 2048-byte aligned.
    let vbar = core::ptr::addr_of!(exception_vectors) as u64;
    // SAFETY: Writing VBAR_EL1 is safe during single-threaded boot.
    // The ISB ensures the new vector table address is visible before any
    // subsequent exception can be taken.
    unsafe {
        aarch64_exceptions_write_vbar_el1(vbar);
    }
}

// ---------------------------------------------------------------------------
// Synchronous External Abort fixup
// ---------------------------------------------------------------------------

/// DFSC value: Synchronous External Abort, not on translation table walk.
const DFSC_SYNC_EXTERNAL_ABORT: u64 = 0x10;

/// Attempt to fixup a Synchronous External Abort from EL0.
///
/// When a user-mode load from device-mapped memory triggers an external
/// abort (e.g., PCI ECAM probe to a non-existent device), this function
/// decodes the faulting instruction and writes all-ones to the destination
/// register — mimicking the x86 PCI convention of returning 0xFFFF_FFFF
/// for non-existent devices.
///
/// Returns `true` if the fixup succeeded and ELR was advanced past the
/// faulting instruction. Returns `false` if the instruction could not be
/// decoded, in which case the caller should fall through to fault delivery.
fn try_fixup_device_load(frame: *mut ExceptionFrame) -> bool {
    // SAFETY: frame was set up by SAVE_REGS and is a valid mutable pointer.
    let f = unsafe { &mut *frame };
    let elr = f.elr_el1;

    let instr = match unsafe { crate::arch::uaccess::copy_from_user::<u32>(elr) } {
        Some(instr) => instr,
        None => return false,
    };

    // --- LDR (immediate, unsigned offset) ---
    // Encoding: size(2) | 111 | V(1) | 01 | opc(2) | imm12(12) | Rn(5) | Rt(5)
    // LDR Wt: size=10, V=0, opc=01 → top 10 bits = 10_111_0_01_01 = 0x2E5
    // LDR Xt: size=11, V=0, opc=01 → top 10 bits = 11_111_0_01_01 = 0x3E5
    let top10 = instr >> 22;
    if top10 == 0x2E5 || top10 == 0x3E5 {
        let rt = (instr & 0x1F) as usize;
        let is_64 = top10 == 0x3E5;
        if rt < 31 {
            f.regs[rt] = if is_64 { u64::MAX } else { 0xFFFF_FFFF };
        }
        // XZR (rt=31) is the zero register — no writeback needed.
        f.elr_el1 = elr.wrapping_add(4);
        return true;
    }

    // --- LDUR (unscaled immediate) ---
    // Encoding: size(2) | 111000 | opc(2) | 0 | imm9(9) | 00 | Rn(5) | Rt(5)
    // LDUR Wt: size=10, opc=01 → top 11 bits = 10_111000_01_0 = 0x5C2
    // LDUR Xt: size=11, opc=01 → top 11 bits = 11_111000_01_0 = 0x7C2
    let top11 = instr >> 21;
    if (top11 == 0x5C2 || top11 == 0x7C2) && ((instr >> 10) & 3) == 0 {
        let rt = (instr & 0x1F) as usize;
        let is_64 = top11 == 0x7C2;
        if rt < 31 {
            f.regs[rt] = if is_64 { u64::MAX } else { 0xFFFF_FFFF };
        }
        f.elr_el1 = elr.wrapping_add(4);
        return true;
    }

    // --- LDR (register) ---
    // Encoding: size(2) | 111000 | opc(2) | 1 | Rm(5) | option(3) | S(1) | 10 | Rn(5) | Rt(5)
    // LDR Wt: size=10, opc=01 → top 11 bits = 10_111000_01_1 = 0x5C3
    // LDR Xt: size=11, opc=01 → top 11 bits = 11_111000_01_1 = 0x7C3
    if (top11 == 0x5C3 || top11 == 0x7C3) && ((instr >> 10) & 3) == 2 {
        let rt = (instr & 0x1F) as usize;
        let is_64 = top11 == 0x7C3;
        if rt < 31 {
            f.regs[rt] = if is_64 { u64::MAX } else { 0xFFFF_FFFF };
        }
        f.elr_el1 = elr.wrapping_add(4);
        return true;
    }

    false
}
