// SPDX-License-Identifier: GPL-2.0-only
//! AArch64 exception vector table and dispatch handlers.
//!
//! Provides the VBAR_EL1 vector table (via `global_asm!`) and Rust-side
//! handlers for synchronous exceptions (SVC, data/instruction aborts) and
//! IRQs from both EL1 and EL0.

use core::arch::global_asm;

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

/// Spurious interrupt ID (no pending interrupt).
const INTID_SPURIOUS: u32 = 1023;
/// Physical timer PPI interrupt ID.
const INTID_PHYS_TIMER: u32 = 30;
/// Maximum SGI interrupt ID (inclusive).
const INTID_SGI_MAX: u32 = 15;

// ---------------------------------------------------------------------------
// Vector table + save/restore macros (assembly)
// ---------------------------------------------------------------------------

global_asm!(
    r#"
// ---- Register save macro ----
// Pushes x0-x30, SP_EL0, ELR_EL1, SPSR_EL1 onto the kernel stack.
// Frame size: 288 bytes (272 payload + 16 padding for alignment).
.macro SAVE_REGS
    sub     sp, sp, #288
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    mrs     x0, SP_EL0
    str     x0, [sp, #248]
    mrs     x0, ELR_EL1
    str     x0, [sp, #256]
    mrs     x0, SPSR_EL1
    str     x0, [sp, #264]
.endm

// ---- Register restore macro ----
// Pops the saved state and returns via ERET.
.macro RESTORE_REGS
    ldr     x0, [sp, #264]
    msr     SPSR_EL1, x0
    ldr     x0, [sp, #256]
    msr     ELR_EL1, x0
    ldr     x0, [sp, #248]
    msr     SP_EL0, x0
    ldp     x28, x29, [sp, #224]
    ldr     x30, [sp, #240]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #288
    eret
.endm

// ---- Vector table ----
// Must be 2048-byte aligned (VBAR_EL1 requirement).
// 16 entries, each 128 bytes (32 instructions max).

    .section .text
    .balign 2048
    .global exception_vectors
exception_vectors:

    // ---- Group 0: Current EL with SP0 (not used) ----
    .balign 128
    b       .                   // Sync
    .balign 128
    b       .                   // IRQ
    .balign 128
    b       .                   // FIQ
    .balign 128
    b       .                   // SError

    // ---- Group 1: Current EL with SPx (kernel exceptions) ----
    .balign 128
    b       el1_sync            // Sync
    .balign 128
    b       el1_irq             // IRQ
    .balign 128
    b       .                   // FIQ (unused)
    .balign 128
    b       el1_serror          // SError

    // ---- Group 2: Lower EL using AArch64 (user exceptions) ----
    .balign 128
    b       el0_sync            // Sync (SVC, data abort, etc.)
    .balign 128
    b       el0_irq             // IRQ
    .balign 128
    b       .                   // FIQ (unused)
    .balign 128
    b       el0_serror          // SError

    // ---- Group 3: Lower EL using AArch32 (not supported) ----
    .balign 128
    b       .
    .balign 128
    b       .
    .balign 128
    b       .
    .balign 128
    b       .

// ---- Handler stubs ----

el1_sync:
    SAVE_REGS
    mov     x0, sp
    bl      el1_sync_handler
    RESTORE_REGS

el1_irq:
    SAVE_REGS
    mov     x0, sp
    bl      el1_irq_handler
    RESTORE_REGS

el0_sync:
    SAVE_REGS
    mov     x0, sp
    bl      el0_sync_handler
    RESTORE_REGS

el0_irq:
    SAVE_REGS
    mov     x0, sp
    bl      el0_irq_handler
    RESTORE_REGS

el1_serror:
    SAVE_REGS
    mov     x0, sp
    bl      el1_serror_handler
    RESTORE_REGS

el0_serror:
    SAVE_REGS
    mov     x0, sp
    bl      el0_serror_handler
    RESTORE_REGS
"#,
);

// ---------------------------------------------------------------------------
// Rust exception handlers
// ---------------------------------------------------------------------------

/// Handle synchronous exceptions taken from EL1 (kernel context).
///
/// Reads ESR_EL1 to determine the exception class and dispatches accordingly.
#[unsafe(no_mangle)]
extern "C" fn el1_sync_handler(frame: *const ExceptionFrame) {
    let esr: u64;
    // SAFETY: Reading ESR_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;

    match ec {
        EC_DABT_CURRENT => {
            // Data abort from EL1 (kernel page fault).
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };

            // Check if this is a write permission fault on a user VA.
            // This happens when the kernel writes to a COW page (e.g. IPC
            // buffer after fork). Resolve the COW fault so the faulting
            // instruction can be retried via ERET.
            let dfsc = esr & 0x3F;
            let is_write = esr & (1 << 6) != 0;
            let is_permission_fault = dfsc >= 0x0D && dfsc <= 0x0F;
            let is_user_va = far < 0x0001_0000_0000_0000;

            if is_user_va && is_permission_fault && is_write {
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

            panic!(
                "EL1 data abort: FAR={:#018x} ESR={:#010x} ELR={:#018x}",
                far, esr, elr,
            );
        }
        EC_IABT_CURRENT => {
            // Instruction abort from EL1.
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            panic!(
                "EL1 instruction abort: FAR={:#018x} ESR={:#010x} ELR={:#018x}",
                far, esr, elr,
            );
        }
        EC_FP_TRAP => {
            // EL1 hit a trapped FP/SIMD instruction.
            let elr = unsafe { (*frame).elr_el1 };
            panic!("EL1 FP/ASIMD trap: ESR={:#010x} ELR={:#018x}", esr, elr);
        }
        _ => {
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            panic!(
                "Unexpected EL1 sync exception: EC={:#04x} ESR={:#010x} ELR={:#018x}",
                ec, esr, elr,
            );
        }
    }
}

/// Handle IRQs taken from EL1 (kernel context).
///
/// Acknowledges the interrupt via the GIC, dispatches based on INTID,
/// and sends EOI.
#[unsafe(no_mangle)]
extern "C" fn el1_irq_handler(_frame: *const ExceptionFrame) {
    let intid = super::gic::acknowledge_irq();

    match intid {
        INTID_PHYS_TIMER => {
            // Physical timer PPI — re-arm before EOI to clear ISTATUS,
            // then EOI before timer_tick (which may context-switch).
            super::timer::rearm();
            super::gic::eoi(intid);
            crate::sched::timer_tick();
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
            crate::ipc::irq::dispatch_irq(intid as usize);
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
/// When a VSpace is being destroyed, all CPUs that have it loaded in
/// TTBR0 must switch away before the page tables can be freed.
/// This handler checks if the current CPU has the target VSpace loaded
/// and if so, processes the pending deactivation.
fn handle_vspace_teardown_ipi() {
    // Trigger the scheduler's pending-deactivate check for this CPU.
    // The scheduler's `with_lock` calls `kernel_exit_epilogue` which
    // processes pending VSpace deactivates.
    crate::sched::scheduler::scheduler().with_lock(|_| {});
}

/// Block on a userspace fault handler when configured, otherwise retire the
/// current thread so the exception does not immediately recur forever.
fn finish_el0_fault(msg: &crate::ipc::Message) {
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();

        if !current.is_null() && !(*current).fault_handler.is_null() {
            let fault_ep = &mut *((*current).fault_handler as *mut crate::ipc::Endpoint);
            fault_ep.deliver_fault(current, msg);
            scheduler.reschedule();
            return;
        } else if !current.is_null() {
            (*current).state = crate::sched::thread::ThreadState::Inactive;
            (*current).blocked_reason = None;
            (*current).blocked_endpoint = core::ptr::null_mut();
            (*current).blocked_notification = core::ptr::null_mut();
            (*current).reply_tcb = core::ptr::null_mut();
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
    crate::serial_puts(prefix);
    unsafe {
        let f = &*frame;
        let s = crate::SerialGuard::acquire();
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
    let esr: u64;
    // SAFETY: Reading ESR_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;

    match ec {
        EC_SVC_AARCH64 => {
            // SVC from AArch64 — system call.
            // AArch64 SVC convention:
            //   x8  = syscall number
            //   x0  = cap_ptr
            //   x1-x5 = arg0-arg4
            // SAFETY: frame was set up by SAVE_REGS and is a valid pointer
            // to a fully-initialized ExceptionFrame on the kernel stack.
            // syscall_handle_rust and the fastpath functions are unsafe
            // because they perform privileged kernel operations.
            unsafe {
                let f = &*frame;
                let syscall_num = f.regs[8];

                // IPC fastpath: Call (2) and ReplyRecv (3).
                // Mirrors x86_64 syscall.S fastpath dispatch. The AAPCS64
                // calling convention matches the register layout exactly
                // (x0-x5 → first 6 arguments), so no remapping is needed.
                if syscall_num == 2 || syscall_num == 3 {
                    let fp_result = if syscall_num == 2 {
                        crate::syscall::fastpath::fastpath_call_rust(
                            f.regs[0], f.regs[1], f.regs[2],
                            f.regs[3], f.regs[4], f.regs[5],
                        )
                    } else {
                        crate::syscall::fastpath::fastpath_reply_recv_rust(
                            f.regs[0], f.regs[1], f.regs[2],
                            f.regs[3], f.regs[4], f.regs[5],
                        )
                    };
                    if fp_result.status != 0 {
                        (*frame).regs[0] = 0;              // x0 = no error
                        (*frame).regs[1] = fp_result.value; // x1 = return value
                        return;
                    }
                }

                // Slowpath: full syscall dispatch.
                let result = crate::syscall::syscall_handle_rust(
                    syscall_num,
                    f.regs[0],  // cap_ptr (x0)
                    f.regs[1],  // arg0 (x1)
                    f.regs[2],  // arg1 (x2)
                    f.regs[3],  // arg2 (x3)
                    f.regs[4],  // arg3 (x4)
                    f.regs[5],  // arg4 (x5)
                );
                // Write return values back into the saved frame so RESTORE_REGS
                // delivers them to userspace.
                (*frame).regs[0] = result.error; // x0 = error code
                (*frame).regs[1] = result.value; // x1 = return value
            }
        }
        EC_DABT_LOWER => {
            // Data abort from EL0 (user page fault or device access error).
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }

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
            //   - Permission Fault (DFSC 0x0D..0x0F): page present, wrong perms
            //   - WnR (bit 6): write access
            //   - Always user mode (EL0 data abort)
            let fault = crate::mm::PageFaultInfo {
                present: dfsc >= 0x0D && dfsc <= 0x0F,
                write: esr & (1 << 6) != 0,
                user: true,
            };
            let handled = unsafe {
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() && !(*current).vspace_root.is_null() {
                    let vspace = &mut *(*current).vspace_root;

                    let resolved =
                        vspace.handle_cow_fault_pooled(far, &fault).unwrap_or(false)
                        || vspace.handle_cow_fault(far, &fault).unwrap_or(false)
                        || vspace.handle_demand_fault(far, &fault).unwrap_or(false)
                        || vspace.handle_stack_growth_fault(
                            far,
                            &fault,
                            (*frame).sp_el0,
                            (*current).user_stack_top,
                            (*current).user_stack_min,
                        ).unwrap_or(false);

                    if resolved
                        && (*current).state
                            == crate::sched::thread::ThreadState::Inactive
                    {
                        scheduler.reschedule();
                    }
                    resolved
                } else {
                    false
                }
            };
            if handled {
                return;
            }

            // Fast-path didn't resolve — fall through to IPC fault delivery.
            log_el0_sync_state("[EXCEPTION] EL0 data abort:", frame, None, esr, Some(far));
            let elr = unsafe { (*frame).elr_el1 };
            let ipc_ec = fault.to_ipc_error_code(false);
            finish_el0_fault(&crate::ipc::vm_fault_message(far, ipc_ec, elr, false));
        }
        EC_IABT_LOWER => {
            // Instruction abort from EL0.
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }

            let ifsc = esr & 0x3F;

            // Kernel fast-path fault handling (mirrors data abort path).
            // Instruction fetches are never writes; no stack growth check
            // needed since instruction faults don't hit the stack guard page.
            let fault = crate::mm::PageFaultInfo {
                present: ifsc >= 0x0D && ifsc <= 0x0F,
                write: false,
                user: true,
            };
            let handled = unsafe {
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() && !(*current).vspace_root.is_null() {
                    let vspace = &mut *(*current).vspace_root;

                    let resolved =
                        vspace.handle_cow_fault_pooled(far, &fault).unwrap_or(false)
                        || vspace.handle_cow_fault(far, &fault).unwrap_or(false)
                        || vspace.handle_demand_fault(far, &fault).unwrap_or(false);

                    if resolved
                        && (*current).state
                            == crate::sched::thread::ThreadState::Inactive
                    {
                        scheduler.reschedule();
                    }
                    resolved
                } else {
                    false
                }
            };
            if handled {
                return;
            }

            // Fast-path didn't resolve — fall through to IPC fault delivery.
            log_el0_sync_state("[EXCEPTION] EL0 instruction abort:", frame, None, esr, Some(far));
            let elr = unsafe { (*frame).elr_el1 };
            let ipc_ec = fault.to_ipc_error_code(true);
            finish_el0_fault(&crate::ipc::vm_fault_message(far, ipc_ec, elr, true));
        }
        EC_PCALIGN => {
            log_el0_sync_state("[EXCEPTION] EL0 PC alignment fault:", frame, Some(ec), esr, None);
            let f = unsafe { &*frame };
            finish_el0_fault(&crate::ipc::user_exception_message(ec, esr, f.elr_el1, f.sp_el0));
        }
        EC_SPALIGN => {
            log_el0_sync_state("[EXCEPTION] EL0 SP alignment fault:", frame, Some(ec), esr, None);
            let f = unsafe { &*frame };
            finish_el0_fault(&crate::ipc::user_exception_message(ec, esr, f.elr_el1, f.sp_el0));
        }
        EC_FP_TRAP => {
            // FPU/NEON access trap — lazy context switching.
            super::fpu::handle_trap();
        }
        _ => {
            log_el0_sync_state("[EXCEPTION] Unknown EL0 sync:", frame, Some(ec), esr, None);
            let f = unsafe { &*frame };
            finish_el0_fault(&crate::ipc::user_exception_message(ec, esr, f.elr_el1, f.sp_el0));
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
    let esr: u64;
    // SAFETY: Reading ESR_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr, options(nomem, nostack));
    }
    let f = unsafe { &*frame };
    let iss = esr & 0x01FF_FFFF;
    let dfsc = iss & 0x3F;
    crate::serial_puts("[SERROR] SError from EL1\n");
    dump_serror_state(f, esr);
    panic!(
        "SError (EL1): ESR={:#010x} ISS={:#09x} DFSC={:#04x} ELR={:#018x}",
        esr, iss, dfsc, f.elr_el1,
    );
}

/// Handle SError taken from EL0 (user context).
///
/// An asynchronous external abort while running user code. Dump state and
/// retire the faulting thread via the fault handler path so the rest of
/// the system can continue.
#[unsafe(no_mangle)]
extern "C" fn el0_serror_handler(frame: *const ExceptionFrame) {
    let esr: u64;
    // SAFETY: Reading ESR_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr, options(nomem, nostack));
    }
    let f = unsafe { &*frame };
    let iss = esr & 0x01FF_FFFF;
    let dfsc = iss & 0x3F;
    crate::serial_puts("[SERROR] SError from EL0\n");
    dump_serror_state(f, esr);
    finish_el0_fault(&crate::ipc::user_exception_message(
        0x2F, // EC for SError (synthetic — real EC field is zero for SError)
        esr,
        f.elr_el1,
        f.sp_el0,
    ));
}

/// Dump register state for SError diagnostics.
fn dump_serror_state(f: &ExceptionFrame, esr: u64) {
    unsafe {
        let s = crate::SerialGuard::acquire();
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
    // SAFETY: exception_vectors is defined in the global_asm! block above
    // and is guaranteed to be 2048-byte aligned.
    let vbar = core::ptr::addr_of!(exception_vectors) as u64;
    // SAFETY: Writing VBAR_EL1 is safe during single-threaded boot from EL1.
    // The ISB ensures the new vector table address is visible before any
    // subsequent exception can be taken.
    unsafe {
        core::arch::asm!(
            "msr VBAR_EL1, {}",
            "isb",
            in(reg) vbar,
            options(nomem, nostack),
        );
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

    // Read the faulting instruction from user text via the current TTBR0
    // mapping. ELR_EL1 holds the user VA of the faulting instruction.
    // SAFETY: The user page tables are still active (we haven't switched
    // TTBR0 during exception entry). The instruction page must be mapped
    // readable if the CPU fetched and executed it. PAN must be temporarily
    // cleared to allow EL1 access to the user-mapped page.
    let _guard = crate::arch::uaccess::UserAccessGuard::new();
    let instr = unsafe { core::ptr::read_volatile(elr as *const u32) };

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
