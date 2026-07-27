//! Interrupt Descriptor Table (IDT)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::mem::size_of;

unsafe extern "C" {
    fn x86_idt_lidt(ptr: *const IdtPtr);
    fn x86_idt_sidt(ptr: *mut IdtPtr);
}

/// IDT entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    pub const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    pub fn set_handler(&mut self, handler: u64) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = 0x08; // Kernel code segment
        self.ist = 0;
        self.type_attr = 0x8E; // Present, Ring 0, Interrupt Gate
    }

    pub fn set_trap(&mut self, handler: u64) {
        self.set_handler(handler);
        self.type_attr = 0x8F; // Trap gate (no interrupt disable)
    }

    pub fn set_handler_ist(&mut self, handler: u64, ist: u8) {
        self.set_handler(handler);
        self.ist = ist;
    }

    /// Update IST field on an already-configured entry (safe to call after lidt)
    pub fn set_ist(&mut self, ist: u8) {
        self.ist = ist;
    }
}

/// IDT structure
#[repr(C, align(16))]
pub struct Idt {
    pub entries: [IdtEntry; 256],
}

impl Idt {
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::null(); 256],
        }
    }
}

/// IDT pointer
#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

/// Interrupt stack frame pushed by x86_64 on interrupt/exception
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InterruptStackFrame {
    /// This value is always pushed by the CPU
    pub rip: u64,
    /// Code segment selector
    pub cs: u64,
    /// CPU flags (RFLAGS register)
    pub rflags: u64,
    /// Stack pointer before interrupt
    pub rsp: u64,
    /// Stack segment selector
    pub ss: u64,
}

/// Lightweight interrupt frame pushed by `irq_stub_nobkl` stubs.
///
/// Only caller-saved registers are preserved (the Rust handler is an
/// `extern "C"` function, so the ABI guarantees callee-saved regs will be
/// preserved across the call). Layout must match the push order in
/// `exceptions.S`: the first push (`rax`) sits at the highest address
/// within the saved region, and the last push (`r11`) is at the lowest —
/// i.e. the top of the stack when the handler is called.
#[repr(C)]
pub struct InterruptFrame {
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Pushed by the CPU on interrupt entry.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl InterruptFrame {
    /// Returns `true` if the interrupted context was user (CS.RPL != 0).
    #[inline]
    pub fn interrupted_user_mode(&self) -> bool {
        self.cs & 0x3 != 0
    }
}

/// Full exception frame built by assembly stubs + CPU
///
/// Layout matches the push order in exceptions.S:
/// Assembly pushes: r15..r8, rbp, rdi, rsi, rdx, rcx, rbx, rax, cr2
/// Stub pushes: vector, error_code
/// CPU pushes: rip, cs, rflags, rsp, ss
#[repr(C)]
pub struct ExceptionFrame {
    // Saved by assembly (push order: r15 first → r15 at lowest address)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // CR2 (pushed by common handler)
    pub cr2: u64,
    // Pushed by stub
    pub vector: u64,
    pub error_code: u64,
    // Pushed by CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl ExceptionFrame {
    pub fn exception_name(&self) -> &'static str {
        match self.vector {
            0 => "#DE Divide Error",
            1 => "#DB Debug",
            2 => "NMI",
            3 => "#BP Breakpoint",
            4 => "#OF Overflow",
            5 => "#BR Bound Range Exceeded",
            6 => "#UD Invalid Opcode",
            7 => "#NM Device Not Available",
            8 => "#DF Double Fault",
            9 => "Coprocessor Segment Overrun",
            10 => "#TS Invalid TSS",
            11 => "#NP Segment Not Present",
            12 => "#SS Stack-Segment Fault",
            13 => "#GP General Protection Fault",
            14 => "#PF Page Fault",
            16 => "#MF x87 Floating-Point",
            17 => "#AC Alignment Check",
            18 => "#MC Machine Check",
            19 => "#XM SIMD Floating-Point",
            20 => "#VE Virtualization",
            21 => "#CP Control Protection",
            28 => "#HV Hypervisor Injection",
            29 => "#VC VMM Communication",
            30 => "#SX Security Exception",
            _ => "(Reserved)",
        }
    }
}

static mut IDT: Idt = Idt::new();

// Assembly stubs (defined in exceptions.S)
unsafe extern "C" {
    // Exception stubs
    fn exception_stub_0();
    fn exception_stub_1();
    fn exception_stub_2();
    fn exception_stub_3();
    fn exception_stub_4();
    fn exception_stub_5();
    fn exception_stub_6();
    fn exception_stub_7();
    fn exception_stub_8();
    fn exception_stub_9();
    fn exception_stub_10();
    fn exception_stub_11();
    fn exception_stub_12();
    fn exception_stub_13();
    fn exception_stub_14();
    fn exception_stub_15();
    fn exception_stub_16();
    fn exception_stub_17();
    fn exception_stub_18();
    fn exception_stub_19();
    fn exception_stub_20();
    fn exception_stub_21();
    fn exception_stub_22();
    fn exception_stub_23();
    fn exception_stub_24();
    fn exception_stub_25();
    fn exception_stub_26();
    fn exception_stub_27();
    fn exception_stub_28();
    fn exception_stub_29();
    fn exception_stub_30();
    fn exception_stub_31();

    // IRQ stubs (with swapgs guards)
    fn irq_stub_timer();
    fn irq_stub_ipi_vspace_teardown();
    fn irq_stub_ipi_reschedule();
    fn irq_stub_ipi_tlb_shootdown();
    fn irq_stub_ipi_tlb_shootdown_all();

    // Generic IRQ stubs for external hardware interrupts
    fn irq_stub_generic_33();
    fn irq_stub_generic_34();
    fn irq_stub_generic_35();
    fn irq_stub_generic_36();
    fn irq_stub_generic_37();
    fn irq_stub_generic_38();
    fn irq_stub_generic_39();
    fn irq_stub_generic_42();
    fn irq_stub_generic_43();
    fn irq_stub_generic_44();
    fn irq_stub_generic_45();
    fn irq_stub_generic_46();
    fn irq_stub_generic_47();
}

/// Load the IDT on the current CPU
///
/// Used by APs to load the shared (global) IDT.
pub fn load() {
    unsafe {
        let idt_ptr = IdtPtr {
            limit: (size_of::<Idt>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };
        x86_idt_lidt(&idt_ptr);
    }
}

/// Set IST for double fault handler (vector 8).
/// Called after frame allocator is available.
pub fn set_double_fault_ist(ist: u8) {
    unsafe {
        (*(&raw mut IDT)).entries[8].set_ist(ist);
    }
}

/// Rust-side exception handler called from assembly stubs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exception_handler_rust(frame: *const ExceptionFrame) {
    let f = unsafe { &*frame };

    // Breakpoint: resume execution immediately
    if f.vector == 3 {
        return;
    }

    // Vector 7: #NM Device Not Available — must not occur in eager FPU mode.
    // CR0.TS is held at 0 throughout, so any #NM is a regression: either a
    // stray set_ts caller still exists, or hardware misbehaved.
    if f.vector == 7 {
        crate::kernel::panic::fatal_exception_context(
            "x86 exception",
            format_args!("unexpected #NM in eager FPU mode"),
            x86_panic_context(f),
            || dump_x86_exception(f),
        );
    }

    // User-mode exception: try fault delivery via IPC
    if (f.cs & 3) != 0 {
        unsafe {
            let scheduler = crate::sched::scheduler::scheduler();
            let current = scheduler.current();

            // COW + demand paging + stack growth fault handling
            // Construct arch-neutral PageFaultInfo from x86 PF error_code.
            // Hoisted so it is available for both the fast-path AND the
            // IPC fallthrough (to_ipc_error_code).
            let pf_fault = if f.vector == 14 {
                Some(crate::mm::PageFaultInfo {
                    present: f.error_code & 1 != 0,
                    write: f.error_code & 2 != 0,
                    user: f.error_code & 4 != 0,
                })
            } else {
                None
            };

            if let Some(ref fault) = pf_fault {
                if !current.is_null() && !(*current).vspace_root.is_null() {
                    let vspace = &mut *(*current).vspace_root;
                    // Phase 2: Kernel fast-path COW with pre-allocated pool.
                    // Falls through to VMFault IPC (Phase 1 path) when pool is empty.
                    let cow_pooled_result = vspace.handle_cow_fault_pooled(f.cr2, fault);
                    if let Ok(true) = cow_pooled_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    let cow_result = vspace.handle_cow_fault(f.cr2, fault);
                    // Non-pooled COW fallback: kernel frame allocator
                    if let Ok(true) = cow_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    // Anonymous zero-fill and stack growth resolve
                    // inline. The PMM/untyped disjointness invariant
                    // (see `mm/frame.rs::OwnerTag`) guarantees that a
                    // frame from `pmm_alloc` cannot sit inside a live
                    // untyped block, so the retype race that motivated
                    // the old IPC-only path no longer exists. File-
                    // backed and shm regions still fall through: the
                    // demand handler gates on MoKind and returns
                    // `Ok(false)` for those so mmsrv pages them in.
                    let demand_result = vspace.handle_demand_fault(f.cr2, fault);
                    if let Ok(true) = demand_result {
                        if (*current).state() == crate::task::state::ThreadState::Dying {
                            scheduler.reschedule();
                        }
                        return;
                    }
                    // Stack growth is handled entirely by the demand
                    // fault path now: every byte of the full-span stack
                    // reserve is covered by a REGION_KIND_STACK VmArea
                    // + DEMAND PTE at map time, so a stack miss is a
                    // normal MO-backed demand fault. An access below
                    // the reserve base falls into the unmapped guard
                    // hole and drops through to SIGSEGV here.
                    let oom =
                        matches!(
                            cow_pooled_result,
                            Err(crate::mm::vspace::VSpaceError::OutOfMemory)
                        ) || matches!(cow_result, Err(crate::mm::vspace::VSpaceError::OutOfMemory))
                            || matches!(
                                demand_result,
                                Err(crate::mm::vspace::VSpaceError::OutOfMemory)
                            );
                    if oom && !current.is_null() && !(*current).fault_pipe.is_null() {
                        let record = crate::ipc::fault::oom_record(f.cr2, f.rip, 0);
                        // `deliver_fault` parks `current` on the
                        // bound fault pipe's `MP_CALL`-shaped reply
                        // path. `true` means the handler replied
                        // `KERNITE_OK` — return to userspace at the
                        // faulting RIP for instruction retry.
                        // `false` means no live handler / non-OK
                        // reply / cancel — escalate to destroy.
                        if crate::ipc::fault::deliver_fault(current, record) {
                            return;
                        }
                        crate::task::quiesce::begin_destroy_on_fault(current);
                        scheduler.reschedule();
                        return;
                    }
                }
            }

            if !current.is_null() && !(*current).fault_pipe.is_null() {
                let record = if let Some(ref fault) = pf_fault {
                    let is_instr = f.error_code & 16 != 0;
                    if fault.present && !(*current).vspace_root.is_null() {
                        let vspace = &mut *(*current).vspace_root;
                        let _ = vspace.note_present_fault_activity(f.cr2);
                    }
                    let ipc_ec = fault.to_ipc_error_code(is_instr);
                    crate::ipc::fault::page_fault_record(f.cr2, ipc_ec, f.rip, is_instr)
                } else {
                    crate::ipc::fault::user_exception_record(f.vector, f.error_code, f.rip, f.rsp)
                };

                if crate::ipc::fault::deliver_fault(current, record) {
                    return; // handler consumed → instruction retry
                }
                crate::task::quiesce::begin_destroy_on_fault(current);
                scheduler.reschedule();
                return;
            }
        }
    }

    if (f.cs & 3) == 0 {
        crate::kernel::panic::fatal_exception_context(
            "x86 exception",
            format_args!(
                "{} vector={} error={:#x}",
                f.exception_name(),
                f.vector,
                f.error_code
            ),
            x86_panic_context(f),
            || dump_x86_exception(f),
        );
    }

    // No fault handler — user diagnostic dump
    // No lock is held on exception entry; assembly stubs do not acquire locks.
    // reschedule() acquires per-CPU scheduler lock internally if needed.
    // Use raw serial — this is a crash path, another CPU may hold SERIAL_LOCK
    {
        crate::kernel::printk::serial_puts_raw("\n*** EXCEPTION: ");
        crate::kernel::printk::serial_puts_raw(f.exception_name());
        crate::kernel::printk::serial_puts_raw(" (vector ");
        crate::kernel::printk::serial_dec_raw(f.vector);
        crate::kernel::printk::serial_puts_raw(", error_code ");
        crate::kernel::printk::serial_hex_raw(f.error_code);
        crate::kernel::printk::serial_puts_raw(")\n");

        if f.vector == 14 {
            crate::kernel::printk::serial_puts_raw("  CR2 (fault addr): ");
            crate::kernel::printk::serial_hex_raw(f.cr2);
            crate::kernel::printk::serial_putc_hw(b'\n');
            crate::kernel::printk::serial_puts_raw("  Flags: ");
            if f.error_code & 1 != 0 {
                crate::kernel::printk::serial_puts_raw("P ");
            } else {
                crate::kernel::printk::serial_puts_raw("NP ");
            }
            if f.error_code & 2 != 0 {
                crate::kernel::printk::serial_puts_raw("W ");
            } else {
                crate::kernel::printk::serial_puts_raw("R ");
            }
            if f.error_code & 4 != 0 {
                crate::kernel::printk::serial_puts_raw("U ");
            } else {
                crate::kernel::printk::serial_puts_raw("S ");
            }
            if f.error_code & 8 != 0 {
                crate::kernel::printk::serial_puts_raw("RSVD ");
            }
            if f.error_code & 16 != 0 {
                crate::kernel::printk::serial_puts_raw("I/D ");
            }
            crate::kernel::printk::serial_putc_hw(b'\n');

            // Dump PTE chain for the faulting address to diagnose NX at any level
            if f.error_code & 16 != 0 {
                use super::paging::PageTable;
                let cr3 = super::paging::read_cr3();
                let addr_mask: u64 = 0x000F_FFFF_FFFF_F000;
                let nx_bit: u64 = 1u64 << 63;

                let pml4 =
                    unsafe { &*(crate::mm::phys_to_virt(cr3 & addr_mask) as *const PageTable) };
                let pml4_idx = ((f.cr2 >> 39) & 0x1FF) as usize;
                let pml4e = pml4.entry(pml4_idx);
                crate::kernel::printk::serial_puts_raw("  PML4E[");
                crate::kernel::printk::serial_dec_raw(pml4_idx as u64);
                crate::kernel::printk::serial_puts_raw("]=");
                crate::kernel::printk::serial_hex_raw(pml4e);
                if pml4e & nx_bit != 0 {
                    crate::kernel::printk::serial_puts_raw(" NX!");
                }
                crate::kernel::printk::serial_putc_hw(b'\n');

                if pml4e & 1 != 0 {
                    let pdpt = unsafe {
                        &*(crate::mm::phys_to_virt(pml4e & addr_mask) as *const PageTable)
                    };
                    let pdpt_idx = ((f.cr2 >> 30) & 0x1FF) as usize;
                    let pdpte = pdpt.entry(pdpt_idx);
                    crate::kernel::printk::serial_puts_raw("  PDPTE[");
                    crate::kernel::printk::serial_dec_raw(pdpt_idx as u64);
                    crate::kernel::printk::serial_puts_raw("]=");
                    crate::kernel::printk::serial_hex_raw(pdpte);
                    if pdpte & nx_bit != 0 {
                        crate::kernel::printk::serial_puts_raw(" NX!");
                    }
                    crate::kernel::printk::serial_putc_hw(b'\n');

                    if pdpte & 1 != 0 {
                        if pdpte & (1 << 7) != 0 {
                            crate::kernel::printk::serial_puts_raw(
                                "  PDPTE is 1GB page (PS=1), no PD\n",
                            );
                        } else {
                            let pd = unsafe {
                                &*(crate::mm::phys_to_virt(pdpte & addr_mask) as *const PageTable)
                            };
                            let pd_idx = ((f.cr2 >> 21) & 0x1FF) as usize;
                            let pde = pd.entry(pd_idx);
                            crate::kernel::printk::serial_puts_raw("  PDE[");
                            crate::kernel::printk::serial_dec_raw(pd_idx as u64);
                            crate::kernel::printk::serial_puts_raw("]=");
                            crate::kernel::printk::serial_hex_raw(pde);
                            if pde & nx_bit != 0 {
                                crate::kernel::printk::serial_puts_raw(" NX!");
                            }
                            crate::kernel::printk::serial_putc_hw(b'\n');

                            if pde & 1 != 0 {
                                if pde & (1 << 7) != 0 {
                                    crate::kernel::printk::serial_puts_raw(
                                        "  PDE is 2MB page (PS=1), no PT\n",
                                    );
                                } else {
                                    let pt = unsafe {
                                        &*(crate::mm::phys_to_virt(pde & addr_mask)
                                            as *const PageTable)
                                    };
                                    let pt_idx = ((f.cr2 >> 12) & 0x1FF) as usize;
                                    let pte = pt.entry(pt_idx);
                                    crate::kernel::printk::serial_puts_raw("  PTE[");
                                    crate::kernel::printk::serial_dec_raw(pt_idx as u64);
                                    crate::kernel::printk::serial_puts_raw("]=");
                                    crate::kernel::printk::serial_hex_raw(pte);
                                    if pte & nx_bit != 0 {
                                        crate::kernel::printk::serial_puts_raw(" NX!");
                                    }
                                    crate::kernel::printk::serial_putc_hw(b'\n');
                                }
                            }
                        }
                    }
                }
            }
        }

        if f.vector == 13 && f.error_code != 0 {
            crate::kernel::printk::serial_puts_raw("  Selector: ");
            crate::kernel::printk::serial_hex_raw(f.error_code & 0xFFF8);
            crate::kernel::printk::serial_puts_raw("  Table: ");
            match (f.error_code >> 1) & 3 {
                0 => crate::kernel::printk::serial_puts_raw("GDT"),
                1 => crate::kernel::printk::serial_puts_raw("IDT"),
                2 => crate::kernel::printk::serial_puts_raw("LDT"),
                3 => crate::kernel::printk::serial_puts_raw("IDT"),
                _ => {}
            }
            if f.error_code & 1 != 0 {
                crate::kernel::printk::serial_puts_raw(" (External)");
            }
            crate::kernel::printk::serial_putc_hw(b'\n');
        }

        crate::kernel::printk::serial_puts_raw("  RIP:    ");
        crate::kernel::printk::serial_hex_raw(f.rip);
        crate::kernel::printk::serial_puts_raw("  CS:     ");
        crate::kernel::printk::serial_hex_raw(f.cs);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  RSP:    ");
        crate::kernel::printk::serial_hex_raw(f.rsp);
        crate::kernel::printk::serial_puts_raw("  SS:     ");
        crate::kernel::printk::serial_hex_raw(f.ss);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  RFLAGS: ");
        crate::kernel::printk::serial_hex_raw(f.rflags);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  RAX: ");
        crate::kernel::printk::serial_hex_raw(f.rax);
        crate::kernel::printk::serial_puts_raw("  RBX: ");
        crate::kernel::printk::serial_hex_raw(f.rbx);
        crate::kernel::printk::serial_puts_raw("  RCX: ");
        crate::kernel::printk::serial_hex_raw(f.rcx);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  RDX: ");
        crate::kernel::printk::serial_hex_raw(f.rdx);
        crate::kernel::printk::serial_puts_raw("  RSI: ");
        crate::kernel::printk::serial_hex_raw(f.rsi);
        crate::kernel::printk::serial_puts_raw("  RDI: ");
        crate::kernel::printk::serial_hex_raw(f.rdi);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  RBP: ");
        crate::kernel::printk::serial_hex_raw(f.rbp);
        crate::kernel::printk::serial_puts_raw("  R8:  ");
        crate::kernel::printk::serial_hex_raw(f.r8);
        crate::kernel::printk::serial_puts_raw("  R9:  ");
        crate::kernel::printk::serial_hex_raw(f.r9);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  R10: ");
        crate::kernel::printk::serial_hex_raw(f.r10);
        crate::kernel::printk::serial_puts_raw("  R11: ");
        crate::kernel::printk::serial_hex_raw(f.r11);
        crate::kernel::printk::serial_puts_raw("  R12: ");
        crate::kernel::printk::serial_hex_raw(f.r12);
        crate::kernel::printk::serial_putc_hw(b'\n');
        crate::kernel::printk::serial_puts_raw("  R13: ");
        crate::kernel::printk::serial_hex_raw(f.r13);
        crate::kernel::printk::serial_puts_raw("  R14: ");
        crate::kernel::printk::serial_hex_raw(f.r14);
        crate::kernel::printk::serial_puts_raw("  R15: ");
        crate::kernel::printk::serial_hex_raw(f.r15);
        crate::kernel::printk::serial_putc_hw(b'\n');
    }

    // User-mode fault without handler: terminate thread and reschedule
    // instead of halting the CPU permanently. `begin_destroy_on_fault`
    // routes through to `arch::system_halt()` if the faulting TCB has
    // no fault sink — that is the core-service self-fault case where
    // tearing down the TCB would deadlock the system.
    if (f.cs & 3) != 0 {
        unsafe {
            let scheduler = crate::sched::scheduler::scheduler();
            let current = scheduler.current();
            if !current.is_null() {
                crate::kernel::printk::serial_puts_raw("[FAULT] Thread terminated, rescheduling\n");
                crate::task::quiesce::begin_destroy_on_fault(current);
            }
        }
    }

    crate::sched::scheduler::scheduler().reschedule();
}

fn dump_x86_exception(f: &ExceptionFrame) {
    use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};

    serial_puts_raw("exception: ");
    serial_puts_raw(f.exception_name());
    serial_puts_raw(" vector=");
    serial_dec_raw(f.vector);
    serial_puts_raw(" error_code=");
    serial_hex_raw(f.error_code);
    serial_putc_hw(b'\n');

    if f.vector == 14 {
        serial_puts_raw("page_fault: cr2=");
        serial_hex_raw(f.cr2);
        serial_puts_raw(" flags=");
        if f.error_code & 1 != 0 {
            serial_puts_raw("P ");
        } else {
            serial_puts_raw("NP ");
        }
        if f.error_code & 2 != 0 {
            serial_puts_raw("W ");
        } else {
            serial_puts_raw("R ");
        }
        if f.error_code & 4 != 0 {
            serial_puts_raw("U ");
        } else {
            serial_puts_raw("S ");
        }
        if f.error_code & 8 != 0 {
            serial_puts_raw("RSVD ");
        }
        if f.error_code & 16 != 0 {
            serial_puts_raw("I/D ");
        }
        serial_putc_hw(b'\n');
        dump_x86_pte_chain(f.cr2);
    }

    if f.vector == 13 && f.error_code != 0 {
        serial_puts_raw("gpf: selector=");
        serial_hex_raw(f.error_code & 0xFFF8);
        serial_puts_raw(" table=");
        match (f.error_code >> 1) & 3 {
            0 => serial_puts_raw("GDT"),
            1 => serial_puts_raw("IDT"),
            2 => serial_puts_raw("LDT"),
            3 => serial_puts_raw("IDT"),
            _ => {}
        }
        if f.error_code & 1 != 0 {
            serial_puts_raw(" external");
        }
        serial_putc_hw(b'\n');
    }

    serial_puts_raw("RIP: ");
    serial_hex_raw(f.rip);
    serial_puts_raw(" CS: ");
    serial_hex_raw(f.cs);
    serial_puts_raw(" RFLAGS: ");
    serial_hex_raw(f.rflags);
    serial_putc_hw(b'\n');
    serial_puts_raw("RSP: ");
    serial_hex_raw(f.rsp);
    serial_puts_raw(" SS: ");
    serial_hex_raw(f.ss);
    serial_puts_raw(" RBP: ");
    serial_hex_raw(f.rbp);
    serial_putc_hw(b'\n');
    serial_puts_raw("RAX: ");
    serial_hex_raw(f.rax);
    serial_puts_raw(" RBX: ");
    serial_hex_raw(f.rbx);
    serial_puts_raw(" RCX: ");
    serial_hex_raw(f.rcx);
    serial_puts_raw(" RDX: ");
    serial_hex_raw(f.rdx);
    serial_putc_hw(b'\n');
    serial_puts_raw("RSI: ");
    serial_hex_raw(f.rsi);
    serial_puts_raw(" RDI: ");
    serial_hex_raw(f.rdi);
    serial_puts_raw(" R8: ");
    serial_hex_raw(f.r8);
    serial_puts_raw(" R9: ");
    serial_hex_raw(f.r9);
    serial_putc_hw(b'\n');
    serial_puts_raw("R10: ");
    serial_hex_raw(f.r10);
    serial_puts_raw(" R11: ");
    serial_hex_raw(f.r11);
    serial_puts_raw(" R12: ");
    serial_hex_raw(f.r12);
    serial_puts_raw(" R13: ");
    serial_hex_raw(f.r13);
    serial_putc_hw(b'\n');
    serial_puts_raw("R14: ");
    serial_hex_raw(f.r14);
    serial_puts_raw(" R15: ");
    serial_hex_raw(f.r15);
    serial_putc_hw(b'\n');
}

fn x86_panic_context(f: &ExceptionFrame) -> crate::kernel::stacktrace::ArchPanicContext {
    crate::kernel::stacktrace::ArchPanicContext {
        kind: crate::kernel::stacktrace::ContextKind::Exception,
        rip: f.rip,
        rsp: f.rsp,
        rbp: f.rbp,
        rflags: f.rflags,
        cr2: f.cr2,
        cr3: super::paging::read_cr3(),
        vector: f.vector,
        error_code: f.error_code,
        irq_state: f.rflags & (1 << 9),
    }
}

fn dump_x86_pte_chain(addr: u64) {
    use super::paging::PageTable;
    use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};

    let cr3 = super::paging::read_cr3();
    let addr_mask: u64 = 0x000F_FFFF_FFFF_F000;
    let nx_bit: u64 = 1u64 << 63;

    let pml4 = unsafe { &*(crate::mm::phys_to_virt(cr3 & addr_mask) as *const PageTable) };
    let pml4_idx = ((addr >> 39) & 0x1FF) as usize;
    let pml4e = pml4.entry(pml4_idx);
    serial_puts_raw("PTE walk: cr3=");
    serial_hex_raw(cr3);
    serial_putc_hw(b'\n');
    serial_puts_raw("  PML4E[");
    serial_dec_raw(pml4_idx as u64);
    serial_puts_raw("]=");
    serial_hex_raw(pml4e);
    if pml4e & nx_bit != 0 {
        serial_puts_raw(" NX");
    }
    serial_putc_hw(b'\n');

    if pml4e & 1 == 0 {
        return;
    }

    let pdpt = unsafe { &*(crate::mm::phys_to_virt(pml4e & addr_mask) as *const PageTable) };
    let pdpt_idx = ((addr >> 30) & 0x1FF) as usize;
    let pdpte = pdpt.entry(pdpt_idx);
    serial_puts_raw("  PDPTE[");
    serial_dec_raw(pdpt_idx as u64);
    serial_puts_raw("]=");
    serial_hex_raw(pdpte);
    if pdpte & nx_bit != 0 {
        serial_puts_raw(" NX");
    }
    serial_putc_hw(b'\n');

    if pdpte & 1 == 0 || pdpte & (1 << 7) != 0 {
        return;
    }

    let pd = unsafe { &*(crate::mm::phys_to_virt(pdpte & addr_mask) as *const PageTable) };
    let pd_idx = ((addr >> 21) & 0x1FF) as usize;
    let pde = pd.entry(pd_idx);
    serial_puts_raw("  PDE[");
    serial_dec_raw(pd_idx as u64);
    serial_puts_raw("]=");
    serial_hex_raw(pde);
    if pde & nx_bit != 0 {
        serial_puts_raw(" NX");
    }
    serial_putc_hw(b'\n');

    if pde & 1 == 0 || pde & (1 << 7) != 0 {
        return;
    }

    let pt = unsafe { &*(crate::mm::phys_to_virt(pde & addr_mask) as *const PageTable) };
    let pt_idx = ((addr >> 12) & 0x1FF) as usize;
    let pte = pt.entry(pt_idx);
    serial_puts_raw("  PTE[");
    serial_dec_raw(pt_idx as u64);
    serial_puts_raw("]=");
    serial_hex_raw(pte);
    if pte & nx_bit != 0 {
        serial_puts_raw(" NX");
    }
    serial_putc_hw(b'\n');
}

/// Initialize IDT
pub fn init() {
    // SAFETY: Single-threaded initialization, IDT is properly structured
    unsafe {
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("\n[IDT] Starting init\n");
            _g.puts("[IDT] IDT addr: ");
            _g.hex((&raw const IDT) as u64);
            _g.putc(b'\n');
            _g.puts("[IDT] Setting exception handlers (0-31)\n");
        });

        let stubs: [u64; 32] = [
            exception_stub_0 as *const () as u64,
            exception_stub_1 as *const () as u64,
            exception_stub_2 as *const () as u64,
            exception_stub_3 as *const () as u64,
            exception_stub_4 as *const () as u64,
            exception_stub_5 as *const () as u64,
            exception_stub_6 as *const () as u64,
            exception_stub_7 as *const () as u64,
            exception_stub_8 as *const () as u64,
            exception_stub_9 as *const () as u64,
            exception_stub_10 as *const () as u64,
            exception_stub_11 as *const () as u64,
            exception_stub_12 as *const () as u64,
            exception_stub_13 as *const () as u64,
            exception_stub_14 as *const () as u64,
            exception_stub_15 as *const () as u64,
            exception_stub_16 as *const () as u64,
            exception_stub_17 as *const () as u64,
            exception_stub_18 as *const () as u64,
            exception_stub_19 as *const () as u64,
            exception_stub_20 as *const () as u64,
            exception_stub_21 as *const () as u64,
            exception_stub_22 as *const () as u64,
            exception_stub_23 as *const () as u64,
            exception_stub_24 as *const () as u64,
            exception_stub_25 as *const () as u64,
            exception_stub_26 as *const () as u64,
            exception_stub_27 as *const () as u64,
            exception_stub_28 as *const () as u64,
            exception_stub_29 as *const () as u64,
            exception_stub_30 as *const () as u64,
            exception_stub_31 as *const () as u64,
        ];

        let idt = &mut *(&raw mut IDT);
        for i in 0..32 {
            if i == 3 {
                // Breakpoint uses trap gate (don't disable interrupts)
                idt.entries[i].set_trap(stubs[i]);
            } else if i == 8 {
                // Double fault: IST will be set later by init_exception_stacks()
                idt.entries[i].set_handler(stubs[i]);
            } else {
                idt.entries[i].set_handler(stubs[i]);
            }
        }

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] Exception handlers set\n");
            _g.puts("[IDT] Setting IRQ handlers\n");
        });
        idt.entries[32].set_handler(irq_stub_timer as *const () as u64);
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT]   timer handler: ");
            _g.hex(irq_stub_timer as *const () as u64);
            _g.putc(b'\n');
        });

        // Vector 40: IPI VSpace Teardown
        idt.entries[40].set_handler(irq_stub_ipi_vspace_teardown as *const () as u64);
        // Vector 41: IPI Reschedule
        idt.entries[41].set_handler(irq_stub_ipi_reschedule as *const () as u64);
        // Vector 48: IPI TLB Shootdown
        idt.entries[48].set_handler(irq_stub_ipi_tlb_shootdown as *const () as u64);
        // Vector 49: IPI full TLB Shootdown
        idt.entries[49].set_handler(irq_stub_ipi_tlb_shootdown_all as *const () as u64);
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] IPI handlers set (vectors 40-41, 48-49)\n");
        });

        // Generic external IRQ handlers (vectors 33-39, 42-47)
        idt.entries[33].set_handler(irq_stub_generic_33 as *const () as u64);
        idt.entries[34].set_handler(irq_stub_generic_34 as *const () as u64);
        idt.entries[35].set_handler(irq_stub_generic_35 as *const () as u64);
        idt.entries[36].set_handler(irq_stub_generic_36 as *const () as u64);
        idt.entries[37].set_handler(irq_stub_generic_37 as *const () as u64);
        idt.entries[38].set_handler(irq_stub_generic_38 as *const () as u64);
        idt.entries[39].set_handler(irq_stub_generic_39 as *const () as u64);
        idt.entries[42].set_handler(irq_stub_generic_42 as *const () as u64);
        idt.entries[43].set_handler(irq_stub_generic_43 as *const () as u64);
        idt.entries[44].set_handler(irq_stub_generic_44 as *const () as u64);
        idt.entries[45].set_handler(irq_stub_generic_45 as *const () as u64);
        idt.entries[46].set_handler(irq_stub_generic_46 as *const () as u64);
        idt.entries[47].set_handler(irq_stub_generic_47 as *const () as u64);
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] External IRQ handlers set (vectors 33-47)\n");
            _g.puts("[IDT] Preparing IDT pointer\n");
        });
        let idt_ptr = IdtPtr {
            limit: (size_of::<Idt>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT]   limit: ");
            _g.hex(idt_ptr.limit as u64);
            _g.puts("\n[IDT]   base: ");
            _g.hex(idt_ptr.base);
            _g.putc(b'\n');
        });

        // Load IDT
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] Calling lidt\n");
        });
        x86_idt_lidt(&idt_ptr);

        // Verify with sidt
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] Verifying with sidt...\n");
        });
        let mut idt_read_back: IdtPtr = IdtPtr { limit: 0, base: 0 };
        x86_idt_sidt(&mut idt_read_back);
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] sidt result: limit=");
            _g.hex(idt_read_back.limit as u64);
            _g.puts(" base=");
            _g.hex(idt_read_back.base);
            _g.putc(b'\n');
        });

        // Verify struct sizes
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] Struct sizes:\n");
            _g.puts("  size_of::<IdtEntry>() = ");
            _g.hex(size_of::<IdtEntry>() as u64);
            _g.puts("\n  size_of::<IdtPtr>() = ");
            _g.hex(size_of::<IdtPtr>() as u64);
            _g.puts("\n  size_of::<Idt>() = ");
            _g.hex(size_of::<Idt>() as u64);
            _g.putc(b'\n');
        });

        assert!(size_of::<IdtEntry>() == 16, "IdtEntry must be 16 bytes!");
        assert!(
            size_of::<IdtPtr>() == 10,
            "IdtPtr must be 10 bytes (packed)!"
        );

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[IDT] IDT loaded and verified successfully\n");
        });
    }
}

/// Timer interrupt handler (called from assembly stub irq_stub_timer)
///
/// Vector 32 - dispatches to APIC or PIT handler based on active timer backend.
/// `frame` points at the saved `InterruptFrame`; the timer backend still passes
/// the interrupted mode hint through to the scheduler's timer API shape, while
/// runtime attribution itself happens in the common entry/exit hooks.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_timer(frame: *const InterruptFrame) {
    if super::has_apic() {
        super::apic::timer_handler(frame);
    } else {
        super::pit::timer_handler(frame);
    }
}

/// IPI VSpace Teardown handler (called from assembly stub irq_stub_ipi_vspace_teardown)
///
/// Vector 40 - sent when a VSpace is being torn down and this CPU
/// needs to switch away from it. Only fires in APIC mode (SMP).
#[unsafe(no_mangle)]
extern "C" fn irq_handler_ipi_vspace_teardown(_frame: *const InterruptFrame) {
    if super::has_apic() {
        super::apic::handle_ipi(super::apic::IpiKind::VSpaceTeardown);
        super::apic::eoi();
    }
}

/// IPI Reschedule handler (called from assembly stub irq_stub_ipi_reschedule)
///
/// Vector 41 - sent when a thread with specific CPU affinity is
/// enqueued and the target CPU should check for work. Only fires in APIC mode.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_ipi_reschedule(_frame: *const InterruptFrame) {
    if super::has_apic() {
        // Send EOI BEFORE handle_ipi: handle_reschedule_ipi() may context-switch
        // via do_context_switch(), and the old thread may not resume for a long
        // time. Without early EOI, the LAPIC ISR bit for vector 41 stays set,
        // blocking all priority-class-2 vectors (32-47) including the timer.
        super::apic::eoi();
        super::apic::handle_ipi(super::apic::IpiKind::Reschedule);
    }
}

/// IPI TLB Shootdown handler (called from assembly stub irq_stub_ipi_tlb_shootdown)
///
/// Vector 48 — sent when a page table entry is modified and remote CPUs
/// must invalidate the corresponding TLB entry via `invlpg`.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_ipi_tlb_shootdown(_frame: *const InterruptFrame) {
    if super::has_apic() {
        let cpu_id = crate::arch::current_cpu() as usize;
        let addr = super::apic::tlb_shootdown_addr(cpu_id);
        if addr != 0 {
            super::paging::invlpg(addr);
        }
        super::apic::eoi();
    }
}

/// IPI full TLB Shootdown handler (called from assembly stub irq_stub_ipi_tlb_shootdown_all)
///
/// Vector 49 — sent when many PTEs are updated in one operation.
/// Reloading CR3 flushes non-global TLB entries in one step.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_ipi_tlb_shootdown_all(_frame: *const InterruptFrame) {
    if super::has_apic() {
        let cr3 = super::paging::read_cr3();
        unsafe {
            super::paging::write_cr3(cr3);
        }
        super::apic::eoi();
    }
}

/// Generic IRQ handler for external hardware interrupts
///
/// Called from assembly stubs for vectors 33-47 (except 40-41 which are IPIs).
/// Dispatches to the IRQ handler system and sends EOI.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_generic(vector: u32) {
    // Convert vector to IRQ number (vector = IRQ + 32)
    let irq_num = vector.saturating_sub(32) as usize;
    crate::event::irq::dispatch_irq(irq_num);
    if super::has_apic() {
        super::apic::eoi();
    } else {
        // PIC EOI: if IRQ >= 8, also send EOI to slave PIC
        if irq_num >= 8 {
            unsafe {
                super::outb(0xA0, 0x20);
            }
        }
        unsafe {
            super::outb(0x20, 0x20);
        }
    }
}
