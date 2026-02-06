//! Interrupt Descriptor Table (IDT)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::mem::size_of;

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

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Write a byte to serial port
unsafe fn serial_putc(c: u8) {
    unsafe {
        while (super::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        super::outb(SERIAL_PORT, c);
    }
}

/// Write a string to serial port
unsafe fn serial_puts(s: &str) {
    for byte in s.bytes() {
        unsafe {
            serial_putc(byte);
        }
    }
}

/// Write a hexadecimal number to serial port
unsafe fn serial_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    unsafe {
        serial_puts("0x");
    }
    if val == 0 {
        unsafe {
            serial_putc(b'0');
        }
        return;
    }
    let mut buf = [0u8; 16];
    let mut pos = 15;
    while val > 0 {
        buf[pos] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
        pos -= 1;
    }
    for &c in &buf[(pos + 1)..] {
        unsafe {
            serial_putc(c);
        }
    }
}

/// Write a decimal number to serial port
unsafe fn serial_dec(mut val: u64) {
    if val == 0 {
        unsafe {
            serial_putc(b'0');
        }
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 19;
    while val > 0 {
        buf[pos] = b'0' + ((val % 10) as u8);
        val /= 10;
        pos -= 1;
    }
    for &c in &buf[(pos + 1)..] {
        unsafe {
            serial_putc(c);
        }
    }
}

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
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &idt_ptr,
            options(nostack)
        );
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

    // User-mode exception: try fault delivery via IPC
    if (f.cs & 3) != 0 {
        unsafe {
            let scheduler = crate::sched::scheduler::scheduler();
            let current = scheduler.current();

            if !current.is_null() && !(*current).fault_handler.is_null() {
                let fault_ep = &mut *((*current).fault_handler
                    as *mut crate::ipc::Endpoint);

                // Build fault message
                let msg = if f.vector == 14 {
                    crate::ipc::vm_fault_message(
                        f.cr2,
                        f.error_code,
                        f.rip,
                        f.error_code & 16 != 0,
                    )
                } else {
                    crate::ipc::user_exception_message(
                        f.vector,
                        f.error_code,
                        f.rip,
                        f.rsp,
                    )
                };

                serial_puts("[FAULT] user exception vec=");
                serial_dec(f.vector);
                serial_puts(" addr=");
                serial_hex(f.cr2);
                serial_puts(" rip=");
                serial_hex(f.rip);
                serial_puts(" -> delivering via IPC\n");

                // Block faulting thread
                (*current).state = crate::sched::thread::ThreadState::Blocked;
                (*current).blocked_reason = Some(
                    crate::sched::thread::BlockedReason::FaultBlocked {
                        msg,
                        badge: 0,
                    },
                );

                // Deliver to handler endpoint
                fault_ep.deliver_fault(current, &msg);

                // Switch to handler (or whoever is next)
                scheduler.reschedule();

                // Handler replied — we're back. Return to assembly which
                // restores GPRs from the exception frame and iretq retries
                // the faulting instruction.
                return;
            }
        }
    }

    // No fault handler or kernel-mode exception: diagnostic dump + halt
    unsafe {
        serial_puts("\n*** EXCEPTION: ");
        serial_puts(f.exception_name());
        serial_puts(" (vector ");
        serial_dec(f.vector);
        serial_puts(", error_code ");
        serial_hex(f.error_code);
        serial_puts(")\n");

        if f.vector == 14 {
            serial_puts("  CR2 (fault addr): ");
            serial_hex(f.cr2);
            serial_putc(b'\n');
            serial_puts("  Flags: ");
            if f.error_code & 1 != 0 { serial_puts("P "); } else { serial_puts("NP "); }
            if f.error_code & 2 != 0 { serial_puts("W "); } else { serial_puts("R "); }
            if f.error_code & 4 != 0 { serial_puts("U "); } else { serial_puts("S "); }
            if f.error_code & 8 != 0 { serial_puts("RSVD "); }
            if f.error_code & 16 != 0 { serial_puts("I/D "); }
            serial_putc(b'\n');
        }

        if f.vector == 13 && f.error_code != 0 {
            serial_puts("  Selector: ");
            serial_hex(f.error_code & 0xFFF8);
            serial_puts("  Table: ");
            match (f.error_code >> 1) & 3 {
                0 => serial_puts("GDT"),
                1 => serial_puts("IDT"),
                2 => serial_puts("LDT"),
                3 => serial_puts("IDT"),
                _ => {}
            }
            if f.error_code & 1 != 0 { serial_puts(" (External)"); }
            serial_putc(b'\n');
        }

        serial_puts("  RIP:    "); serial_hex(f.rip);
        serial_puts("  CS:     "); serial_hex(f.cs); serial_putc(b'\n');
        serial_puts("  RSP:    "); serial_hex(f.rsp);
        serial_puts("  SS:     "); serial_hex(f.ss); serial_putc(b'\n');
        serial_puts("  RFLAGS: "); serial_hex(f.rflags); serial_putc(b'\n');
        serial_puts("  RAX: "); serial_hex(f.rax);
        serial_puts("  RBX: "); serial_hex(f.rbx);
        serial_puts("  RCX: "); serial_hex(f.rcx); serial_putc(b'\n');
        serial_puts("  RDX: "); serial_hex(f.rdx);
        serial_puts("  RSI: "); serial_hex(f.rsi);
        serial_puts("  RDI: "); serial_hex(f.rdi); serial_putc(b'\n');
        serial_puts("  RBP: "); serial_hex(f.rbp);
        serial_puts("  R8:  "); serial_hex(f.r8);
        serial_puts("  R9:  "); serial_hex(f.r9); serial_putc(b'\n');
        serial_puts("  R10: "); serial_hex(f.r10);
        serial_puts("  R11: "); serial_hex(f.r11);
        serial_puts("  R12: "); serial_hex(f.r12); serial_putc(b'\n');
        serial_puts("  R13: "); serial_hex(f.r13);
        serial_puts("  R14: "); serial_hex(f.r14);
        serial_puts("  R15: "); serial_hex(f.r15); serial_putc(b'\n');
    }

    loop {
        super::halt();
    }
}

/// Initialize IDT
pub fn init() {
    // SAFETY: Single-threaded initialization, IDT is properly structured
    unsafe {
        serial_puts("\n[IDT] Starting init\n");

        // Print IDT address
        serial_puts("[IDT] IDT addr: ");
        serial_hex((&raw const IDT) as u64);
        serial_putc(b'\n');

        // Set up exception handlers (vectors 0-31) using assembly stubs
        serial_puts("[IDT] Setting exception handlers (0-31)\n");

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

        serial_puts("[IDT] Exception handlers set\n");

        // Set up IRQ handlers (vectors 32+) using assembly stubs with swapgs
        serial_puts("[IDT] Setting IRQ handlers\n");
        idt.entries[32].set_handler(irq_stub_timer as *const () as u64);
        serial_puts("[IDT]   timer handler: ");
        serial_hex(irq_stub_timer as *const () as u64);
        serial_putc(b'\n');

        // Vector 40: IPI VSpace Teardown
        idt.entries[40].set_handler(irq_stub_ipi_vspace_teardown as *const () as u64);
        // Vector 41: IPI Reschedule
        idt.entries[41].set_handler(irq_stub_ipi_reschedule as *const () as u64);
        serial_puts("[IDT] IPI handlers set (vectors 40-41)\n");

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
        serial_puts("[IDT] External IRQ handlers set (vectors 33-47)\n");

        // Prepare IDT pointer
        serial_puts("[IDT] Preparing IDT pointer\n");
        let idt_ptr = IdtPtr {
            limit: (size_of::<Idt>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };

        serial_puts("[IDT]   limit: ");
        serial_hex(idt_ptr.limit as u64);
        serial_puts("\n[IDT]   base: ");
        serial_hex(idt_ptr.base);
        serial_putc(b'\n');

        // Load IDT
        serial_puts("[IDT] Calling lidt\n");
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &idt_ptr,
            options(nostack)
        );

        // Verify with sidt
        serial_puts("[IDT] Verifying with sidt...\n");
        let mut idt_read_back: IdtPtr = IdtPtr { limit: 0, base: 0 };
        core::arch::asm!(
            "sidt [{}]",
            in(reg) &mut idt_read_back,
            options(nostack)
        );
        serial_puts("[IDT] sidt result: limit=");
        serial_hex(idt_read_back.limit as u64);
        serial_puts(" base=");
        serial_hex(idt_read_back.base);
        serial_putc(b'\n');

        // Verify struct sizes
        serial_puts("[IDT] Struct sizes:\n");
        serial_puts("  size_of::<IdtEntry>() = ");
        serial_hex(size_of::<IdtEntry>() as u64);
        serial_putc(b'\n');
        serial_puts("  size_of::<IdtPtr>() = ");
        serial_hex(size_of::<IdtPtr>() as u64);
        serial_putc(b'\n');
        serial_puts("  size_of::<Idt>() = ");
        serial_hex(size_of::<Idt>() as u64);
        serial_putc(b'\n');

        assert!(size_of::<IdtEntry>() == 16, "IdtEntry must be 16 bytes!");
        assert!(size_of::<IdtPtr>() == 10, "IdtPtr must be 10 bytes (packed)!");

        serial_puts("[IDT] IDT loaded and verified successfully\n");
    }
}

/// APIC Timer interrupt handler (called from assembly stub irq_stub_timer)
///
/// Vector 32 - called every 1ms by the APIC timer.
/// This is the primary scheduler tick interrupt.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_timer() {
    super::apic::timer_handler();
}

/// IPI VSpace Teardown handler (called from assembly stub irq_stub_ipi_vspace_teardown)
///
/// Vector 40 - sent when a VSpace is being torn down and this CPU
/// needs to switch away from it.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_ipi_vspace_teardown() {
    super::apic::handle_ipi(super::apic::IpiKind::VSpaceTeardown);
    super::apic::eoi();
}

/// IPI Reschedule handler (called from assembly stub irq_stub_ipi_reschedule)
///
/// Vector 41 - sent when a thread with specific CPU affinity is
/// enqueued and the target CPU should check for work.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_ipi_reschedule() {
    super::apic::handle_ipi(super::apic::IpiKind::Reschedule);
    super::apic::eoi();
}

/// Generic IRQ handler for external hardware interrupts
///
/// Called from assembly stubs for vectors 33-47 (except 40-41 which are IPIs).
/// Dispatches to the IRQ handler system and sends EOI.
#[unsafe(no_mangle)]
extern "C" fn irq_handler_generic(vector: u32) {
    // Convert vector to IRQ number (vector = IRQ + 32)
    let irq_num = vector.saturating_sub(32) as usize;
    crate::ipc::irq::dispatch_irq(irq_num);
    super::apic::eoi();
}
