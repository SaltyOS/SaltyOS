//! Init Task Bootstrap
//!
//! Creates and dispatches the first user-mode task from kmain().
//! The init task is a minimal syscall-yield loop that proves ring-3
//! execution works end-to-end.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::{alloc_frame, phys_to_virt, VSpace, PAGE_SIZE};
use crate::mm::vspace::PageFlags;
use crate::sched::thread::{SchedContext, Tcb};
use core::mem::MaybeUninit;

/// User code virtual address (4 MB)
const INIT_CODE_VADDR: u64 = 0x0000_0040_0000;
/// User stack virtual address (8 MB)
const INIT_STACK_VADDR: u64 = 0x0000_0080_0000;
/// Top of user stack (stack grows down)
const INIT_STACK_TOP: u64 = INIT_STACK_VADDR + PAGE_SIZE as u64;

/// Minimal user program: yield loop
///
/// ```asm
/// loop:
///   mov rax, 8       ; SYS_YIELD
///   syscall
///   jmp loop
/// ```
static INIT_USER_CODE: [u8; 12] = [
    0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00, // mov rax, 8
    0x0F, 0x05,                                 // syscall
    0xEB, 0xF5,                                 // jmp -11 (back to mov)
    0x00,                                       // padding
];

/// Static storage for init task (never freed)
static mut INIT_TCB: Tcb = Tcb::new();
static mut INIT_SCHED_CTX: SchedContext = SchedContext::new();
static mut INIT_VSPACE: MaybeUninit<VSpace> = MaybeUninit::uninit();

/// Bootstrap the first user-mode init task
pub fn bootstrap() {
    crate::serial_puts("[INIT] Creating user VSpace\n");

    // Read current (kernel) CR3 for copying higher-half entries
    let kernel_cr3 = crate::arch::x86_64::paging::read_cr3();

    // Allocate PML4 for user VSpace
    let pml4_phys = alloc_frame().expect("init: PML4 alloc failed");
    let pml4_virt = phys_to_virt(pml4_phys) as *mut u64;

    // Zero the PML4
    unsafe {
        core::ptr::write_bytes(pml4_virt, 0, PAGE_SIZE / 8);
    }

    // Copy kernel higher-half PML4 entries (256..511) from current CR3
    let kernel_pml4 = phys_to_virt(kernel_cr3) as *const u64;
    unsafe {
        for i in 256..512 {
            let entry = kernel_pml4.add(i).read();
            pml4_virt.add(i).write(entry);
        }
    }

    // Create VSpace from the new PML4
    let mut vspace = VSpace::new(pml4_phys);

    // Allocate and map user code page
    let code_phys = alloc_frame().expect("init: code frame alloc failed");
    let code_virt = phys_to_virt(code_phys) as *mut u8;
    unsafe {
        core::ptr::write_bytes(code_virt, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(
            INIT_USER_CODE.as_ptr(),
            code_virt,
            INIT_USER_CODE.len(),
        );
    }
    vspace
        .map(INIT_CODE_VADDR, code_phys, PageFlags::USER_RX)
        .expect("init: code map failed");

    // Allocate and map user stack page
    let stack_phys = alloc_frame().expect("init: stack frame alloc failed");
    let stack_virt = phys_to_virt(stack_phys) as *mut u8;
    unsafe {
        core::ptr::write_bytes(stack_virt, 0, PAGE_SIZE);
    }
    vspace
        .map(INIT_STACK_VADDR, stack_phys, PageFlags::USER_RW)
        .expect("init: stack map failed");

    // Allocate a kernel stack for the trampoline
    let tramp_stack_phys = alloc_frame().expect("init: trampoline stack alloc failed");
    let tramp_stack_virt = phys_to_virt(tramp_stack_phys);
    let tramp_stack_top = tramp_stack_virt + PAGE_SIZE as u64;
    unsafe {
        core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, PAGE_SIZE);
    }

    let vspace_root = vspace.root();

    crate::serial_puts("[INIT] VSpace created, configuring TCB\n");

    // Store VSpace in static so it isn't dropped
    unsafe {
        let vspace_ptr = (&raw mut INIT_VSPACE).cast::<MaybeUninit<VSpace>>();
        (*vspace_ptr).write(vspace);
    }

    // Configure init TCB
    unsafe {
        let tcb = &raw mut INIT_TCB;
        let sc = &raw mut INIT_SCHED_CTX;

        // The trampoline function is entered via context_switch's `ret`.
        // It reads r12/r13/r14 and performs iretq to ring 3.
        (*tcb).context.rip = crate::arch::usermode_trampoline as *const () as u64;
        (*tcb).context.rsp = tramp_stack_top;
        (*tcb).context.r12 = INIT_CODE_VADDR;    // User RIP
        (*tcb).context.r13 = INIT_STACK_TOP;      // User RSP
        (*tcb).context.r14 = vspace_root;          // User CR3
        (*tcb).context.rflags = 0x202;             // IF=1

        // SchedContext: 10ms budget, 100ms period
        (*sc).budget = 10;
        (*sc).period = 100;
        (*sc).remaining = 10;
        (*sc).deadline = 100;
        (*sc).bound_tcb = tcb;

        (*tcb).priority = 100; // deadline for EDF
        (*tcb).cpu_affinity = 0;
        (*tcb).sched_context = sc;
        (*tcb).vspace = (&raw mut INIT_VSPACE).cast::<VSpace>();

        // Enqueue the init task
        crate::sched::scheduler::scheduler().enqueue(tcb);
    }

    crate::serial_puts("[INIT] Init task enqueued, entering user mode at 0x400000\n");
}
