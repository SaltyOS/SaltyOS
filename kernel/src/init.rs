//! Init Task Bootstrap
//!
//! Creates and dispatches the first user-mode task from kmain().
//!
//! If an initrd is present in BootInfo, loads init.elf from the CPIO archive
//! using the kernel ELF loader. Otherwise falls back to a hardcoded bytecode
//! yield loop.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::{alloc_frame, phys_to_virt, VSpace, PAGE_SIZE};
use crate::mm::vspace::PageFlags;
use crate::sched::thread::{SchedContext, Tcb};
use crate::ParsedBootInfo;
use core::mem::MaybeUninit;

/// User code virtual address (4 MB)
const INIT_CODE_VADDR: u64 = 0x0000_0040_0000;
/// User stack virtual address (8 MB)
const INIT_STACK_VADDR: u64 = 0x0000_0080_0000;
/// Top of user stack (stack grows down)
const INIT_STACK_TOP: u64 = INIT_STACK_VADDR + PAGE_SIZE as u64;

/// Minimal user program: yield loop (fallback when no initrd)
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
pub fn bootstrap(boot_info: Option<&ParsedBootInfo>) {
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

    // Load init program: try ELF from initrd, fall back to hardcoded bytecode
    let (user_rip, user_stack_top) = if let Some(info) = boot_info {
        if info.initrd_addr != 0 && info.initrd_size != 0 {
            load_from_initrd(info, &mut vspace)
        } else {
            load_hardcoded_fallback(&mut vspace)
        }
    } else {
        load_hardcoded_fallback(&mut vspace)
    };

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
        (*tcb).context.r12 = user_rip;            // User RIP
        (*tcb).context.r13 = user_stack_top;       // User RSP
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

    crate::serial_puts("[INIT] Init task enqueued, entering user mode at ");
    crate::serial_hex(user_rip);
    crate::serial_puts("\n");
}

/// Load init.elf from CPIO initrd using the kernel ELF loader
fn load_from_initrd(info: &ParsedBootInfo, vspace: &mut VSpace) -> (u64, u64) {
    crate::serial_puts("[INIT] Parsing CPIO initrd\n");

    let initrd = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(info.initrd_addr) as *const u8,
            info.initrd_size as usize,
        )
    };

    let elf_entry = crate::cpio::find_file(initrd, "init.elf");
    let elf_data = match elf_entry {
        Some(entry) => {
            crate::serial_puts("[INIT] Found init.elf in initrd (");
            crate::serial_dec(entry.data.len() as u64);
            crate::serial_puts(" bytes)\n");
            entry.data
        }
        None => {
            crate::serial_puts("[INIT] WARNING: init.elf not found in initrd, using fallback\n");
            return load_hardcoded_fallback(vspace);
        }
    };

    crate::serial_puts("[INIT] Loading ELF from initrd\n");
    let result = match crate::elf::load_elf(elf_data, vspace, INIT_CODE_VADDR) {
        Ok(r) => r,
        Err(e) => {
            crate::serial_puts("[INIT] FATAL: ELF load failed: ");
            match e {
                crate::elf::ElfError::NotElf => crate::serial_puts("not ELF"),
                crate::elf::ElfError::Not64Bit => crate::serial_puts("not 64-bit"),
                crate::elf::ElfError::NotLittleEndian => crate::serial_puts("not LE"),
                crate::elf::ElfError::BadType => crate::serial_puts("bad type"),
                crate::elf::ElfError::BadArch => crate::serial_puts("bad arch"),
                crate::elf::ElfError::NoLoadSegment => crate::serial_puts("no LOAD"),
                crate::elf::ElfError::RelocFailed => crate::serial_puts("reloc failed"),
                crate::elf::ElfError::OutOfMemory => crate::serial_puts("OOM"),
                crate::elf::ElfError::TooSmall => crate::serial_puts("too small"),
                crate::elf::ElfError::TooManyPages => crate::serial_puts("too many pages"),
                crate::elf::ElfError::MapFailed => crate::serial_puts("map failed"),
            }
            crate::serial_puts("\n");
            panic!("init ELF load failed");
        }
    };

    crate::serial_puts("[INIT] ELF loaded: entry=");
    crate::serial_hex(result.entry);
    crate::serial_puts(" base=");
    crate::serial_hex(result.base);
    crate::serial_puts(" brk=");
    crate::serial_hex(result.brk);
    crate::serial_puts("\n");

    // Allocate user stack
    let stack_phys = alloc_frame().expect("init: stack alloc failed");
    unsafe {
        core::ptr::write_bytes(phys_to_virt(stack_phys) as *mut u8, 0, PAGE_SIZE);
    }
    vspace
        .map(INIT_STACK_VADDR, stack_phys, PageFlags::USER_RW)
        .expect("init: stack map failed");

    (result.entry, INIT_STACK_TOP)
}

/// Load the hardcoded yield-loop bytecode (fallback when no initrd)
fn load_hardcoded_fallback(vspace: &mut VSpace) -> (u64, u64) {
    crate::serial_puts("[INIT] Using hardcoded bytecode fallback\n");

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

    (INIT_CODE_VADDR, INIT_STACK_TOP)
}
