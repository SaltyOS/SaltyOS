//! Init Task Bootstrap
//!
//! Creates and dispatches the first user-mode task from kmain().
//!
//! If an initrd is present in BootInfo, loads init.elf from the CPIO archive
//! using the kernel ELF loader. Otherwise falls back to a hardcoded bytecode
//! yield loop.
//!
//! Sets up the init task's CSpace with well-known capability slots for
//! TCB, VSpace, CSpace, and Untyped memory regions.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{
    alloc_slot, get_cap_mut, CNode, CapRef, CapRights, IoPortRange, ObjectType, UntypedMemory,
};
use crate::ipc::{IrqHandler, Notification};
use crate::mm::vspace::PageFlags;
use crate::mm::{alloc_contiguous_frames, alloc_frame, phys_to_virt, VSpace, PAGE_SIZE};
use crate::sched::thread::{SchedContext, Tcb};
use crate::ParsedBootInfo;
use core::mem::MaybeUninit;

/// User code virtual address (4 MB)
const INIT_CODE_VADDR: u64 = 0x0000_0040_0000;
/// User stack virtual address (8 MB)
const INIT_STACK_VADDR: u64 = 0x0000_0080_0000;
/// Init user stack size (pages)
const INIT_STACK_PAGES: usize = 8;
/// Init user stack size in bytes
const INIT_STACK_SIZE: u64 = INIT_STACK_PAGES as u64 * PAGE_SIZE as u64;
/// Top of user stack (stack grows down)
const INIT_STACK_TOP: u64 = INIT_STACK_VADDR + INIT_STACK_SIZE;

/// Well-known CSpace slot indices (must match userland/init/main.c)
const CAP_SELF_TCB: usize = 0;
const CAP_SELF_VSPACE: usize = 1;
const CAP_SELF_CSPACE: usize = 2;
/// COM1 serial port capabilities
const CAP_COM1_IOPORT: usize = 8;
const CAP_COM1_IRQ: usize = 9;
const CAP_COM1_NOTIFICATION: usize = 10;
/// Initrd info slots (vaddr and size passed as badge values)
const CAP_INITRD_VSPACE: usize = 11;
const CAP_UNTYPED_START: usize = 16;

/// Initrd mapping virtual address (16 MB)
const INITRD_VADDR: u64 = 0x0000_0100_0000;
/// Boot info page virtual address (12 MB) -- read-only page with initrd info
const BOOTINFO_VADDR: u64 = 0x0000_00C0_0000;

/// Maximum number of untyped regions to hand to init
const MAX_INIT_UNTYPEDS: usize = 64;

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
static mut INIT_CNODE: CNode = CNode::new();
static mut INIT_UNTYPEDS: [UntypedMemory; MAX_INIT_UNTYPEDS] = {
    const EMPTY: UntypedMemory = UntypedMemory::new(0, 0, false);
    [EMPTY; MAX_INIT_UNTYPEDS]
};

/// COM1 serial port objects (static, never freed)
static mut INIT_COM1_IOPORT: IoPortRange = IoPortRange::new(0x3F8, 8);
static mut INIT_COM1_IRQ: IrqHandler = IrqHandler::new(4);
static mut INIT_COM1_NOTIFICATION: Notification = Notification::new();

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

    // Map initrd into user VSpace (for procmgr to parse CPIO)
    if let Some(info) = boot_info {
        if info.initrd_addr != 0 && info.initrd_size != 0 {
            map_initrd(info, &mut vspace);
            map_bootinfo(&mut vspace);
        }
    }

    // Allocate a kernel stack for the trampoline (used by context_switch → iretq)
    let tramp_stack_phys = alloc_frame().expect("init: trampoline stack alloc failed");
    let tramp_stack_virt = phys_to_virt(tramp_stack_phys);
    let tramp_stack_top = tramp_stack_virt + PAGE_SIZE as u64;
    unsafe {
        core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, PAGE_SIZE);
    }

    // Allocate per-thread kernel stack for syscall entry
    let kstack_phys = alloc_frame().expect("init: kernel stack alloc failed");
    let kstack_virt = phys_to_virt(kstack_phys);
    let kstack_top = kstack_virt + PAGE_SIZE as u64;
    unsafe {
        core::ptr::write_bytes(kstack_virt as *mut u8, 0, PAGE_SIZE);
    }

    let vspace_root = vspace.root();

    crate::serial_puts("[INIT] VSpace created, configuring TCB\n");

    // Store VSpace in static so it isn't dropped
    unsafe {
        let vspace_ptr = (&raw mut INIT_VSPACE).cast::<MaybeUninit<VSpace>>();
        (*vspace_ptr).write(vspace);
    }

    // Set up CSpace for init task
    setup_init_cspace(boot_info);

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
        (*tcb).context.r15 = 0x3202;               // User RFLAGS: IF=1, IOPL=3
        (*tcb).context.rflags = 0x202;             // Kernel RFLAGS for context_switch

        // SchedContext: 10ms budget, 100ms period
        (*sc).budget = 10;
        (*sc).period = 100;
        (*sc).remaining = 10;
        (*sc).deadline = 100;
        (*sc).bound_tcb = tcb;

        (*tcb).priority = 100; // deadline for EDF
        (*tcb).cpu_affinity = 0;
        (*tcb).sched_context = sc;
        (*tcb).vspace_root = (&raw mut INIT_VSPACE).cast::<VSpace>();
        (*tcb).cspace_root = &raw mut INIT_CNODE;
        (*tcb).kernel_stack_top = kstack_top;

        // Set per-CPU kernel stack to init's stack before first scheduling
        crate::arch::set_kernel_stack(kstack_top);
        crate::arch::set_tss_rsp0(kstack_top);

        // Enqueue the init task
        crate::sched::scheduler::scheduler().enqueue(tcb);
    }

    crate::serial_puts("[INIT] Init task enqueued, entering user mode at ");
    crate::serial_hex(user_rip);
    crate::serial_puts("\n");
}

/// Set up init task's CSpace with well-known capabilities
fn setup_init_cspace(boot_info: Option<&ParsedBootInfo>) {
    crate::serial_puts("[INIT] Setting up CSpace\n");

    unsafe {
        let cnode = &mut *(&raw mut INIT_CNODE);

        // Slot 0: CAP_SELF_TCB - capability to init's own TCB
        insert_static_cap(
            cnode,
            CAP_SELF_TCB,
            &raw mut INIT_TCB as *mut crate::cap::KernelObject,
            ObjectType::Tcb,
        );

        // Slot 1: CAP_SELF_VSPACE - capability to init's VSpace
        insert_static_cap(
            cnode,
            CAP_SELF_VSPACE,
            (&raw mut INIT_VSPACE).cast::<crate::cap::KernelObject>(),
            ObjectType::VSpace,
        );

        // Slot 2: CAP_SELF_CSPACE - capability to init's own CNode
        insert_static_cap(
            cnode,
            CAP_SELF_CSPACE,
            &raw mut INIT_CNODE as *mut crate::cap::KernelObject,
            ObjectType::CNode,
        );

        // Slot 8: COM1 IoPort capability (ports 0x3F8..0x3FF)
        insert_static_cap(
            cnode,
            CAP_COM1_IOPORT,
            &raw mut INIT_COM1_IOPORT as *mut crate::cap::KernelObject,
            ObjectType::IoPort,
        );

        // Slot 9: COM1 IRQ handler capability (IRQ 4)
        {
            let irq_ptr = &raw mut INIT_COM1_IRQ;
            insert_static_cap(
                cnode,
                CAP_COM1_IRQ,
                irq_ptr as *mut crate::cap::KernelObject,
                ObjectType::IrqHandler,
            );
            // Register in global IRQ table so hardware IRQ4 dispatches to it
            crate::ipc::irq::register_handler(4, irq_ptr);
        }

        // Slot 10: COM1 notification (for IRQ delivery)
        insert_static_cap(
            cnode,
            CAP_COM1_NOTIFICATION,
            &raw mut INIT_COM1_NOTIFICATION as *mut crate::cap::KernelObject,
            ObjectType::Notification,
        );

        // Slots 16+: Untyped memory capabilities from usable memory regions
        if let Some(info) = boot_info {
            create_untyped_caps(cnode, info);
        }
    }

    crate::serial_puts("[INIT] CSpace setup complete\n");
}

/// Insert a capability for a statically-allocated kernel object into a CNode
unsafe fn insert_static_cap(
    cnode: &mut CNode,
    cnode_index: usize,
    object: *mut crate::cap::KernelObject,
    obj_type: ObjectType,
) {
    let slot = alloc_slot().expect("init: cap slot alloc failed");
    let cap = get_cap_mut(slot);
    cap.object = object;
    cap.obj_type = obj_type;
    cap.rights = CapRights::ALL;
    cap.depth = 0;
    cap.badge = 0;
    cnode
        .insert_ref(cnode_index, CapRef { slot })
        .expect("init: CNode insert failed");
}

/// Create untyped memory capabilities from boot info memory map
unsafe fn create_untyped_caps(cnode: &mut CNode, _info: &ParsedBootInfo) {
    // Allocate backing memory from the frame allocator so untyped regions
    // do not overlap frames already in use by the kernel.
    const MAX_SIZE_BITS: u8 = 28; // 256 MiB
    const MIN_SIZE_BITS: u8 = 12; // 4 KiB

    let mut ut_index = 0;

    for size_bits in (MIN_SIZE_BITS..=MAX_SIZE_BITS).rev() {
        if ut_index >= MAX_INIT_UNTYPEDS {
            break;
        }

        let size_bytes = 1usize << size_bits;
        let frame_count = size_bytes / PAGE_SIZE;

        let Some(base) = alloc_contiguous_frames(frame_count) else {
            continue;
        };

        // Initialize the UntypedMemory object in static storage
        let ut = &raw mut INIT_UNTYPEDS[ut_index];
        (*ut) = UntypedMemory::new(base, size_bits, false);

        // Allocate a global cap slot and populate it
        let slot = alloc_slot().expect("init: untyped cap slot alloc failed");
        let cap = get_cap_mut(slot);
        cap.object = ut as *mut crate::cap::KernelObject;
        cap.obj_type = ObjectType::Untyped;
        cap.rights = CapRights::ALL;
        cap.depth = 0;
        cap.badge = 0;

        let cnode_slot = CAP_UNTYPED_START + ut_index;
        cnode
            .insert_ref(cnode_slot, CapRef { slot })
            .expect("init: untyped CNode insert failed");

        crate::serial_puts("[INIT]   Untyped ");
        crate::serial_dec(ut_index as u64);
        crate::serial_puts(": phys=");
        crate::serial_hex(base);
        crate::serial_puts(" size=");
        crate::serial_hex(1u64 << size_bits);
        crate::serial_puts(" (2^");
        crate::serial_dec(size_bits as u64);
        crate::serial_puts(")\n");

        ut_index += 1;
    }

    if ut_index == 0 {
        crate::serial_puts("[INIT] WARNING: no contiguous untyped region available\n");
    }

    crate::serial_puts("[INIT] Created ");
    crate::serial_dec(ut_index as u64);
    crate::serial_puts(" untyped capabilities\n");
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

    // Allocate and map a multi-page user stack
    for pg in 0..INIT_STACK_PAGES {
        let stack_phys = alloc_frame().expect("init: stack alloc failed");
        unsafe {
            core::ptr::write_bytes(phys_to_virt(stack_phys) as *mut u8, 0, PAGE_SIZE);
        }
        let stack_vaddr = INIT_STACK_VADDR + (pg as u64) * PAGE_SIZE as u64;
        vspace
            .map(stack_vaddr, stack_phys, PageFlags::USER_RW)
            .expect("init: stack map failed");
    }

    (result.entry, INIT_STACK_TOP)
}

/// Map initrd into user VSpace as read-only pages
///
/// Maps the physical initrd pages at INITRD_VADDR so userspace can parse
/// the CPIO archive to find and load additional binaries (console, procmgr).
fn map_initrd(info: &ParsedBootInfo, vspace: &mut VSpace) {
    let initrd_phys = info.initrd_addr;
    let initrd_size = info.initrd_size as usize;
    let num_pages = (initrd_size + PAGE_SIZE - 1) / PAGE_SIZE;

    crate::serial_puts("[INIT] Mapping initrd: phys=");
    crate::serial_hex(initrd_phys);
    crate::serial_puts(" size=");
    crate::serial_dec(initrd_size as u64);
    crate::serial_puts(" pages=");
    crate::serial_dec(num_pages as u64);
    crate::serial_puts(" -> vaddr=");
    crate::serial_hex(INITRD_VADDR);
    crate::serial_puts("\n");

    for i in 0..num_pages {
        let phys = initrd_phys + (i * PAGE_SIZE) as u64;
        let virt = INITRD_VADDR + (i * PAGE_SIZE) as u64;

        // Allocate a new frame and copy the initrd data into it, since the
        // original physical pages may not be frame-aligned or may overlap
        // with kernel-managed memory.
        let frame_phys = alloc_frame().expect("init: initrd frame alloc failed");
        let frame_virt = phys_to_virt(frame_phys) as *mut u8;
        let src = phys_to_virt(phys) as *const u8;
        let copy_len = if (i + 1) * PAGE_SIZE > initrd_size {
            initrd_size - i * PAGE_SIZE
        } else {
            PAGE_SIZE
        };
        unsafe {
            core::ptr::write_bytes(frame_virt, 0, PAGE_SIZE);
            core::ptr::copy_nonoverlapping(src, frame_virt, copy_len);
        }

        vspace
            .map(virt, frame_phys, PageFlags::USER_RO)
            .expect("init: initrd page map failed");
    }

    // Store initrd info in statics so we can pass to userspace via IPC buffer
    // or well-known memory location
    unsafe {
        INITRD_USER_VADDR = INITRD_VADDR;
        INITRD_USER_SIZE = initrd_size as u64;
    }

    crate::serial_puts("[INIT] Initrd mapped OK\n");
}

/// Initrd location in user VSpace (set by map_initrd, read by userspace)
static mut INITRD_USER_VADDR: u64 = 0;
static mut INITRD_USER_SIZE: u64 = 0;

/// Map a boot info page at BOOTINFO_VADDR containing initrd location
///
/// Layout (all u64, little-endian):
///   offset 0: magic (0x534C5459_424F4F54 = "SLTYBOOT")
///   offset 8: initrd virtual address
///   offset 16: initrd size in bytes
fn map_bootinfo(vspace: &mut VSpace) {
    let frame_phys = alloc_frame().expect("init: bootinfo frame alloc failed");
    let frame_virt = phys_to_virt(frame_phys) as *mut u8;
    unsafe {
        core::ptr::write_bytes(frame_virt, 0, PAGE_SIZE);
        let data = frame_virt as *mut u64;
        data.write(0x534C5459_424F4F54); // magic "SLTYBOOT"
        data.add(1).write(INITRD_USER_VADDR);
        data.add(2).write(INITRD_USER_SIZE);
    }
    vspace
        .map(BOOTINFO_VADDR, frame_phys, PageFlags::USER_RO)
        .expect("init: bootinfo map failed");

    crate::serial_puts("[INIT] Boot info page mapped at ");
    crate::serial_hex(BOOTINFO_VADDR);
    crate::serial_puts("\n");
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

    // Allocate and map a multi-page user stack
    for pg in 0..INIT_STACK_PAGES {
        let stack_phys = alloc_frame().expect("init: stack frame alloc failed");
        let stack_virt = phys_to_virt(stack_phys) as *mut u8;
        unsafe {
            core::ptr::write_bytes(stack_virt, 0, PAGE_SIZE);
        }
        let stack_vaddr = INIT_STACK_VADDR + (pg as u64) * PAGE_SIZE as u64;
        vspace
            .map(stack_vaddr, stack_phys, PageFlags::USER_RW)
            .expect("init: stack map failed");
    }

    (INIT_CODE_VADDR, INIT_STACK_TOP)
}
