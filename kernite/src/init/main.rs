//! Init Task Bootstrap
//!
//! Creates and dispatches the first user-mode task from kmain().
//!
//! Loads init from the initrd CPIO archive using the kernel ELF loader.
//! The initrd is required; there is no hardcoded user-mode fallback.
//!
//! Sets up the init task's CSpace with well-known capability slots for
//! TCB, VSpace, CSpace, and Untyped memory regions.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::IoPortRange;
use crate::cap::{
    CNode, CapRef, CapRights, Capability, KernelObject, ObjectType, UntypedMemory, alloc_slot,
    write_capability,
};
use crate::event::irq::IrqHandler;
use crate::init::bootinfo::{MemoryKind, ParsedBootInfo};
use crate::mm::vspace::PageFlags;
use crate::mm::{
    PAGE_SIZE, VSpace, frame::FrameOwner, frame::KernelMetaKind, phys_to_virt, pmm_alloc,
    pmm_alloc_contiguous, pmm_free_count, pmm_set_owner,
};
use crate::sched::thread::{SchedContext, Tcb};
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

/// Fatal boot error — prints message and halts.
/// Used instead of .expect() to avoid unwinding/panic infrastructure.
macro_rules! boot_fatal {
    ($msg:expr) => {{
        crate::kernel::panic::panic_now(
            format_args!("[INIT] FATAL: {}", $msg),
            Some(crate::kernel::panic::PanicLocation::new(
                file!(),
                line!(),
                column!(),
            )),
        )
    }};
}

/// Unwrap an Option during boot, halting with message on None.
macro_rules! boot_unwrap {
    ($opt:expr, $msg:expr) => {
        match $opt {
            Some(v) => v,
            None => boot_fatal!($msg),
        }
    };
}

/// User code virtual address (4 MB)
const INIT_CODE_VADDR: u64 = 0x0000_0040_0000;
/// User stack virtual address (8 MB)
const INIT_STACK_VADDR: u64 = 0x0000_0080_0000;
/// Init user stack size (pages).
///
/// PID1 now hosts the supervisor/control-plane logic, so the original tiny
/// bootstrap-only stack is not enough once unit orchestration is active.
const INIT_STACK_PAGES: usize = 64;
/// Init user stack size in bytes
const INIT_STACK_SIZE: u64 = INIT_STACK_PAGES as u64 * PAGE_SIZE as u64;
/// Top of user stack (stack grows down)
const INIT_STACK_TOP: u64 = INIT_STACK_VADDR + INIT_STACK_SIZE;
const INIT_IPC_BUFFER_VADDR: u64 = 0x0000_0000_0020_0000;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;

/// Well-known CSpace slot indices (must match userland/init/main.c)
const CAP_SELF_TCB: usize = 0;
const CAP_SELF_VSPACE: usize = 1;
const CAP_SELF_CSPACE: usize = 2;
const CAP_KERNEL_RNG: usize = 3;
const CAP_CLOCK: usize = 4;
const CAP_SYSTEM_CONTROL: usize = 5;
const CAP_SYSTEM_INFO: usize = 6;
const CAP_KERNEL_DEBUG: usize = 7;
/// PS/2 keyboard capabilities (x86 only)
#[cfg(target_arch = "x86_64")]
const CAP_KBD_IOPORT: usize = 22;
#[cfg(target_arch = "x86_64")]
const CAP_KBD_IRQ: usize = 23;
/// COM1 serial port capabilities
const CAP_COM1_IOPORT: usize = 20;
const CAP_COM1_IRQ: usize = 21;
/// Initrd device untyped capability (for map_device into child VSpaces)
const CAP_INITRD_UNTYPED: usize = 17;
/// Framebuffer device untyped
const CAP_FB_UNTYPED: usize = 18;
const CAP_UNTYPED_START: usize = 16;

/// Initrd mapping virtual address (16 MB)
const INITRD_VADDR: u64 = 0x0000_0100_0000;
/// Boot info page virtual address -- sits just below the IPC buffer (0x200000),
/// clear of the ELF code region (0x210000+) so large binaries cannot collide.
const BOOTINFO_VADDR: u64 = 0x0000_001F_F000;

/// Maximum number of untyped regions to hand to init
const MAX_INIT_UNTYPEDS: usize = 16;

/// Init's CNode size: 4096 slots (2^12) to accommodate initrd mapping
const INIT_CNODE_SIZE_BITS: u8 = 12;
const INIT_CNODE_SLOTS: usize = 1 << (INIT_CNODE_SIZE_BITS as usize);

/// Static backing for init's CNode: header + guard fields + 4096 CapRef slots.
/// Memory layout matches CNode header followed by guard and trailing slots.
#[repr(C, align(16))]
struct InitCNodeStorage {
    header: KernelObject,
    guard_bits: u8,
    _pad: [u8; 3],
    guard: u64,
    slots: [CapRef; INIT_CNODE_SLOTS],
}

/// Static storage for init task (never freed)
static mut INIT_TCB: Tcb = Tcb::new();
static mut INIT_SCHED_CTX: SchedContext = SchedContext::new();
static mut INIT_VSPACE: MaybeUninit<VSpace> = MaybeUninit::uninit();
/// Static VSpaceTracking for init's VSpace (bootstrap, not from untyped)
static mut INIT_VSPACE_TRACKING: crate::mm::VSpaceTracking = crate::mm::VSpaceTracking::new(0);
static mut INIT_CNODE_STORAGE: InitCNodeStorage = InitCNodeStorage {
    header: KernelObject::new(ObjectType::CNode, INIT_CNODE_SIZE_BITS),
    guard_bits: 0,
    _pad: [0; 3],
    guard: 0,
    slots: [CapRef::null(); INIT_CNODE_SLOTS],
};
static mut INIT_UNTYPEDS: [UntypedMemory; MAX_INIT_UNTYPEDS] = {
    const EMPTY: UntypedMemory = UntypedMemory::new(0, 0, false);
    [EMPTY; MAX_INIT_UNTYPEDS]
};
/// Number of init untyped regions actually created (set by create_untyped_caps).
static mut INIT_UNTYPED_COUNT: usize = 0;
static mut INIT_KERNEL_RNG: crate::cap::system::KernelRng = crate::cap::system::KernelRng::new();
static mut INIT_CLOCK: crate::cap::system::Clock = crate::cap::system::Clock::new();
static mut INIT_SYSTEM_CONTROL: crate::cap::system::SystemControl =
    crate::cap::system::SystemControl::new();
static mut INIT_SYSTEM_INFO: crate::cap::system::SystemInfo = crate::cap::system::SystemInfo::new();
static mut INIT_KERNEL_DEBUG: crate::cap::system::KernelDebug =
    crate::cap::system::KernelDebug::new();

/// COM1 serial port IoPort (x86 only — aarch64 uses PL011 device untyped)
#[cfg(target_arch = "x86_64")]
static mut INIT_COM1_IOPORT: IoPortRange = IoPortRange::new(0x3F8, 8);
/// COM1 IRQ handler (IRQ 4 on x86, INTID 33 on aarch64)
#[cfg(target_arch = "x86_64")]
static mut INIT_COM1_IRQ: IrqHandler = IrqHandler::new(4);

/// PL011 UART IRQ handler (INTID 33 = SPI 1 on QEMU virt)
#[cfg(target_arch = "aarch64")]
static mut INIT_PL011_IRQ: IrqHandler = IrqHandler::new(33);
/// PL011 UART device untyped (phys 0x0900_0000, 4 KiB)
#[cfg(target_arch = "aarch64")]
static mut INIT_PL011_UNTYPED: UntypedMemory = UntypedMemory::new(0x0900_0000, 12, true);
/// PCIe ECAM device untyped (phys 0x3f00_0000, 16 MiB for PCIe config space)
#[cfg(target_arch = "aarch64")]
static mut INIT_ECAM_UNTYPED: UntypedMemory = UntypedMemory::new(0x3f00_0000, 24, true);

/// PS/2 keyboard objects (x86 only — no PS/2 on aarch64)
#[cfg(target_arch = "x86_64")]
static mut INIT_KBD_IOPORT: IoPortRange = IoPortRange::new(0x60, 5); // ports 0x60-0x64
#[cfg(target_arch = "x86_64")]
static mut INIT_KBD_IRQ: IrqHandler = IrqHandler::new(1); // IRQ1

/// PCI config space I/O port (0xCF8..0xCFF, 8 ports for CONFIG_ADDRESS + CONFIG_DATA)
#[cfg(target_arch = "x86_64")]
static mut INIT_PCI_IOPORT: IoPortRange = IoPortRange::new(0xCF8, 8);
/// PCI config space well-known slot index (IoPort on x86_64, ECAM device untyped on aarch64)
const CAP_PCI_IOPORT: usize = 19;

/// DeviceControl capability for trusted device-discovery services to mint
/// IoPort, device-Untyped, and IRQ-handler caps.
static mut INIT_DEVICE_CONTROL: crate::cap::system::DeviceControl =
    crate::cap::system::DeviceControl::new();
/// DeviceControl well-known slot index.
const CAP_DEVICE_CONTROL: usize = 24;

/// Boot ExecAuthority — the sole cap authorizing `mo_mark_executable`, the only
/// path by which EXECUTE enters the system. PID1 confers EXECUTE on
/// borrowed-frames boot images with it, then MOVEs it to the code-loading
/// authority (`ldsrv`) once that service is up, so EXECUTE keeps a single origin.
static mut INIT_EXEC_AUTHORITY: crate::cap::system::ExecAuthority =
    crate::cap::system::ExecAuthority::new();
/// Boot ExecAuthority well-known slot index.
const CAP_EXEC_AUTHORITY: usize = 25;

/// Framebuffer device untyped (static, never freed)
static mut INIT_FB_UNTYPED: UntypedMemory = UntypedMemory::new(0, 0, true);
/// Initrd-backed pseudo-device untyped for zero-copy child initrd mapping
static mut INIT_INITRD_UNTYPED: UntypedMemory = UntypedMemory::new(0, 0, true);

/// Maximum number of dynamically-created device untypeds (for PCI BAR MMIO etc.)
const MAX_DEVICE_UNTYPEDS: usize = 16;
/// Pool of device untyped objects for runtime MMIO provisioning
static mut DEVICE_UNTYPED_POOL: [UntypedMemory; MAX_DEVICE_UNTYPEDS] = {
    const EMPTY: UntypedMemory = UntypedMemory::new(0, 0, true);
    [EMPTY; MAX_DEVICE_UNTYPEDS]
};
/// Next free index in the device untyped pool
static mut DEVICE_UNTYPED_NEXT: usize = 0;

/// Maximum number of dynamically-created IRQ handlers (for per-device IRQ routing).
/// Sized for shared IRQs: QEMU q35 assigns the same IRQ to multiple PCI devices,
/// so each device gets its own handler even when sharing an IRQ line.
const MAX_DYNAMIC_IRQ_HANDLERS: usize = 64;
/// Pool of IRQ handler objects for runtime provisioning
static mut DYNAMIC_IRQ_HANDLER_POOL: [IrqHandler; MAX_DYNAMIC_IRQ_HANDLERS] = {
    const EMPTY: IrqHandler = IrqHandler::new(0);
    [EMPTY; MAX_DYNAMIC_IRQ_HANDLERS]
};
/// Next free index in the dynamic IRQ handler pool
static mut DYNAMIC_IRQ_HANDLER_NEXT: usize = 0;

/// Maximum number of dynamically-created IoPort ranges (for PCI I/O BAR provisioning)
const MAX_DYNAMIC_IOPORTS: usize = 8;
/// Pool of IoPort range objects for runtime provisioning
static mut DYNAMIC_IOPORT_POOL: [IoPortRange; MAX_DYNAMIC_IOPORTS] = {
    const EMPTY: IoPortRange = IoPortRange::new(0, 0);
    [EMPTY; MAX_DYNAMIC_IOPORTS]
};
/// Next free index in the dynamic IoPort pool
static mut DYNAMIC_IOPORT_NEXT: usize = 0;
/// Exact byte limit (page-aligned) for initrd map_device exposure
static mut INITRD_DEVICE_LIMIT_BYTES: u64 = 0;
/// Pointer identity for the initrd pseudo-device untyped object
static mut INITRD_DEVICE_UT_PTR: *const UntypedMemory = core::ptr::null();

/// Exact byte limit (page-aligned) for framebuffer map_device exposure
static mut FB_DEVICE_LIMIT_BYTES: u64 = 0;
/// Pointer identity for the framebuffer device untyped object
static mut FB_DEVICE_UT_PTR: *const UntypedMemory = core::ptr::null();

/// Kernel entry point called from the bootloader.
///
/// The bootloader passes a pointer to a TLV-encoded BootInfo structure via RDI
/// on x86_64 or x0 on aarch64.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(raw_boot_info: *const u8) -> ! {
    crate::kernel::printk::serial_puts_raw("[ENTRY] ");
    crate::kernel::printk::serial_puts_raw("\nSaltyOS Kernel loaded\n");
    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[KMAIN] Entry addr: ");
        _g.hex(kmain as *const () as u64);
        _g.puts("\n[KMAIN] Boot info ptr: ");
        _g.hex(raw_boot_info as u64);
        _g.puts("\n");
    });

    let boot_info = unsafe { crate::init::bootinfo::parse(raw_boot_info) };

    if let Some(info) = boot_info {
        crate::kernel::printk::kinfo!(|_g| {
            _g.puts("[KMAIN] BootInfo parsed: ");
            _g.dec(info.memory_map_len as u64);
            _g.puts(" memory map entries\n");
        });
    } else {
        crate::kernel::printk::kwarn!(|_g| {
            _g.puts("[KMAIN] WARNING: Failed to parse BootInfo!\n");
        });
    }

    crate::arch::init(boot_info);
    crate::kernel::time::BOOT_TIME_NS.store(crate::arch::now_ns(), Ordering::Relaxed);

    if let Some(info) = boot_info {
        crate::console::init(&info.framebuffer);
    }

    crate::cap::init();
    crate::sched::init();
    crate::arch::start_timer();
    crate::arch::init_smp(boot_info);
    crate::arch::clear_boot_identity_map();

    bootstrap(boot_info);
    crate::sched::scheduler::scheduler().reschedule();

    loop {
        crate::arch::halt();
    }
}

/// Bootstrap the first user-mode init task
pub fn bootstrap(boot_info: Option<&ParsedBootInfo>) {
    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Creating user VSpace\n");
    });

    // Allocate PML4 for user VSpace
    let pml4_phys = boot_unwrap!(
        pmm_alloc(&FrameOwner::KernelPrivate {
            subkind: KernelMetaKind::General
        }),
        "PML4 alloc failed"
    );
    let pml4_virt = phys_to_virt(pml4_phys) as *mut u64;

    // Zero the PML4
    unsafe {
        core::ptr::write_bytes(pml4_virt, 0, PAGE_SIZE / 8);
    }

    // Copy kernel upper-half top-level entries so the kernel remains mapped
    // after switching into this address space.
    let kernel_cr3 = crate::mm::vspace::kernel_vspace_root();
    let kernel_pml4 = phys_to_virt(kernel_cr3) as *const u64;
    unsafe {
        for i in 256..512 {
            let entry = kernel_pml4.add(i).read();
            pml4_virt.add(i).write(entry);
        }
    }

    // Create VSpace from the new PML4 with static tracking (bootstrap, not from untyped)
    unsafe {
        let tracking = &raw mut INIT_VSPACE_TRACKING;
        (*tracking) = crate::mm::VSpaceTracking::new(pml4_phys);
    }
    let mut vspace = VSpace::new(pml4_phys, &raw mut INIT_VSPACE_TRACKING);

    // Initrd is required now that kernel fallback init is removed.
    let info = match boot_info {
        Some(info) => info,
        None => boot_fatal!("boot info missing; required initrd unavailable"),
    };
    if info.initrd_addr == 0 || info.initrd_size == 0 {
        boot_fatal!("initrd missing; required init unavailable");
    }

    // Load init program from initrd.
    let init_load = load_from_initrd(info, &mut vspace);
    let user_rip = init_load.entry;
    let user_stack_top = init_load.stack_top;

    // Map initrd + boot info into init address space.
    map_initrd(info, &mut vspace);
    map_bootinfo(&mut vspace, boot_info);
    map_init_ipc_buffer(&mut vspace);

    #[cfg(target_arch = "x86_64")]
    let tramp_stack_top = {
        // Allocate a kernel stack for the trampoline (used by context_switch → iretq)
        let tramp_stack_phys = boot_unwrap!(
            pmm_alloc(&FrameOwner::KernelPrivate {
                subkind: KernelMetaKind::KernelStack
            }),
            "trampoline stack alloc failed"
        );
        let tramp_stack_virt = phys_to_virt(tramp_stack_phys);
        let tramp_stack_top = tramp_stack_virt + PAGE_SIZE as u64;
        unsafe {
            core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, PAGE_SIZE);
        }
        tramp_stack_top
    };

    // Allocate per-thread kernel stack for syscall entry (4 pages = 16 KiB).
    // A single page (4 KiB) overflows on deep syscall paths.
    const KSTACK_PAGES: usize = 4;
    let kstack_phys = boot_unwrap!(
        pmm_alloc_contiguous(KSTACK_PAGES),
        "kernel stack alloc failed"
    );
    let kstack_owner = FrameOwner::KernelPrivate {
        subkind: KernelMetaKind::KernelStack,
    };
    for i in 0..KSTACK_PAGES {
        pmm_set_owner(kstack_phys + (i * PAGE_SIZE) as u64, &kstack_owner);
    }
    let kstack_virt = phys_to_virt(kstack_phys);
    let kstack_top = kstack_virt + (KSTACK_PAGES * PAGE_SIZE) as u64;
    unsafe {
        core::ptr::write_bytes(kstack_virt as *mut u8, 0, KSTACK_PAGES * PAGE_SIZE);
    }

    #[cfg(target_arch = "x86_64")]
    let vspace_root = vspace.root();

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] VSpace created, configuring TCB\n");
    });

    // Store VSpace in static so it isn't dropped
    unsafe {
        let vspace_ptr = (&raw mut INIT_VSPACE).cast::<MaybeUninit<VSpace>>();
        (*vspace_ptr).write(vspace);
        crate::mm::vspace::register_live_vspace((&raw mut INIT_VSPACE).cast::<VSpace>());
    }

    // Set up CSpace for init task
    setup_init_cspace(boot_info);
    patch_init_startup_boot_untyped(init_load.startup_block_phys);

    // Configure init TCB
    unsafe {
        let tcb = &raw mut INIT_TCB;
        let sc = &raw mut INIT_SCHED_CTX;

        (*tcb).ensure_trace_id();

        // Configure thread context for initial dispatch via context_switch.
        #[cfg(target_arch = "x86_64")]
        {
            // The trampoline function is entered via context_switch's `ret`.
            // It reads r12/r13/r14 and performs iretq to ring 3.
            (*tcb).context.rip = crate::arch::usermode_trampoline as *const () as u64;
            (*tcb).context.rsp = tramp_stack_top;
            (*tcb).context.r12 = user_rip; // User RIP
            (*tcb).context.r13 = user_stack_top; // User RSP
            (*tcb).context.r14 = vspace_root; // User CR3
            (*tcb).context.r15 = 0x0202; // User RFLAGS: IF=1, IOPL=0
            (*tcb).context.rflags = 0x202; // Kernel RFLAGS for context_switch
            (*tcb).debug_user_entry = user_rip;
        }
        #[cfg(target_arch = "aarch64")]
        {
            // First dispatch returns into the AArch64 usermode trampoline on
            // the thread's kernel stack; the trampoline then installs ELR,
            // SPSR, and SP_EL0 before `eret`.
            crate::arch::aarch64::context::init_user_thread_context(
                &mut (*tcb).context,
                kstack_top,
                user_rip,
                user_stack_top,
                0x0, // EL0t with IRQs unmasked
            );
            (*tcb).debug_user_entry = user_rip;
        }

        // SchedContext: 10ms budget, 100ms period
        let init_period_ns = 100_000_000;
        let init_budget_ns = 10_000_000;
        let init_deadline_ns = crate::arch::now_ns().saturating_add(init_period_ns);
        (*sc).budget = init_budget_ns;
        (*sc).period = init_period_ns;
        (*sc).remaining = init_budget_ns;
        (*sc).deadline = init_deadline_ns;
        (*sc).bound_tcb = tcb;

        (*tcb).cpu_affinity = 0;
        (*tcb).sched_context = sc;
        (*tcb).vspace_root = (&raw mut INIT_VSPACE).cast::<VSpace>();
        (*tcb).cspace_root = &raw mut INIT_CNODE_STORAGE as *mut CNode;
        (*tcb).kernel_stack_top = kstack_top;
        #[cfg(target_arch = "x86_64")]
        {
            (*tcb).trampoline_stack_top = tramp_stack_top;
        }
        (*tcb).stack_canary = crate::arch::generate_stack_canary();
        (*tcb).recompute_sched_key();

        // Seed %gs:32 with init's canary so the first syscall entry picks it up
        crate::arch::set_per_cpu_canary((*tcb).stack_canary);

        // Set per-CPU kernel stack to init's stack before first scheduling
        crate::arch::set_kernel_stack(kstack_top);
        crate::arch::set_tss_rsp0(kstack_top);

        // Enqueue the init task
        crate::sched::scheduler::scheduler().enqueue(tcb);
    }

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Init task enqueued, entering user mode at ");
        _g.hex(user_rip);
        _g.putc(b'\n');
    });
}

/// Compute ceil(log2(n)), returning the smallest k such that 2^k >= n.
fn ceil_log2(n: u64) -> u8 {
    if n <= 1 {
        return 0;
    }
    64 - (n - 1).leading_zeros() as u8
}

fn align_down_usize(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

unsafe fn write_u64(page: *mut u8, off: usize, value: u64) {
    unsafe {
        (page.add(off) as *mut u64).write(value);
    }
}

unsafe fn write_cap_entry(page: *mut u8, off: usize, role: u32, slot: u32) {
    unsafe {
        (page.add(off) as *mut u32).write(role);
        (page.add(off + 4) as *mut u32).write(slot);
        (page.add(off + 8) as *mut u32).write(0);
        (page.add(off + 12) as *mut u32).write(0);
    }
}

fn compose_init_startup_stack(
    result: &crate::init::elf::ElfLoadResult,
    top_page_phys: u64,
    boot_info: Option<&ParsedBootInfo>,
) -> (u64, u64) {
    let page = phys_to_virt(top_page_phys) as *mut u8;
    let page_base_va = INIT_STACK_TOP - PAGE_SIZE as u64;
    let mut cursor = PAGE_SIZE;

    let startup_size = core::mem::size_of::<uapi::SaltyOSStartupLayoutV1>();
    let cspace_size = core::mem::size_of::<uapi::SaltyOSCspaceLayoutV1>();
    const CAP_ENTRY_SIZE: usize = core::mem::size_of::<uapi::SaltyOSCapEntryV1>();
    const CAP_HEADER_SIZE: usize = 16;
    const MAX_CAP_ENTRIES: usize = 16;
    let cap_table_size = CAP_HEADER_SIZE + MAX_CAP_ENTRIES * CAP_ENTRY_SIZE;

    cursor = align_down_usize(cursor - startup_size, 8);
    let startup_off = cursor;
    let startup_va = page_base_va + startup_off as u64;
    cursor = align_down_usize(cursor - cap_table_size, 8);
    let cap_table_off = cursor;
    let cap_table_va = page_base_va + cap_table_off as u64;
    cursor = align_down_usize(cursor - cspace_size, 8);
    let cspace_off = cursor;
    let cspace_va = page_base_va + cspace_off as u64;

    unsafe {
        let layout = page.add(cspace_off) as *mut uapi::SaltyOSCspaceLayoutV1;
        layout.write(uapi::SaltyOSCspaceLayoutV1 {
            version: uapi::SALTYOS_CSPACE_LAYOUT_VERSION as u64,
            flags: 0,
            cnode_bits: INIT_CNODE_SIZE_BITS as u64,
            rtld_untyped_base: CAP_UNTYPED_START as u64,
            rtld_untyped_count: 1,
            rtld_untyped_size_bits: 0,
            frame_slot_base: 72,
            frame_slot_limit: INIT_CNODE_SLOTS as u64,
            alloc_base: 72,
            alloc_limit: INIT_CNODE_SLOTS as u64,
            recv_base: 0,
            recv_limit: 0,
            expand_base: 0,
            expand_limit: 0,
        });

        write_u64(page, cap_table_off, uapi::SALTYOS_CAP_TABLE_MAGIC as u64);
        write_u64(page, cap_table_off + 8, 0);
        let count_ptr = page.add(cap_table_off + 8) as *mut u32;
        let mut count = 0usize;
        macro_rules! cap {
            ($role:expr, $slot:expr) => {{
                write_cap_entry(
                    page,
                    cap_table_off + CAP_HEADER_SIZE + count * CAP_ENTRY_SIZE,
                    $role as u32,
                    $slot as u32,
                );
                count += 1;
            }};
        }
        (page.add(cap_table_off) as *mut u32).write(uapi::SALTYOS_CAP_TABLE_MAGIC as u32);
        (page.add(cap_table_off + 4) as *mut u32).write(uapi::SALTYOS_CAP_TABLE_VERSION as u32);
        cap!(uapi::SALTYOS_CAP_ROLE_KERNEL_RNG, CAP_KERNEL_RNG);
        cap!(uapi::SALTYOS_CAP_ROLE_CLOCK, CAP_CLOCK);
        cap!(uapi::SALTYOS_CAP_ROLE_SYSTEM_CONTROL, CAP_SYSTEM_CONTROL);
        cap!(uapi::SALTYOS_CAP_ROLE_SYSTEM_INFO, CAP_SYSTEM_INFO);
        cap!(uapi::SALTYOS_CAP_ROLE_KERNEL_DEBUG, CAP_KERNEL_DEBUG);
        cap!(uapi::SALTYOS_CAP_ROLE_INITRD_UNTYPED, CAP_INITRD_UNTYPED);
        cap!(uapi::SALTYOS_CAP_ROLE_FB_UNTYPED, CAP_FB_UNTYPED);
        cap!(uapi::SALTYOS_CAP_ROLE_PCI_IOPORT, CAP_PCI_IOPORT);
        cap!(uapi::SALTYOS_CAP_ROLE_COM1_IOPORT, CAP_COM1_IOPORT);
        cap!(uapi::SALTYOS_CAP_ROLE_COM1_IRQ, CAP_COM1_IRQ);
        #[cfg(target_arch = "x86_64")]
        {
            cap!(uapi::SALTYOS_CAP_ROLE_KBD_IOPORT, CAP_KBD_IOPORT);
            cap!(uapi::SALTYOS_CAP_ROLE_KBD_IRQ, CAP_KBD_IRQ);
        }
        cap!(uapi::SALTYOS_CAP_ROLE_DEVICE_CONTROL, CAP_DEVICE_CONTROL);
        count_ptr.write(count as u32);

        let mut startup: uapi::SaltyOSStartupLayoutV1 = core::mem::zeroed();
        startup.magic = uapi::SALTYOS_STARTUP_MAGIC as u32;
        startup.version = uapi::SALTYOS_STARTUP_VERSION as u32;
        startup.ipc_buffer_vaddr = INIT_IPC_BUFFER_VADDR;
        startup.cap_table_ptr = cap_table_va;
        startup.cspace_layout_ptr = cspace_va;
        startup.main_image.kind = uapi::SALTYOS_IMAGE_KIND_ELF as u32;
        startup.main_image.base = result.load_start;
        startup.main_image.size = result.load_end.saturating_sub(result.load_start);
        startup.main_image.entry = result.entry;
        if let Some(info) = boot_info {
            let fb = &info.framebuffer;
            if fb.addr != 0 && fb.width != 0 && fb.height != 0 && fb.pitch != 0 {
                startup.framebuffer = uapi::SaltyOSFramebufferInfoV1 {
                    phys_addr: fb.addr,
                    width: fb.width,
                    height: fb.height,
                    pitch: fb.pitch,
                    bpp: fb.bpp,
                    red_pos: fb.red_pos,
                    red_size: fb.red_size,
                    green_pos: fb.green_pos,
                    green_size: fb.green_size,
                    blue_pos: fb.blue_pos,
                    blue_size: fb.blue_size,
                    reserved: 0,
                };
            }
        }
        startup.mapped_image_count = 1;
        startup.mapped_images[0].image = startup.main_image;
        let name = b"/bin/init";
        startup.mapped_images[0].name_len = name.len() as u32;
        core::ptr::copy_nonoverlapping(
            name.as_ptr(),
            startup.mapped_images[0].name.as_mut_ptr(),
            name.len(),
        );
        (page.add(startup_off) as *mut uapi::SaltyOSStartupLayoutV1).write(startup);
    }

    let arg0 = b"/bin/init\0";
    cursor -= arg0.len();
    let arg0_off = cursor;
    unsafe {
        core::ptr::copy_nonoverlapping(arg0.as_ptr(), page.add(arg0_off), arg0.len());
    }
    let arg0_va = page_base_va + arg0_off as u64;

    let auxv = [
        (AT_PHDR, result.phdr),
        (AT_PHENT, result.phent),
        (AT_PHNUM, result.phnum),
        (AT_ENTRY, result.entry),
        (AT_BASE, 0),
        (AT_PAGESZ, PAGE_SIZE as u64),
        (uapi::AT_SALTYOS_STARTUP as u64, startup_va),
        (AT_NULL, 0),
    ];
    let word_count = 1 + 1 + 1 + 1 + auxv.len() * 2;
    cursor = align_down_usize(cursor - word_count * 8, 16);
    let child_sp = page_base_va + cursor as u64;
    unsafe {
        write_u64(page, cursor, 1);
        cursor += 8;
        write_u64(page, cursor, arg0_va);
        cursor += 8;
        write_u64(page, cursor, 0);
        cursor += 8;
        write_u64(page, cursor, 0);
        cursor += 8;
        for (tag, value) in auxv {
            write_u64(page, cursor, tag);
            write_u64(page, cursor + 8, value);
            cursor += 16;
        }
    }

    (child_sp, top_page_phys + startup_off as u64)
}

fn patch_init_startup_boot_untyped(startup_block_phys: u64) {
    let startup = phys_to_virt(startup_block_phys) as *mut uapi::SaltyOSStartupLayoutV1;
    unsafe {
        if (*startup).magic != uapi::SALTYOS_STARTUP_MAGIC as u32
            || (*startup).version != uapi::SALTYOS_STARTUP_VERSION as u32
        {
            boot_fatal!("init startup block corrupt");
        }
        let count = *(&raw const INIT_UNTYPED_COUNT);
        if count == 0 {
            return;
        }
        let ut = &raw const INIT_UNTYPEDS[0];
        let size_bytes = 1u64 << (*ut).size_bits;
        (*startup).boot_untyped_slot = CAP_UNTYPED_START as u64;
        (*startup).boot_untyped_size_bits = (*ut).size_bits as u64;
        (*startup).boot_untyped_size_bytes = size_bytes;
        (*startup).boot_untyped_available_bytes = size_bytes.saturating_sub((*ut).watermark);
    }
}

/// Set up init task's CSpace with well-known capabilities
fn setup_init_cspace(boot_info: Option<&ParsedBootInfo>) {
    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Setting up CSpace\n");
    });

    unsafe {
        let cnode = &mut *(&raw mut INIT_CNODE_STORAGE as *mut CNode);

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
            &raw mut INIT_CNODE_STORAGE as *mut crate::cap::KernelObject,
            ObjectType::CNode,
        );

        insert_static_cap(
            cnode,
            CAP_KERNEL_RNG,
            &raw mut INIT_KERNEL_RNG as *mut crate::cap::KernelObject,
            ObjectType::KernelRng,
        );
        insert_static_cap(
            cnode,
            CAP_CLOCK,
            &raw mut INIT_CLOCK as *mut crate::cap::KernelObject,
            ObjectType::Clock,
        );
        insert_static_cap(
            cnode,
            CAP_SYSTEM_CONTROL,
            &raw mut INIT_SYSTEM_CONTROL as *mut crate::cap::KernelObject,
            ObjectType::SystemControl,
        );
        insert_static_cap(
            cnode,
            CAP_SYSTEM_INFO,
            &raw mut INIT_SYSTEM_INFO as *mut crate::cap::KernelObject,
            ObjectType::SystemInfo,
        );
        insert_static_cap(
            cnode,
            CAP_KERNEL_DEBUG,
            &raw mut INIT_KERNEL_DEBUG as *mut crate::cap::KernelObject,
            ObjectType::KernelDebug,
        );
        // --- x86_64: I/O port capabilities ---
        #[cfg(target_arch = "x86_64")]
        {
            // Slot 20: COM1 IoPort capability (ports 0x3F8..0x3FF)
            insert_static_cap(
                cnode,
                CAP_COM1_IOPORT,
                &raw mut INIT_COM1_IOPORT as *mut crate::cap::KernelObject,
                ObjectType::IoPort,
            );

            // Slot 21: COM1 IRQ handler capability (IRQ 4)
            {
                let irq_ptr = &raw mut INIT_COM1_IRQ;
                insert_static_cap(
                    cnode,
                    CAP_COM1_IRQ,
                    irq_ptr as *mut crate::cap::KernelObject,
                    ObjectType::IrqHandler,
                );
                // Register in global IRQ table so hardware IRQ4 dispatches to it
                crate::event::irq::register_handler(4, irq_ptr);
            }

            // Slot 22: PS/2 Keyboard IoPort (ports 0x60-0x64)
            insert_static_cap(
                cnode,
                CAP_KBD_IOPORT,
                &raw mut INIT_KBD_IOPORT as *mut crate::cap::KernelObject,
                ObjectType::IoPort,
            );

            // Slot 23: PS/2 Keyboard IRQ handler (IRQ1)
            {
                let irq_ptr = &raw mut INIT_KBD_IRQ;
                insert_static_cap(
                    cnode,
                    CAP_KBD_IRQ,
                    irq_ptr as *mut crate::cap::KernelObject,
                    ObjectType::IrqHandler,
                );
                crate::event::irq::register_handler(1, irq_ptr);
            }

            // Slot 19: PCI config space IoPort (0xCF8..0xCFF, 8 ports)
            insert_static_cap(
                cnode,
                CAP_PCI_IOPORT,
                &raw mut INIT_PCI_IOPORT as *mut crate::cap::KernelObject,
                ObjectType::IoPort,
            );
        }

        // --- aarch64: MMIO device untypeds ---
        #[cfg(target_arch = "aarch64")]
        {
            // Slot 20: PL011 UART device untyped (phys 0x0900_0000, 4 KiB)
            // Reuses CAP_COM1_IOPORT slot — on aarch64 device MMIO is accessed
            // via device untypeds + frame mapping instead of I/O ports.
            insert_static_cap(
                cnode,
                CAP_COM1_IOPORT,
                &raw mut INIT_PL011_UNTYPED as *mut crate::cap::KernelObject,
                ObjectType::Untyped,
            );

            // Slot 21: PL011 UART IRQ handler (INTID 33 = SPI 1)
            //
            // PL011 uses level-triggered interrupts: the IRQ line stays
            // asserted as long as unread data sits in the RX FIFO.
            // dispatch_irq must mask the interrupt in the GIC after the
            // first delivery (acknowledged → false) to prevent an
            // interrupt storm that starves the console server.
            {
                let irq_ptr = &raw mut INIT_PL011_IRQ;
                (*irq_ptr).level_triggered = true;
                insert_static_cap(
                    cnode,
                    CAP_COM1_IRQ,
                    irq_ptr as *mut crate::cap::KernelObject,
                    ObjectType::IrqHandler,
                );
                // Register in global IRQ table so GIC INTID 33 dispatches to it
                crate::event::irq::register_handler(33, irq_ptr);
            }

            // Slot 19: PCI ECAM device untyped.
            // Discover the actual ECAM base address from ACPI MCFG table.
            // Falls back to the compile-time default (0x3f00_0000) if MCFG
            // is not present.
            if let Some(info) = boot_info {
                if let Some(ecam) = crate::firmware::acpi::parse_mcfg(info.rsdp_addr) {
                    let ut = &raw mut INIT_ECAM_UNTYPED;
                    (*ut).phys_addr = ecam.phys_addr;
                    (*ut).size_bits = ecam.size_bits;
                }
            }
            insert_static_cap(
                cnode,
                CAP_PCI_IOPORT,
                &raw mut INIT_ECAM_UNTYPED as *mut crate::cap::KernelObject,
                ObjectType::Untyped,
            );
        }

        // Slot 24: DeviceControl authority for dynamic device-cap creation.
        insert_static_cap(
            cnode,
            CAP_DEVICE_CONTROL,
            &raw mut INIT_DEVICE_CONTROL as *mut crate::cap::KernelObject,
            ObjectType::DeviceControl,
        );

        // Slot 25: boot ExecAuthority — the sole authority for
        // `mo_mark_executable`. CONFIGURE authorizes the privileged conferral;
        // GRANT + TRANSFER let PID1 hand it to ldsrv once that service is up. No
        // EXECUTE: the cap is an authority token, never a mappable object.
        insert_static_cap_with_rights(
            cnode,
            CAP_EXEC_AUTHORITY,
            &raw mut INIT_EXEC_AUTHORITY as *mut crate::cap::KernelObject,
            ObjectType::ExecAuthority,
            CapRights::READ | CapRights::CONFIGURE | CapRights::GRANT | CapRights::TRANSFER,
        );

        // Slot 17: Initrd pseudo-device untyped for map_device-based sharing
        if let Some(info) = boot_info {
            if info.initrd_addr != 0 && info.initrd_size != 0 {
                let size_bits =
                    ceil_log2(core::cmp::max(PAGE_SIZE as u64, info.initrd_size as u64));
                let initrd_ut = &raw mut INIT_INITRD_UNTYPED;
                (*initrd_ut) = UntypedMemory::new(info.initrd_addr, size_bits, true);
                INITRD_DEVICE_LIMIT_BYTES = ((info.initrd_size as u64 + PAGE_SIZE as u64 - 1)
                    / PAGE_SIZE as u64)
                    * PAGE_SIZE as u64;
                INITRD_DEVICE_UT_PTR = initrd_ut as *const UntypedMemory;

                insert_static_cap_with_rights(
                    cnode,
                    CAP_INITRD_UNTYPED,
                    initrd_ut as *mut crate::cap::KernelObject,
                    ObjectType::Untyped,
                    // No EXECUTE: the initrd is borrowed as code via the
                    // exec-conferring path (mo_mark_executable), never mapped
                    // executable directly from this cap.
                    CapRights::READ | CapRights::GRANT,
                );

                crate::kernel::printk::kdebug!(init, |_g| {
                    _g.puts("[INIT] Initrd: device untyped phys=");
                    _g.hex(info.initrd_addr);
                    _g.puts(" size=2^");
                    _g.dec(size_bits as u64);
                    _g.putc(b'\n');
                });
            }
        }

        // Slot 18: Framebuffer device untyped (if framebuffer is available)
        if let Some(info) = boot_info {
            let fb = &info.framebuffer;
            if fb.addr != 0 && fb.pitch > 0 && fb.height > 0 {
                let fb_size = fb.height as u64 * fb.pitch as u64;
                let size_bits = ceil_log2(fb_size);

                let fb_ut = &raw mut INIT_FB_UNTYPED;
                (*fb_ut) = UntypedMemory::new(fb.addr, size_bits, true);

                FB_DEVICE_LIMIT_BYTES =
                    ((fb_size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) * PAGE_SIZE as u64;
                FB_DEVICE_UT_PTR = fb_ut as *const UntypedMemory;

                insert_static_cap(
                    cnode,
                    CAP_FB_UNTYPED,
                    fb_ut as *mut crate::cap::KernelObject,
                    ObjectType::Untyped,
                );

                crate::kernel::printk::kdebug!(init, |_g| {
                    _g.puts("[INIT] Framebuffer: device untyped phys=");
                    _g.hex(fb.addr);
                    _g.puts(" size=2^");
                    _g.dec(size_bits as u64);
                    _g.putc(b'\n');
                });
            }
        }

        // Slot 16 is the primary boot untyped; extra root untypeds live
        // above init's fixed startup window so hardware slots 17..24
        // remain stable.
        if let Some(info) = boot_info {
            create_untyped_caps(cnode, info);
        }
    }

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] CSpace setup complete\n");
    });
}

/// Insert a capability for a statically-allocated kernel object into a CNode
unsafe fn insert_static_cap(
    cnode: &mut CNode,
    cnode_index: usize,
    object: *mut crate::cap::KernelObject,
    obj_type: ObjectType,
) {
    unsafe {
        // Kernel-minted egress caps never confer EXECUTE: executable memory
        // enters the system only via the exec-authority (mo_mark_executable).
        insert_static_cap_with_rights(
            cnode,
            cnode_index,
            object,
            obj_type,
            CapRights::ALL.without(CapRights::EXECUTE),
        );
    }
}

/// Insert a capability for a statically-allocated kernel object with explicit rights.
unsafe fn insert_static_cap_with_rights(
    cnode: &mut CNode,
    cnode_index: usize,
    object: *mut crate::cap::KernelObject,
    obj_type: ObjectType,
    rights: CapRights,
) {
    let slot = boot_unwrap!(alloc_slot(), "cap slot alloc failed");
    let mut cap = Capability::null();
    cap.object = object;
    cap.obj_type = obj_type;
    cap.rights = rights;
    cap.depth = 0;
    cap.badge = 0;
    write_capability(slot, cap);
    cnode
        .insert_ref(cnode_index, CapRef::new(slot))
        .unwrap_or_else(|_| boot_fatal!("CNode insert failed"));
}

/// If `obj` is the initrd pseudo-device untyped, returns its exact map limit bytes.
pub fn initrd_device_limit_for(obj: *const UntypedMemory) -> Option<u64> {
    unsafe {
        let tracked = INITRD_DEVICE_UT_PTR;
        if tracked.is_null() || obj != tracked {
            None
        } else {
            Some(INITRD_DEVICE_LIMIT_BYTES)
        }
    }
}

/// Allocate a device untyped from the static pool for MMIO provisioning.
///
/// Returns a pointer to the initialized UntypedMemory, or None if pool is full.
pub fn alloc_device_untyped(phys_addr: u64, size_bits: u8) -> Option<*mut UntypedMemory> {
    unsafe {
        let idx = DEVICE_UNTYPED_NEXT;
        if idx >= MAX_DEVICE_UNTYPEDS {
            return None;
        }
        DEVICE_UNTYPED_NEXT = idx + 1;
        let ut = &raw mut DEVICE_UNTYPED_POOL[idx];
        (*ut) = UntypedMemory::new(phys_addr, size_bits, true);
        Some(ut)
    }
}

/// Allocate an IoPort range from the static pool for runtime provisioning.
///
/// Returns a pointer to the initialized IoPortRange, or None if pool is full.
pub fn alloc_dynamic_ioport(base_port: u16, num_ports: u16) -> Option<*mut IoPortRange> {
    unsafe {
        let idx = DYNAMIC_IOPORT_NEXT;
        if idx >= MAX_DYNAMIC_IOPORTS {
            return None;
        }
        DYNAMIC_IOPORT_NEXT = idx + 1;
        let iop = &raw mut DYNAMIC_IOPORT_POOL[idx];
        (*iop) = IoPortRange::new(base_port, num_ports);
        Some(iop)
    }
}

/// Allocate an IrqHandler from the static pool for runtime provisioning.
///
/// Returns a pointer to the initialized IrqHandler, or None if pool is full.
pub fn alloc_dynamic_irq_handler(irq_num: u32) -> Option<*mut IrqHandler> {
    unsafe {
        let idx = DYNAMIC_IRQ_HANDLER_NEXT;
        if idx >= MAX_DYNAMIC_IRQ_HANDLERS {
            return None;
        }
        DYNAMIC_IRQ_HANDLER_NEXT = idx + 1;
        let handler = &raw mut DYNAMIC_IRQ_HANDLER_POOL[idx];
        (*handler) = IrqHandler::new(irq_num);
        Some(handler)
    }
}

/// If `obj` is the framebuffer device untyped, returns its exact map limit bytes.
pub fn fb_device_limit_for(obj: *const UntypedMemory) -> Option<u64> {
    unsafe {
        let tracked = FB_DEVICE_UT_PTR;
        if tracked.is_null() || obj != tracked {
            None
        } else {
            Some(FB_DEVICE_LIMIT_BYTES)
        }
    }
}

/// Find the init untyped that contains `phys`.
///
/// Searches the static `INIT_UNTYPEDS` array for a region whose
/// `[phys_addr, phys_addr + size_bytes)` range covers `phys`.
/// Returns a raw pointer to the UntypedMemory, or null if not found.
///
/// # Safety
/// The returned pointer is valid for the system lifetime (static storage).
/// Caller must acquire `ut.alloc_lock` before mutating allocator state.
///
/// Lookup precedence:
/// 1. **PMM frame metadata.** Live MO pages committed from untyped are
///    owned as `MoData` and carry their exact source in `source_ut`.
///    Carvable untyped ranges and live untyped objects use
///    `UntypedReserved { ut }`, where `ut` may be a child untyped rather
///    than a root. Both cases return the immediate source, not merely
///    the covering init untyped.
/// 2. **`INIT_UNTYPEDS` linear scan.** Fallback for phys ranges not
///    PMM-tracked or whose owner is not `UntypedReserved` (e.g. device
///    untypeds; pages still inside a typed object but whose typed cap
///    was revoked-then-reclaimed without going through PMM transition).
pub fn find_untyped_for_phys(phys: u64) -> *mut UntypedMemory {
    unsafe {
        if let Some(meta) = crate::mm::pmm_lookup(phys) {
            if meta.source_ut != 0 {
                return meta.source_ut as *mut UntypedMemory;
            }
            if let crate::mm::frame::FrameOwner::UntypedReserved { ut } = meta.to_owner() {
                if !ut.is_null() {
                    return ut as *mut UntypedMemory;
                }
            }
        }
        let count = *(&raw const INIT_UNTYPED_COUNT);
        for i in 0..count {
            let ut = &raw mut INIT_UNTYPEDS[i];
            let base = (*ut).phys_addr;
            let size = (*ut).size_bytes() as u64;
            if phys >= base && phys < base + size {
                return ut;
            }
        }
    }
    core::ptr::null_mut()
}

/// Create untyped memory capabilities from boot info memory map
unsafe fn create_untyped_caps(cnode: &mut CNode, _info: &ParsedBootInfo) {
    // Allocate backing memory from the frame allocator so untyped regions
    // do not overlap frames already in use by the kernel.
    const MAX_SIZE_BITS: u8 = 38; // 256 GiB
    const MIN_SIZE_BITS: u8 = 12; // 4 KiB
    const NORMAL_MIN_KERNEL_RESERVE_FRAMES: usize = 1024; // 4 MiB
    const LOWMEM_ABS_RESERVE_FRAMES: usize = 16; // 64 KiB reserved for kernel runtime allocations
    const LOWMEM_THRESHOLD_FRAMES: usize = 2048; // 8 MiB

    const INIT_BOOT_UNTYPED_COUNT: usize = 1;
    let mut ut_index = 0;
    let mut free_frames = pmm_free_count();
    let reserve_frames = if free_frames <= LOWMEM_THRESHOLD_FRAMES {
        core::cmp::max(LOWMEM_ABS_RESERVE_FRAMES, free_frames / 16)
    } else {
        core::cmp::max(NORMAL_MIN_KERNEL_RESERVE_FRAMES, free_frames / 8)
    };

    crate::kernel::printk::kdebug!(init, |_g| {
        _g.puts("[INIT] Untyped reserve frames: ");
        _g.dec(reserve_frames as u64);
        _g.puts(" (free=");
        _g.dec(free_frames as u64);
        _g.puts(")\n");
    });

    // At lowmem, start from 1MB instead of 256MB to avoid wasting
    // iteration and to produce multiple smaller regions for flexibility.
    let start_bits = if free_frames <= LOWMEM_THRESHOLD_FRAMES {
        if MAX_SIZE_BITS > 20 {
            20
        } else {
            MAX_SIZE_BITS
        }
    } else {
        MAX_SIZE_BITS
    };

    'size_loop: for size_bits in (MIN_SIZE_BITS..=start_bits).rev() {
        let size_bytes = 1usize << size_bits;
        let frame_count = size_bytes / PAGE_SIZE;

        // Allocate as many regions as possible at this size before moving
        // to smaller chunks. This maximizes exposed untyped memory while
        // still preferring larger blocks first.
        while ut_index < INIT_BOOT_UNTYPED_COUNT {
            // Keep a reserve for kernel page-table growth and runtime mappings.
            if free_frames <= reserve_frames {
                break 'size_loop;
            }
            if frame_count > free_frames.saturating_sub(reserve_frames) {
                break;
            }

            let Some(base) = pmm_alloc_contiguous(frame_count) else {
                break;
            };
            free_frames = free_frames.saturating_sub(frame_count);

            // Initialize the UntypedMemory object in static storage
            let ut = unsafe { &raw mut INIT_UNTYPEDS[ut_index] };
            unsafe {
                (*ut) = UntypedMemory::new(base, size_bits, false);
            }

            // Transition every covered frame from the PMM free pool to
            // `UntypedReserved` with the back-pointer set to the static
            // storage slot. This establishes the PMM/untyped disjointness
            // invariant for the root untyped: `pmm_alloc` no longer draws
            // from this range; `retype` is the sole gateway.
            unsafe {
                (*ut).reserve_range(ut as *const UntypedMemory);
            }

            // Allocate a global cap slot and populate it
            let slot = boot_unwrap!(alloc_slot(), "untyped cap slot alloc failed");
            let mut cap = Capability::null();
            cap.object = ut as *mut crate::cap::KernelObject;
            cap.obj_type = ObjectType::Untyped;
            cap.rights = CapRights::ALL.without(CapRights::EXECUTE);
            cap.depth = 0;
            cap.badge = 0;
            write_capability(slot, cap);

            let cnode_slot = CAP_UNTYPED_START;
            cnode
                .insert_ref(cnode_slot, CapRef::new(slot))
                .unwrap_or_else(|_| boot_fatal!("untyped CNode insert failed"));

            crate::kernel::printk::kdebug!(init, |_g| {
                _g.puts("[INIT]   Untyped ");
                _g.dec(ut_index as u64);
                _g.puts(": phys=");
                _g.hex(base);
                _g.puts(" size=");
                _g.hex(1u64 << size_bits);
                _g.puts(" (2^");
                _g.dec(size_bits as u64);
                _g.puts(")\n");
            });

            ut_index += 1;
        }
    }

    // Low-memory fallback: ensure init gets at least one small untyped.
    if ut_index == 0 && free_frames > LOWMEM_ABS_RESERVE_FRAMES {
        if let Some(base) = pmm_alloc_contiguous(1) {
            let ut = unsafe { &raw mut INIT_UNTYPEDS[ut_index] };
            unsafe {
                (*ut) = UntypedMemory::new(base, MIN_SIZE_BITS, false);
                (*ut).reserve_range(ut as *const UntypedMemory);
            }

            let slot = boot_unwrap!(alloc_slot(), "fallback untyped cap slot alloc failed");
            let mut cap = Capability::null();
            cap.object = ut as *mut crate::cap::KernelObject;
            cap.obj_type = ObjectType::Untyped;
            cap.rights = CapRights::ALL.without(CapRights::EXECUTE);
            cap.depth = 0;
            cap.badge = 0;
            write_capability(slot, cap);

            cnode
                .insert_ref(CAP_UNTYPED_START, CapRef::new(slot))
                .unwrap_or_else(|_| boot_fatal!("fallback untyped CNode insert failed"));

            crate::kernel::printk::kdebug!(init, |_g| {
                _g.puts("[INIT]   Untyped fallback: phys=");
                _g.hex(base);
                _g.puts(" size=0x1000\n");
            });
            ut_index += 1;
        }
    }

    if ut_index == 0 {
        crate::kernel::printk::kerror!(|_g| {
            _g.puts("[INIT] WARNING: no contiguous untyped region available\n");
        });
    }

    // Store the count for find_untyped_for_phys
    // SAFETY: Single-threaded init, no concurrent access yet.
    unsafe {
        *(&raw mut INIT_UNTYPED_COUNT) = ut_index;
    }

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Created ");
        _g.dec(ut_index as u64);
        _g.puts(" untyped capabilities\n");
    });
}

struct InitLoad {
    entry: u64,
    stack_top: u64,
    startup_block_phys: u64,
}

/// Load init from CPIO initrd using the kernel ELF loader
fn load_from_initrd(info: &ParsedBootInfo, vspace: &mut VSpace) -> InitLoad {
    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Parsing CPIO initrd\n");
    });

    let initrd = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(info.initrd_addr) as *const u8,
            info.initrd_size as usize,
        )
    };

    let elf_entry = crate::init::cpio::find_file(initrd, "/bin/init");
    let elf_data = match elf_entry {
        Some(entry) => {
            crate::kernel::printk::kinfo!(|_g| {
                _g.puts("[INIT] Found init in initrd (");
                _g.dec(entry.data.len() as u64);
                _g.puts(" bytes)\n");
            });
            entry.data
        }
        None => boot_fatal!("init not found in initrd"),
    };

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Loading ELF from initrd\n");
    });
    let result = match crate::init::elf::load_elf(elf_data, vspace, INIT_CODE_VADDR) {
        Ok(r) => r,
        Err(e) => {
            crate::kernel::printk::kerror!(|_g| {
                _g.puts("[INIT] FATAL: ELF load failed: ");
                match e {
                    crate::init::elf::ElfError::NotElf => _g.puts("not ELF"),
                    crate::init::elf::ElfError::Not64Bit => _g.puts("not 64-bit"),
                    crate::init::elf::ElfError::NotLittleEndian => _g.puts("not LE"),
                    crate::init::elf::ElfError::BadType => _g.puts("bad type"),
                    crate::init::elf::ElfError::BadArch => _g.puts("bad arch"),
                    crate::init::elf::ElfError::NoLoadSegment => _g.puts("no LOAD"),
                    crate::init::elf::ElfError::RelocFailed => _g.puts("reloc failed"),
                    crate::init::elf::ElfError::OutOfMemory => _g.puts("OOM"),
                    crate::init::elf::ElfError::TooSmall => _g.puts("too small"),
                    crate::init::elf::ElfError::MapFailed => _g.puts("map failed"),
                }
                _g.puts("\n");
            });
            boot_fatal!("init ELF load failed");
        }
    };

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] ELF loaded: entry=");
        _g.hex(result.entry);
        _g.puts(" base=");
        _g.hex(result.base);
        _g.puts(" brk=");
        _g.hex(result.brk);
        _g.putc(b'\n');
    });

    // Allocate and map a multi-page user stack
    let mut top_page_phys = 0;
    for pg in 0..INIT_STACK_PAGES {
        let stack_phys = boot_unwrap!(
            pmm_alloc(&FrameOwner::KernelPrivate {
                subkind: KernelMetaKind::General
            }),
            "stack alloc failed"
        );
        unsafe {
            core::ptr::write_bytes(phys_to_virt(stack_phys) as *mut u8, 0, PAGE_SIZE);
        }
        let stack_vaddr = INIT_STACK_VADDR + (pg as u64) * PAGE_SIZE as u64;
        vspace
            .map(stack_vaddr, stack_phys, PageFlags::USER_RW)
            .unwrap_or_else(|_| boot_fatal!("stack map failed"));
        if pg + 1 == INIT_STACK_PAGES {
            top_page_phys = stack_phys;
        }
    }

    let (child_sp, startup_block_phys) =
        compose_init_startup_stack(&result, top_page_phys, Some(info));
    InitLoad {
        entry: result.entry,
        stack_top: child_sp,
        startup_block_phys,
    }
}

/// Map initrd into user VSpace as read-only pages
///
/// Maps the physical initrd pages at INITRD_VADDR so userspace can parse
/// the CPIO archive to find and load additional binaries (console, procmgr).
fn map_initrd(info: &ParsedBootInfo, vspace: &mut VSpace) {
    let initrd_phys = info.initrd_addr;
    let initrd_size = info.initrd_size as usize;
    let num_pages = (initrd_size + PAGE_SIZE - 1) / PAGE_SIZE;
    let direct_map_ok = (initrd_phys & (PAGE_SIZE as u64 - 1)) == 0;

    crate::kernel::printk::kdebug!(init, |_g| {
        _g.puts("[INIT] Mapping initrd: phys=");
        _g.hex(initrd_phys);
        _g.puts(" size=");
        _g.dec(initrd_size as u64);
        _g.puts(" pages=");
        _g.dec(num_pages as u64);
        _g.puts(" -> vaddr=");
        _g.hex(INITRD_VADDR);
        _g.puts(" mode=");
        if direct_map_ok {
            _g.puts("direct");
        } else {
            _g.puts("copy");
        }
        _g.putc(b'\n');
    });

    for i in 0..num_pages {
        let phys = initrd_phys + (i * PAGE_SIZE) as u64;
        let virt = INITRD_VADDR + (i * PAGE_SIZE) as u64;

        let map_phys = if direct_map_ok {
            phys
        } else {
            // Fallback path for non-page-aligned bootloader initrd.
            let frame_phys = boot_unwrap!(
                pmm_alloc(&FrameOwner::KernelPrivate {
                    subkind: KernelMetaKind::General
                }),
                "initrd frame alloc failed"
            );
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
            frame_phys
        };

        vspace
            .map(virt, map_phys, PageFlags::USER_RO)
            .unwrap_or_else(|_| boot_fatal!("initrd page map failed"));

        // Publish the page to the point of coherency so the EL0 USER_RO
        // mapping observes the bytes written through the kernel alias
        // (UEFI on the direct path, the copy on the fallback). Without it
        // init's CPIO walk can read stale data and miss every binary.
        crate::arch::publish_page_table_page(map_phys);
    }

    // Store initrd info in statics so we can pass to userspace via IPC buffer
    // or well-known memory location
    unsafe {
        INITRD_USER_VADDR = INITRD_VADDR;
        INITRD_USER_SIZE = initrd_size as u64;
    }

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Initrd mapped OK\n");
    });
}

/// Map PID1's initial IPC buffer at the VA published in
/// `SaltyOSStartupLayoutV1`. The runtime installs this VA into
/// `KERNITE_CAP_SELF_TCB`; kernel syscalls such as `EQ_WAIT` then
/// copy extended results through the current task's user VSpace.
fn map_init_ipc_buffer(vspace: &mut VSpace) {
    let frame_phys = boot_unwrap!(
        pmm_alloc(&FrameOwner::KernelPrivate {
            subkind: KernelMetaKind::General
        }),
        "init ipc buffer frame alloc failed"
    );
    unsafe {
        core::ptr::write_bytes(phys_to_virt(frame_phys) as *mut u8, 0, PAGE_SIZE);
    }
    vspace
        .map(INIT_IPC_BUFFER_VADDR, frame_phys, PageFlags::USER_RW)
        .unwrap_or_else(|_| boot_fatal!("init ipc buffer map failed"));
}

/// Initrd location in user VSpace (set by map_initrd, read by userspace)
static mut INITRD_USER_VADDR: u64 = 0;
static mut INITRD_USER_SIZE: u64 = 0;

/// Convert kernel-internal `MemoryKind` to UAPI `KERNITE_MEM_KIND_*`.
///
/// The kernel-side enum's discriminants come from the bootloader TLV
/// schema and don't line up with the UAPI numbering, so this match
/// runs once per memory-map entry when emitting the user-visible
/// bootinfo. The mapping is loss-tolerant — `BadMemory` and `BootInfo`
/// fold into `RESERVED` because userland has no use for the
/// distinction.
fn memory_kind_to_uapi(kind: MemoryKind) -> u32 {
    match kind {
        MemoryKind::Usable => uapi::KERNITE_MEM_KIND_USABLE,
        MemoryKind::Reserved => uapi::KERNITE_MEM_KIND_RESERVED,
        MemoryKind::AcpiReclaimable => uapi::KERNITE_MEM_KIND_ACPI_RECLAIM,
        MemoryKind::AcpiNvs => uapi::KERNITE_MEM_KIND_ACPI_NVS,
        MemoryKind::BadMemory => uapi::KERNITE_MEM_KIND_RESERVED,
        MemoryKind::Bootloader => uapi::KERNITE_MEM_KIND_BOOTLOADER,
        MemoryKind::Kernel => uapi::KERNITE_MEM_KIND_KERNEL,
        MemoryKind::Initrd => uapi::KERNITE_MEM_KIND_INITRD,
        MemoryKind::BootInfo => uapi::KERNITE_MEM_KIND_RESERVED,
    }
}

/// Write a TLV record at `*cursor` with the given tag and a
/// fixed-size payload. Advances `*cursor` past the record (header +
/// payload + 8-byte alignment padding). Returns `false` if the
/// record would overflow the bounded page; the caller silently
/// drops over-budget records (the page is bounded at 4 KiB and we
/// never approach that limit in practice).
///
/// # Safety
/// `*cursor` and `end` must be valid pointers into the same bootinfo
/// frame; the frame must be page-aligned and at least one page large.
unsafe fn write_tlv<T: Copy>(cursor: &mut *mut u8, end: *mut u8, tag: u16, payload: &T) -> bool {
    let hdr_size = core::mem::size_of::<uapi::kernite_bootinfo_tlv>();
    let payload_size = core::mem::size_of::<T>();
    let total = (hdr_size + payload_size + 7) & !7;
    // Always leave room for the trailing TAG_END terminator so the
    // closing `write_tlv_end` call cannot land past the page.
    let end_terminator = (hdr_size + 7) & !7;
    if unsafe { (*cursor).add(total + end_terminator) } > end {
        return false;
    }
    unsafe {
        let hdr = *cursor as *mut uapi::kernite_bootinfo_tlv;
        (*hdr).tag = tag;
        (*hdr).reserved = 0;
        (*hdr).length = payload_size as u32;
        let payload_ptr = (*cursor).add(hdr_size) as *mut T;
        core::ptr::write_unaligned(payload_ptr, *payload);
        *cursor = (*cursor).add(total);
    }
    true
}

/// Write the `TAG_END` terminator at `cursor`. The frame is zero-
/// filled at allocation so no further writes are necessary; this
/// exists to make the emit sequence read top-to-bottom.
///
/// # Safety
/// `cursor` must point to at least
/// `sizeof(struct kernite_bootinfo_tlv)` bytes inside the bootinfo
/// frame.
unsafe fn write_tlv_end(cursor: *mut u8) {
    unsafe {
        let hdr = cursor as *mut uapi::kernite_bootinfo_tlv;
        (*hdr).tag = uapi::KERNITE_BOOTINFO_TAG_END as u16;
        (*hdr).reserved = 0;
        (*hdr).length = 0;
    }
}

/// Map a boot info page at `BOOTINFO_VADDR` carrying TLV-encoded
/// boot metadata for userland. Format defined in
/// `kernite/include/uapi/boot.h`: the page starts with
/// `KERNITE_BOOTINFO_MAGIC` at offset 0, followed by a stream of
/// TLV records terminated by `KERNITE_BOOTINFO_TAG_END`.
fn map_bootinfo(vspace: &mut VSpace, boot_info: Option<&ParsedBootInfo>) {
    let frame_phys = boot_unwrap!(
        pmm_alloc(&FrameOwner::KernelPrivate {
            subkind: KernelMetaKind::General
        }),
        "bootinfo frame alloc failed"
    );
    let frame_virt = phys_to_virt(frame_phys) as *mut u8;
    unsafe {
        core::ptr::write_bytes(frame_virt, 0, PAGE_SIZE);

        // Magic at page start.
        (frame_virt as *mut u64).write(uapi::KERNITE_BOOTINFO_MAGIC);
        let mut cursor = frame_virt.add(8);
        let end = frame_virt.add(PAGE_SIZE);

        if INITRD_USER_VADDR != 0 {
            let payload = uapi::kernite_bootinfo_initrd {
                user_va: INITRD_USER_VADDR,
                length: INITRD_USER_SIZE,
            };
            let _ = write_tlv(
                &mut cursor,
                end,
                uapi::KERNITE_BOOTINFO_TAG_INITRD as u16,
                &payload,
            );
        }

        if let Some(info) = boot_info {
            let fb = &info.framebuffer;
            if fb.addr != 0 {
                let payload = uapi::kernite_bootinfo_framebuffer {
                    phys_addr: fb.addr,
                    width: fb.width,
                    height: fb.height,
                    pitch: fb.pitch,
                    bpp: fb.bpp,
                    red_pos: fb.red_pos,
                    red_size: fb.red_size,
                    green_pos: fb.green_pos,
                    green_size: fb.green_size,
                    blue_pos: fb.blue_pos,
                    blue_size: fb.blue_size,
                    reserved: 0,
                };
                let _ = write_tlv(
                    &mut cursor,
                    end,
                    uapi::KERNITE_BOOTINFO_TAG_FRAMEBUFFER as u16,
                    &payload,
                );
            }

            if info.memory_map_len > 0 {
                let entry_size = core::mem::size_of::<uapi::kernite_bootinfo_memory_entry>();
                let payload_size = info.memory_map_len * entry_size;
                let hdr_size = core::mem::size_of::<uapi::kernite_bootinfo_tlv>();
                let total = (hdr_size + payload_size + 7) & !7;
                // Reserve trailing TAG_END terminator space (same
                // contract as `write_tlv`'s bounds check).
                let end_terminator = (hdr_size + 7) & !7;
                if cursor.add(total + end_terminator) <= end {
                    let hdr = cursor as *mut uapi::kernite_bootinfo_tlv;
                    (*hdr).tag = uapi::KERNITE_BOOTINFO_TAG_MEMORY_MAP as u16;
                    (*hdr).reserved = 0;
                    (*hdr).length = payload_size as u32;
                    let entries_ptr =
                        cursor.add(hdr_size) as *mut uapi::kernite_bootinfo_memory_entry;
                    for i in 0..info.memory_map_len {
                        let src = info.memory_map[i];
                        let entry = uapi::kernite_bootinfo_memory_entry {
                            base: src.base,
                            length: src.length,
                            kind: memory_kind_to_uapi(src.kind),
                            reserved: 0,
                        };
                        core::ptr::write_unaligned(entries_ptr.add(i), entry);
                    }
                    cursor = cursor.add(total);
                }
            }

            if info.rsdp_addr != 0 {
                let payload = uapi::kernite_bootinfo_rsdp {
                    rsdp_addr: info.rsdp_addr,
                    revision: 0,
                    reserved: [0; 7],
                };
                let _ = write_tlv(
                    &mut cursor,
                    end,
                    uapi::KERNITE_BOOTINFO_TAG_RSDP as u16,
                    &payload,
                );
            }

            if info.kernel_phys_base != 0 || info.kernel_virt_base != 0 {
                let payload = uapi::kernite_bootinfo_kernel_base {
                    phys_base: info.kernel_phys_base,
                    virt_base: info.kernel_virt_base,
                    size: info.kernel_size,
                    entry_point: 0,
                };
                let _ = write_tlv(
                    &mut cursor,
                    end,
                    uapi::KERNITE_BOOTINFO_TAG_KERNEL_BASE as u16,
                    &payload,
                );
            }
        }

        write_tlv_end(cursor);
    }

    // Publish the kernel-written bootinfo frame to the point of coherency
    // before exposing it at the EL0 VA. Without this clean an EL0 reader
    // observes stale bytes: the magic check fails and init's initrd pointer
    // stays zero, so every CPIO lookup short-circuits as NOT_FOUND.
    crate::arch::publish_page_table_page(frame_phys);

    vspace
        .map(BOOTINFO_VADDR, frame_phys, PageFlags::USER_RO)
        .unwrap_or_else(|_| boot_fatal!("bootinfo map failed"));

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[INIT] Boot info page mapped at ");
        _g.hex(BOOTINFO_VADDR);
        _g.putc(b'\n');
    });
}
