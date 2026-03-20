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

use crate::cap::{
    alloc_slot, get_cap_mut, CNode, CapRef, CapRights, IoPortRange, KernelObject, ObjectType,
    UntypedMemory,
};
use crate::ipc::{IrqHandler, Notification};
use crate::mm::vspace::PageFlags;
use crate::mm::{
    alloc_contiguous_frames, alloc_frame, free_frame_count, phys_to_virt, VSpace, PAGE_SIZE,
};
use crate::sched::thread::{SchedContext, Tcb};
use crate::bootinfo::MemoryKind;
use crate::ParsedBootInfo;
use core::mem::MaybeUninit;

/// Fatal boot error — prints message and halts.
/// Used instead of .expect() to avoid unwinding/panic infrastructure.
macro_rules! boot_fatal {
    ($msg:expr) => {{
        crate::serial_puts("[INIT] FATAL: ");
        crate::serial_puts($msg);
        crate::serial_puts("\n");
        loop {
            crate::arch::halt()
        }
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
/// PS/2 keyboard capabilities
const CAP_KBD_IOPORT: usize = 6;
const CAP_KBD_IRQ: usize = 7;
/// COM1 serial port capabilities
const CAP_COM1_IOPORT: usize = 8;
const CAP_COM1_IRQ: usize = 9;
const CAP_COM1_NOTIFICATION: usize = 10;
/// Initrd device untyped capability (for map_device into child VSpaces)
const CAP_INITRD_UNTYPED: usize = 12;
/// Framebuffer device untyped
const CAP_FB_UNTYPED: usize = 13;
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

/// COM1 serial port objects (static, never freed)
static mut INIT_COM1_IOPORT: IoPortRange = IoPortRange::new(0x3F8, 8);
static mut INIT_COM1_IRQ: IrqHandler = IrqHandler::new(4);
static mut INIT_COM1_NOTIFICATION: Notification = Notification::new();

/// PS/2 keyboard objects (static, never freed)
static mut INIT_KBD_IOPORT: IoPortRange = IoPortRange::new(0x60, 5); // ports 0x60-0x64
static mut INIT_KBD_IRQ: IrqHandler = IrqHandler::new(1);           // IRQ1

/// PCI config space I/O port (0xCF8..0xCFF, 8 ports for CONFIG_ADDRESS + CONFIG_DATA)
static mut INIT_PCI_IOPORT: IoPortRange = IoPortRange::new(0xCF8, 8);
/// PCI config space IoPort well-known slot index
const CAP_PCI_IOPORT: usize = 15;

/// IrqControl capability (IrqHandler with CONFIGURE rights, for dynamic IoPort creation)
static mut INIT_IRQ_CONTROL: IrqHandler = IrqHandler::new(0);
/// IrqControl well-known slot index (init slot 11, shared with pcisrv via CopyCap)
const CAP_IRQ_CONTROL: usize = 11;

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

/// Bootstrap the first user-mode init task
pub fn bootstrap(boot_info: Option<&ParsedBootInfo>) {
    crate::serial_puts("[INIT] Creating user VSpace\n");

    // Read current (kernel) CR3 for copying higher-half entries
    let kernel_cr3 = crate::arch::paging::read_cr3();

    // Allocate PML4 for user VSpace
    let pml4_phys = boot_unwrap!(alloc_frame(), "PML4 alloc failed");
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
    let (user_rip, user_stack_top) = load_from_initrd(info, &mut vspace);

    // Map initrd + boot info into init address space.
    map_initrd(info, &mut vspace);
    map_bootinfo(&mut vspace, boot_info);

    // Allocate a kernel stack for the trampoline (used by context_switch → iretq)
    let tramp_stack_phys = boot_unwrap!(alloc_frame(), "trampoline stack alloc failed");
    let tramp_stack_virt = phys_to_virt(tramp_stack_phys);
    let tramp_stack_top = tramp_stack_virt + PAGE_SIZE as u64;
    unsafe {
        core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, PAGE_SIZE);
    }

    // Allocate per-thread kernel stack for syscall entry (4 pages = 16 KiB).
    // A single page (4 KiB) overflows on deep syscall paths.
    const KSTACK_PAGES: usize = 4;
    let kstack_phys = boot_unwrap!(alloc_contiguous_frames(KSTACK_PAGES), "kernel stack alloc failed");
    let kstack_virt = phys_to_virt(kstack_phys);
    let kstack_top = kstack_virt + (KSTACK_PAGES * PAGE_SIZE) as u64;
    unsafe {
        core::ptr::write_bytes(kstack_virt as *mut u8, 0, KSTACK_PAGES * PAGE_SIZE);
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

        // Configure thread context for initial dispatch via context_switch.
        #[cfg(target_arch = "x86_64")]
        {
            // The trampoline function is entered via context_switch's `ret`.
            // It reads r12/r13/r14 and performs iretq to ring 3.
            (*tcb).context.rip = crate::arch::usermode_trampoline as *const () as u64;
            (*tcb).context.rsp = tramp_stack_top;
            (*tcb).context.r12 = user_rip;            // User RIP
            (*tcb).context.r13 = user_stack_top;       // User RSP
            (*tcb).context.r14 = vspace_root;          // User CR3
            (*tcb).context.r15 = 0x0202;               // User RFLAGS: IF=1, IOPL=0
            (*tcb).context.rflags = 0x202;             // Kernel RFLAGS for context_switch
        }
        #[cfg(target_arch = "aarch64")]
        {
            // On aarch64, the trampoline sets ELR_EL1/SPSR_EL1/SP_EL0 and erets.
            (*tcb).context.elr_el1 = user_rip;
            (*tcb).context.sp = user_stack_top;
            (*tcb).context.spsr_el1 = 0x0;            // EL0t with IRQs unmasked
            // x0 will hold the argument (if any) when entering usermode
        }

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
        (*tcb).cspace_root = &raw mut INIT_CNODE_STORAGE as *mut CNode;
        (*tcb).kernel_stack_top = kstack_top;
        (*tcb).stack_canary = crate::arch::generate_stack_canary();

        // Seed %gs:40 with init's canary so the first syscall entry picks it up
        crate::arch::set_per_cpu_canary((*tcb).stack_canary);

        // Set per-CPU kernel stack to init's stack before first scheduling
        crate::arch::set_kernel_stack(kstack_top);
        crate::arch::set_tss_rsp0(kstack_top);

        // Enqueue the init task
        crate::sched::scheduler::scheduler().enqueue(tcb);
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[INIT] Init task enqueued, entering user mode at ");
        s.hex(user_rip);
        s.putc(b'\n');
    }
}

/// Compute ceil(log2(n)), returning the smallest k such that 2^k >= n.
fn ceil_log2(n: u64) -> u8 {
    if n <= 1 {
        return 0;
    }
    64 - (n - 1).leading_zeros() as u8
}

/// Set up init task's CSpace with well-known capabilities
fn setup_init_cspace(boot_info: Option<&ParsedBootInfo>) {
    crate::serial_puts("[INIT] Setting up CSpace\n");

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

        // Slot 6: PS/2 Keyboard IoPort (ports 0x60-0x64)
        insert_static_cap(
            cnode,
            CAP_KBD_IOPORT,
            &raw mut INIT_KBD_IOPORT as *mut crate::cap::KernelObject,
            ObjectType::IoPort,
        );

        // Slot 7: PS/2 Keyboard IRQ handler (IRQ1)
        {
            let irq_ptr = &raw mut INIT_KBD_IRQ;
            insert_static_cap(
                cnode,
                CAP_KBD_IRQ,
                irq_ptr as *mut crate::cap::KernelObject,
                ObjectType::IrqHandler,
            );
            crate::ipc::irq::register_handler(1, irq_ptr);
        }

        // Slot 11: IrqControl (IrqHandler with ALL rights, for dynamic IoPort/DeviceUntyped creation)
        insert_static_cap(
            cnode,
            CAP_IRQ_CONTROL,
            &raw mut INIT_IRQ_CONTROL as *mut crate::cap::KernelObject,
            ObjectType::IrqHandler,
        );

        // Slot 15: PCI config space IoPort (0xCF8..0xCFF, 8 ports)
        insert_static_cap(
            cnode,
            CAP_PCI_IOPORT,
            &raw mut INIT_PCI_IOPORT as *mut crate::cap::KernelObject,
            ObjectType::IoPort,
        );

        // Slot 12: Initrd pseudo-device untyped for map_device-based sharing
        if let Some(info) = boot_info {
            if info.initrd_addr != 0 && info.initrd_size != 0 {
                let size_bits = ceil_log2(core::cmp::max(PAGE_SIZE as u64, info.initrd_size as u64));
                let initrd_ut = &raw mut INIT_INITRD_UNTYPED;
                (*initrd_ut) = UntypedMemory::new(info.initrd_addr, size_bits, true);
                INITRD_DEVICE_LIMIT_BYTES =
                    ((info.initrd_size as u64 + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64)
                        * PAGE_SIZE as u64;
                INITRD_DEVICE_UT_PTR = initrd_ut as *const UntypedMemory;

                insert_static_cap_with_rights(
                    cnode,
                    CAP_INITRD_UNTYPED,
                    initrd_ut as *mut crate::cap::KernelObject,
                    ObjectType::Untyped,
                    CapRights::READ | CapRights::EXECUTE | CapRights::GRANT,
                );

                {
                    let s = crate::SerialGuard::acquire();
                    s.puts("[INIT] Initrd: device untyped phys=");
                    s.hex(info.initrd_addr);
                    s.puts(" size=2^");
                    s.dec(size_bits as u64);
                    s.putc(b'\n');
                }
            }
        }

        // Slot 13: Framebuffer device untyped (if framebuffer is available)
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

                {
                    let s = crate::SerialGuard::acquire();
                    s.puts("[INIT] Framebuffer: device untyped phys=");
                    s.hex(fb.addr);
                    s.puts(" size=2^");
                    s.dec(size_bits as u64);
                    s.putc(b'\n');
                }
            }
        }

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
    unsafe {
        insert_static_cap_with_rights(cnode, cnode_index, object, obj_type, CapRights::ALL);
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
    let cap = get_cap_mut(slot);
    cap.object = object;
    cap.obj_type = obj_type;
    cap.rights = rights;
    cap.depth = 0;
    cap.badge = 0;
    cnode
        .insert_ref(cnode_index, CapRef { slot })
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

/// Create untyped memory capabilities from boot info memory map
unsafe fn create_untyped_caps(cnode: &mut CNode, _info: &ParsedBootInfo) {
    // Allocate backing memory from the frame allocator so untyped regions
    // do not overlap frames already in use by the kernel.
    const MAX_SIZE_BITS: u8 = 38; // 256 GiB
    const MIN_SIZE_BITS: u8 = 12; // 4 KiB
    const NORMAL_MIN_KERNEL_RESERVE_FRAMES: usize = 1024; // 4 MiB
    const LOWMEM_ABS_RESERVE_FRAMES: usize = 16; // 64 KiB reserved for kernel runtime allocations
    const LOWMEM_THRESHOLD_FRAMES: usize = 2048; // 8 MiB

    let mut ut_index = 0;
    let mut free_frames = free_frame_count();
    let reserve_frames = if free_frames <= LOWMEM_THRESHOLD_FRAMES {
        core::cmp::max(LOWMEM_ABS_RESERVE_FRAMES, free_frames / 16)
    } else {
        core::cmp::max(NORMAL_MIN_KERNEL_RESERVE_FRAMES, free_frames / 8)
    };

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[INIT] Untyped reserve frames: ");
        s.dec(reserve_frames as u64);
        s.puts(" (free=");
        s.dec(free_frames as u64);
        s.puts(")\n");
    }

    // At lowmem, start from 1MB instead of 256MB to avoid wasting
    // iteration and to produce multiple smaller regions for flexibility.
    let start_bits = if free_frames <= LOWMEM_THRESHOLD_FRAMES {
        if MAX_SIZE_BITS > 20 { 20 } else { MAX_SIZE_BITS }
    } else {
        MAX_SIZE_BITS
    };

    'size_loop: for size_bits in (MIN_SIZE_BITS..=start_bits).rev() {
        let size_bytes = 1usize << size_bits;
        let frame_count = size_bytes / PAGE_SIZE;

        // Allocate as many regions as possible at this size before moving
        // to smaller chunks. This maximizes exposed untyped memory while
        // still preferring larger blocks first.
        while ut_index < MAX_INIT_UNTYPEDS {
            // Keep a reserve for kernel page-table growth and runtime mappings.
            if free_frames <= reserve_frames {
                break 'size_loop;
            }
            if frame_count > free_frames.saturating_sub(reserve_frames) {
                break;
            }

            let Some(base) = alloc_contiguous_frames(frame_count) else {
                break;
            };
            free_frames = free_frames.saturating_sub(frame_count);

            // Initialize the UntypedMemory object in static storage
            let ut = unsafe { &raw mut INIT_UNTYPEDS[ut_index] };
            unsafe { (*ut) = UntypedMemory::new(base, size_bits, false); }

            // Allocate a global cap slot and populate it
            let slot = boot_unwrap!(alloc_slot(), "untyped cap slot alloc failed");
            let cap = get_cap_mut(slot);
            cap.object = ut as *mut crate::cap::KernelObject;
            cap.obj_type = ObjectType::Untyped;
            cap.rights = CapRights::ALL;
            cap.depth = 0;
            cap.badge = 0;

            let cnode_slot = CAP_UNTYPED_START + ut_index;
            cnode
                .insert_ref(cnode_slot, CapRef { slot })
                .unwrap_or_else(|_| boot_fatal!("untyped CNode insert failed"));

            {
                let s = crate::SerialGuard::acquire();
                s.puts("[INIT]   Untyped ");
                s.dec(ut_index as u64);
                s.puts(": phys=");
                s.hex(base);
                s.puts(" size=");
                s.hex(1u64 << size_bits);
                s.puts(" (2^");
                s.dec(size_bits as u64);
                s.puts(")\n");
            }

            ut_index += 1;
        }
    }

    // Low-memory fallback: ensure init gets at least one small untyped.
    if ut_index == 0 && free_frames > LOWMEM_ABS_RESERVE_FRAMES {
        if let Some(base) = alloc_frame() {
            let ut = unsafe { &raw mut INIT_UNTYPEDS[ut_index] };
            unsafe { (*ut) = UntypedMemory::new(base, MIN_SIZE_BITS, false); }

            let slot = boot_unwrap!(alloc_slot(), "fallback untyped cap slot alloc failed");
            let cap = get_cap_mut(slot);
            cap.object = ut as *mut crate::cap::KernelObject;
            cap.obj_type = ObjectType::Untyped;
            cap.rights = CapRights::ALL;
            cap.depth = 0;
            cap.badge = 0;

            cnode
                .insert_ref(CAP_UNTYPED_START + ut_index, CapRef { slot })
                .unwrap_or_else(|_| boot_fatal!("fallback untyped CNode insert failed"));

            {
                let s = crate::SerialGuard::acquire();
                s.puts("[INIT]   Untyped fallback: phys=");
                s.hex(base);
                s.puts(" size=0x1000\n");
            }
            ut_index += 1;
        }
    }

    if ut_index == 0 {
        crate::serial_puts("[INIT] WARNING: no contiguous untyped region available\n");
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[INIT] Created ");
        s.dec(ut_index as u64);
        s.puts(" untyped capabilities\n");
    }
}

/// Load init from CPIO initrd using the kernel ELF loader
fn load_from_initrd(info: &ParsedBootInfo, vspace: &mut VSpace) -> (u64, u64) {
    crate::serial_puts("[INIT] Parsing CPIO initrd\n");

    let initrd = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(info.initrd_addr) as *const u8,
            info.initrd_size as usize,
        )
    };

    let elf_entry = crate::cpio::find_file(initrd, "init")
        .or_else(|| crate::cpio::find_file(initrd, "init.elf"));
    let elf_data = match elf_entry {
        Some(entry) => {
            {
                let s = crate::SerialGuard::acquire();
                s.puts("[INIT] Found init in initrd (");
                s.dec(entry.data.len() as u64);
                s.puts(" bytes)\n");
            }
            entry.data
        }
        None => boot_fatal!("init not found in initrd"),
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
                crate::elf::ElfError::MapFailed => crate::serial_puts("map failed"),
            }
            crate::serial_puts("\n");
            boot_fatal!("init ELF load failed");
        }
    };

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[INIT] ELF loaded: entry=");
        s.hex(result.entry);
        s.puts(" base=");
        s.hex(result.base);
        s.puts(" brk=");
        s.hex(result.brk);
        s.putc(b'\n');
    }

    // Allocate and map a multi-page user stack
    for pg in 0..INIT_STACK_PAGES {
        let stack_phys = boot_unwrap!(alloc_frame(), "stack alloc failed");
        unsafe {
            core::ptr::write_bytes(phys_to_virt(stack_phys) as *mut u8, 0, PAGE_SIZE);
        }
        let stack_vaddr = INIT_STACK_VADDR + (pg as u64) * PAGE_SIZE as u64;
        vspace
            .map(stack_vaddr, stack_phys, PageFlags::USER_RW)
            .unwrap_or_else(|_| boot_fatal!("stack map failed"));
    }

    // x86-64 C ABI: extern "C" fn _start expects RSP ≡ 8 (mod 16),
    // simulating a call instruction having pushed a return address.
    (result.entry, INIT_STACK_TOP - 8)
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

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[INIT] Mapping initrd: phys=");
        s.hex(initrd_phys);
        s.puts(" size=");
        s.dec(initrd_size as u64);
        s.puts(" pages=");
        s.dec(num_pages as u64);
        s.puts(" -> vaddr=");
        s.hex(INITRD_VADDR);
        s.puts(" mode=");
        if direct_map_ok {
            s.puts("direct");
        } else {
            s.puts("copy");
        }
        s.putc(b'\n');
    }

    for i in 0..num_pages {
        let phys = initrd_phys + (i * PAGE_SIZE) as u64;
        let virt = INITRD_VADDR + (i * PAGE_SIZE) as u64;

        let map_phys = if direct_map_ok {
            phys
        } else {
            // Fallback path for non-page-aligned bootloader initrd.
            let frame_phys = boot_unwrap!(alloc_frame(), "initrd frame alloc failed");
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
/// and framebuffer metadata.
///
/// Layout (little-endian):
///   offset  0: magic (u64) = 0x534C5459_424F4F54 "SLTYBOOT"
///   offset  8: initrd virtual address (u64)
///   offset 16: initrd size in bytes (u64)
///   offset 24: fb_phys_addr (u64)
///   offset 32: fb_width (u32)
///   offset 36: fb_height (u32)
///   offset 40: fb_pitch (u32)
///   offset 44: fb_bpp (u8)
///   offset 45: fb_red_pos (u8)
///   offset 46: fb_red_size (u8)
///   offset 47: fb_green_pos (u8)
///   offset 48: fb_green_size (u8)
///   offset 49: fb_blue_pos (u8)
///   offset 50: fb_blue_size (u8)
///   offset 56: total_usable_bytes (u64)
fn map_bootinfo(vspace: &mut VSpace, boot_info: Option<&ParsedBootInfo>) {
    let total_usable = match boot_info {
        Some(info) => bootinfo_total_usable_bytes(info),
        None => 0,
    };
    let frame_phys = boot_unwrap!(alloc_frame(), "bootinfo frame alloc failed");
    let frame_virt = phys_to_virt(frame_phys) as *mut u8;
    unsafe {
        core::ptr::write_bytes(frame_virt, 0, PAGE_SIZE);
        let data = frame_virt as *mut u64;
        data.write(0x534C5459_424F4F54); // magic "SLTYBOOT"
        data.add(1).write(INITRD_USER_VADDR);
        data.add(2).write(INITRD_USER_SIZE);

        // Write framebuffer metadata if available
        if let Some(info) = boot_info {
            let fb = &info.framebuffer;
            if fb.addr != 0 {
                data.add(3).write(fb.addr);
                let p32 = frame_virt.add(32) as *mut u32;
                p32.write(fb.width);
                p32.add(1).write(fb.height);
                p32.add(2).write(fb.pitch);
                *frame_virt.add(44) = fb.bpp;
                *frame_virt.add(45) = fb.red_pos;
                *frame_virt.add(46) = fb.red_size;
                *frame_virt.add(47) = fb.green_pos;
                *frame_virt.add(48) = fb.green_size;
                *frame_virt.add(49) = fb.blue_pos;
                *frame_virt.add(50) = fb.blue_size;
            }
        }

        // Total usable memory in bytes (for userspace memory scaling)
        let total_ptr = frame_virt.add(56) as *mut u64;
        total_ptr.write(total_usable);
    }
    vspace
        .map(BOOTINFO_VADDR, frame_phys, PageFlags::USER_RO)
        .unwrap_or_else(|_| boot_fatal!("bootinfo map failed"));

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[INIT] Boot info page mapped at ");
        s.hex(BOOTINFO_VADDR);
        s.putc(b'\n');
    }
}

fn bootinfo_total_usable_bytes(info: &ParsedBootInfo) -> u64 {
    let mut total = 0u64;
    for i in 0..info.memory_map_len {
        let entry = info.memory_map[i];
        if entry.kind == MemoryKind::Usable {
            total = total.saturating_add(entry.length);
        }
    }
    total
}
