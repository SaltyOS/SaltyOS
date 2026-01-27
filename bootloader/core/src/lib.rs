//! Common bootloader core shared by BIOS/UEFI stubs.
//!
//! Provides:
//! - BootContext -> BootInfo builder
//! - RELA (R_X86_64_RELATIVE) relocation applier

#![no_std]

use core::mem::size_of;
use saltyos_ska::{
    BootInfo, BootFlags, FramebufferInfo, ModuleInfo, PhysAddr, BOOTINFO_MAGIC,
    BOOTINFO_VERSION, KERNEL_VIRT_BASE,
};

/// Minimal, C-compatible context for building BootInfo.
///
/// BIOS/UEFI stubs should fill this and pass it to `build_bootinfo`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootContext {
    pub flags: BootFlags,
    pub memory_map: PhysAddr,
    pub memory_map_entries: u32,
    pub framebuffer: FramebufferInfo,
    pub initrd: ModuleInfo,
    pub cmdline: PhysAddr,
    pub cmdline_len: u32,
    pub rsdp: PhysAddr,
}

impl BootContext {
    pub const fn empty() -> Self {
        Self {
            flags: BootFlags::empty(),
            memory_map: PhysAddr::new(0),
            memory_map_entries: 0,
            framebuffer: FramebufferInfo {
                address: PhysAddr::new(0),
                width: 0,
                height: 0,
                pitch: 0,
                format: saltyos_ska::PixelFormat::Rgb,
                bpp: 0,
            },
            initrd: ModuleInfo {
                address: PhysAddr::new(0),
                size: 0,
                name: [0; 64],
            },
            cmdline: PhysAddr::new(0),
            cmdline_len: 0,
            rsdp: PhysAddr::new(0),
        }
    }
}

/// Build a BootInfo instance from a BootContext.
pub fn build_bootinfo(ctx: &BootContext) -> BootInfo {
    let framebuffer = if ctx.flags.contains(BootFlags::FRAMEBUFFER) {
        Some(ctx.framebuffer)
    } else {
        None
    };

    let initrd = if ctx.flags.contains(BootFlags::INITRD) {
        Some(ctx.initrd)
    } else {
        None
    };

    let rsdp = if ctx.flags.contains(BootFlags::ACPI) {
        Some(ctx.rsdp)
    } else {
        None
    };

    BootInfo {
        magic: *BOOTINFO_MAGIC,
        version: BOOTINFO_VERSION,
        flags: ctx.flags,
        size: core::mem::size_of::<BootInfo>() as u32,
        memory_map: ctx.memory_map,
        memory_map_entries: ctx.memory_map_entries,
        framebuffer,
        initrd,
        cmdline: ctx.cmdline,
        cmdline_len: ctx.cmdline_len,
        rsdp,
        extra: PhysAddr::new(0),
        extra_len: 0,
    }
}

/// Handoff structure for bootcore entry.
///
/// BIOS/UEFI stubs should fill this and call `bootcore_enter`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootHandoff {
    pub boot_context: BootContext,
    pub bootinfo_ptr: *mut BootInfo,
    pub kernel_phys_base: u64,
    pub kernel_vaddr_base: u64,
    pub kernel_entry: u64,
    pub kernel_dyn_phys: u64,
    pub kernel_dyn_size: u64,
    pub user_image_phys: u64,
    pub user_image_pages: u64,
    pub user_stack_phys: u64,
    pub user_stack_pages: u64,
    pub pt_alloc_base: u64,
    pub pt_alloc_size: u64,
    pub identity_map_gib: u64,
    pub extra_ptr: u64,
    pub extra_len: u64,
}

// ELF64 dynamic constants
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;

// x86_64 relocation type
const R_X86_64_RELATIVE: u32 = 8;

#[repr(C)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

/// Apply RELA relocations (R_X86_64_RELATIVE) if a PT_DYNAMIC segment exists.
///
/// `dyn_phys` and `dyn_size` are the *physical* address/size of the PT_DYNAMIC
/// segment. `vaddr_base` is the minimum PT_LOAD vaddr; `phys_base` is the
/// physical base where the image was loaded.
pub fn apply_relocations(dyn_phys: u64, dyn_size: u64, vaddr_base: u64, phys_base: u64) {
    if dyn_phys == 0 || dyn_size == 0 {
        return;
    }

    let mut rela_ptr = 0u64;
    let mut rela_sz = 0u64;
    let mut rela_ent = 0u64;

    let mut offset = 0u64;
    while offset + size_of::<Elf64Dyn>() as u64 <= dyn_size {
        let dyn_entry = unsafe { &*(dyn_phys.wrapping_add(offset) as *const Elf64Dyn) };
        if dyn_entry.d_tag == DT_NULL {
            break;
        }
        match dyn_entry.d_tag {
            DT_RELA => rela_ptr = dyn_entry.d_val,
            DT_RELASZ => rela_sz = dyn_entry.d_val,
            DT_RELAENT => rela_ent = dyn_entry.d_val,
            _ => {}
        }
        offset = offset.wrapping_add(size_of::<Elf64Dyn>() as u64);
    }

    if rela_ptr == 0 || rela_sz == 0 {
        return;
    }

    if rela_ent == 0 {
        rela_ent = size_of::<Elf64Rela>() as u64;
    }

    let slide = KERNEL_VIRT_BASE.wrapping_sub(vaddr_base);
    let rela_phys = phys_base + (rela_ptr - vaddr_base);
    let count = rela_sz / rela_ent;

    for i in 0..count {
        let rela = unsafe { &*(rela_phys.wrapping_add(i * rela_ent) as *const Elf64Rela) };
        let r_type = (rela.r_info & 0xffff_ffff) as u32;
        if r_type == R_X86_64_RELATIVE {
            let reloc_phys = phys_base + (rela.r_offset - vaddr_base);
            let value = slide.wrapping_add(rela.r_addend as u64);
            unsafe {
                core::ptr::write_unaligned(reloc_phys as *mut u64, value);
            }
        }
    }
}

/// Compute runtime kernel entry in higher-half address space.
pub fn runtime_entry(link_entry: u64, vaddr_base: u64) -> u64 {
    KERNEL_VIRT_BASE + (link_entry - vaddr_base)
}

#[inline(always)]
fn serial_putc(b: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") b,
            options(nostack, preserves_flags)
        );
    }
}

static mut BIOS_DEBUG: bool = false;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[inline(always)]
fn debug_mark(b: u8) {
    unsafe {
        if BIOS_DEBUG {
            serial_putc(b);
        }
    }
}

#[inline(always)]
fn debug_hex32(v: u32) {
    unsafe {
        if !BIOS_DEBUG {
            return;
        }
    }
    for i in (0..8).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as usize;
        serial_putc(HEX_DIGITS[nib]);
    }
}

const PAGE_SIZE: u64 = 4096;
const PAGE_TABLE_ENTRIES: usize = 512;
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_HUGE: u64 = 1 << 7;

struct PtAllocator {
    next: u64,
    end: u64,
}

impl PtAllocator {
    fn new(base: u64, size: u64) -> Self {
        Self {
            next: base,
            end: base.saturating_add(size),
        }
    }

    fn alloc_page(&mut self) -> u64 {
        let addr = self.next;
        let next = addr.saturating_add(PAGE_SIZE);
        if next > self.end {
            serial_putc(b'X');
            loop {
                unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
            }
        }
        self.next = next;
        debug_mark(b'p');
        unsafe {
            core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize);
        }
        debug_mark(b'q');
        addr
    }
}

fn pml4_index(addr: u64) -> usize {
    ((addr >> 39) & 0x1ff) as usize
}

fn pdpt_index(addr: u64) -> usize {
    ((addr >> 30) & 0x1ff) as usize
}

fn pd_index(addr: u64) -> usize {
    ((addr >> 21) & 0x1ff) as usize
}

fn pt_index(addr: u64) -> usize {
    ((addr >> 12) & 0x1ff) as usize
}

/// Build final page tables and return PML4 physical address.
fn build_page_tables(
    alloc: &mut PtAllocator,
    identity_map_gib: u64,
    kernel_phys_base: u64,
    user_image_phys: u64,
    user_image_pages: u64,
    user_stack_phys: u64,
    user_stack_pages: u64,
) -> u64 {
    let pml4 = alloc.alloc_page();
    let pdpt_low = alloc.alloc_page();
    let pdpt_high = alloc.alloc_page();
    debug_mark(b'a');

    let pml4_ptr = pml4 as *mut u64;
    let pdpt_low_ptr = pdpt_low as *mut u64;
    let pdpt_high_ptr = pdpt_high as *mut u64;

    unsafe {
        core::ptr::write_volatile(pml4_ptr.add(0), pdpt_low | PTE_PRESENT | PTE_WRITABLE);
    }

    let map_gib = core::cmp::max(identity_map_gib, 1);
    for gi in 0..map_gib {
        let pd = alloc.alloc_page();
        unsafe {
            core::ptr::write_volatile(
                pdpt_low_ptr.add(gi as usize),
                pd | PTE_PRESENT | PTE_WRITABLE,
            );
        }

        let pd_ptr = pd as *mut u64;
        for i in 0..PAGE_TABLE_ENTRIES {
            let phys = (gi * 1024 * 1024 * 1024) + (i as u64 * 2 * 1024 * 1024);
            unsafe {
                core::ptr::write_volatile(
                    pd_ptr.add(i),
                    phys | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE,
                );
            }
        }
    }
    debug_mark(b'b');

    let kernel_pml4 = pml4_index(KERNEL_VIRT_BASE);
    let kernel_pdpt = pdpt_index(KERNEL_VIRT_BASE);
    unsafe {
        core::ptr::write_volatile(
            pml4_ptr.add(kernel_pml4),
            pdpt_high | PTE_PRESENT | PTE_WRITABLE,
        );
    }
    debug_mark(b'c');

    let pd_high = alloc.alloc_page();
    unsafe {
        core::ptr::write_volatile(
            pdpt_high_ptr.add(kernel_pdpt),
            pd_high | PTE_PRESENT | PTE_WRITABLE,
        );
    }

    let pd_high_ptr = pd_high as *mut u64;
    for i in 0..PAGE_TABLE_ENTRIES {
        let phys = kernel_phys_base + (i as u64 * 2 * 1024 * 1024);
        unsafe {
            core::ptr::write_volatile(
                pd_high_ptr.add(i),
                phys | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE,
            );
        }
    }
    debug_mark(b'd');

    if user_image_pages > 0 || user_stack_pages > 0 {
        let pdpt_user = alloc.alloc_page();
        let pd_user = alloc.alloc_page();
        let pt_user = alloc.alloc_page();

        let user_pml4 = pml4_index(saltyos_ska::USER_CODE_BASE);
        let user_pdpt = pdpt_index(saltyos_ska::USER_CODE_BASE);
        let user_pd = pd_index(saltyos_ska::USER_CODE_BASE);

        let user_flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER;

        unsafe {
            core::ptr::write_volatile(pml4_ptr.add(user_pml4), pdpt_user | user_flags);
            core::ptr::write_volatile((pdpt_user as *mut u64).add(user_pdpt), pd_user | user_flags);
            core::ptr::write_volatile((pd_user as *mut u64).add(user_pd), pt_user | user_flags);
        }

        let pt_ptr = pt_user as *mut u64;
        for i in 0..(user_image_pages as usize) {
            let phys = user_image_phys + (i as u64 * PAGE_SIZE);
            unsafe {
                core::ptr::write_volatile(pt_ptr.add(i), phys | user_flags);
            }
        }

        let stack_idx = pt_index(saltyos_ska::USER_STACK_BASE);
        for i in 0..(user_stack_pages as usize) {
            let phys = user_stack_phys + (i as u64 * PAGE_SIZE);
            unsafe {
                core::ptr::write_volatile(pt_ptr.add(stack_idx + i), phys | user_flags);
            }
        }
    }
    debug_mark(b'e');

    pml4
}

unsafe fn load_cr3(pml4_phys: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) pml4_phys, options(nostack, preserves_flags));
}

/// Common bootcore entry: build BootInfo, apply relocations, jump to kernel.
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn bootcore_enter(handoff: *const BootHandoff) -> ! {
    let handoff = &*handoff;
    BIOS_DEBUG = handoff.boot_context.flags.contains(BootFlags::BIOS);
    debug_mark(b'A');

    let mut bootinfo = build_bootinfo(&handoff.boot_context);
    bootinfo.extra = PhysAddr::new(handoff.extra_ptr);
    bootinfo.extra_len = handoff.extra_len as u32;
    core::ptr::write(handoff.bootinfo_ptr, bootinfo);
    debug_mark(b'B');

    if handoff.pt_alloc_base != 0 && handoff.pt_alloc_size != 0 {
        debug_mark(b'1');
        debug_mark(b'[');
        debug_hex32(handoff.pt_alloc_base as u32);
        debug_mark(b':');
        debug_hex32(handoff.pt_alloc_size as u32);
        debug_mark(b']');
        let mut alloc = PtAllocator::new(handoff.pt_alloc_base, handoff.pt_alloc_size);
        let pml4 = build_page_tables(
            &mut alloc,
            handoff.identity_map_gib,
            handoff.kernel_phys_base,
            handoff.user_image_phys,
            handoff.user_image_pages,
            handoff.user_stack_phys,
            handoff.user_stack_pages,
        );
        debug_mark(b'2');
        load_cr3(pml4);
    }
    debug_mark(b'C');

    apply_relocations(
        handoff.kernel_dyn_phys,
        handoff.kernel_dyn_size,
        handoff.kernel_vaddr_base,
        handoff.kernel_phys_base,
    );
    debug_mark(b'D');

    let entry = runtime_entry(handoff.kernel_entry, handoff.kernel_vaddr_base);
    debug_mark(b'E');
    let kernel_fn: extern "sysv64" fn(&BootInfo) -> ! =
        core::mem::transmute(entry as usize);
    kernel_fn(&*handoff.bootinfo_ptr);
}
