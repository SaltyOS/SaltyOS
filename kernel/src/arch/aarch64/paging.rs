//! AArch64 page table management
//!
//! Provides the same public interface as x86_64::paging so that shared kernel
//! code (vspace.rs, init.rs, console/fb.rs) can reference `crate::arch::paging::*`.
//!
//! ## PTE Translation Layer
//!
//! vspace.rs manipulates "logical" PTE flags using x86 bit positions. The
//! aarch64 PageTable methods transparently translate between the logical format
//! and the hardware aarch64 descriptor format on every read/write.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::{
    pmm_alloc, frame::FrameOwner, frame::KernelMetaKind, phys_to_virt, PAGE_SIZE,
    PHYS_MAP_OFFSET, SpinLock,
};

/// Dedicated TTBR1 root used for kernel higher-half mappings.
static mut KERNEL_ROOT_EARLY: u64 = 0;

#[inline]
fn kernel_root() -> u64 {
    let registered = crate::mm::vspace::kernel_vspace_root();
    if registered != 0 {
        return registered;
    }
    // SAFETY: Early boot writes this once before any concurrent access.
    unsafe { KERNEL_ROOT_EARLY }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum direct physical mapping size (512 GB cap)
const MAX_DIRECT_MAP_SIZE: usize = 512 * 1024 * 1024 * 1024;

/// QEMU virt guest RAM starts at 1 GB on aarch64.
const QEMU_VIRT_RAM_BASE: u64 = 0x4000_0000;

/// MAIR_EL1 value:
///   Index 0 = 0x00 (Device-nGnRnE)
///   Index 1 = 0x44 (Normal Non-Cacheable)
///   Index 2 = 0xFF (Normal Write-Back, RA+WA)
const MAIR_VALUE: u64 = 0x00_00_00_00_00_FF_44_00;

/// Mask for the physical-address portion of a page-table entry (logical format).
/// Identical to the x86_64 value — bits [47:12].
pub const ENTRY_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// -- Logical (x86-style) PTE bit positions ----------------------------------

const LOGICAL_PRESENT: u64 = 1 << 0;
const LOGICAL_WRITABLE: u64 = 1 << 1;
const LOGICAL_USER: u64 = 1 << 2;
const LOGICAL_WRITE_THROUGH: u64 = 1 << 3;
const LOGICAL_CACHE_DISABLE: u64 = 1 << 4;
const LOGICAL_HUGE_PAGE: u64 = 1 << 7;
const LOGICAL_COW: u64 = 1 << 9;
const LOGICAL_DEMAND: u64 = 1 << 10;
const LOGICAL_NO_EXECUTE: u64 = 1u64 << 63;

// -- Hardware aarch64 descriptor bits ---------------------------------------

/// Valid bit (bit 0). Present in both table/page (0b11) and block (0b01).
const HW_VALID: u64 = 1 << 0;
/// Table/Page descriptor type (bit 1). Combined with HW_VALID → 0b11.
const HW_TABLE_OR_PAGE: u64 = 1 << 1;
/// AP[1] — EL0 access (bit 6).
const HW_AP1_USER: u64 = 1 << 6;
/// AP[2] — Read-only when set (bit 7).
const HW_AP2_RO: u64 = 1 << 7;
/// SH[1:0] = Inner Shareable (bits 9:8 = 0b11).
const HW_SH_IS: u64 = 3 << 8;
/// Access Flag (bit 10). Must always be set for valid descriptors.
const HW_AF: u64 = 1 << 10;
/// PXN — Privileged Execute-Never (bit 53).
#[allow(dead_code)]
const HW_PXN: u64 = 1u64 << 53;
/// UXN — Unprivileged Execute-Never (bit 54).
const HW_UXN: u64 = 1u64 << 54;
/// Software-available bit 55: COW marker.
const HW_SW_COW: u64 = 1u64 << 55;
/// Software-available bit 56: DEMAND marker (only when not valid).
const HW_SW_DEMAND: u64 = 1u64 << 56;

/// AttrIndx shift (bits [4:2]).
const HW_ATTRINDX_SHIFT: u32 = 2;

/// MAIR index for Device-nGnRnE.
const MAIR_IDX_DEVICE: u64 = 0;
/// MAIR index for Normal Non-Cacheable.
const MAIR_IDX_NORMAL_NC: u64 = 1;
/// MAIR index for Normal Write-Back.
const MAIR_IDX_NORMAL_WB: u64 = 2;

/// Address mask for hardware descriptors — same as logical.
const HW_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// PTE encode / decode
// ---------------------------------------------------------------------------

/// Translate a logical (x86-style) PTE into an aarch64 hardware descriptor.
///
/// The logical format is what vspace.rs produces. The hardware format is what
/// the MMU reads from the page tables.
#[inline(always)]
fn encode_pte(logical: u64) -> u64 {
    if logical == 0 {
        return 0;
    }

    let phys = logical & ENTRY_ADDR_MASK;
    let mut hw = phys;

    if logical & LOGICAL_PRESENT != 0 {
        // Descriptor type: block (0b01) for huge pages, table/page (0b11) otherwise.
        if logical & LOGICAL_HUGE_PAGE != 0 {
            // L2 block descriptor (2 MB) — bits[1:0] = 0b01
            hw |= HW_VALID; // bit 0 only
        } else {
            // Table descriptor (L0-L2) or page descriptor (L3) — bits[1:0] = 0b11
            hw |= HW_VALID | HW_TABLE_OR_PAGE;
        }

        // Access Flag must always be set for valid descriptors.
        hw |= HW_AF;

        // Inner Shareable for all normal memory.
        hw |= HW_SH_IS;

        // AttrIndx selection based on cache flags:
        //   CACHE_DISABLE → Device-nGnRnE (idx 0)
        //   WRITE_THROUGH → Normal-NC (idx 1)
        //   default       → Normal-WB (idx 2)
        let attr_idx = if logical & LOGICAL_CACHE_DISABLE != 0 {
            MAIR_IDX_DEVICE
        } else if logical & LOGICAL_WRITE_THROUGH != 0 {
            MAIR_IDX_NORMAL_NC
        } else {
            MAIR_IDX_NORMAL_WB
        };
        hw |= attr_idx << HW_ATTRINDX_SHIFT;

        // Access permissions.
        // AP[2] = 0 → RW; AP[2] = 1 → RO.
        if logical & LOGICAL_WRITABLE == 0 {
            hw |= HW_AP2_RO;
        }
        // AP[1] = 1 → EL0 accessible.
        if logical & LOGICAL_USER != 0 {
            hw |= HW_AP1_USER;
        }

        // Execute-never.
        if logical & LOGICAL_NO_EXECUTE != 0 {
            hw |= HW_UXN;
        }
    }

    // Software-available bits (valid regardless of PRESENT state).
    if logical & LOGICAL_COW != 0 {
        hw |= HW_SW_COW;
    }
    if logical & LOGICAL_DEMAND != 0 {
        hw |= HW_SW_DEMAND;
    }

    // When not present (Valid=0), preserve access-control flags directly in
    // their logical bit positions. The hardware ignores all bits when Valid=0,
    // and these positions (1, 2, 63) don't collide with the page-aligned
    // physical address stored in bits [47:12]. This allows decode_pte to
    // recover WRITABLE/USER/NX so demand-fault resolution produces correct
    // permissions.
    if logical & LOGICAL_PRESENT == 0 {
        hw |= logical & (LOGICAL_WRITABLE | LOGICAL_USER | LOGICAL_NO_EXECUTE);
    }

    hw
}

/// Translate an aarch64 hardware descriptor back into the logical (x86-style)
/// format that vspace.rs expects.
#[inline(always)]
fn decode_pte(hw: u64) -> u64 {
    if hw == 0 {
        return 0;
    }

    let phys = hw & HW_ADDR_MASK;
    let mut logical = phys;

    // Valid bit present?
    if hw & HW_VALID != 0 {
        logical |= LOGICAL_PRESENT;

        // Block descriptor: bits[1:0] = 0b01 (valid but not table/page).
        if hw & HW_TABLE_OR_PAGE == 0 {
            logical |= LOGICAL_HUGE_PAGE;
        }

        // AP[2] = 0 → writable.
        if hw & HW_AP2_RO == 0 {
            logical |= LOGICAL_WRITABLE;
        }

        // AP[1] = 1 → user accessible.
        if hw & HW_AP1_USER != 0 {
            logical |= LOGICAL_USER;
        }

        // AttrIndx → cache flags.
        let attr_idx = (hw >> HW_ATTRINDX_SHIFT) & 0x7;
        match attr_idx {
            0 => {
                // Device-nGnRnE → CACHE_DISABLE
                logical |= LOGICAL_CACHE_DISABLE;
            }
            1 => {
                // Normal-NC → WRITE_THROUGH
                logical |= LOGICAL_WRITE_THROUGH;
            }
            _ => {
                // Normal-WB or anything else → default (no extra flags)
            }
        }

        // UXN → NO_EXECUTE.
        if hw & HW_UXN != 0 {
            logical |= LOGICAL_NO_EXECUTE;
        }
    } else {
        // Not present — recover access flags stored in logical bit positions
        // by encode_pte (hardware ignores all bits when Valid=0).
        logical |= hw & (LOGICAL_WRITABLE | LOGICAL_USER | LOGICAL_NO_EXECUTE);
    }

    // Software-available bits.
    if hw & HW_SW_COW != 0 {
        logical |= LOGICAL_COW;
    }
    if hw & HW_SW_DEMAND != 0 {
        logical |= LOGICAL_DEMAND;
    }

    logical
}

// ---------------------------------------------------------------------------
// PageFlags — must use x86 bit positions (used as `PageFlags::Foo as u64`)
// ---------------------------------------------------------------------------

/// Page table entry flags.
///
/// Values match x86_64 bit positions because shared code (vspace.rs,
/// console/fb.rs) uses `PageFlags::Foo as u64` to build logical PTEs.
/// The translation to hardware format happens inside `PageTable::set_entry`
/// and `PageTable::entry`.
#[repr(u64)]
pub enum PageFlags {
    Present = 1 << 0,
    Writable = 1 << 1,
    User = 1 << 2,
    WriteThrough = 1 << 3,
    CacheDisable = 1 << 4,
    Accessed = 1 << 5,
    Dirty = 1 << 6,
    HugePage = 1 << 7,
    Global = 1 << 8,
    NoExecute = 1u64 << 63,
}

// ---------------------------------------------------------------------------
// PageTable
// ---------------------------------------------------------------------------

/// Page table structure (4 KB granule, 512 entries per level).
///
/// Entries are stored in hardware aarch64 descriptor format. The `entry()`
/// and `set_entry()` methods translate between the logical (x86-style) format
/// used by vspace.rs and the hardware format transparently.
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        Self { entries: [0; 512] }
    }

    /// Read an entry, translating from hardware to logical format.
    pub fn entry(&self, index: usize) -> u64 {
        // SAFETY: Volatile read is required because PTEs may be modified by
        // other CPUs or observed by the hardware page walker. Prevents the
        // compiler from caching or eliminating PTE reads across TLB
        // invalidation boundaries.
        let hw = unsafe { core::ptr::read_volatile(&self.entries[index]) };
        decode_pte(hw)
    }

    /// Write an entry, translating from logical to hardware format.
    pub fn set_entry(&mut self, index: usize, entry: u64) {
        let hw = encode_pte(entry);
        // SAFETY: Volatile write ensures every PTE store is architecturally
        // significant. Prevents the compiler from reordering or eliminating
        // stores relative to subsequent TLB invalidation.
        unsafe { core::ptr::write_volatile(&mut self.entries[index], hw) }
    }
}

// ---------------------------------------------------------------------------
// System register accessors
// ---------------------------------------------------------------------------

/// Read the current page table root (TTBR0_EL1).
pub fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: Reading TTBR0_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, TTBR0_EL1", out(reg) val, options(nomem, nostack));
    }
    val
}

#[inline]
unsafe fn write_ttbr1(root: u64) {
    // SAFETY: Caller guarantees `root` is a valid top-level page table root.
    unsafe {
        core::arch::asm!(
            "msr TTBR1_EL1, {}",
            "isb",
            in(reg) root,
            options(nostack),
        );
    }
}

/// Write the page table root (TTBR0_EL1) with an embedded ASID.
///
/// The caller must encode the ASID in bits [63:48] of `value`.  Because each
/// VSpace carries a distinct ASID, the hardware TLB naturally partitions
/// entries per address-space — no full TLB flush is needed on a plain switch.
///
/// # Safety
/// `value` must encode a valid, 4 KB-aligned page table address in bits [47:0]
/// and a valid ASID in bits [63:48].
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: Caller guarantees value is a valid TTBR0 encoding.
    // DSB ISH before the TTBR write ensures all prior PTE stores (e.g. from
    // COW clone) are visible to the page walker before it consults the new
    // page tables.  Without this barrier the walker may see stale zero
    // entries in freshly-allocated child page tables after fork.
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "msr TTBR0_EL1, {}",
            "isb",
            in(reg) value,
            options(nostack),
        );
    }
}

/// Invalidate the TLB entry for a single virtual address with the
/// ASID of the currently loaded TTBR0 (inner-shareable).
///
/// Uses `TLBI VAE1IS` which targets a specific ASID, avoiding
/// collateral invalidation of other VSpaces that map the same VA.
pub fn invlpg(virt: u64) {
    unsafe {
        // Read current TTBR0 to get the active ASID
        let ttbr0: u64;
        core::arch::asm!("mrs {}, TTBR0_EL1", out(reg) ttbr0, options(nomem, nostack));
        let asid = (ttbr0 >> 48) & 0xFFFF;
        // TLBI VAE1IS: bits [63:48] = ASID, bits [43:0] = VA >> 12
        let operand = (asid << 48) | (virt >> 12);
        core::arch::asm!(
            "tlbi vae1is, {}",
            "dsb ish",
            "isb",
            in(reg) operand,
            options(nostack),
        );
    }
}

/// Invalidate the TLB entry for a single virtual address with a
/// specific ASID (inner-shareable).
pub fn invlpg_asid(virt: u64, asid: u16) {
    unsafe {
        let operand = ((asid as u64) << 48) | (virt >> 12);
        core::arch::asm!(
            "tlbi vae1is, {}",
            "dsb ish",
            "isb",
            in(reg) operand,
            options(nostack),
        );
    }
}

/// Invalidate the TLB entry for a single virtual address across ALL
/// ASIDs (inner-shareable). Use only when the ASID is unknown or when
/// invalidating kernel mappings.
pub fn invlpg_all_asid(virt: u64) {
    unsafe {
        let va_shifted = virt >> 12;
        core::arch::asm!(
            "tlbi vaae1is, {}",
            "dsb ish",
            "isb",
            in(reg) va_shifted,
            options(nostack),
        );
    }
}

/// Flush the entire TLB (inner-shareable).
pub fn flush_tlb_all() {
    // SAFETY: Full TLB invalidation is always safe from EL1.
    unsafe {
        core::arch::asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack),
        );
    }
}

/// Flush all TLB entries matching a specific ASID (inner-shareable).
pub fn flush_asid(asid: u16) {
    // SAFETY: TLBI is always safe from EL1. The ASID operand occupies
    // bits [63:48] of the register passed to TLBI ASIDE1IS.
    unsafe {
        let val = (asid as u64) << 48;
        core::arch::asm!(
            "tlbi aside1is, {}",
            "dsb ish",
            "isb",
            in(reg) val,
            options(nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// ASID allocator
// ---------------------------------------------------------------------------

/// 8-bit ASID space: 256 IDs. ASID 0 is reserved (kernel / no-ASID), so
/// the usable range is 1..=255.
const ASID_COUNT: usize = 256;

/// Bitmap: 256 bits = 4 × u64.
static mut ASID_BITMAP: [u64; ASID_COUNT / 64] = [0; ASID_COUNT / 64];

/// Generation counter — bumped when the ASID space is exhausted and recycled.
pub static mut ASID_GENERATION: u64 = 1;

/// Spinlock protecting `ASID_BITMAP` and `ASID_GENERATION` for SMP safety.
///
/// Lock ordering: nests after `sched.lock_cpu`, before `FRAME_LOCK`.
/// Callers must hold this lock for the duration of any ASID allocation,
/// free, or generation recycle operation.
static ASID_LOCK: SpinLock = SpinLock::new();

/// Allocate a fresh ASID.  Returns `(asid, generation)`.
///
/// If the bitmap is full, flushes the entire TLB, resets the bitmap,
/// bumps the generation counter, and retries.
///
/// # Safety
/// Must be called with IRQs disabled.
pub unsafe fn asid_alloc() -> (u16, u64) {
    ASID_LOCK.lock();
    // SAFETY: ASID_LOCK serializes all access to ASID_BITMAP and
    // ASID_GENERATION across CPUs. IRQ disable (caller obligation)
    // prevents re-entrant allocation on the same CPU.
    let result = unsafe {
        let bmp = &raw mut ASID_BITMAP;
        let words = ASID_COUNT / 64;
        'alloc: loop {
            for word_idx in 0..words {
                let wp = (*bmp).as_mut_ptr().add(word_idx);
                let word = *wp;
                if word == u64::MAX {
                    continue;
                }
                let bit = (!word).trailing_zeros() as usize;
                let asid = word_idx * 64 + bit;
                if asid == 0 {
                    *(*bmp).as_mut_ptr() |= 1;
                    continue;
                }
                if asid >= ASID_COUNT {
                    break;
                }
                *wp |= 1u64 << bit;
                break 'alloc (asid as u16, *(&raw const ASID_GENERATION));
            }

            // Bitmap full — recycle.
            // Order: flush TLB first so stale entries for old-generation ASIDs
            // are gone, reset the bitmap, then bump generation. This ensures no
            // CPU observes the new generation until the bitmap is clean.
            flush_tlb_all();
            for i in 0..words {
                *(*bmp).as_mut_ptr().add(i) = 0;
            }
            // Reserve ASID 0
            *(*bmp).as_mut_ptr() |= 1;
            *(&raw mut ASID_GENERATION) += 1;
        }
    };
    ASID_LOCK.unlock();
    result
}

/// Release an ASID back to the pool and flush its TLB entries.
///
/// # Safety
/// Must be called with IRQs disabled.
pub unsafe fn asid_free(asid: u16) {
    if asid == 0 || asid as usize >= ASID_COUNT {
        return;
    }
    ASID_LOCK.lock();
    // SAFETY: ASID_LOCK serializes bitmap access across CPUs.
    unsafe {
        let bmp = &raw mut ASID_BITMAP;
        let word_idx = asid as usize / 64;
        let bit = asid as usize % 64;
        *(*bmp).as_mut_ptr().add(word_idx) &= !(1u64 << bit);
        flush_asid(asid);
    }
    ASID_LOCK.unlock();
}

// ---------------------------------------------------------------------------
// init()
// ---------------------------------------------------------------------------

/// Initialize aarch64 paging: configure MAIR, build the direct physical map,
/// and register the kernel VSpace.
pub fn init() {
    // Step 1: Configure MAIR_EL1 (memory attribute indirection register).
    // SAFETY: Writing MAIR_EL1 is safe during single-threaded boot from EL1.
    unsafe {
        core::arch::asm!(
            "msr MAIR_EL1, {}",
            "isb",
            in(reg) MAIR_VALUE,
            options(nomem, nostack),
        );
    }

    // Step 2: Split the shared Stage 3 root into a dedicated TTBR1 kernel
    // root. In the boot root, L0 indices mean different things for TTBR0 and
    // TTBR1: for example index 0 is the boot identity map in TTBR0 but the
    // kernel text region in TTBR1. Teardown of the boot alias therefore
    // requires independent roots.
    let boot_root = read_cr3();
    let kernel_root = unsafe { clone_kernel_root(boot_root) };
    // SAFETY: `kernel_root` is a valid L0 root cloned from the active boot tables.
    unsafe {
        write_ttbr1(kernel_root);
        KERNEL_ROOT_EARLY = kernel_root;
    }

    // Step 3: Build the direct physical map sized to actual RAM in TTBR1.
    let max_phys = crate::mm::max_phys();
    // SAFETY: Single-threaded boot context, frame allocator initialized.
    unsafe {
        init_direct_map(kernel_root, max_phys);
    }

    // Step 4: Register kernel VSpace tracking (needed before any VSpace::new()).
    crate::mm::vspace::init_kernel_vspace(kernel_root);
}

// ---------------------------------------------------------------------------
// init_direct_map()
// ---------------------------------------------------------------------------

/// Map physical memory [0..direct_map_size] to virtual address space starting
/// at PHYS_MAP_OFFSET using 2 MB block descriptors.
///
/// Uses the existing bootloader identity map (TTBR0) for early page-table
/// access, since the direct map does not exist yet.
///
/// # Safety
/// Must be called after the frame allocator is initialized.
/// Must only be called once during boot.
unsafe fn init_direct_map(kernel_root: u64, max_phys: u64) {
    // Use 2 MB block descriptors (Level 2) for the direct physical map.
    // 2 MB blocks are universally supported on ARMv8-A, whereas 1 GB blocks
    // (Level 1) require FEAT_LPA and specific TGran4 support. This also
    // matches the x86_64 port's use of 2 MB large pages.
    let huge_page_size: usize = 2 * 1024 * 1024;
    let direct_map_end = core::cmp::min(
        ((max_phys as usize + (huge_page_size - 1)) / huge_page_size) * huge_page_size,
        MAX_DIRECT_MAP_SIZE,
    ) as u64;
    if direct_map_end <= QEMU_VIRT_RAM_BASE {
        return;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[PAGING] Direct map range: ");
        s.hex(QEMU_VIRT_RAM_BASE);
        s.puts("..");
        s.hex(direct_map_end);
        s.puts(" (max_phys=");
        s.hex(max_phys);
        s.puts(")\n");
    }

    // Use identity mapping (bootloader maps low memory phys==virt via TTBR0).
    let l0_virt = kernel_root as *mut u64;

    // L0 index for PHYS_MAP_OFFSET (0xFFFF_8000_0000_0000).
    // (0xFFFF_8000_0000_0000 >> 39) & 0x1FF = 256
    let l0_idx = ((PHYS_MAP_OFFSET >> 39) & 0x1FF) as usize;

    // --- L0 → L1 (equivalent to PML4 → PDPT) ---

    // SAFETY: l0_virt points to the bootloader L0 table via identity map.
    let l0e = unsafe { core::ptr::read_volatile(l0_virt.add(l0_idx)) };
    let l1_phys = if l0e & HW_VALID == 0 {
        let frame = pmm_alloc(&FrameOwner::KernelPrivate { subkind: KernelMetaKind::PageTable }).expect("Failed to allocate L1 table for direct map");
        // SAFETY: frame is a freshly allocated page reachable via identity map.
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
        }
        // L0 table descriptor: valid + table (0b11) + AF
        let desc = frame | HW_VALID | HW_TABLE_OR_PAGE;
        // SAFETY: Writing to L0 entry via identity map.
        unsafe {
            core::ptr::write_volatile(l0_virt.add(l0_idx), desc);
        }
        frame
    } else {
        l0e & HW_ADDR_MASK
    };

    let l1_virt = l1_phys as *mut u64;

    // --- L1 → L2 tables, filled with 2 MB block descriptors ---

    let mut phys_addr = QEMU_VIRT_RAM_BASE;
    while phys_addr < direct_map_end {
        let virt_addr = PHYS_MAP_OFFSET + phys_addr;
        let l1_idx = ((virt_addr >> 30) & 0x1FF) as usize;

        // SAFETY: l1_virt points to an L1 table via identity map.
        let l1e = unsafe { core::ptr::read_volatile(l1_virt.add(l1_idx)) };
        let l2_phys = if l1e & HW_VALID == 0 {
            let frame = pmm_alloc(&FrameOwner::KernelPrivate { subkind: KernelMetaKind::PageTable }).expect("Failed to allocate L2 table for direct map");
            // SAFETY: Freshly allocated, identity-mapped.
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
            }
            let desc = frame | HW_VALID | HW_TABLE_OR_PAGE;
            // SAFETY: Writing to L1 entry via identity map.
            unsafe {
                core::ptr::write_volatile(l1_virt.add(l1_idx), desc);
            }
            frame
        } else {
            l1e & HW_ADDR_MASK
        };

        let l2_virt = l2_phys as *mut u64;
        while phys_addr < direct_map_end {
            let virt_addr = PHYS_MAP_OFFSET + phys_addr;
            if ((virt_addr >> 30) & 0x1FF) as usize != l1_idx {
                break;
            }

            let entry_idx = ((virt_addr >> 21) & 0x1FF) as usize;
            let desc = phys_addr
                | HW_VALID
                | HW_AF
                | HW_SH_IS
                | (MAIR_IDX_NORMAL_WB << HW_ATTRINDX_SHIFT)
                | HW_UXN;

            // SAFETY: Writing to L2 entry via identity map.
            unsafe {
                core::ptr::write_volatile(l2_virt.add(entry_idx), desc);
            }

            phys_addr += huge_page_size as u64;
        }
    }

    // Flush the TLB to pick up all new mappings.
    flush_tlb_all();
}

// ---------------------------------------------------------------------------
// ensure_next_table() — helper for map_mmio_page
// ---------------------------------------------------------------------------

/// Ensure that a non-leaf table descriptor exists at `index` and return its
/// physical address.
///
/// If the entry is absent, allocates a new zeroed page table frame.
///
/// # Safety
/// - `table` must point to a valid page table in the active kernel address
///   space (via the direct physical map).
/// - Must only be called when creating kernel-global mappings during boot or
///   while otherwise serialized against concurrent page-table modification.
unsafe fn ensure_next_table(table: &mut PageTable, index: usize, context: &'static str) -> u64 {
    // Read the raw hardware entry directly (bypass decode since we check HW bits).
    // SAFETY: Volatile read of a valid PTE slot.
    let raw = unsafe { core::ptr::read_volatile(&table.entries[index]) };

    if raw & HW_VALID != 0 {
        // Already present. If it is a block descriptor, that is a collision.
        if raw & HW_TABLE_OR_PAGE == 0 {
            panic!("kernel 4K mapping collided with block descriptor");
        }
        return raw & HW_ADDR_MASK;
    }

    let frame = pmm_alloc(&FrameOwner::KernelPrivate { subkind: KernelMetaKind::PageTable }).expect(context);

    // SAFETY: `frame` is a freshly allocated page-table frame reachable via
    // the direct map. Zeroing initializes all entries to empty.
    unsafe {
        core::ptr::write_bytes(phys_to_virt(frame) as *mut u8, 0, PAGE_SIZE);
    }

    // Write a table descriptor: Valid + Table (0b11).
    let desc = frame | HW_VALID | HW_TABLE_OR_PAGE;
    // SAFETY: Volatile write to a valid PTE slot.
    unsafe {
        core::ptr::write_volatile(&mut table.entries[index], desc);
    }

    frame
}

// ---------------------------------------------------------------------------
// map_mmio_page()
// ---------------------------------------------------------------------------

/// Map one 4 KB MMIO page into the higher-half physmap slot with Device
/// attributes (uncached, strongly-ordered).
///
/// The direct map only covers usable RAM. Device MMIO pages above `max_phys`
/// are installed sparsely at `PHYS_MAP_OFFSET + phys` so existing
/// physmap-based callers can access them transparently.
///
/// Returns the virtual address corresponding to `phys`.
///
/// # Safety
/// - Must be called after `init_direct_map()` has established access to page
///   tables via `phys_to_virt()`.
/// - The caller must ensure the requested physical page is valid MMIO.
pub unsafe fn map_mmio_page(phys: u64) -> u64 {
    let page_mask = PAGE_SIZE as u64 - 1;
    let phys_page = phys & !page_mask;
    let virt_page = PHYS_MAP_OFFSET + phys_page;

    let kernel_root = kernel_root();
    if kernel_root == 0 {
        panic!("kernel MMIO mapping requested before kernel TTBR1 root was registered");
    }
    // SAFETY: kernel_root points at the dedicated kernel L0 table, reachable
    // via the already-established direct map.
    let l0 = unsafe { &mut *(phys_to_virt(kernel_root) as *mut PageTable) };

    // L0 → L1
    let l1_phys = unsafe {
        ensure_next_table(
            l0,
            ((virt_page >> 39) & 0x1FF) as usize,
            "Failed to allocate L1 for kernel MMIO mapping",
        )
    };
    // SAFETY: l1_phys is a present page-table frame returned by ensure_next_table.
    let l1 = unsafe { &mut *(phys_to_virt(l1_phys) as *mut PageTable) };

    // L1 → L2
    let l2_phys = unsafe {
        ensure_next_table(
            l1,
            ((virt_page >> 30) & 0x1FF) as usize,
            "Failed to allocate L2 for kernel MMIO mapping",
        )
    };
    // SAFETY: l2_phys is a present page-table frame returned by ensure_next_table.
    let l2 = unsafe { &mut *(phys_to_virt(l2_phys) as *mut PageTable) };

    // L2 → L3
    let l3_phys = unsafe {
        ensure_next_table(
            l2,
            ((virt_page >> 21) & 0x1FF) as usize,
            "Failed to allocate L3 for kernel MMIO mapping",
        )
    };
    // SAFETY: l3_phys is a present page-table frame returned by ensure_next_table.
    let l3 = unsafe { &mut *(phys_to_virt(l3_phys) as *mut PageTable) };

    let pte_idx = ((virt_page >> 12) & 0x1FF) as usize;

    // Check for existing mapping (read raw hardware entry).
    // SAFETY: Volatile read of a valid PTE slot.
    let current = unsafe { core::ptr::read_volatile(&l3.entries[pte_idx]) };
    if current & HW_VALID != 0 {
        let current_phys = current & HW_ADDR_MASK;
        if current_phys != phys_page {
            panic!("kernel MMIO mapping collided with existing page");
        }
    }

    // L3 page descriptor: Valid + Page (0b11), Device-nGnRnE (AttrIdx=0),
    // AF=1, SH=IS, AP=RW, UXN=1.
    let desc = phys_page
        | HW_VALID
        | HW_TABLE_OR_PAGE
        | HW_AF
        | HW_SH_IS
        | (MAIR_IDX_DEVICE << HW_ATTRINDX_SHIFT)
        | HW_UXN;

    // SAFETY: Volatile write to a valid L3 PTE slot.
    unsafe {
        core::ptr::write_volatile(&mut l3.entries[pte_idx], desc);
    }
    invlpg(virt_page);

    virt_page + (phys & page_mask)
}

// ---------------------------------------------------------------------------
// clear_boot_identity_map()
// ---------------------------------------------------------------------------

/// Clear the bootloader identity mapping from the TTBR0 boot root.
///
/// Must be called AFTER all APs have booted. The kernel higher-half now lives
/// in a dedicated TTBR1 root, so removing TTBR0.L0[0] only drops the low boot
/// alias without tearing down kernel text/data mappings.
pub fn clear_boot_identity_map() {
    let cr3 = read_cr3();
    // SAFETY: cr3 → L0 table via the direct map.
    let l0 = unsafe { &mut *(phys_to_virt(cr3) as *mut PageTable) };
    // Write a zero descriptor (raw, bypass encode since 0 encodes to 0).
    // SAFETY: Volatile write to clear the L0[0] entry.
    unsafe {
        core::ptr::write_volatile(&mut l0.entries[0], 0);
    }

    // Flush to drop any stale identity-mapped TLB entries.
    flush_tlb_all();
}

unsafe fn clone_kernel_root(boot_root: u64) -> u64 {
    let kernel_root = pmm_alloc(&FrameOwner::KernelPrivate { subkind: KernelMetaKind::PageTable }).expect("Failed to allocate TTBR1 kernel root");

    // The boot root is still identity-mapped via TTBR0 at this point.
    let src = boot_root as *const u64;
    let dst = kernel_root as *mut u64;
    for i in 0..512 {
        // SAFETY: both roots are valid 4 KiB L0 tables reachable via the
        // boot identity mapping during early boot.
        unsafe {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }

    kernel_root
}
