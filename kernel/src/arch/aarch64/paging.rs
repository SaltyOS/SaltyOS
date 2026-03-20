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
    alloc_frame, mark_frame_kernel_runtime, mark_frame_pt_owned, phys_to_virt, PAGE_SIZE,
    PHYS_MAP_OFFSET,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum direct physical mapping size (512 GB cap)
const MAX_DIRECT_MAP_SIZE: usize = 512 * 1024 * 1024 * 1024;

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

/// Write the page table root (TTBR0_EL1) and issue an ISB.
///
/// # Safety
/// `value` must point to a valid, 4 KB-aligned page table hierarchy.
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: Caller guarantees value is a valid page table address.
    unsafe {
        core::arch::asm!(
            "msr TTBR0_EL1, {}",
            "isb",
            in(reg) value,
            options(nostack),
        );
    }
}

/// Invalidate the TLB entry for a single virtual address (inner-shareable).
pub fn invlpg(virt: u64) {
    // SAFETY: TLBI is always safe from EL1. The VA operand is shifted
    // right by 12 per the ARMv8 TLBI encoding.
    unsafe {
        let va_shifted = virt >> 12;
        core::arch::asm!(
            "tlbi vae1is, {}",
            "dsb ish",
            "isb",
            in(reg) va_shifted,
            options(nomem, nostack),
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
            options(nomem, nostack),
        );
    }
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

    // Step 2: Build the direct physical map sized to actual RAM.
    let max_phys = crate::mm::max_phys();
    // SAFETY: Single-threaded boot context, frame allocator initialized.
    unsafe {
        init_direct_map(max_phys);
    }

    // Step 3: Register kernel VSpace tracking (needed before any VSpace::new()).
    crate::mm::vspace::init_kernel_vspace(read_cr3());
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
unsafe fn init_direct_map(max_phys: u64) {
    let huge_page_size: usize = 2 * 1024 * 1024;
    let direct_map_size = core::cmp::min(
        ((max_phys as usize + (huge_page_size - 1)) / huge_page_size) * huge_page_size,
        MAX_DIRECT_MAP_SIZE,
    );
    if direct_map_size == 0 {
        return;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[PAGING] Direct map size: ");
        s.hex(direct_map_size as u64);
        s.puts(" (max_phys=");
        s.hex(max_phys);
        s.puts(")\n");
    }

    let cr3 = read_cr3();
    // Use identity mapping (bootloader maps low memory phys==virt via TTBR0).
    let l0_virt = cr3 as *mut u64;

    // L0 index for PHYS_MAP_OFFSET (0xFFFF_8000_0000_0000).
    // (0xFFFF_8000_0000_0000 >> 39) & 0x1FF = 256
    let l0_idx = ((PHYS_MAP_OFFSET >> 39) & 0x1FF) as usize;

    // --- L0 → L1 (equivalent to PML4 → PDPT) ---

    // SAFETY: l0_virt points to the bootloader L0 table via identity map.
    let l0e = unsafe { core::ptr::read_volatile(l0_virt.add(l0_idx)) };
    let l1_phys = if l0e & HW_VALID == 0 {
        let frame = alloc_frame().expect("Failed to allocate L1 table for direct map");
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

    let num_huge_pages = direct_map_size / huge_page_size;
    let entries_per_l2 = 512usize;
    let num_l2_tables = (num_huge_pages + entries_per_l2 - 1) / entries_per_l2;

    for l2_idx in 0..num_l2_tables {
        // SAFETY: l1_virt points to an L1 table via identity map.
        let l1e = unsafe { core::ptr::read_volatile(l1_virt.add(l2_idx)) };

        let l2_phys = if l1e & HW_VALID == 0 {
            let frame = alloc_frame().expect("Failed to allocate L2 table for direct map");
            // SAFETY: Freshly allocated, identity-mapped.
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
            }
            // L1 table descriptor.
            let desc = frame | HW_VALID | HW_TABLE_OR_PAGE;
            // SAFETY: Writing to L1 entry via identity map.
            unsafe {
                core::ptr::write_volatile(l1_virt.add(l2_idx), desc);
            }
            frame
        } else {
            l1e & HW_ADDR_MASK
        };

        let l2_virt = l2_phys as *mut u64;

        // Fill L2 with 2 MB block descriptors.
        for entry_idx in 0..entries_per_l2 {
            let phys_addr = ((l2_idx * entries_per_l2 + entry_idx) * huge_page_size) as u64;
            if phys_addr >= direct_map_size as u64 {
                break;
            }

            // Block descriptor: bits[1:0] = 0b01 (Valid, not Table)
            // AttrIdx = 2 (Normal-WB), SH = Inner Shareable, AF = 1
            // AP = RW (AP[2]=0), UXN = 1 (no execute from direct map)
            let desc = phys_addr
                | HW_VALID              // bit 0 (block: 0b01)
                | HW_AF                 // bit 10
                | HW_SH_IS             // bits 9:8
                | (MAIR_IDX_NORMAL_WB << HW_ATTRINDX_SHIFT) // bits 4:2
                | HW_UXN;              // bit 54

            // SAFETY: Writing to L2 entry via identity map.
            unsafe {
                core::ptr::write_volatile(l2_virt.add(entry_idx), desc);
            }
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

    let frame = alloc_frame().expect(context);
    mark_frame_pt_owned(frame);
    mark_frame_kernel_runtime(frame);

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

    let cr3 = read_cr3();
    // SAFETY: CR3 points at the active kernel L0 table, reachable via the
    // already-established direct map.
    let l0 = unsafe { &mut *(phys_to_virt(cr3) as *mut PageTable) };

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

/// Clear the bootloader identity mapping (L0[0]).
///
/// Must be called AFTER all APs have booted. On aarch64 the AP trampoline
/// executes in low physical memory via TTBR0. Once all APs are in
/// higher-half kernel code, L0[0] can be safely cleared.
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
