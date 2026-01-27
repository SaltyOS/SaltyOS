//! Virtual Address Space
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PhysAddr, VirtAddr, PAGE_SIZE, alloc_frame, phys_to_virt};
use crate::arch::x86_64::paging::PageTable;

/// Page table entry flag bits
const ENTRY_PRESENT: u64 = 1 << 0;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_USER: u64 = 1 << 2;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;

/// Physical address mask in page table entry
const ENTRY_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Virtual address space (wraps page table root)
#[repr(C)]
pub struct VSpace {
    /// Physical address of PML4
    root: PhysAddr,
}

impl VSpace {
    pub fn new(pml4_addr: PhysAddr) -> Self {
        Self { root: pml4_addr }
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// Extract PML4 index from virtual address
    #[inline]
    fn pml4_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 39) & 0x1FF) as usize
    }

    /// Extract PDPT index from virtual address
    #[inline]
    fn pdpt_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 30) & 0x1FF) as usize
    }

    /// Extract PD index from virtual address
    #[inline]
    fn pd_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 21) & 0x1FF) as usize
    }

    /// Extract PT index from virtual address
    #[inline]
    fn pt_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 12) & 0x1FF) as usize
    }

    /// Get PML4 table (root) as mutable reference
    fn pml4(&self) -> *mut PageTable {
        phys_to_virt(self.root) as *mut PageTable
    }

    /// Read page table entry at specified level
    /// level: 1=PT, 2=PD, 3=PDPT, 4=PML4
    /// Returns None if entry or table doesn't exist
    fn read_entry(&self, vaddr: VirtAddr, level: usize) -> Option<u64> {
        let pml4 = unsafe { &*self.pml4() };

        match level {
            4 => Some(pml4.entry(Self::pml4_index(vaddr))),
            3 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };
                Some(pdpt.entry(Self::pdpt_index(vaddr)))
            }
            2 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pd = unsafe { &*(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *const PageTable) };
                Some(pd.entry(Self::pd_index(vaddr)))
            }
            1 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pd = unsafe { &*(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *const PageTable) };
                let pde = pd.entry(Self::pd_index(vaddr));
                if pde & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pt = unsafe { &*(phys_to_virt(pde & ENTRY_ADDR_MASK) as *const PageTable) };
                Some(pt.entry(Self::pt_index(vaddr)))
            }
            _ => None,
        }
    }

    /// Ensure page table exists at specified level, creating if needed
    /// level: 1=PT, 2=PD, 3=PDPT
    /// Returns physical address of the page table
    fn ensure_table(&mut self, vaddr: VirtAddr, level: usize, is_user: bool)
        -> Result<PhysAddr, VSpaceError>
    {
        let user_flag = if is_user { ENTRY_USER } else { 0 };
        let table_flags = ENTRY_PRESENT | ENTRY_WRITABLE | user_flag;

        // Walk from PML4 down to target level
        let mut current_table: PhysAddr = self.root;
        let mut current_level = 4;

        while current_level > level {
            let table = unsafe { &mut *(phys_to_virt(current_table) as *mut PageTable) };
            let idx = match current_level {
                4 => Self::pml4_index(vaddr),
                3 => Self::pdpt_index(vaddr),
                2 => Self::pd_index(vaddr),
                _ => unreachable!(),
            };

            let entry = table.entry(idx);

            // If entry doesn't exist, create a new page table
            if entry & ENTRY_PRESENT == 0 {
                let new_frame = alloc_frame().ok_or(VSpaceError::OutOfMemory)?;
                let new_table_virt = phys_to_virt(new_frame) as *mut PageTable;

                // Zero the new page table
                unsafe {
                    core::ptr::write_bytes(new_table_virt, 0, 1);
                }

                // Set the entry
                table.set_entry(idx, new_frame | table_flags);

                current_table = new_frame;
            } else {
                current_table = entry & ENTRY_ADDR_MASK;
            }

            current_level -= 1;
        }

        Ok(current_table)
    }

    /// Write page table entry at specified level
    /// level: 1=PT, 2=PD, 3=PDPT, 4=PML4
    fn write_entry(&mut self, vaddr: VirtAddr, level: usize, value: u64)
        -> Result<(), VSpaceError>
    {
        let pml4 = unsafe { &mut *self.pml4() };

        match level {
            4 => {
                pml4.set_entry(Self::pml4_index(vaddr), value);
                Ok(())
            }
            3 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pdpt = unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
                pdpt.set_entry(Self::pdpt_index(vaddr), value);
                Ok(())
            }
            2 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pdpt = unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pd = unsafe { &mut *(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *mut PageTable) };
                pd.set_entry(Self::pd_index(vaddr), value);
                Ok(())
            }
            1 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pdpt = unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pd = unsafe { &mut *(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *mut PageTable) };
                let pde = pd.entry(Self::pd_index(vaddr));
                if pde & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pt = unsafe { &mut *(phys_to_virt(pde & ENTRY_ADDR_MASK) as *mut PageTable) };
                pt.set_entry(Self::pt_index(vaddr), value);
                Ok(())
            }
            _ => Err(VSpaceError::NotMapped),
        }
    }

    /// Convert PageFlags to page table entry flags
    fn flags_to_entry_flags(flags: PageFlags) -> u64 {
        let mut entry = ENTRY_PRESENT;

        if flags.writable {
            entry |= ENTRY_WRITABLE;
        }

        if flags.user {
            entry |= ENTRY_USER;
        }

        if !flags.executable {
            entry |= ENTRY_NO_EXECUTE;
        }

        entry
    }

    /// Map a page
    pub fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        // Check alignment
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        if phys & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        // Ensure all intermediate page tables exist
        self.ensure_table(virt, 1, flags.user)?;

        // Check if already mapped
        if let Some(entry) = self.read_entry(virt, 1) {
            if entry & ENTRY_PRESENT != 0 {
                return Err(VSpaceError::AlreadyMapped);
            }
        }

        // Create the mapping
        let entry_flags = Self::flags_to_entry_flags(flags);
        self.write_entry(virt, 1, phys | entry_flags)?;

        // Flush TLB for this page
        crate::arch::x86_64::paging::invlpg(virt);

        Ok(())
    }

    /// Unmap a page
    pub fn unmap(&mut self, virt: VirtAddr) -> Result<(), VSpaceError> {
        // Check alignment
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        // Check if mapped
        let entry = self.read_entry(virt, 1).ok_or(VSpaceError::NotMapped)?;
        if entry & ENTRY_PRESENT == 0 {
            return Err(VSpaceError::NotMapped);
        }

        // Clear the entry
        self.write_entry(virt, 1, 0)?;

        // Flush TLB for this page
        crate::arch::x86_64::paging::invlpg(virt);

        Ok(())
    }

    /// Switch to this address space
    pub unsafe fn activate(&self) {
        // SAFETY: Caller ensures this VSpace has valid page tables
        unsafe {
            crate::arch::x86_64::paging::write_cr3(self.root);
        }
    }
}

/// Page mapping flags
#[derive(Clone, Copy)]
pub struct PageFlags {
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
}

impl PageFlags {
    pub const KERNEL_RO: Self = Self {
        writable: false,
        user: false,
        executable: false,
    };

    pub const KERNEL_RW: Self = Self {
        writable: true,
        user: false,
        executable: false,
    };

    pub const KERNEL_RX: Self = Self {
        writable: false,
        user: false,
        executable: true,
    };

    pub const USER_RO: Self = Self {
        writable: false,
        user: true,
        executable: false,
    };

    pub const USER_RW: Self = Self {
        writable: true,
        user: true,
        executable: false,
    };

    pub const USER_RX: Self = Self {
        writable: false,
        user: true,
        executable: true,
    };
}

#[derive(Debug)]
pub enum VSpaceError {
    Alignment,
    AlreadyMapped,
    NotMapped,
    OutOfMemory,
}

impl core::fmt::Display for VSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VSpaceError::Alignment => write!(f, "Address not aligned to page boundary"),
            VSpaceError::AlreadyMapped => write!(f, "Page is already mapped"),
            VSpaceError::NotMapped => write!(f, "Page is not mapped"),
            VSpaceError::OutOfMemory => write!(f, "Out of memory for page table allocation"),
        }
    }
}
