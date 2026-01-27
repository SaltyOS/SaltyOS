//! Virtual Address Space
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PhysAddr, VirtAddr};

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

    /// Map a page
    pub fn map(
        &mut self,
        _virt: VirtAddr,
        _phys: PhysAddr,
        _flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        // TODO: Walk page tables and create mapping
        Ok(())
    }

    /// Unmap a page
    pub fn unmap(&mut self, _virt: VirtAddr) -> Result<(), VSpaceError> {
        // TODO: Walk page tables and remove mapping
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
    AlreadyMapped,
    NotMapped,
    OutOfMemory,
}
