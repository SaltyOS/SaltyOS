//! Child process virtual address layout planner.
//!
//! Computes a `VmLayoutPlan` for a child process based on the actual sizes
//! of its ELF, RTLD, and shared library regions. Eliminates hardcoded VA
//! constants across init and procmgr.
//!
//! Supports ASLR via `compute_vm_layout_randomized()`, which applies random
//! page-aligned offsets to the code base and stack base.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Number of 4K stack pages allocated per child process (default 16K stack).
pub const CHILD_STACK_PAGES: usize = 4;

// ---- Default VA addresses (private to layout computation) ----
// These define the canonical user address space layout within the first
// 2MiB and second 2MiB windows. If code regions overflow the first window,
// the stack is relocated to the second window.
const IPC_BUF_BASE: u64 = 0x0000_0000_0020_0000;
const ELF_CODE_BASE: u64 = 0x0000_0000_0021_0000;
const DEFAULT_STACK_BASE: u64 = 0x0000_0000_003F_8000;
const DEFAULT_SCRATCH_BASE: u64 = 0x0000_0000_003F_F000;
const DEFAULT_STACK_TOP: u64 = DEFAULT_STACK_BASE + (CHILD_STACK_PAGES as u64) * 0x1000;
const INITRD_BASE: u64 = 0x0000_0000_0100_0000;
/// Gap between existing mapped regions and the start of mmap allocations.
const MMAP_BASE_GAP: u64 = 0x1000_0000; // 256 MiB

// Second 2MiB window for stack relocation
const WINDOW2_STACK_BASE: u64 = 0x0000_0000_007F_8000;
const WINDOW2_SCRATCH_BASE: u64 = 0x0000_0000_007F_F000;

/// A contiguous page-aligned region in the child's virtual address space.
#[derive(Clone, Copy)]
pub struct VmRegion {
    /// Starting virtual address (page-aligned).
    pub base: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
}

impl VmRegion {
    /// An empty region (base=0, size=0).
    pub const fn zero() -> Self {
        VmRegion { base: 0, size: 0 }
    }
    /// Virtual address one byte past the end of this region.
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }
    /// Number of 4K pages in this region.
    pub const fn page_count(&self) -> usize {
        (self.size / 0x1000) as usize
    }
}

/// Complete virtual address layout for a child process.
///
/// Each field is a `VmRegion` describing a contiguous mapping. Regions with
/// `size == 0` are unused. `stack_top == 0` signals layout failure (code
/// regions overflow all available windows).
#[derive(Clone, Copy)]
pub struct VmLayoutPlan {
    /// IPC buffer page (1 page).
    pub ipc_buf: VmRegion,
    /// ELF code/data segments.
    pub elf_code: VmRegion,
    /// Runtime dynamic linker (rtld).
    pub rtld: VmRegion,
    /// Shared library cache region.
    pub shared_libs: VmRegion,
    /// User stack.
    pub stack: VmRegion,
    /// Scratch page for ELF loader page-copy operations.
    pub scratch: VmRegion,
    /// Initrd CPIO archive mapping window.
    pub initrd: VmRegion,
    /// Top of stack (initial RSP value).
    pub stack_top: u64,
}

impl VmLayoutPlan {
    pub const fn zeroed() -> Self {
        VmLayoutPlan {
            ipc_buf: VmRegion { base: 0, size: 0 },
            elf_code: VmRegion { base: 0, size: 0 },
            rtld: VmRegion { base: 0, size: 0 },
            shared_libs: VmRegion { base: 0, size: 0 },
            stack: VmRegion { base: 0, size: 0 },
            scratch: VmRegion { base: 0, size: 0 },
            initrd: VmRegion { base: 0, size: 0 },
            stack_top: 0,
        }
    }

    /// End of the highest code region (shared_libs > rtld > elf_code).
    pub fn code_end(&self) -> u64 {
        if self.shared_libs.size > 0 {
            self.shared_libs.end()
        } else if self.rtld.size > 0 {
            self.rtld.end()
        } else {
            self.elf_code.end()
        }
    }

    /// Starting address for the heap. Above all code, stack, and scratch
    /// regions to prevent upward heap growth from colliding with them.
    pub fn heap_base(&self) -> u64 {
        let mut highest = self.code_end();
        if self.stack.size > 0 && self.stack.end() > highest {
            highest = self.stack.end();
        }
        if self.scratch.size > 0 && self.scratch.end() > highest {
            highest = self.scratch.end();
        }
        if self.initrd.size > 0 && self.initrd.end() > highest {
            highest = self.initrd.end();
        }
        page_align_up(highest)
    }

    /// Highest mapped virtual end address across all planned regions.
    pub fn max_mapped_end(&self) -> u64 {
        let mut high = 0u64;
        let regions = [
            self.ipc_buf,
            self.elf_code,
            self.rtld,
            self.shared_libs,
            self.stack,
            self.scratch,
            self.initrd,
        ];
        for r in regions {
            if r.size == 0 {
                continue;
            }
            let end = r.end();
            if end > high {
                high = end;
            }
        }
        high
    }
}

/// Round up to the next 4K page boundary.
fn page_align_up(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

/// Compute a collision-safe default mmap base for a process layout.
///
/// Starts after the highest currently-mapped VA region and heap base, with a
/// fixed guard gap to keep brk growth and anonymous mmap naturally separated.
pub fn compute_mmap_base(plan: &VmLayoutPlan, heap_base: u64) -> u64 {
    let high = core::cmp::max(plan.max_mapped_end(), heap_base);
    page_align_up(high.saturating_add(MMAP_BASE_GAP))
}

/// Compute a dynamic VA layout for a child process.
///
/// Given the actual byte spans of the ELF and RTLD, plus shared library
/// page count and initrd window size, returns a complete layout plan.
/// If the code regions overflow both 2MiB windows, returns a plan with
/// `stack_top == 0` to signal failure.
pub fn compute_vm_layout(
    elf_span: u64,
    rtld_span: u64,
    shared_lib_cache_pages: usize,
    map_initrd: bool,
    initrd_window_size: usize,
) -> VmLayoutPlan {
    let ipc_buf = VmRegion { base: IPC_BUF_BASE, size: 0x1000 };
    let elf_code = VmRegion { base: ELF_CODE_BASE, size: page_align_up(elf_span) };

    let rtld = if rtld_span > 0 {
        let base = page_align_up(elf_code.end() + 0x1000);
        VmRegion { base, size: page_align_up(rtld_span) }
    } else {
        VmRegion::zero()
    };

    let shared_libs = if shared_lib_cache_pages > 0 && rtld.size > 0 {
        let base = page_align_up(rtld.end() + 0x1000);
        VmRegion { base, size: (shared_lib_cache_pages as u64) * 0x1000 }
    } else {
        VmRegion::zero()
    };

    let code_end = if shared_libs.size > 0 {
        shared_libs.end()
    } else if rtld.size > 0 {
        rtld.end()
    } else {
        elf_code.end()
    };

    let stack_size = (CHILD_STACK_PAGES as u64) * 0x1000;

    let (stack, scratch, stack_top) = if code_end <= DEFAULT_STACK_BASE {
        (
            VmRegion { base: DEFAULT_STACK_BASE, size: stack_size },
            VmRegion { base: DEFAULT_SCRATCH_BASE, size: 0x1000 },
            DEFAULT_STACK_TOP,
        )
    } else if code_end <= WINDOW2_STACK_BASE {
        let stk = VmRegion { base: WINDOW2_STACK_BASE, size: stack_size };
        (
            stk,
            VmRegion { base: WINDOW2_SCRATCH_BASE, size: 0x1000 },
            WINDOW2_STACK_BASE + stack_size,
        )
    } else {
        (VmRegion::zero(), VmRegion::zero(), 0)
    };

    let initrd = if map_initrd && initrd_window_size > 0 {
        VmRegion { base: INITRD_BASE, size: page_align_up(initrd_window_size as u64) }
    } else {
        VmRegion::zero()
    };

    VmLayoutPlan {
        ipc_buf,
        elf_code,
        rtld,
        shared_libs,
        stack,
        scratch,
        initrd,
        stack_top,
    }
}

/// Maximum ASLR slide for code base (in pages). 256 pages = 1 MiB entropy.
const ASLR_CODE_MAX_PAGES: u64 = 256;
/// Maximum ASLR slide for stack base (in pages). 64 pages = 256 KiB entropy.
const ASLR_STACK_MAX_PAGES: u64 = 64;

/// Compute a randomized VA layout for a child process (ASLR).
///
/// Applies random page-aligned offsets to the code base and stack base.
/// If `rand_u64` returns `None` (hardware RNG unavailable), falls back
/// to the deterministic layout.
///
/// `rand_u64` is a callback that returns a random u64.
pub fn compute_vm_layout_randomized(
    elf_span: u64,
    rtld_span: u64,
    shared_lib_cache_pages: usize,
    map_initrd: bool,
    initrd_window_size: usize,
    rand_u64: fn() -> Option<u64>,
) -> VmLayoutPlan {
    // Get random offsets; fall back to 0 if RNG unavailable
    let code_slide = match rand_u64() {
        Some(v) => (v % ASLR_CODE_MAX_PAGES) * 0x1000,
        None => 0,
    };
    let stack_slide = match rand_u64() {
        Some(v) => (v % ASLR_STACK_MAX_PAGES) * 0x1000,
        None => 0,
    };

    let ipc_buf = VmRegion { base: IPC_BUF_BASE, size: 0x1000 };

    let code_base = ELF_CODE_BASE + code_slide;
    let elf_code = VmRegion { base: code_base, size: page_align_up(elf_span) };

    let rtld = if rtld_span > 0 {
        let base = page_align_up(elf_code.end() + 0x1000);
        VmRegion { base, size: page_align_up(rtld_span) }
    } else {
        VmRegion::zero()
    };

    let shared_libs = if shared_lib_cache_pages > 0 && rtld.size > 0 {
        let base = page_align_up(rtld.end() + 0x1000);
        VmRegion { base, size: (shared_lib_cache_pages as u64) * 0x1000 }
    } else {
        VmRegion::zero()
    };

    let code_end = if shared_libs.size > 0 {
        shared_libs.end()
    } else if rtld.size > 0 {
        rtld.end()
    } else {
        elf_code.end()
    };

    let stack_size = (CHILD_STACK_PAGES as u64) * 0x1000;

    // Stack base with ASLR: slide down from default base (stack_slide reduces the
    // base address, creating a random gap above the code region).
    let (stack, scratch, stack_top) = if code_end <= DEFAULT_STACK_BASE.saturating_sub(stack_slide) {
        let sbase = DEFAULT_STACK_BASE - stack_slide;
        (
            VmRegion { base: sbase, size: stack_size },
            VmRegion { base: DEFAULT_SCRATCH_BASE, size: 0x1000 },
            sbase + stack_size,
        )
    } else if code_end <= WINDOW2_STACK_BASE.saturating_sub(stack_slide) {
        let sbase = WINDOW2_STACK_BASE - stack_slide;
        (
            VmRegion { base: sbase, size: stack_size },
            VmRegion { base: WINDOW2_SCRATCH_BASE, size: 0x1000 },
            sbase + stack_size,
        )
    } else {
        // Fall back to deterministic layout if ASLR causes overflow
        return compute_vm_layout(elf_span, rtld_span, shared_lib_cache_pages, map_initrd, initrd_window_size);
    };

    // Verify stack doesn't overlap scratch page
    if stack.end() > scratch.base {
        return compute_vm_layout(elf_span, rtld_span, shared_lib_cache_pages, map_initrd, initrd_window_size);
    }

    let initrd = if map_initrd && initrd_window_size > 0 {
        VmRegion { base: INITRD_BASE, size: page_align_up(initrd_window_size as u64) }
    } else {
        VmRegion::zero()
    };

    VmLayoutPlan {
        ipc_buf,
        elf_code,
        rtld,
        shared_libs,
        stack,
        scratch,
        initrd,
        stack_top,
    }
}
