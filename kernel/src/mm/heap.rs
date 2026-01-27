//! Kernel Heap Allocator
//!
//! Bump allocator that expands on demand using physical frames.
//! Uses KERNEL_HEAP_BASE, NOT the direct map offset!

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use saltyos_ska::BootInfo;

use super::{VirtAddr, KERNEL_HEAP_BASE, PAGE_SIZE};
use crate::mm::{allocate_frame, deallocate_frame};
use crate::mm::vm::{map_page, frame_to_virt, PageFlags, unmap_page};

/// Heap base address
const HEAP_BASE: VirtAddr = VirtAddr::new(KERNEL_HEAP_BASE);

/// Initial heap size in pages
const INITIAL_PAGES: usize = 16; // 64 KiB

/// Current heap pointer
static HEAP_PTR: AtomicU64 = AtomicU64::new(KERNEL_HEAP_BASE);

/// Heap end pointer (exclusive)
static HEAP_END: AtomicU64 = AtomicU64::new(KERNEL_HEAP_BASE);

/// Heap mutex
static HEAP_LOCK: Mutex<()> = Mutex::new(());

/// Kernel error type
#[derive(Debug)]
pub enum KernelError {
    OutOfMemory,
    InvalidPointer,
}

/// Initialize the kernel heap
///
/// # Safety
/// Must be called after virtual memory initialization.
pub unsafe fn init(_bootinfo: &BootInfo) {
    // Track successfully mapped pages for cleanup on failure
    // INITIAL_PAGES is 16, so we can use a fixed-size array
    let mut mapped_count = 0usize;

    // Initial allocation: map INITIAL_PAGES pages
    for i in 0..INITIAL_PAGES {
        let frame = match allocate_frame() {
            Some(f) => f,
            None => {
                // Clean up previously mapped pages
                for j in 0..mapped_count {
                    let addr = VirtAddr::new(KERNEL_HEAP_BASE + (j as u64 * PAGE_SIZE));
                    let _ = unmap_page(addr); // unmap_page deallocates the frame
                }
                panic!("Failed to allocate initial heap pages");
            }
        };

        let addr = VirtAddr::new(KERNEL_HEAP_BASE + (i as u64 * PAGE_SIZE));
        if let Err(_) = map_page(addr, frame, PageFlags::PRESENT | PageFlags::WRITABLE) {
            // Clean up this frame and previously mapped pages
            deallocate_frame(frame);
            for j in 0..mapped_count {
                let addr = VirtAddr::new(KERNEL_HEAP_BASE + (j as u64 * PAGE_SIZE));
                let _ = unmap_page(addr); // unmap_page deallocates the frame
            }
            panic!("Failed to map initial heap page");
        }

        // Zero the page
        let virt = frame_to_virt(frame);
        core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, PAGE_SIZE as usize);

        mapped_count += 1;
    }

    HEAP_END.store(KERNEL_HEAP_BASE + (INITIAL_PAGES as u64 * PAGE_SIZE), Ordering::Release);
}

/// Expand the heap by one page
unsafe fn expand_heap() -> Result<(), KernelError> {
    let frame = allocate_frame().ok_or(KernelError::OutOfMemory)?;

    let current_end = HEAP_END.load(Ordering::Acquire);
    let new_addr = VirtAddr::new(current_end);

    if let Err(_) = map_page(new_addr, frame, PageFlags::PRESENT | PageFlags::WRITABLE) {
        deallocate_frame(frame);
        return Err(KernelError::OutOfMemory);
    }

    // Zero the new page
    let virt = frame_to_virt(frame);
    core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, PAGE_SIZE as usize);

    HEAP_END.store(current_end + PAGE_SIZE, Ordering::Release);
    Ok(())
}

/// Allocate memory from the kernel heap
///
/// # Safety
/// Must be called with valid size and alignment.
pub unsafe fn heap_alloc(size: usize, align: usize) -> Result<*mut u8, KernelError> {
    let _lock = HEAP_LOCK.lock();

    let ptr = HEAP_PTR.load(Ordering::Acquire);
    let end = HEAP_END.load(Ordering::Acquire);

    // Align pointer
    let align = align.max(1) as u64;
    let aligned_ptr = ((ptr + align - 1) & !(align - 1)) as u64;

    // Check if we need to expand
    let needed = aligned_ptr - ptr + size as u64;
    let available = end - aligned_ptr;

    if available < needed as u64 {
        // Expand heap
        let pages_needed = ((needed as u64 - available + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        for _ in 0..pages_needed {
            expand_heap()?;
        }
        let new_end = HEAP_END.load(Ordering::Acquire);
        let new_available = new_end - aligned_ptr;
        if new_available < needed as u64 {
            return Err(KernelError::OutOfMemory);
        }
    }

    // Update heap pointer
    HEAP_PTR.store(aligned_ptr + size as u64, Ordering::Release);

    Ok(aligned_ptr as *mut u8)
}

/// Free memory to the kernel heap
///
/// Note: This is a bump allocator, so we don't actually free memory.
/// This function exists for API compatibility only.
///
/// # Safety
/// Must be called with a pointer returned by heap_alloc.
pub unsafe fn heap_free(_ptr: *mut u8, _size: usize) {
    // Bump allocator doesn't support freeing individual allocations
    // In a real kernel, we would use a more sophisticated allocator
}
