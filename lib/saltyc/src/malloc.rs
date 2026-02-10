//! malloc/free/realloc/calloc — sbrk-based free-list allocator
//! SPDX-License-Identifier: GPL-2.0-only

use crate::errno;

/// Allocation header stored before each allocation
/// size includes the header itself
const HEADER_SIZE: usize = 16;

#[repr(C)]
struct BlockHeader {
    size: usize,   // total block size including header
    next: *mut BlockHeader, // next free block (only valid when free)
}

static mut FREE_LIST: *mut BlockHeader = core::ptr::null_mut();

/// Minimum allocation alignment
const ALIGN: usize = 16;

fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }

    let total = align_up(size + HEADER_SIZE, ALIGN);

    unsafe {
        // Search free list (first-fit)
        let mut prev: *mut BlockHeader = core::ptr::null_mut();
        let mut curr = FREE_LIST;

        while !curr.is_null() {
            if (*curr).size >= total {
                // Found a fit
                if (*curr).size >= total + HEADER_SIZE + ALIGN {
                    // Split the block
                    let new_block = (curr as *mut u8).add(total) as *mut BlockHeader;
                    (*new_block).size = (*curr).size - total;
                    (*new_block).next = (*curr).next;
                    (*curr).size = total;

                    if prev.is_null() {
                        FREE_LIST = new_block;
                    } else {
                        (*prev).next = new_block;
                    }
                } else {
                    // Use the whole block
                    if prev.is_null() {
                        FREE_LIST = (*curr).next;
                    } else {
                        (*prev).next = (*curr).next;
                    }
                }
                (*curr).next = core::ptr::null_mut();
                return (curr as *mut u8).add(HEADER_SIZE);
            }
            prev = curr;
            curr = (*curr).next;
        }

        // No free block found, get more memory from sbrk
        let ptr = salty::posix_mm::posix_sbrk(total as i64);
        if ptr == u64::MAX {
            errno::set_errno(errno::ENOMEM);
            return core::ptr::null_mut();
        }

        let header = ptr as *mut BlockHeader;
        (*header).size = total;
        (*header).next = core::ptr::null_mut();
        (header as *mut u8).add(HEADER_SIZE)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let header = ptr.sub(HEADER_SIZE) as *mut BlockHeader;

        // Insert into free list (sorted by address for coalescing)
        let mut prev: *mut BlockHeader = core::ptr::null_mut();
        let mut curr = FREE_LIST;

        while !curr.is_null() && (curr as usize) < (header as usize) {
            prev = curr;
            curr = (*curr).next;
        }

        // Try to coalesce with next block
        let header_end = (header as *mut u8).add((*header).size) as *mut BlockHeader;
        if header_end == curr {
            (*header).size += (*curr).size;
            (*header).next = (*curr).next;
        } else {
            (*header).next = curr;
        }

        // Try to coalesce with previous block
        if !prev.is_null() {
            let prev_end = (prev as *mut u8).add((*prev).size) as *mut BlockHeader;
            if prev_end == header {
                (*prev).size += (*header).size;
                (*prev).next = (*header).next;
            } else {
                (*prev).next = header;
            }
        } else {
            FREE_LIST = header;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    if ptr.is_null() {
        return unsafe { malloc(size) };
    }
    if size == 0 {
        unsafe { free(ptr) };
        return core::ptr::null_mut();
    }

    unsafe {
        let header = ptr.sub(HEADER_SIZE) as *const BlockHeader;
        let old_data_size = (*header).size - HEADER_SIZE;

        let new_ptr = malloc(size);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }

        let copy_size = if old_data_size < size {
            old_data_size
        } else {
            size
        };
        core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
        free(ptr);
        new_ptr
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let total = match nmemb.checked_mul(size) {
        Some(t) => t,
        None => {
            errno::set_errno(errno::ENOMEM);
            return core::ptr::null_mut();
        }
    };

    unsafe {
        let ptr = malloc(total);
        if !ptr.is_null() {
            core::ptr::write_bytes(ptr, 0, total);
        }
        ptr
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strdup(s: *const u8) -> *mut u8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let len = crate::string::strlen(s);
        let p = malloc(len + 1);
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(s, p, len + 1);
        }
        p
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strndup(s: *const u8, n: usize) -> *mut u8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let mut len = 0;
        while len < n && *s.add(len) != 0 {
            len += 1;
        }
        let p = malloc(len + 1);
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(s, p, len);
            *p.add(len) = 0;
        }
        p
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut u8,
    alignment: usize,
    size: usize,
) -> i32 {
    if alignment < core::mem::size_of::<*mut u8>() || !alignment.is_power_of_two() {
        return errno::EINVAL;
    }
    unsafe {
        let ptr = malloc(size + alignment);
        if ptr.is_null() {
            return errno::ENOMEM;
        }
        let aligned = ((ptr as usize + alignment - 1) & !(alignment - 1)) as *mut u8;
        *memptr = aligned;
        0
    }
}
