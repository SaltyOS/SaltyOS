//! User memory access control — SMAP (Supervisor Mode Access Prevention) on x86_64.
//!
//! When SMAP is enabled (CR4.SMAP=1), any kernel-mode access to a user-mode
//! page causes a #PF unless EFLAGS.AC is temporarily set via `stac`.
//!
//! This module provides:
//! - `stac()` / `clac()` primitives (runtime-gated by SMAP detection)
//! - RAII `UserAccessGuard` for exception-safe user memory access
//! - `copy_from_user` / `copy_to_user` helpers with address validation
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

unsafe extern "C" {
    fn x86_uaccess_stac();
    fn x86_uaccess_clac();
}

/// Maximum valid user-space address (canonical lower half).
const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Runtime flag set to `true` once CR4.SMAP is enabled.
/// On CPUs without SMAP support, this stays `false` and stac/clac become no-ops.
static SMAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Mark SMAP as active. Called from `fpu.rs` after setting CR4.SMAP.
pub fn enable_smap_runtime() {
    SMAP_ACTIVE.store(true, Ordering::Release);
}

/// Set EFLAGS.AC to allow supervisor access to user pages (SMAP bypass).
///
/// No-op if SMAP is not supported/enabled on this CPU.
///
/// # Safety
/// Caller must ensure `clac()` is called promptly after user access completes.
#[inline(always)]
pub unsafe fn stac() {
    if SMAP_ACTIVE.load(Ordering::Relaxed) {
        // SAFETY: SMAP is confirmed active; stac sets EFLAGS.AC.
        unsafe {
            x86_uaccess_stac();
        }
    }
}

/// Clear EFLAGS.AC to re-enable SMAP protection.
///
/// No-op if SMAP is not supported/enabled on this CPU.
///
/// # Safety
/// Must be called to restore SMAP protection after a `stac()` call.
#[inline(always)]
pub unsafe fn clac() {
    if SMAP_ACTIVE.load(Ordering::Relaxed) {
        // SAFETY: SMAP is confirmed active; clac clears EFLAGS.AC.
        unsafe {
            x86_uaccess_clac();
        }
    }
}

/// RAII guard that enables user memory access on creation and
/// restores SMAP protection on drop.
///
/// ```rust
/// let _guard = UserAccessGuard::new();
/// // ... access user memory ...
/// // clac() called automatically on drop
/// ```
pub struct UserAccessGuard;

impl UserAccessGuard {
    /// Create a new guard, executing `stac` to allow user memory access.
    #[inline(always)]
    pub fn new() -> Self {
        // SAFETY: We pair this stac with clac in Drop.
        unsafe {
            stac();
        }
        Self
    }
}

impl Drop for UserAccessGuard {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: Restoring SMAP protection that was relaxed in new().
        unsafe {
            clac();
        }
    }
}

/// Validate that `[addr, addr + size)` is entirely within user address space.
#[inline]
fn validate_user_range(addr: u64, size: usize) -> bool {
    if addr >= USER_ADDR_LIMIT {
        return false;
    }
    match addr.checked_add(size as u64) {
        Some(end) => end <= USER_ADDR_LIMIT,
        None => false,
    }
}

#[inline]
fn current_vspace_root() -> Option<*mut crate::mm::VSpace> {
    let current = crate::sched::scheduler::scheduler().current();
    if current.is_null() {
        return None;
    }
    let vspace = unsafe { (*current).vspace_root };
    if vspace.is_null() {
        return None;
    }
    Some(vspace)
}

/// Copy raw bytes from the current thread's user address space into kernel memory.
///
/// Returns `false` when the range is out of user space or any covered page is not
/// currently mapped in the active thread's VSpace.
pub unsafe fn copy_from_user_bytes(addr: u64, dst: *mut u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !validate_user_range(addr, len) {
        return false;
    }

    let Some(vspace) = current_vspace_root() else {
        return false;
    };

    let mut copied = 0usize;
    while copied < len {
        let cur = addr + copied as u64;
        let page_off = cur as usize & (crate::mm::PAGE_SIZE - 1);
        let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, len - copied);
        let phys = match unsafe { (&*vspace).resolve_page(cur) } {
            Some(phys) => phys,
            None => return false,
        };
        let src = (crate::mm::phys_to_virt(phys) as *const u8).wrapping_add(page_off);
        unsafe {
            ptr::copy_nonoverlapping(src, dst.add(copied), chunk);
        }
        copied += chunk;
    }

    true
}

/// Copy raw bytes from kernel memory into the current thread's user address space.
///
/// Returns `false` when the range is out of user space or any covered page cannot
/// be made writable in the active thread's VSpace.
pub unsafe fn copy_to_user_bytes(addr: u64, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !validate_user_range(addr, len) {
        return false;
    }

    let Some(vspace) = current_vspace_root() else {
        return false;
    };

    let mut copied = 0usize;
    while copied < len {
        let cur = addr + copied as u64;
        let page_off = cur as usize & (crate::mm::PAGE_SIZE - 1);
        let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, len - copied);
        let vspace_ref = unsafe { &mut *vspace };
        if !vspace_ref.ensure_writable(cur) {
            return false;
        }
        let phys = match vspace_ref.resolve_page(cur) {
            Some(phys) => phys,
            None => return false,
        };
        let dst = (crate::mm::phys_to_virt(phys) as *mut u8).wrapping_add(page_off);
        unsafe {
            ptr::copy_nonoverlapping(src.add(copied), dst, chunk);
        }
        copied += chunk;
    }

    true
}

/// Copy a value of type `T` from user-space address `addr`.
///
/// Returns `None` if the address is not in the valid user range or is not
/// fully readable in the current thread's VSpace.
pub unsafe fn copy_from_user<T: Copy>(addr: u64) -> Option<T> {
    let mut value = MaybeUninit::<T>::uninit();
    if !unsafe {
        copy_from_user_bytes(
            addr,
            value.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<T>(),
        )
    } {
        return None;
    }
    Some(unsafe { value.assume_init() })
}

/// Write a value of type `T` to user-space address `addr`.
///
/// Returns `false` if the address is not in the valid user range or is not
/// fully writable in the current thread's VSpace.
pub unsafe fn copy_to_user<T: Copy>(addr: u64, val: &T) -> bool {
    unsafe {
        copy_to_user_bytes(
            addr,
            (val as *const T).cast::<u8>(),
            core::mem::size_of::<T>(),
        )
    }
}
