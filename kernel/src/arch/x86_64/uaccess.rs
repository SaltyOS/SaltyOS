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

use core::sync::atomic::{AtomicBool, Ordering};

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
            core::arch::asm!("stac", options(nomem, nostack));
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
            core::arch::asm!("clac", options(nomem, nostack));
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
        unsafe { stac(); }
        Self
    }
}

impl Drop for UserAccessGuard {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: Restoring SMAP protection that was relaxed in new().
        unsafe { clac(); }
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

/// Copy a value of type `T` from user-space address `addr`.
///
/// Returns `None` if the address is not in the valid user range.
///
/// # Safety
/// The user address must point to a mapped, readable page. If the page
/// is not mapped, this will #PF. Caller is responsible for ensuring the
/// page exists (e.g., via VSpace resolve_page check).
pub unsafe fn copy_from_user<T: Copy>(addr: u64) -> Option<T> {
    if !validate_user_range(addr, core::mem::size_of::<T>()) {
        return None;
    }
    let _guard = UserAccessGuard::new();
    // SAFETY: Address validated above; SMAP relaxed by guard; caller
    // ensures page is mapped.
    let val = unsafe { core::ptr::read_volatile(addr as *const T) };
    Some(val)
}

/// Write a value of type `T` to user-space address `addr`.
///
/// Returns `false` if the address is not in the valid user range.
///
/// # Safety
/// The user address must point to a mapped, writable page.
pub unsafe fn copy_to_user<T: Copy>(addr: u64, val: &T) -> bool {
    if !validate_user_range(addr, core::mem::size_of::<T>()) {
        return false;
    }
    let _guard = UserAccessGuard::new();
    // SAFETY: Address validated above; SMAP relaxed by guard; caller
    // ensures page is mapped and writable.
    unsafe { core::ptr::write_volatile(addr as *mut T, *val); }
    true
}
