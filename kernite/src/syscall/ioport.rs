// SPDX-License-Identifier: GPL-2.0-only
//! I/O port range invocation handlers.
//!
//! Each invocation takes a `cap` to an `IoPortRange` object, validates
//! that `arg0` (the requested port) lies inside `[base_port,
//! base_port + num_ports)`, and performs the requested in/out.
//! The cap's `WRITE` right gates `OUT_*` ops, `READ` gates `IN_*`.
//!
//! Reads surface the value in `SyscallResult.value`; writes return a
//! plain 0.
//!
//! On aarch64 the underlying `arch::in*` / `arch::out*` helpers are
//! `panic!` stubs — the dispatcher never reaches an `IoPort` cap on
//! that arch (no IoPortRange retype recipe is published), so this
//! file's port-range check is the only thing that needs to compile
//! cross-arch.
use super::{CapRights, Capability, ObjectType, SyscallError, SyscallResult, validate_capability};
use crate::cap::ioport::IoPortRange;

/// Verify the requested port falls inside the IoPortRange's window.
fn check_port(range: &IoPortRange, port: u64) -> Result<u16, SyscallError> {
    if port > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let port = port as u16;
    let base = range.base_port;
    let end = base.saturating_add(range.num_ports);
    if port < base || port >= end {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(port)
}

#[inline]
fn range_from(cap: &Capability) -> *mut IoPortRange {
    cap.object as *mut IoPortRange
}

pub(super) fn syscall_ioport_read_8(cap: &Capability, port: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let range = range_from(cap);
    if range.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    let port = match unsafe { check_port(&*range, port) } {
        Ok(p) => p,
        Err(e) => return SyscallResult::err(e),
    };
    let value = unsafe { crate::arch::inb(port) } as u64;
    SyscallResult::ok(value)
}

pub(super) fn syscall_ioport_read_16(cap: &Capability, port: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let range = range_from(cap);
    if range.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    let port = match unsafe { check_port(&*range, port) } {
        Ok(p) => p,
        Err(e) => return SyscallResult::err(e),
    };
    // 16-bit read needs `port..port+2` to lie inside the window.
    if (port as u32) + 1 >= unsafe { (*range).base_port as u32 + (*range).num_ports as u32 } {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let value = unsafe { crate::arch::inw(port) } as u64;
    SyscallResult::ok(value)
}

pub(super) fn syscall_ioport_read_32(cap: &Capability, port: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let range = range_from(cap);
    if range.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    let port = match unsafe { check_port(&*range, port) } {
        Ok(p) => p,
        Err(e) => return SyscallResult::err(e),
    };
    if (port as u32) + 3 >= unsafe { (*range).base_port as u32 + (*range).num_ports as u32 } {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let value = unsafe { crate::arch::inl(port) } as u64;
    SyscallResult::ok(value)
}

pub(super) fn syscall_ioport_write_8(cap: &Capability, port: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let range = range_from(cap);
    if range.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    let port = match unsafe { check_port(&*range, port) } {
        Ok(p) => p,
        Err(e) => return SyscallResult::err(e),
    };
    unsafe { crate::arch::outb(port, value as u8) };
    SyscallResult::ok(0)
}

pub(super) fn syscall_ioport_write_16(cap: &Capability, port: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let range = range_from(cap);
    if range.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    let port = match unsafe { check_port(&*range, port) } {
        Ok(p) => p,
        Err(e) => return SyscallResult::err(e),
    };
    if (port as u32) + 1 >= unsafe { (*range).base_port as u32 + (*range).num_ports as u32 } {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    unsafe { crate::arch::outw(port, value as u16) };
    SyscallResult::ok(0)
}

pub(super) fn syscall_ioport_write_32(cap: &Capability, port: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let range = range_from(cap);
    if range.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    let port = match unsafe { check_port(&*range, port) } {
        Ok(p) => p,
        Err(e) => return SyscallResult::err(e),
    };
    if (port as u32) + 3 >= unsafe { (*range).base_port as u32 + (*range).num_ports as u32 } {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    unsafe { crate::arch::outl(port, value as u32) };
    SyscallResult::ok(0)
}
