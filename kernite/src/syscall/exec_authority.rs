// SPDX-License-Identifier: GPL-2.0-only
//! Exec-authority capability handlers.
//!
//! The exec-authority is the only kernel mechanism that introduces EXECUTE
//! into the system: `mo_mark_executable` derives a `READ|EXECUTE|GRANT|TRANSFER`
//! capability to an existing MemoryObject as a CDT child of the source MO cap.
//! `UntypedMemory::retype` never confers EXECUTE, so this gate is the sole
//! source of executable-memory authority — `ldsrv` holds it for code objects,
//! a JIT holder for anonymous executable memory.

use super::cspace::{resolve_confer_exec_request, with_cap_lock};
use super::{
    CapRights, Capability, ObjectType, SyscallResult, syscall_error_from_cap_error,
    validate_capability,
};

/// `mo_mark_executable(exec_authority, src_mo_cap, dest_cnode, dest_slot)`.
///
/// Gated by possession of an `ExecAuthority` cap with CONFIGURE. Derives a new
/// `READ|EXECUTE|GRANT|TRANSFER` capability to the same MemoryObject as the cap
/// at `src_mo_cap_ptr` (in the caller's root CSpace) into
/// `(dest_cnode_cap_ptr, dest_slot)`, as a CDT child of the source cap — so
/// revoking the source cascades to the conferred cap. The source cap is never
/// mutated and must be a readable MemoryObject: EXECUTE cannot be conferred on
/// an object the caller cannot even read.
pub(super) fn syscall_mo_mark_executable(
    cap: &Capability,
    src_mo_cap_ptr: u64,
    dest_cnode_cap_ptr: u64,
    dest_slot: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::ExecAuthority, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    unsafe {
        with_cap_lock(|| {
            let request =
                match resolve_confer_exec_request(src_mo_cap_ptr, dest_cnode_cap_ptr, dest_slot) {
                    Ok(v) => v,
                    Err(e) => return SyscallResult::err(e),
                };
            match request.confer_exec() {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}
