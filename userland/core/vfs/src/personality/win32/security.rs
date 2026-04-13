// SPDX-License-Identifier: GPL-2.0-only
//! NT security descriptor — binary parsing and DACL-based access control.
//!
//! Windows files carry an NT security descriptor (owner SID, group SID,
//! DACL, SACL) queried via `GetFileSecurity` / `NtQuerySecurityObject`
//! and set via `SetFileSecurity` / `NtSetSecurityObject`.
//!
//! The raw descriptor bytes are persisted in the `"security.NTACL"` xattr.
//! This module parses the self-relative binary format, evaluates the DACL
//! against a client SID, and provides `check_nt_acl` for the dispatch layer
//! to call before `VopVector.access` for Win32 clients.
//!
//! ## Limitations
//!
//! - Only ACCESS_ALLOWED_ACE (type 0) and ACCESS_DENIED_ACE (type 1) are
//!   evaluated. Object-specific and callback ACE types are skipped.
//! - SACL (audit) is stored but not interpreted.
//! - SID-to-uid mapping uses a simplified 1:1 scheme for unknown SIDs.
//! - Maximum descriptor size is limited by the xattr backend's inline
//!   limit (typically 4096 bytes for ramfs/saltyfs).

use crate::server::types::ClientState;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::vop_context::{data_ctx_from_meta, VopContext};

/// Xattr name used to persist the raw NT security descriptor.
const NTACL_XATTR: &[u8] = b"security.NTACL";

/// Maximum security descriptor size we accept. NT descriptors in
/// practice are rarely larger than 4 KB; this prevents a rogue
/// client from stuffing unbounded data into the xattr.
const MAX_SECURITY_DESCRIPTOR_SIZE: usize = 4096;

// =========================================================================
// Security information flags (SECURITY_INFORMATION bitmask)
// =========================================================================

/// Owner SID portion of the security descriptor.
pub(crate) const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
/// Group SID portion.
pub(crate) const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
/// Discretionary ACL.
pub(crate) const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
/// System ACL.
pub(crate) const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;

// =========================================================================
// Security descriptor control flags
// =========================================================================

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;

// =========================================================================
// ACE types
// =========================================================================

const ACE_TYPE_ACCESS_ALLOWED: u8 = 0;
const ACE_TYPE_ACCESS_DENIED: u8 = 1;

// =========================================================================
// Security descriptor header offsets and sizes
// =========================================================================

const SD_HEADER_SIZE: usize = 20;
const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 8;
const SID_FIXED_SIZE: usize = 8;

// =========================================================================
// Well-known SIDs (binary self-relative format)
// =========================================================================

/// S-1-5-18 (NT AUTHORITY\SYSTEM) — maps to uid 0.
const SID_LOCAL_SYSTEM: [u8; 12] = [
    1, 1, // revision=1, sub_authority_count=1
    0, 0, 0, 0, 0, 5, // identifier_authority = 5 (NT Authority)
    18, 0, 0, 0, // sub_authorities[0] = 18 (LE)
];

/// S-1-5-32-544 (BUILTIN\Administrators) — maps to gid 0.
#[allow(dead_code)]
const SID_BUILTIN_ADMINS: [u8; 16] = [
    1, 2, // revision=1, sub_authority_count=2
    0, 0, 0, 0, 0, 5, // identifier_authority = 5 (NT Authority)
    32, 0, 0, 0, // sub_authorities[0] = 32 (BUILTIN)
    32, 2, 0, 0, // sub_authorities[1] = 544 (Administrators)
];

/// S-1-1-0 (Everyone) — matches all clients.
const SID_EVERYONE: [u8; 12] = [
    1, 1, // revision=1, sub_authority_count=1
    0, 0, 0, 0, 0, 1, // identifier_authority = 1 (World)
    0, 0, 0, 0, // sub_authorities[0] = 0
];

// =========================================================================
// Parsed SD references (zero-copy into the xattr buffer)
// =========================================================================

/// Borrowed reference to a SID within a security descriptor buffer.
#[derive(Clone, Copy)]
struct SidRef {
    data: *const u8,
    len: usize,
}

/// Borrowed reference to a DACL within a security descriptor buffer.
#[derive(Clone, Copy)]
struct DaclRef {
    data: *const u8,
    ace_count: u16,
}

/// Parsed security descriptor — borrows into the raw xattr buffer.
struct ParsedSd {
    owner_sid: SidRef,
    #[allow(dead_code)]
    group_sid: SidRef,
    dacl: Option<DaclRef>,
}

// =========================================================================
// Binary helpers
// =========================================================================

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

/// Compute the total size of a SID starting at `buf[off..]`.
/// Returns `None` if the SID header would read past `buf_len`.
fn sid_size(buf: &[u8], off: usize) -> Option<usize> {
    if off + SID_FIXED_SIZE > buf.len() {
        return None;
    }
    let sub_count = buf[off + 1] as usize;
    let total = SID_FIXED_SIZE + 4 * sub_count;
    if off + total > buf.len() {
        return None;
    }
    Some(total)
}

// =========================================================================
// SD parsing
// =========================================================================

/// Parse a self-relative NT security descriptor from raw bytes.
///
/// Validates the revision, control flags, and internal offsets. Returns
/// `None` if the buffer is malformed or too small.
fn parse_sd(buf: &[u8]) -> Option<ParsedSd> {
    if buf.len() < SD_HEADER_SIZE {
        return None;
    }

    let revision = buf[0];
    if revision != 1 {
        return None;
    }

    let control = read_u16_le(buf, 2);
    if control & SE_SELF_RELATIVE == 0 {
        return None;
    }

    let owner_off = read_u32_le(buf, 4) as usize;
    let group_off = read_u32_le(buf, 8) as usize;
    let _sacl_off = read_u32_le(buf, 12) as usize;
    let dacl_off = read_u32_le(buf, 16) as usize;

    // Owner SID is mandatory.
    if owner_off == 0 || owner_off >= buf.len() {
        return None;
    }
    let owner_len = sid_size(buf, owner_off)?;
    let owner_sid = SidRef {
        data: buf[owner_off..].as_ptr(),
        len: owner_len,
    };

    // Group SID is mandatory.
    if group_off == 0 || group_off >= buf.len() {
        return None;
    }
    let group_len = sid_size(buf, group_off)?;
    let group_sid = SidRef {
        data: buf[group_off..].as_ptr(),
        len: group_len,
    };

    // DACL is optional — absent means no explicit ACL (grant all).
    let dacl = if control & SE_DACL_PRESENT != 0 && dacl_off != 0 {
        if dacl_off + ACL_HEADER_SIZE > buf.len() {
            return None;
        }
        let acl_revision = buf[dacl_off];
        if acl_revision != 2 && acl_revision != 4 {
            return None;
        }
        let acl_size = read_u16_le(buf, dacl_off + 2) as usize;
        if dacl_off + acl_size > buf.len() {
            return None;
        }
        let ace_count = read_u16_le(buf, dacl_off + 4);
        Some(DaclRef {
            data: buf[dacl_off..].as_ptr(),
            ace_count,
        })
    } else {
        None
    };

    Some(ParsedSd {
        owner_sid,
        group_sid,
        dacl,
    })
}

// =========================================================================
// SID comparison
// =========================================================================

/// Byte-exact SID equality.
fn sid_equal(a: SidRef, b: SidRef) -> bool {
    if a.len != b.len {
        return false;
    }
    // SAFETY: Both `a.data` and `b.data` point into valid xattr or
    // static buffers of at least `a.len` bytes.
    for i in 0..a.len {
        unsafe {
            if *a.data.add(i) != *b.data.add(i) {
                return false;
            }
        }
    }
    true
}

/// Check whether `sid` is the S-1-1-0 (Everyone) SID.
fn sid_is_everyone(sid: SidRef) -> bool {
    let everyone = SidRef {
        data: SID_EVERYONE.as_ptr(),
        len: SID_EVERYONE.len(),
    };
    sid_equal(sid, everyone)
}

// =========================================================================
// SID <-> uid mapping
// =========================================================================

/// Build a SID for a POSIX uid: S-1-5-21-0-0-<uid>.
///
/// Writes into the caller-provided buffer and returns the byte length.
/// The buffer must be at least 28 bytes (fixed 8 + 5 sub-authorities * 4).
fn uid_to_sid(uid: u32, buf: &mut [u8; 28]) -> usize {
    // uid 0 maps to S-1-5-18 (SYSTEM).
    if uid == 0 {
        buf[..SID_LOCAL_SYSTEM.len()].copy_from_slice(&SID_LOCAL_SYSTEM);
        return SID_LOCAL_SYSTEM.len();
    }

    // Generic mapping: S-1-5-21-0-0-<uid> (5 sub-authorities, 28 bytes).
    buf[0] = 1; // revision
    buf[1] = 5; // sub_authority_count
    buf[2] = 0;
    buf[3] = 0;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 5; // NT Authority

    // sub_authorities[0] = 21 (SECURITY_NT_NON_UNIQUE)
    buf[8] = 21;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;

    // sub_authorities[1..2] = 0 (domain placeholder)
    buf[12] = 0;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 0;
    buf[16] = 0;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 0;

    // sub_authorities[3..4] = <uid> as RID
    buf[20] = 0;
    buf[21] = 0;
    buf[22] = 0;
    buf[23] = 0;
    buf[24] = uid as u8;
    buf[25] = (uid >> 8) as u8;
    buf[26] = (uid >> 16) as u8;
    buf[27] = (uid >> 24) as u8;

    28
}

/// Extract a uid from a SID. Returns the last sub_authority value for
/// unknown SIDs (1:1 mapping).
#[allow(dead_code)]
fn sid_to_uid(sid: SidRef) -> u32 {
    let sys = SidRef {
        data: SID_LOCAL_SYSTEM.as_ptr(),
        len: SID_LOCAL_SYSTEM.len(),
    };
    if sid_equal(sid, sys) {
        return 0;
    }

    // For any other SID, the uid is the last sub_authority.
    if sid.len < SID_FIXED_SIZE + 4 {
        return u32::MAX;
    }
    let sub_count = unsafe { *sid.data.add(1) } as usize;
    if sub_count == 0 {
        return u32::MAX;
    }
    let last_off = SID_FIXED_SIZE + 4 * (sub_count - 1);
    if last_off + 4 > sid.len {
        return u32::MAX;
    }
    unsafe {
        (*sid.data.add(last_off) as u32)
            | ((*sid.data.add(last_off + 1) as u32) << 8)
            | ((*sid.data.add(last_off + 2) as u32) << 16)
            | ((*sid.data.add(last_off + 3) as u32) << 24)
    }
}

// =========================================================================
// DACL evaluation
// =========================================================================

/// Evaluate a DACL against a requested access mask and client SID.
///
/// Iterates ACEs in order. Standard NT semantics: explicit DENY takes
/// precedence, then explicit ALLOW accumulates. If no ACE covers the
/// full requested mask, access is denied.
fn evaluate_dacl(dacl: &DaclRef, requested: u32, client_sid: SidRef) -> bool {
    if requested == 0 {
        return true;
    }

    let mut allowed_mask: u32 = 0;
    // SAFETY: `dacl.data` points into a validated xattr buffer.
    // ACE traversal uses the per-ACE `ace_size` field for bounds.
    let acl_size = unsafe { read_u16_le_raw(dacl.data, 2) } as usize;
    let mut offset: usize = ACL_HEADER_SIZE;

    for _ in 0..dacl.ace_count {
        if offset + ACE_HEADER_SIZE > acl_size {
            break;
        }

        let ace_type = unsafe { *dacl.data.add(offset) };
        let ace_size = unsafe { read_u16_le_raw(dacl.data, offset + 2) } as usize;

        if ace_size < ACE_HEADER_SIZE || offset + ace_size > acl_size {
            break;
        }

        // Only evaluate ALLOW and DENY types; skip object/callback ACEs.
        if ace_type != ACE_TYPE_ACCESS_ALLOWED && ace_type != ACE_TYPE_ACCESS_DENIED {
            offset += ace_size;
            continue;
        }

        let ace_mask = unsafe { read_u32_le_raw(dacl.data, offset + 4) };

        // SID starts at offset+8 within the ACE, length is remainder.
        let sid_off = offset + ACE_HEADER_SIZE;
        let sid_len = ace_size - ACE_HEADER_SIZE;
        if sid_len < SID_FIXED_SIZE {
            offset += ace_size;
            continue;
        }

        // Validate sub_authority_count vs available bytes.
        let sub_count = unsafe { *dacl.data.add(sid_off + 1) } as usize;
        let expected_sid_len = SID_FIXED_SIZE + 4 * sub_count;
        if expected_sid_len > sid_len {
            offset += ace_size;
            continue;
        }

        let ace_sid = SidRef {
            data: unsafe { dacl.data.add(sid_off) },
            len: expected_sid_len,
        };

        let matches = sid_equal(ace_sid, client_sid) || sid_is_everyone(ace_sid);

        if matches {
            if ace_type == ACE_TYPE_ACCESS_DENIED {
                if ace_mask & requested != 0 {
                    return false;
                }
            } else {
                allowed_mask |= ace_mask;
            }
        }

        offset += ace_size;
    }

    (allowed_mask & requested) == requested
}

/// Read a little-endian u16 from a raw pointer + offset.
///
/// # Safety
///
/// `base` must point to at least `off + 2` readable bytes.
#[inline]
unsafe fn read_u16_le_raw(base: *const u8, off: usize) -> u16 {
    unsafe { (*base.add(off) as u16) | ((*base.add(off + 1) as u16) << 8) }
}

/// Read a little-endian u32 from a raw pointer + offset.
///
/// # Safety
///
/// `base` must point to at least `off + 4` readable bytes.
#[inline]
unsafe fn read_u32_le_raw(base: *const u8, off: usize) -> u32 {
    unsafe {
        (*base.add(off) as u32)
            | ((*base.add(off + 1) as u32) << 8)
            | ((*base.add(off + 2) as u32) << 16)
            | ((*base.add(off + 3) as u32) << 24)
    }
}

// =========================================================================
// NT ACL access check (dispatch-layer entry point)
// =========================================================================

/// Check whether `client` is permitted `requested_access` on `vp` according
/// to the vnode's stored NT security descriptor.
///
/// Reads the `"security.NTACL"` xattr, parses the self-relative SD, maps
/// the client's cred_uid to a SID, and evaluates the DACL.
///
/// Returns `Ok(())` if access is granted, `Err(VfsError::Perm)` if denied.
/// If no SD is stored on the vnode, returns `Ok(())` — the absence of an
/// NT ACL means no NT-level restriction applies (the POSIX mode check in
/// `VopVector.access` still runs separately).
///
/// # Safety
///
/// `ctx` must reference a valid active vnode and mount. `client` must be a
/// valid pointer to an active `ClientState`.
pub(crate) unsafe fn check_nt_acl(
    ctx: &VopContext,
    requested_access: u32,
    client: *const ClientState,
) -> VfsResult<()> {
    let mut sd_buf = [0u8; MAX_SECURITY_DESCRIPTOR_SIZE];

    // SAFETY: caller guarantees `vp` and `client` validity.
    let sd_len = unsafe {
        get_security_descriptor(ctx, sd_buf.as_mut_ptr(), sd_buf.len())?
    };

    if sd_len == 0 {
        return Ok(());
    }

    let sd = match parse_sd(&sd_buf[..sd_len]) {
        Some(sd) => sd,
        None => return Ok(()),
    };

    let dacl = match sd.dacl {
        Some(ref d) => d,
        // SE_DACL_PRESENT not set or dacl_offset==0: no DACL means
        // full access granted (NT null-DACL semantics).
        None => return Ok(()),
    };

    // Build the client SID from cred_uid.
    let euid = unsafe { (*client).cred_uid };
    let mut client_sid_buf = [0u8; 28];
    let client_sid_len = uid_to_sid(euid, &mut client_sid_buf);
    let client_sid = SidRef {
        data: client_sid_buf.as_ptr(),
        len: client_sid_len,
    };

    // uid 0 (SYSTEM) bypasses DACL evaluation, matching NT's
    // SE_PRIVILEGE_ENABLED behavior for LocalSystem.
    if euid == 0 {
        return Ok(());
    }

    // Check if client is the owner — owners always get READ_CONTROL and
    // WRITE_DAC per NT semantics, but we simplify: owner bypass all.
    if sid_equal(client_sid, sd.owner_sid) {
        return Ok(());
    }

    if evaluate_dacl(dacl, requested_access, client_sid) {
        Ok(())
    } else {
        Err(VfsError::Perm)
    }
}

// =========================================================================
// Get / Set (raw xattr pass-through)
// =========================================================================

/// Read the raw NT security descriptor from the vnode's xattr store.
///
/// On success, returns the number of bytes written to `buf[..buf_len]`.
/// If the xattr does not exist, returns `Ok(0)` — the caller should
/// synthesize a default empty descriptor.
///
/// # Safety
///
/// `ctx` must reference a valid active vnode and mount. `buf` must point to
/// at least `buf_len` writable bytes.
pub(crate) unsafe fn get_security_descriptor(
    ctx: &VopContext,
    buf: *mut u8,
    buf_len: usize,
) -> VfsResult<usize> {
    unsafe {
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            return Err(VfsError::Io);
        }

        let data_ctx = data_ctx_from_meta(ctx);
        let result = ((*ops).data.getxattr)(
            &data_ctx,
            NTACL_XATTR.as_ptr(),
            NTACL_XATTR.len() as u8,
            buf,
            buf_len,
        );

        match result {
            Ok(n) => Ok(n),
            // Xattr not found — no descriptor stored yet.
            Err(VfsError::NotFound) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

/// Write a raw NT security descriptor to the vnode's xattr store.
///
/// The descriptor bytes are stored verbatim — no validation or
/// interpretation is performed.
///
/// # Safety
///
/// `ctx` must reference a valid active vnode and mount. `buf` must point to
/// at least `len` readable bytes.
pub(crate) unsafe fn set_security_descriptor(
    ctx: &VopContext,
    buf: *const u8,
    len: usize,
) -> VfsResult<()> {
    if len > MAX_SECURITY_DESCRIPTOR_SIZE {
        return Err(VfsError::TooLarge);
    }

    unsafe {
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            return Err(VfsError::Io);
        }

        let data_ctx = data_ctx_from_meta(ctx);
        ((*ops).data.setxattr)(
            &data_ctx,
            NTACL_XATTR.as_ptr(),
            NTACL_XATTR.len() as u8,
            buf,
            len,
            0, // no XATTR_CREATE / XATTR_REPLACE constraint
        )
    }
}
