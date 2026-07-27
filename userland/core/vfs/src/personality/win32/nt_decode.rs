// SPDX-License-Identifier: GPL-2.0-only
//
//! NT inbound wire decoders.
//!
//! The Win32 personality uses the NT-native struct shapes
//! (`OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `IO_STATUS_BLOCK`,
//! `FILE_*_INFORMATION`) on the wire — see `super::types` for the
//! `#[repr(C)]` definitions. This module pulls the inbound
//! `TronaMsg::regs[..]` byte view back into those structs and
//! flattens the `UNICODE_STRING.Buffer` UTF-16 payload into a
//! UTF-8 path through [`super::utf16`].
//!
//! All decoders are layout-strict: misaligned / undersized / out
//! of bounds reads return `None` so the caller can surface
//! `STATUS_INVALID_PARAMETER` instead of trusting partial bytes.
//!
//! The wire packs `regs[..]` as a flat byte buffer — `regs[0]` is
//! the first 8 bytes, etc. Decoders index by byte offset for
//! direct alignment with the NT struct layouts.

#![allow(dead_code)]

use trona_kernel::core_types::TronaMsg;

use super::types::{
    FileBasicInformation, FileStandardInformation, IoStatusBlock, LargeInteger,
    ObjectAttributesHeader, UnicodeStringHeader,
};

/// Maximum NT path length the decoder will accept. Generous —
/// NT_MAX_PATH on Windows is 32767 wchars (= 65534 bytes), but
/// the saltyos walker caps at `WALK_PATH_MAX` and the regs[] area
/// is 256 bytes minus headers; the runtime cap below pins the
/// upper bound for a single inbound message.
pub(crate) const NT_PATH_BUFFER_MAX: usize = 1024;

/// Inbound NT path payload as a UTF-8 byte slice plus its
/// `UnicodeStringHeader` envelope. The header carries the byte
/// length the encoder claimed, the UTF-8 bytes are the decoded
/// payload — together they let downstream callers cross-check
/// the wire envelope against what actually fits in `regs[]`.
#[derive(Clone, Copy)]
pub(crate) struct NtPathView<'a> {
    pub header: UnicodeStringHeader,
    pub utf8: &'a [u8],
}

/// Decoded `OBJECT_ATTRIBUTES` envelope. The published Win32 ABI
/// drops the `ObjectName` / `SecurityDescriptor` pointer fields
/// (vfs cannot deref caller addresses); the wire delivers the
/// path inline as a trailing `UnicodeStringHeader` + UTF-16
/// payload. The decoded path is surfaced separately via
/// [`decode_object_attributes_path`] so [`OaView`] can stay
/// `Copy`.
#[derive(Clone, Copy)]
pub(crate) struct OaView {
    pub header: ObjectAttributesHeader,
}

/// Read `n` bytes starting at `byte_off` from `msg.regs[..]` into
/// the supplied scratch buffer. Returns the borrow as a slice on
/// success, `None` if the request runs past the end of `regs[]`.
fn read_regs_slice<'a>(
    msg: &TronaMsg,
    byte_off: usize,
    n: usize,
    scratch: &'a mut [u8],
) -> Option<&'a [u8]> {
    let total = msg.regs.len() * 8;
    if byte_off + n > total || n > scratch.len() {
        return None;
    }
    // SAFETY: regs is `[u64; 32]` — 256 contiguous bytes when
    // viewed as a u8 array. The bounds check above guarantees
    // the read window is in-bounds.
    let regs_bytes =
        unsafe { ::core::slice::from_raw_parts(msg.regs.as_ptr() as *const u8, total) };
    scratch[..n].copy_from_slice(&regs_bytes[byte_off..byte_off + n]);
    Some(&scratch[..n])
}

/// Strip an aligned `T` out of `msg.regs[..]` at byte offset
/// `byte_off`. Returns `None` on bounds failure.
unsafe fn read_aligned<T: Copy>(msg: &TronaMsg, byte_off: usize) -> Option<T> {
    let size = ::core::mem::size_of::<T>();
    let total = msg.regs.len() * 8;
    if byte_off + size > total {
        return None;
    }
    if byte_off % ::core::mem::align_of::<T>() != 0 {
        return None;
    }
    let ptr = unsafe { (msg.regs.as_ptr() as *const u8).add(byte_off) as *const T };
    Some(unsafe { ::core::ptr::read(ptr) })
}

/// Decode an `OBJECT_ATTRIBUTES` envelope at the given byte
/// offset, plus its trailing `UNICODE_STRING` path. The path's
/// UTF-16 bytes are converted into UTF-8 in `path_utf8` and the
/// returned `NtPathView::utf8` borrows the populated prefix.
///
/// `path_utf8` must have at least `NT_PATH_BUFFER_MAX` bytes so
/// the caller can blanket-allocate without worrying about each
/// path's exact UTF-8 expansion.
pub(crate) unsafe fn decode_object_attributes_with_path<'a>(
    msg: &TronaMsg,
    oa_byte_off: usize,
    path_utf8: &'a mut [u8],
) -> Option<(OaView, NtPathView<'a>)> {
    let oa_size = ::core::mem::size_of::<ObjectAttributesHeader>();
    let usz_size = ::core::mem::size_of::<UnicodeStringHeader>();

    let oa: ObjectAttributesHeader = unsafe { read_aligned(msg, oa_byte_off)? };

    let usz_off = oa_byte_off + oa_size;
    let usz: UnicodeStringHeader = unsafe { read_aligned(msg, usz_off)? };

    let utf16_off = usz_off + usz_size;
    let utf16_len = usz.length as usize;
    if utf16_len == 0 || utf16_len > NT_PATH_BUFFER_MAX {
        return None;
    }

    let mut utf16_scratch = [0u8; NT_PATH_BUFFER_MAX];
    let utf16_bytes = read_regs_slice(msg, utf16_off, utf16_len, &mut utf16_scratch)?;
    let written = super::utf16::utf16le_bytes_to_utf8(utf16_bytes, path_utf8)?;
    Some((
        OaView { header: oa },
        NtPathView {
            header: usz,
            utf8: &path_utf8[..written],
        },
    ))
}

/// Decode a stand-alone `UNICODE_STRING` (no `OBJECT_ATTRIBUTES`
/// envelope) — used by `NtRenameFile`'s `FileRenameInformation`,
/// `NtCreateSymbolicLinkObject`'s target string, etc.
pub(crate) unsafe fn decode_unicode_string<'a>(
    msg: &TronaMsg,
    usz_byte_off: usize,
    out_utf8: &'a mut [u8],
) -> Option<NtPathView<'a>> {
    let usz_size = ::core::mem::size_of::<UnicodeStringHeader>();
    let usz: UnicodeStringHeader = unsafe { read_aligned(msg, usz_byte_off)? };

    let utf16_off = usz_byte_off + usz_size;
    let utf16_len = usz.length as usize;
    if utf16_len == 0 || utf16_len > NT_PATH_BUFFER_MAX {
        return None;
    }
    let mut utf16_scratch = [0u8; NT_PATH_BUFFER_MAX];
    let utf16_bytes = read_regs_slice(msg, utf16_off, utf16_len, &mut utf16_scratch)?;
    let written = super::utf16::utf16le_bytes_to_utf8(utf16_bytes, out_utf8)?;
    Some(NtPathView {
        header: usz,
        utf8: &out_utf8[..written],
    })
}

/// `FILE_RENAME_INFORMATION` payload. Wire layout (NT, condensed
/// to the bits vfs needs):
///   regs[byte_off]      = ReplaceIfExists (u8) + 7 bytes pad
///   regs[byte_off+8]    = RootDirectory (u64)  // 0 = absolute
///   regs[byte_off+16]   = FileNameLength (u32) // bytes
///   regs[byte_off+24..] = FileName (UTF-16LE, FileNameLength bytes)
#[derive(Clone, Copy)]
pub(crate) struct FileRenameInfoView<'a> {
    pub replace_if_exists: bool,
    pub root_directory: u64,
    pub new_name_utf8: &'a [u8],
}

pub(crate) unsafe fn decode_file_rename_information<'a>(
    msg: &TronaMsg,
    byte_off: usize,
    out_utf8: &'a mut [u8],
) -> Option<FileRenameInfoView<'a>> {
    let total = msg.regs.len() * 8;
    if byte_off + 24 > total {
        return None;
    }
    let regs_bytes =
        unsafe { ::core::slice::from_raw_parts(msg.regs.as_ptr() as *const u8, total) };
    let replace = regs_bytes[byte_off] != 0;
    let root_directory =
        u64::from_le_bytes(regs_bytes[byte_off + 8..byte_off + 16].try_into().ok()?);
    let name_len =
        u32::from_le_bytes(regs_bytes[byte_off + 16..byte_off + 20].try_into().ok()?) as usize;
    if name_len == 0 || name_len > NT_PATH_BUFFER_MAX {
        return None;
    }
    let utf16_off = byte_off + 24;
    if utf16_off + name_len > total {
        return None;
    }
    let mut utf16_scratch = [0u8; NT_PATH_BUFFER_MAX];
    utf16_scratch[..name_len].copy_from_slice(&regs_bytes[utf16_off..utf16_off + name_len]);
    let written = super::utf16::utf16le_bytes_to_utf8(&utf16_scratch[..name_len], out_utf8)?;
    Some(FileRenameInfoView {
        replace_if_exists: replace,
        root_directory,
        new_name_utf8: &out_utf8[..written],
    })
}

/// `FILE_DISPOSITION_INFORMATION` — one byte. `1` flags the file
/// for delete-on-close, `0` clears the flag.
pub(crate) unsafe fn decode_file_disposition_information(
    msg: &TronaMsg,
    byte_off: usize,
) -> Option<bool> {
    let total = msg.regs.len() * 8;
    if byte_off + 1 > total {
        return None;
    }
    let regs_bytes =
        unsafe { ::core::slice::from_raw_parts(msg.regs.as_ptr() as *const u8, total) };
    Some(regs_bytes[byte_off] != 0)
}

/// `FILE_POSITION_INFORMATION` — one `LARGE_INTEGER`.
pub(crate) unsafe fn decode_file_position_information(
    msg: &TronaMsg,
    byte_off: usize,
) -> Option<i64> {
    let li: LargeInteger = unsafe { read_aligned(msg, byte_off)? };
    Some(li.0)
}

/// `FILE_END_OF_FILE_INFORMATION` — one `LARGE_INTEGER`.
pub(crate) unsafe fn decode_file_end_of_file_information(
    msg: &TronaMsg,
    byte_off: usize,
) -> Option<u64> {
    let li: LargeInteger = unsafe { read_aligned(msg, byte_off)? };
    if li.0 < 0 {
        return None;
    }
    Some(li.0 as u64)
}

/// Stub decoder for `FILE_BASIC_INFORMATION` — primarily for
/// `NtSetInformationFile(FileBasicInformation)` which carries
/// the four timestamps + attribute word as the payload.
pub(crate) unsafe fn decode_file_basic_information(
    msg: &TronaMsg,
    byte_off: usize,
) -> Option<FileBasicInformation> {
    unsafe { read_aligned(msg, byte_off) }
}

/// Stub decoder for `FILE_STANDARD_INFORMATION` — symmetric
/// counterpart used by query-vs-reply call sites.
pub(crate) unsafe fn decode_file_standard_information(
    msg: &TronaMsg,
    byte_off: usize,
) -> Option<FileStandardInformation> {
    unsafe { read_aligned(msg, byte_off) }
}

/// Stub decoder for `IO_STATUS_BLOCK` inbound — most NT calls
/// take an `IoStatusBlock*` for the kernel to fill, so the
/// inbound side carries an opaque caller-supplied address. vfs
/// does not deref caller addresses, so the inbound IoStatusBlock
/// is parsed only to keep wire ordering — the reply emits a
/// fresh value via [`super::nt_reply::pack_io_status_block`].
pub(crate) unsafe fn decode_io_status_block(
    msg: &TronaMsg,
    byte_off: usize,
) -> Option<IoStatusBlock> {
    unsafe { read_aligned(msg, byte_off) }
}
