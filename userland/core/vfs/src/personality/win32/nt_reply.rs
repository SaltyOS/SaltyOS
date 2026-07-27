// SPDX-License-Identifier: GPL-2.0-only
//
//! NT outbound wire serialisers.
//!
//! Replies on the Win32 personality wire pack NT-native struct
//! shapes back into the `TronaMsg::regs[..]` byte buffer:
//!
//! * Every Win32 reply carries a leading [`IoStatusBlock`] —
//!   `Status` is the NTSTATUS, `Information` is the op-specific
//!   info word (bytes transferred for read/write, returned HANDLE
//!   for create/open, the `FILE_*` create disposition for create,
//!   the byte count of the trailing variable-length payload for
//!   query calls).
//! * Query-info calls follow the IO_STATUS_BLOCK with the
//!   matching `FILE_*_INFORMATION` struct.
//! * Directory enumeration packs `FILE_NAMES_INFORMATION` /
//!   `FILE_DIRECTORY_INFORMATION` records contiguously.
//!
//! The output `TronaMsg` carries the
//! [`crate::ipc::protocol::public::VFS_PUBLIC_REPLY_OK`] label —
//! the NTSTATUS (success / failure) is inside the IoStatusBlock,
//! not the IPC label itself.

#![allow(dead_code)]

use trona_kernel::core_types::TronaMsg;

use super::types::{FileBasicInformation, FileStandardInformation, IoStatusBlock, LargeInteger};

/// Pack `iosb` into `out.regs[..]` at `byte_off`. Returns the
/// next free byte offset on success, `None` if the IoStatusBlock
/// would overrun the regs buffer.
pub(crate) unsafe fn pack_io_status_block(
    out: &mut TronaMsg,
    byte_off: usize,
    iosb: IoStatusBlock,
) -> Option<usize> {
    let size = ::core::mem::size_of::<IoStatusBlock>();
    let total = out.regs.len() * 8;
    if byte_off + size > total {
        return None;
    }
    if byte_off % ::core::mem::align_of::<IoStatusBlock>() != 0 {
        return None;
    }
    unsafe {
        let dst = (out.regs.as_mut_ptr() as *mut u8).add(byte_off) as *mut IoStatusBlock;
        ::core::ptr::write(dst, iosb);
    }
    Some(byte_off + size)
}

/// Pack a `FILE_BASIC_INFORMATION` struct after the IoStatusBlock.
pub(crate) unsafe fn pack_file_basic_information(
    out: &mut TronaMsg,
    byte_off: usize,
    fbi: FileBasicInformation,
) -> Option<usize> {
    let size = ::core::mem::size_of::<FileBasicInformation>();
    let total = out.regs.len() * 8;
    if byte_off + size > total {
        return None;
    }
    if byte_off % ::core::mem::align_of::<FileBasicInformation>() != 0 {
        return None;
    }
    unsafe {
        let dst = (out.regs.as_mut_ptr() as *mut u8).add(byte_off) as *mut FileBasicInformation;
        ::core::ptr::write(dst, fbi);
    }
    Some(byte_off + size)
}

/// Pack a `FILE_STANDARD_INFORMATION` struct after the IoStatusBlock.
pub(crate) unsafe fn pack_file_standard_information(
    out: &mut TronaMsg,
    byte_off: usize,
    fsi: FileStandardInformation,
) -> Option<usize> {
    let size = ::core::mem::size_of::<FileStandardInformation>();
    let total = out.regs.len() * 8;
    if byte_off + size > total {
        return None;
    }
    if byte_off % ::core::mem::align_of::<FileStandardInformation>() != 0 {
        return None;
    }
    unsafe {
        let dst = (out.regs.as_mut_ptr() as *mut u8).add(byte_off) as *mut FileStandardInformation;
        ::core::ptr::write(dst, fsi);
    }
    Some(byte_off + size)
}

/// `FILE_DIRECTORY_INFORMATION` record header. The trailing
/// `FileName` UTF-16 buffer follows this header in the same
/// `regs[]` region.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct FileDirectoryInformationHeader {
    /// Byte offset to the next entry in this batch, or `0` if
    /// this is the last entry. The next entry is at `byte_off +
    /// next_entry_offset` in `regs[]`.
    pub next_entry_offset: u32,
    /// Per-entry index into the directory cookie space. The
    /// caller may pass this back as the `cookie` for a follow-up
    /// `NtQueryDirectoryFile` to resume from this entry.
    pub file_index: u32,
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub end_of_file: LargeInteger,
    pub allocation_size: LargeInteger,
    pub file_attributes: u32,
    pub file_name_length: u32, // bytes
                               // FileName: WCHAR[] follows here.
}

/// Maps POSIX `mode_t` (the high 4 bits of which encode file
/// type) to a Win32 `FILE_ATTRIBUTE_*` mask. The mapping is
/// minimal — directories surface `FILE_ATTRIBUTE_DIRECTORY`,
/// read-only files surface `FILE_ATTRIBUTE_READONLY`, otherwise
/// `FILE_ATTRIBUTE_NORMAL`.
pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Translate POSIX mode (`S_IFREG` / `S_IFDIR` / etc + permission
/// bits) into a Win32 attribute mask suitable for
/// `FILE_BASIC_INFORMATION.FileAttributes`.
pub(crate) fn posix_mode_to_win32_attributes(mode: u32) -> u32 {
    let s_ifmt = 0o170000u32;
    let s_ifdir = 0o040000u32;
    let mut attrs = 0u32;
    if (mode & s_ifmt) == s_ifdir {
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }
    // Owner write bit cleared → READONLY.
    if (mode & 0o200) == 0 {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }
    if attrs == 0 {
        attrs = FILE_ATTRIBUTE_NORMAL;
    }
    attrs
}

/// Translate POSIX nanoseconds-since-epoch into NT's
/// `LARGE_INTEGER` 100-ns units since 1601-01-01. The NT epoch
/// is 11644473600 seconds before the POSIX epoch.
pub(crate) fn posix_nanos_to_nt_filetime(posix_nanos: u64) -> LargeInteger {
    const NT_EPOCH_OFFSET_SECONDS: i64 = 11644473600;
    const NT_TICKS_PER_SECOND: i64 = 10_000_000;
    let posix_seconds = (posix_nanos / 1_000_000_000) as i64;
    let posix_remainder_nanos = (posix_nanos % 1_000_000_000) as i64;
    let nt_seconds_part = (posix_seconds + NT_EPOCH_OFFSET_SECONDS) * NT_TICKS_PER_SECOND;
    let nt_remainder = posix_remainder_nanos / 100;
    LargeInteger(nt_seconds_part + nt_remainder)
}
