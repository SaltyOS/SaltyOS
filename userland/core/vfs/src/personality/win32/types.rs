// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 NT wire types — `OBJECT_ATTRIBUTES`, `IO_STATUS_BLOCK`,
//! `FILE_BASIC_INFORMATION`, `FILE_STANDARD_INFORMATION`,
//! `LARGE_INTEGER`, `UNICODE_STRING`, `SECURITY_ATTRIBUTES`. These
//! mirror the NT kernel ABI shapes the personality layer projects
//! the personality-neutral vnode metadata onto.
//!
//! `#[repr(C)]` everywhere — wire layout matters. Field order /
//! padding is fixed and must not be reordered without bumping the
//! corresponding wire-version slot.
//!
//! Pointer-bearing variants of the published Win32 ABI
//! (`UNICODE_STRING.Buffer`, `OBJECT_ATTRIBUTES.ObjectName` /
//! `SecurityDescriptor`, `SECURITY_ATTRIBUTES.lpSecurityDescriptor`)
//! are intentionally absent. A pointer field would name a buffer
//! in the caller's address space, which the vfs server cannot
//! dereference. The wire instead delivers the equivalent payload
//! inline: a trailing [`UnicodeStringHeader`] is followed by its
//! UTF-16 byte payload packed into the same IPC `regs[]` region as
//! the rest of the message; security descriptors are not honoured
//! because vfs derives access from the per-client capability set
//! rather than from a Win32 SD.
#![allow(dead_code)]

/// 64-bit signed file offset / size. Win32 callers consume this
/// through the `LowPart` / `HighPart` halves; we keep it as a
/// single `i64` and let the wire encoder split when emitting.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct LargeInteger(pub i64);

/// Header for an NT counted UTF-16 string carried inline in the
/// IPC payload. The trailing UTF-16 byte payload follows this
/// header in the same `regs[]` region as the rest of the message.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct UnicodeStringHeader {
    /// Length in bytes (not codepoints, not wchars) of the UTF-16
    /// payload that follows this header.
    pub length: u16,
    /// Capacity in bytes of the inline payload region the caller
    /// reserved. Mirrors the published `MaximumLength` field.
    pub maximum_length: u16,
    /// Padding to align the trailing UTF-16 payload to four
    /// bytes. Always zero on the wire.
    pub _reserved: u32,
}

/// Header for `OBJECT_ATTRIBUTES`. The `ObjectName` and
/// `SecurityDescriptor` pointers of the published Win32 ABI are
/// dropped — the path arrives inline as a
/// [`UnicodeStringHeader`] plus its UTF-16 byte payload trailing
/// this header in the IPC region; security descriptors are not
/// transmitted.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ObjectAttributesHeader {
    pub length: u32,
    /// Optional root handle the path is relative to. Zero =
    /// absolute path (drive-letter prefix or `\??\`).
    pub root_directory: u64,
    /// `OBJ_*` attribute mask (case-insensitive lookup, inherit,
    /// permanent, exclusive, ...).
    pub attributes: u32,
    /// Padding to align the trailing
    /// [`UnicodeStringHeader`]. Always zero on the wire.
    pub _reserved: u32,
}

/// `IO_STATUS_BLOCK` — completion status / per-op information
/// echoed back to the caller after every NtCreateFile /
/// NtReadFile / NtWriteFile. The published ABI's `Information`
/// field is `ULONG_PTR`; the wire pins it at `u64` so the field
/// is server-architecture invariant.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct IoStatusBlock {
    /// NTSTATUS value (see `STATUS_*` constants in
    /// `personality::win32::consts`).
    pub status: u32,
    /// Padding so `information` lands on an 8-byte boundary.
    pub _reserved: u32,
    /// Op-specific information word — for NtCreateFile this is
    /// `FILE_CREATED` / `FILE_OPENED` / `FILE_OVERWRITTEN`; for
    /// NtRead / NtWrite this is the byte count transferred.
    pub information: u64,
}

/// `FILE_BASIC_INFORMATION` — base timestamps + attribute bits,
/// emitted by `NtQueryInformationFile(FileBasicInformation)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileBasicInformation {
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    /// `FILE_ATTRIBUTE_*` bit field.
    pub file_attributes: u32,
}

/// `FILE_STANDARD_INFORMATION` — size + link count, emitted by
/// `NtQueryInformationFile(FileStandardInformation)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileStandardInformation {
    pub allocation_size: LargeInteger,
    pub end_of_file: LargeInteger,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
    pub _reserved: [u8; 2],
}

/// `SECURITY_ATTRIBUTES` header. The pointer-bearing
/// `lpSecurityDescriptor` of the published ABI is dropped — the
/// descriptor would live in the caller's address space. The
/// remaining `bInheritHandle` flag is the only field vfs honours
/// (Win32's CLOEXEC complement: 0 = handle is not inherited
/// across `CreateProcess`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SecurityAttributesHeader {
    pub n_length: u32,
    /// Padding so `b_inherit_handle` lands on a 4-byte boundary
    /// matching the published ABI's overall struct size.
    pub _reserved: u32,
    pub b_inherit_handle: u32,
}
