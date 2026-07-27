// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-tagged reply intent — selects the wire shape used
//! by the matching `personality/{posix,win32}/reply.rs` emitter.
//!
//! `ops` helpers do not know whether the eventual reply
//! goes back as POSIX errno + payload or NT IoStatusBlock + FILE_*
//! struct. The dispatch layer attaches one of the enums in this
//! module to the [`crate::owner::resume::NameiTerminal`] (and to
//! the matching [`crate::owner::resume::FsResume`] for parked
//! ops) at issue time. When the helper terminates — either
//! synchronously or via the resume path — the personality reply
//! formatter consumes the intent and produces the wire bytes.
//!
//! # Why a separate enum per op
//!
//! A single fat `ReplyIntent` union would let an `Open` terminal
//! accidentally carry an `AttrReplyIntent` and only fail at
//! runtime as a wire shape mismatch. Splitting per logical op
//! lets the type system reject the mis-routed intent at the call
//! site: `NameiTerminal::Open` only accepts an
//! [`OpenReplyIntent`], `NameiTerminal::GetAttr` only accepts an
//! [`AttrReplyIntent`], etc.
//!
//! # Default is forbidden — HARD invariant
//!
//! **None of the enums below derive `Default`, and none ever
//! will.** A `Default` impl turns "I forgot to attach an intent"
//! from a compile error into a silent fallback to whichever
//! variant happens to be first in the source — almost always
//! the POSIX one, which is exactly the second-class trap this
//! layer exists to break. Every construction site must select a
//! variant explicitly.

#![allow(dead_code)]

// ============================================================
// Open
// ============================================================

/// Wire shape for the reply to an open + create-mode operation.
///
/// POSIX returns the new fd in `regs[0]`. NT returns an
/// IoStatusBlock (status + create-disposition action code) plus
/// the new HANDLE in dedicated regs slots.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OpenReplyIntent {
    /// POSIX `open` / `openat` / `creat` — `regs[0] = fd`.
    PosixOpen,
    /// NT `NtCreateFile` — IoStatusBlock + HANDLE; the
    /// IoStatusBlock.Information field carries the
    /// `FILE_OPENED` / `FILE_CREATED` / `FILE_OVERWRITTEN` /
    /// `FILE_SUPERSEDED` action code derived from
    /// [`crate::ops::spec::OpenCreateAction`].
    NtCreateFile {
        desired_access: u32,
        share_access: u32,
        create_options: u32,
    },
    /// NT `NtOpenFile` — strict-existing variant. Same wire
    /// shape as [`Self::NtCreateFile`] but the action code is
    /// always `FILE_OPENED`; the helper validates the variant
    /// match against the spec at issue time.
    NtOpenFile {
        desired_access: u32,
        share_access: u32,
        create_options: u32,
    },
}

// ============================================================
// GetAttr
// ============================================================

/// Wire shape for the reply to an attribute query.
///
/// NT splits `NtQueryInformationFile` into a dozen+ information
/// classes; the variants below cover the ones reachable from the
/// public Win32 surface. Adding a new class is a matter of
/// adding one variant here plus the matching emitter in
/// `personality/win32/reply.rs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AttrReplyIntent {
    /// POSIX `stat` / `lstat` / `fstat` — pack VAttr into
    /// regs in the layout the basaltc shim expects.
    PosixStat,
    /// NT `FileBasicInformation` — four FILETIMEs + attribute
    /// mask.
    NtFileBasicInformation,
    /// NT `FileStandardInformation` — alloc / EOF /
    /// number-of-links / delete-pending / directory.
    NtFileStandardInformation,
    /// NT `FileNetworkOpenInformation` — basic + standard
    /// merged into a single struct (the legacy NetworkOpen
    /// shape).
    NtFileNetworkOpenInformation,
    /// NT `FileAllInformation` — basic + standard + internal +
    /// EA + access + position + mode + alignment + name in one
    /// shot.
    NtFileAllInformation,
    /// NT `FilePositionInformation` — current file pointer
    /// (handle attribute, no vop call).
    NtFilePositionInformation,
    /// NT `FileEaInformation` — extended attributes byte count.
    NtFileEaInformation,
    /// NT `FileAccessInformation` — granted access mask.
    NtFileAccessInformation,
    /// NT `FileNameInformation` — full file name (UTF-16LE).
    NtFileNameInformation,
    /// NT `FileAlignmentInformation` — device alignment
    /// requirement.
    NtFileAlignmentInformation,
    /// NT `FileInternalInformation` — file-id (inode-equivalent).
    NtFileInternalInformation,
    /// NT `FileModeInformation` — handle's open-mode bits.
    NtFileModeInformation,
}

// ============================================================
// Acknowledgement (no payload)
// ============================================================

/// Wire shape for an ack reply (no body, just success).
///
/// Used by mutation ops (`unlink` / `rename` / `link` / `mkdir`
/// / `mkfifo` / `chmod` / `chown` / `utimes` / `truncate` /
/// `fsync`). POSIX surfaces ack as `errno=0` with no body; NT
/// surfaces it as an IoStatusBlock with `Status=0` and
/// `Information=0`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AckReplyIntent {
    /// POSIX `errno=0` ack — no body.
    PosixAck,
    /// NT IoStatusBlock with `Status=STATUS_SUCCESS` and the
    /// supplied `information` word.
    NtIoStatusBlock,
}

// ============================================================
// Read / Write
// ============================================================

/// Wire shape for the reply to a data-read operation.
///
/// POSIX returns `bytes_read` in `regs[0]`; the data lives in
/// the caller's bulk-SHM region (or inline regs for tiny reads).
/// NT packs `bytes_read` into IoStatusBlock.Information.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ReadReplyIntent {
    PosixRead,
    NtReadFile,
}

/// Wire shape for the reply to a data-write operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum WriteReplyIntent {
    PosixWrite,
    NtWriteFile,
}

// ============================================================
// ReadDir
// ============================================================

/// Wire shape for the reply to a directory enumeration.
///
/// POSIX `getdents` packs Linux-shaped `dirent64` records.
/// NT `NtQueryDirectoryFile` selects one of seven variants
/// based on the `FileInformationClass` argument; each has a
/// distinct on-wire record layout (with vs without short-name,
/// with vs without file-id, etc.).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ReadDirReplyIntent {
    /// POSIX `getdents` / `getdents64` — Linux dirent64 records.
    PosixGetDents,
    /// NT `FileDirectoryInformation`.
    NtFileDirectoryInformation,
    /// NT `FileNamesInformation` — name-only, no attributes.
    NtFileNamesInformation,
    /// NT `FileFullDirectoryInformation` — directory + EA size.
    NtFileFullDirectoryInformation,
    /// NT `FileBothDirectoryInformation` — directory + EA size
    /// + 8.3 short name.
    NtFileBothDirectoryInformation,
    /// NT `FileIdFullDirectoryInformation` — full + file-id.
    NtFileIdFullDirectoryInformation,
    /// NT `FileIdBothDirectoryInformation` — both + file-id.
    NtFileIdBothDirectoryInformation,
}

// ============================================================
// Statfs (volume / mount info)
// ============================================================

/// Wire shape for the reply to a volume / mount query.
///
/// POSIX `statvfs` returns one large struct. NT
/// `NtQueryVolumeInformationFile` splits volume metadata across
/// four+ information classes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum StatfsReplyIntent {
    /// POSIX `statvfs` / `fstatvfs`.
    PosixStatvfs,
    /// NT `FileFsVolumeInformation` — volume label + creation
    /// time + serial number.
    NtFileFsVolumeInformation,
    /// NT `FileFsSizeInformation` — total / free allocation
    /// units, sectors per unit, bytes per sector.
    NtFileFsSizeInformation,
    /// NT `FileFsAttributeInformation` — fs name + max
    /// component length + attribute flags.
    NtFileFsAttributeInformation,
    /// NT `FileFsDeviceInformation` — device type +
    /// characteristics.
    NtFileFsDeviceInformation,
}

// ============================================================
// Seek
// ============================================================

/// Wire shape for the reply to a seek operation.
///
/// POSIX `lseek` returns the new offset in `regs[0]`. NT seeks
/// via `NtSetInformationFile(FilePositionInformation)` which
/// returns just an IoStatusBlock (no offset echo).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SeekReplyIntent {
    PosixSeek,
    NtSetFilePosition,
}

// ============================================================
// Ioctl / DeviceIoControl
// ============================================================

/// Wire shape for an ioctl-style device control reply.
///
/// POSIX `ioctl` echoes the vop-provided words directly. NT
/// `NtDeviceIoControlFile` wraps the same payload behind an
/// IoStatusBlock whose `Information` field carries the byte count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IoctlReplyIntent {
    PosixIoctl,
    NtDeviceIoControlFile,
}
