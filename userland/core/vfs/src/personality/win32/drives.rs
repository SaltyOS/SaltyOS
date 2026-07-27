// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 drive-letter resolution.
//!
//! Win32 paths are rooted at one of 26 drive letters (`A:` ..
//! `Z:`) — each letter is a separate root that maps to a vfs
//! mount handle. The mapping is per-process: every Win32 client
//! carries its own drive table on its `ClientState`'s
//! win32-personality side, populated at registration time from
//! the parent's table (or from the Win32 subsystem's default
//! mapping when the process is the first Win32 entry).
//!
//! The vfs core stays personality-neutral — drive resolution
//! happens at the wire seam, then the resolved mount handle
//! feeds the same `core::namei_async` walker the POSIX
//! side uses.
#![allow(dead_code)]

/// Number of drive letters Win32 recognises (A..=Z).
pub(crate) const DRIVE_LETTER_COUNT: usize = 26;

/// Per-process drive table — index 0 is `A:`, 25 is `Z:`. Each
/// entry holds the mount handle slot the drive letter resolves
/// to, or [`MountSlot::UNASSIGNED`] when the letter is not
/// mapped (the Win32 path classification still rejects writes
/// to unmapped drives at the dispatch layer).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct DriveTable {
    /// One slot per drive letter. Stored as a 32-bit slot
    /// index pointing into `VfsState.mounts`. `u32::MAX` is
    /// the unassigned sentinel.
    pub mounts: [MountSlot; DRIVE_LETTER_COUNT],
    /// Currently-selected drive — Win32 has a per-process
    /// notion of "current drive" that relative paths starting
    /// with `\` resolve against. 0..25 = drive index, 0xFF =
    /// no current drive (process did not pick one yet).
    pub current_drive: u8,
}

impl DriveTable {
    pub(crate) const EMPTY: Self = Self {
        mounts: [MountSlot::UNASSIGNED; DRIVE_LETTER_COUNT],
        current_drive: 0xFF,
    };

    /// Default Win32 projection used until per-client drive tables
    /// are plumbed through registration. Each drive letter maps to
    /// the matching namespace prefix (`C:\foo` -> `/c/foo`); the
    /// root mount remains resolved by the shared namei walker.
    pub(crate) const fn default_table() -> Self {
        Self {
            mounts: [
                MountSlot(0),
                MountSlot(1),
                MountSlot(2),
                MountSlot(3),
                MountSlot(4),
                MountSlot(5),
                MountSlot(6),
                MountSlot(7),
                MountSlot(8),
                MountSlot(9),
                MountSlot(10),
                MountSlot(11),
                MountSlot(12),
                MountSlot(13),
                MountSlot(14),
                MountSlot(15),
                MountSlot(16),
                MountSlot(17),
                MountSlot(18),
                MountSlot(19),
                MountSlot(20),
                MountSlot(21),
                MountSlot(22),
                MountSlot(23),
                MountSlot(24),
                MountSlot(25),
            ],
            current_drive: 2,
        }
    }

    /// Resolve a UTF-16 drive letter to its index (0..=25).
    /// Accepts both upper- and lower-case ASCII letters; any
    /// other code unit returns `None`.
    #[inline]
    pub(crate) fn letter_to_index(letter: u16) -> Option<u8> {
        let lo = letter.to_ascii_lowercase_u16();
        if (b'a' as u16..=b'z' as u16).contains(&lo) {
            Some((lo - b'a' as u16) as u8)
        } else {
            None
        }
    }

    /// Look up the mount slot for a drive letter (0..=25).
    /// Returns `MountSlot::UNASSIGNED` if the slot is empty —
    /// the dispatcher returns `STATUS_OBJECT_PATH_NOT_FOUND`
    /// for unmapped drives.
    #[inline]
    pub(crate) fn lookup(&self, drive_index: u8) -> MountSlot {
        if (drive_index as usize) >= DRIVE_LETTER_COUNT {
            return MountSlot::UNASSIGNED;
        }
        self.mounts[drive_index as usize]
    }

    /// Map a drive letter to a vfs mount slot. Used during
    /// Win32 client registration when the parent process or
    /// the Win32 subsystem populates the table.
    #[inline]
    pub(crate) fn assign(&mut self, drive_index: u8, slot: MountSlot) {
        if (drive_index as usize) < DRIVE_LETTER_COUNT {
            self.mounts[drive_index as usize] = slot;
        }
    }
}

/// Slot index into `VfsState.mounts`. `u32::MAX` means the
/// drive letter is not mapped to any mount.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountSlot(pub u32);

impl MountSlot {
    pub(crate) const UNASSIGNED: Self = Self(u32::MAX);

    #[inline]
    pub(crate) const fn is_assigned(self) -> bool {
        self.0 != u32::MAX
    }
}

/// UTF-16 ASCII helpers — Rust's `char` methods do not work
/// directly on `u16`, so the drive parser carries its own
/// case-folding helper.
trait Utf16AsciiExt {
    fn to_ascii_lowercase_u16(self) -> u16;
}

impl Utf16AsciiExt for u16 {
    #[inline]
    fn to_ascii_lowercase_u16(self) -> u16 {
        if self >= b'A' as u16 && self <= b'Z' as u16 {
            self + (b'a' as u16 - b'A' as u16)
        } else {
            self
        }
    }
}
