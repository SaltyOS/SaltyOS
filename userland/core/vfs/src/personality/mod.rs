// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality projections. The `core` and `fs/*` layers carry
//! a personality-neutral view (Vnode kind, mount kind, OpenObject
//! ref); the personality modules project that view onto a specific
//! ABI surface (POSIX `S_IFREG` / `O_RDONLY` / `S_ISVTX`, Win32
//! `GENERIC_READ` / `FILE_ATTRIBUTE_DIRECTORY` / drive letters).
//!
//! Backend filesystems hang opaque per-vnode state off `Vnode.data`
//! and reach for personality types only at the wire seam — the
//! same vnode is observable from both POSIX and Win32 callers.
//!
//! # Topology
//!
//! Each `ClientState` carries a `Personality` discriminator stamped
//! at register time (init's per-client spawn wire encodes the
//! subsystem id; the dispatcher reads it on the first RPC). The
//! frontend label range maps deterministically onto the
//! personality:
//!
//! | label range     | personality | dispatch entry           |
//! |-----------------|-------------|--------------------------|
//! | 0x500..=0x53F   | POSIX       | `personality::posix`     |
//! | 0x540..=0x57F   | Win32       | `personality::win32`     |
//! | 0x580..=0x5BF   | neutral     | reserved for shared ABI  |
//! | 0x5C0..=0x5DF   | POSIX ext   | `personality::posix`     |
//! | 0x5E0..=0x5FF   | reserved    | malformed-label rejection|
//!
//! A request whose label range and the client's
//! [`Personality`] disagree is rejected with `EINVAL` — a Win32
//! process cannot smuggle a POSIX wire shape through an
//! `personality::win32` slot, and vice versa.

pub(crate) mod namei_terminal;
pub(crate) mod posix;
pub(crate) mod reply;
pub(crate) mod reply_intent;
pub(crate) mod win32;
pub(crate) mod wire;

/// Personality discriminator. Carried on `ClientState` and
/// stamped at client-register time. Determines which
/// label-range entry the dispatcher routes the inbound request to.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Personality {
    /// POSIX wire (S_IF* mode bits, dirent layout, sigset_t,
    /// sockaddr_un / sockaddr_in / sockaddr_in6, AT_* openat
    /// flags, case-sensitive UTF-8 names, symlink hop limit 40).
    Posix = 0,
    /// Win32 NT wire (GENERIC_READ / FILE_ATTRIBUTE_*, drive
    /// letters, `\\?\`-prefixed extended-length paths, UNC
    /// `\\server\share`, DOS reserved names CON / NUL / PRN,
    /// case-insensitive name lookup with case preservation).
    Win32 = 1,
}

impl Personality {
    /// Default for clients whose register wire did not stamp a
    /// personality byte. The bootstrap path (init / namesrv /
    /// rsrcsrv / mmsrv handshakes that pre-date subsystem-aware
    /// spawn) lands here, plus any client that arrives through a
    /// pre-personality compatibility path. POSIX is the historical
    /// default — every existing trona-substrate caller is POSIX.
    pub(crate) const DEFAULT: Self = Self::Posix;
}
