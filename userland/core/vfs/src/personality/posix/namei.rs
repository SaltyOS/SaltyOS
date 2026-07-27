// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX path-policy decisions consumed by the namei async
//! state machine.
//!
//! `core::namei_async` owns the *mechanics* — splitting the
//! path into components, recursing on dotdot, parking on
//! BACKEND_LOOKUP / BACKEND_READLINK responses. This module owns
//! the *policy* — what is the absolute root, how does dotdot
//! behave, where do `.` / empty / repeated `/` collapse, what is
//! the symlink-loop hop limit, what does AT_FDCWD select.
//!
//! Win32 has its own (drive-letter rooted, `\` separated, UNC,
//! DOS reserved) policy in [`super::super::win32::namei`].
#![allow(dead_code)]

use trona_kernel::core_types::TronaMsg;

use crate::core::identity::VnodeKey;
use crate::owner::VfsState;
use crate::owner::pending::{WALK_PATH_MAX, WalkPolicy as CoreWalkPolicy};
use crate::owner::resume::NameiTerminal;
use crate::server::types::ClientHandle;

use crate::ops::anchor::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW};

/// POSIX-mandated maximum number of symlinks resolved during a
/// single namei walk before the kernel returns ELOOP. Linux
/// uses 40; the personality layer enforces it as the
/// `WalkPolicy::max_symlink_hops` ceiling regardless of the
/// individual mount's preferences.
pub(crate) const POSIX_SYMLOOP_MAX: u8 = 40;

/// POSIX-mandated maximum filename length per component. Same
/// as `Dirent::POSIX_NAME_MAX` — re-exported here so the namei
/// driver can consult one constant.
pub(crate) const POSIX_NAME_MAX: usize = super::types::POSIX_NAME_MAX;

/// POSIX-mandated maximum total path length, including the
/// terminating NUL. Linux uses 4096.
pub(crate) const POSIX_PATH_MAX: usize = 4096;

/// POSIX wire wrapper for the shared async namei walker.
pub(crate) unsafe fn begin_path_walk(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_override: VnodeKey,
    msg: &TronaMsg,
    path_words_start: usize,
    path_len: usize,
    policy: CoreWalkPolicy,
    flags: u32,
    terminal: NameiTerminal,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let mut path_buf = [0u8; WALK_PATH_MAX];
        let copied = path_len.min(WALK_PATH_MAX);
        super::wire::decode_path_bytes(msg, path_words_start, copied, &mut path_buf);
        crate::core::namei_async::begin_path_walk_from_bytes(
            state,
            client,
            anchor_override,
            &path_buf[..copied],
            copied,
            policy,
            flags,
            terminal,
            reply_lease,
        );
    }
}

/// Resolution roots — what the namei walker is rooted at when
/// it starts the descent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalkRoot {
    /// `/` — namespace root for the caller's mount namespace.
    NamespaceRoot,
    /// `dirfd` — caller passed `*at(dirfd, …)` and the dirfd
    /// resolves to a directory vnode.
    DirFd { fd: i32 },
    /// AT_FDCWD shortcut — caller passed AT_FDCWD; resolve
    /// against the caller's per-process CWD vnode.
    Cwd,
}

/// What to do when the final component is a symlink. Bit-flag
/// boolean so the caller can read `at_flags & AT_SYMLINK_NOFOLLOW`
/// directly off the wire and translate it through
/// [`final_symlink_policy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalSymlinkPolicy {
    /// Always resolve through the symlink (default for `open`,
    /// `stat`, etc.).
    Follow,
    /// Stop at the symlink itself — return its vnode (used by
    /// `lstat`, `readlink`, `O_NOFOLLOW open`, etc.).
    DoNotFollow,
}

/// Whether the walk demands the resolved vnode be a directory.
/// Used by `chdir`, `opendir`, `O_DIRECTORY`, and the trailing
/// `/` rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectoryRequirement {
    /// Either a file or a directory is acceptable.
    Either,
    /// Walk must end at a directory; if not, return `ENOTDIR`.
    MustBeDirectory,
}

/// Policy bundle that the personality layer hands the namei
/// driver alongside the path bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WalkPolicy {
    pub root: WalkRoot,
    pub final_symlink: FinalSymlinkPolicy,
    pub directory_required: DirectoryRequirement,
    /// Maximum symlinks the walker is allowed to traverse.
    /// Capped at [`POSIX_SYMLOOP_MAX`].
    pub max_symlink_hops: u8,
    /// `AT_EMPTY_PATH` was set — the path is allowed to be
    /// empty, in which case the walk ends at `root`.
    pub allow_empty_path: bool,
}

impl WalkPolicy {
    /// Build a policy from the AT_FDCWD selector + at-flags + a
    /// directory-required hint. The hint comes from the caller
    /// (`O_DIRECTORY` / `chdir` set it, others leave it
    /// `Either`).
    pub(crate) fn from_at(
        dirfd: i32,
        at_flags: i32,
        directory_required: DirectoryRequirement,
    ) -> Self {
        let root = if dirfd == AT_FDCWD {
            WalkRoot::Cwd
        } else {
            WalkRoot::DirFd { fd: dirfd }
        };
        let final_symlink = if (at_flags & AT_SYMLINK_NOFOLLOW) != 0 {
            FinalSymlinkPolicy::DoNotFollow
        } else if (at_flags & AT_SYMLINK_FOLLOW) != 0 {
            FinalSymlinkPolicy::Follow
        } else {
            FinalSymlinkPolicy::Follow
        };
        let allow_empty_path = (at_flags & AT_EMPTY_PATH) != 0;
        Self {
            root,
            final_symlink,
            directory_required,
            max_symlink_hops: POSIX_SYMLOOP_MAX,
            allow_empty_path,
        }
    }
}

/// Component-level classification used by the namei step
/// dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Component<'a> {
    /// Empty component — collapsed by the walker (matches
    /// repeated / leading slash semantics).
    Empty,
    /// `.` — the current directory; the walker drops the step.
    Dot,
    /// `..` — pop one level. The walker handles the
    /// mount-crossing case (`..` at a mount point goes back to
    /// the parent mount's directory).
    DotDot,
    /// Regular name component.
    Name(&'a [u8]),
}

/// Classify a component, applying POSIX `.` / `..` semantics.
/// The walker calls this on every separator-bounded slice it
/// pulls off the path. Empty strings (from `//`, leading `/`,
/// or trailing `/`) classify as `Empty` so the walker can
/// treat them uniformly.
#[inline]
pub(crate) fn classify_component(bytes: &[u8]) -> Component<'_> {
    if bytes.is_empty() {
        return Component::Empty;
    }
    if bytes == b"." {
        return Component::Dot;
    }
    if bytes == b".." {
        return Component::DotDot;
    }
    Component::Name(bytes)
}

/// Trailing-slash semantics: if the path ends with `/` (or
/// `/.` / `/..`), POSIX requires the resolved vnode to be a
/// directory. The personality layer sets
/// [`DirectoryRequirement::MustBeDirectory`] when this returns
/// true.
#[inline]
pub(crate) fn trailing_slash_demands_directory(path: &[u8]) -> bool {
    if let Some(&last) = path.last() {
        if last == b'/' {
            return true;
        }
    }
    if path.ends_with(b"/.") || path.ends_with(b"/..") {
        return true;
    }
    false
}

/// Project the policy into `final_symlink_policy(at_flags)`
/// the way `posix/open` and friends invoke it directly off
/// the wire.
#[inline]
pub(crate) const fn final_symlink_policy(at_flags: i32) -> FinalSymlinkPolicy {
    if (at_flags & AT_SYMLINK_NOFOLLOW) != 0 {
        FinalSymlinkPolicy::DoNotFollow
    } else {
        FinalSymlinkPolicy::Follow
    }
}

/// Validate the path's encoding against POSIX rules. Returns
/// `false` on malformed input the dispatcher must reject with
/// EINVAL — interior NUL byte (POSIX strings are NUL-terminated;
/// an interior NUL is a wire-encoding bug) or oversize total
/// length (longer than [`POSIX_PATH_MAX`]).
///
/// Component-level NAME_MAX checking happens lazily inside the
/// walker so a single overlong component does not invalidate the
/// entire path eagerly.
#[inline]
pub(crate) fn is_valid_path_encoding(path: &[u8]) -> bool {
    if path.len() >= POSIX_PATH_MAX {
        return false;
    }
    if path.contains(&0) {
        return false;
    }
    true
}

/// Determine whether a path is absolute (starts with `/`).
/// Absolute paths root at [`WalkRoot::NamespaceRoot`]; relative
/// paths use the policy's [`WalkRoot`].
#[inline]
pub(crate) const fn is_absolute(path: &[u8]) -> bool {
    !path.is_empty() && path[0] == b'/'
}
