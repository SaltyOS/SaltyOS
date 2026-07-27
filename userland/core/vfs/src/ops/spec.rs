// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral data shapes consumed by `ops`.
//!
//! Each personality (POSIX / Win32) decodes its own wire format
//! into these structs at dispatch time, then hands the decoded
//! request to the matching `ops::*` helper. The helper
//! drives the vop chain (`core::namei_async` walker + `meta.*`
//! / `data.*` / `dir.*` ops), produces a personality-neutral
//! result, and the personality reply layer formats the wire
//! response.
//!
//! Nothing in this module references `kernel IPC message`, POSIX `O_*` /
//! `S_*` literals, Windows `create-disposition` / `status` literals, or wire
//! protocol labels — the entire point of the indirection is to
//! prevent either personality from leaking into the other's
//! lookup path.

// ============================================================
// Open
// ============================================================

/// What the caller wants to do with the resulting handle.
///
/// POSIX and Windows both express the same access surface; the wire
/// shapes differ (POSIX `O_RDONLY` / `O_WRONLY` / `O_RDWR` bit
/// pair, Windows `Windows-specific value` / `Windows-specific value` mask) but
/// collapse to one of these four states for the purpose of
/// permission and vop selection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OpenAccess {
    /// Read access only.
    ///
    /// POSIX `O_RDONLY` / Windows `Windows-specific value | Windows-specific value`.
    Read,
    /// Write access only.
    Write,
    /// Both read and write.
    ReadWrite,
    /// Metadata-only handle (no data I/O permitted). Windows
    /// `Windows-specific value` without any data bit reaches here;
    /// the POSIX wire has no direct equivalent so the personality
    /// layer never produces this variant from POSIX.
    AttributesOnly,
}

/// What the lookup should do when the leaf is missing or already
/// exists.
///
/// POSIX builds this from `O_CREAT | O_EXCL | O_TRUNC`; Windows
/// supplies `CreateDisposition` directly. Both end up here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CreateMode {
    /// Open the existing leaf; fail with [`VfsError::NoEnt`] if
    /// the leaf does not exist.
    ///
    /// POSIX: `flags & O_CREAT == 0`. Windows: `OPEN_EXISTING (Windows-specific value)`.
    Open,
    /// Open the existing leaf, or create a new one if missing
    /// (POSIX `O_CREAT` without `O_EXCL`, Windows `OPEN_ALWAYS`).
    OpenAlways,
    /// Create a new leaf; fail with [`VfsError::Exist`] if one
    /// already exists.
    ///
    /// POSIX: `O_CREAT | O_EXCL`. Windows: `CREATE_NEW (Windows-specific value)`.
    Create,
    /// Create a new leaf, replacing any existing leaf with a
    /// fresh one (truncate semantics on existing data).
    ///
    /// POSIX: `O_CREAT | O_TRUNC`. Windows: `CREATE_ALWAYS (Windows-specific value)`.
    CreateAlways,
    /// Replace an existing leaf wholesale, or create it if it is
    /// missing. POSIX has no direct equivalent; Windows reaches
    /// this through `FILE_SUPERSEDE`.
    Supersede,
    /// Open the existing leaf and truncate it to zero length;
    /// fail if it does not exist.
    ///
    /// POSIX: `O_TRUNC` without `O_CREAT`. Windows: `TRUNCATE_EXISTING
    /// (Windows-specific value)`.
    Truncate,
}

/// Side-channel flags carried alongside the access + create mode.
///
/// Personality-neutral bitmap; each personality maps its own wire
/// flag bits onto these positions. New flags appended to the end
/// to keep numeric values stable across rebuilds.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OpenOptions(u32);

impl OpenOptions {
    pub(crate) const NON_BLOCKING: u32 = 1 << 0;
    pub(crate) const APPEND: u32 = 1 << 1;
    /// Caller wants the leaf to be a directory; reject otherwise
    /// with [`VfsError::NotDir`]. POSIX `O_DIRECTORY`, Windows
    /// `Windows-specific value`.
    pub(crate) const DIRECTORY: u32 = 1 << 2;
    /// Do not follow a symlink at the leaf. POSIX `O_NOFOLLOW`,
    /// Windows `Windows-specific value`.
    pub(crate) const NO_FOLLOW_LEAF: u32 = 1 << 3;
    /// Caller forbids creating a TTY for this open. POSIX
    /// `O_NOCTTY` only — Windows has no analogue.
    pub(crate) const NO_CTTY: u32 = 1 << 4;
    /// Open for synchronous I/O. POSIX `O_SYNC` / `O_DSYNC`, Windows
    /// `Windows-specific value`.
    pub(crate) const SYNC_WRITES: u32 = 1 << 5;
    /// Caller hints sequential access. Windows
    /// `Windows-specific value`; POSIX has no direct flag (callers
    /// use `posix_fadvise` post-open).
    pub(crate) const SEQUENTIAL_HINT: u32 = 1 << 6;
    /// Caller hints random access. Windows `Windows-specific value`;
    /// POSIX equivalent is `posix_fadvise` post-open.
    pub(crate) const RANDOM_HINT: u32 = 1 << 7;
    /// Bypass the page cache (direct I/O). POSIX `O_DIRECT`, Windows
    /// `Windows-specific value`.
    pub(crate) const DIRECT: u32 = 1 << 8;

    pub(crate) const fn empty() -> Self {
        Self(0)
    }
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
    pub(crate) const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
    pub(crate) const fn with(mut self, flag: u32) -> Self {
        self.0 |= flag;
        self
    }
}

/// Sharing policy for the new handle.
///
/// Windows carries `ShareAccess` natively (`Windows-specific value` /
/// `Windows-specific value` / `Windows-specific value`); POSIX has no
/// equivalent and always opens with the most permissive sharing.
/// The personality layer is responsible for composing this value;
/// `ops` honours it during vop conflict checks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SharePolicy(u32);

impl SharePolicy {
    pub(crate) const SHARE_READ: u32 = 1 << 0;
    pub(crate) const SHARE_WRITE: u32 = 1 << 1;
    pub(crate) const SHARE_DELETE: u32 = 1 << 2;

    /// POSIX-equivalent: every concurrent open is permitted.
    pub(crate) const fn permissive() -> Self {
        Self(Self::SHARE_READ | Self::SHARE_WRITE | Self::SHARE_DELETE)
    }
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
    pub(crate) const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// What actually happened during an open + create-mode sequence.
///
/// The personality reply layer surfaces this as POSIX `error-code=0`
/// (no distinction) or Windows `create-disposition` action codes (`Windows-specific value` =
/// 1, `Windows-specific value` = 2, `Windows-specific value` = 3, `Windows-specific value`
/// = 4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OpenCreateAction {
    /// Existing leaf opened, no creation performed.
    Opened,
    /// Leaf did not exist; new one created.
    Created,
    /// Existing leaf truncated to zero (POSIX `O_TRUNC` /
    /// Windows `Windows-specific value`).
    Overwritten,
    /// Existing leaf replaced wholesale (Windows `Windows-specific value`,
    /// POSIX has no direct equivalent).
    Superseded,
}

/// Successful result of [`crate::ops::open::do_namei_open`].
///
/// `fd` is the slot into which the new handle was installed in
/// the caller's slot table; `action` lets the personality layer
/// fill `status information` for Windows or simply return
/// `fd` for POSIX.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenResult {
    pub fd: u32,
    pub action: OpenCreateAction,
}

/// Personality-neutral open request.
///
/// Both POSIX and Windows entries decode their own wire shape into
/// this struct. `ops::open::do_namei_open` consumes it.
#[derive(Clone, Copy)]
pub(crate) struct VfsOpenSpec {
    pub access: OpenAccess,
    pub create: CreateMode,
    /// File mode applied when the create-mode actually creates a
    /// new leaf (POSIX `mode & ~umask`, Windows `FileAttributes` bits
    /// projected onto a 0o644-equivalent default). Ignored when
    /// no creation occurs.
    pub mode: u32,
    pub share: SharePolicy,
    /// Name-removal access requested by the handle. POSIX opens
    /// never request this implicitly; NT `DELETE` desired access
    /// does, and share arbitration must account for it even before
    /// delete-on-close itself is implemented.
    pub delete_access: bool,
    pub options: OpenOptions,
    /// FD-level flags requested by the caller. The single bit
    /// currently used is `FD_CLOEXEC` (POSIX `O_CLOEXEC`, Windows
    /// has no direct analogue and produces zero here).
    pub fd_flags: u8,
}

// ============================================================
// SetAttr — leaf attribute mutations
// ============================================================

/// Which attribute(s) the caller wants to modify on a leaf
/// vnode.
///
/// Distinct from [`UnlinkKind`] / [`RenameLinkKind`] /
/// [`CreateLeafKind`] because the walker terminal is the leaf
/// itself — no parent directory mutation. POSIX surfaces these
/// through `chmod` / `chown` / `utimes` (path-based) and
/// `fchmod` / `fchown` / `futimes` (fd-based); Windows collapses them
/// into Win32 attribute updates which
/// touches timestamps and attributes simultaneously.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SetAttrKind {
    /// Replace the file mode (permission bits).
    Mode { mode: u32 },
    /// Replace owner uid and/or gid. `None` leaves the field
    /// unchanged — both `None` is a no-op the personality layer
    /// should reject before reaching the helper.
    Owner { uid: Option<u32>, gid: Option<u32> },
    /// Replace access and modification timestamps. `None` falls
    /// back to "now" (POSIX `UTIME_NOW`, Win32 current time).
    Times {
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    },
    /// Bulk-replace the four Windows timestamps + attribute mask in
    /// one call. The helper splits it into constituent `chmod` +
    /// `utimes` vop calls under the hood.
    BasicBundle {
        creation_time_nanos: Option<u64>,
        last_access_nanos: Option<u64>,
        last_write_nanos: Option<u64>,
        change_time_nanos: Option<u64>,
        nt_file_attributes: Option<u32>,
    },
    /// Path-based truncate. POSIX `truncate(path, size)` walks
    /// namei to the leaf and applies `VATTR_SIZE`. Fd-based
    /// `ftruncate` skips the walker via
    /// [`crate::ops::io::do_truncate_fd`].
    PathTruncate { new_size: u64 },
}

// ============================================================
// UnlinkLeaf — parent + name, single removal
// ============================================================

/// Variant carrying the kind of unlink the caller asked for.
/// `ops` distinguishes `unlink` (file) from `rmdir`
/// (directory) because the vop chain rejects the wrong vnode
/// kind at the leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum UnlinkKind {
    /// Reject directories. POSIX `unlink`, Win32 deletion on a
    /// non-directory.
    File,
    /// Reject non-directories. POSIX `rmdir`, Win32 deletion on a
    /// directory.
    Directory,
    /// Either kind permitted (POSIX `remove(3)` semantics; Windows
    /// has no direct equivalent so the personality layer never
    /// produces this variant from Windows).
    Either,
}

// ============================================================
// RenameOrLink — old leaf + new parent + new name
// ============================================================

/// Whether the caller wants to move (rename) or alias (hardlink)
/// the source leaf into the target name slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RenameLinkKind {
    /// Move the directory entry: the source name vanishes, the
    /// target name appears, and any pre-existing target is
    /// removed atomically (POSIX `rename` / Windows
    /// `Windows-specific value`).
    Rename {
        /// Windows-only: rename refuses if a target exists. POSIX
        /// always replaces, so the personality layer always
        /// passes `false` from POSIX entries.
        no_replace: bool,
    },
    /// Add a second directory entry pointing at the same
    /// underlying inode (POSIX `link`, Windows
    /// `Windows-specific value`).
    Link {
        /// Windows-only: link refuses if a target exists. POSIX
        /// `link` rejects existing targets unconditionally.
        no_replace: bool,
    },
}

// ============================================================
// CreateLeaf — parent + name + child shape
// ============================================================

/// What kind of new leaf the caller wants the helper to create.
/// `ops::create_leaf::do_create_leaf` walks the parent,
/// then calls the matching vop (`meta.mkdir` / `meta.symlink` /
/// `meta.mkfifo`) on the parent.
///
/// The symlink target bytes are *not* carried inline on this enum.
/// `crate::owner::resume::NameiTerminal::CreateLeaf` carries an
/// auxiliary handle into `state.namei_aux[..]` whose `Symlink`
/// variant holds the target buffer (POSIX symlink targets can run
/// to `WALK_SYMLINK_TARGET_MAX` bytes and would not fit in a
/// `Copy` enum variant).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CreateLeafKind {
    /// New directory with the given mode.
    Mkdir { mode: u32 },
    /// New symlink. POSIX `symlink(target, name)` /
    /// Win32 symlink creation. `mode` defaults to
    /// `S_IFLNK | 0o777` for POSIX; the personality layer fills
    /// it from the wire request. The symlink target bytes live
    /// on the matching `NameiAuxState::Symlink` entry.
    Symlink { mode: u32 },
    /// New FIFO / named pipe with the given mode. POSIX `mkfifo`,
    /// Win32 named-pipe creation.
    Mkfifo { mode: u32 },
    /// New device node. POSIX `mknod` only — Windows has no path-based
    /// device-node creation in the public ABI surface vfs serves.
    Mknod { mode: u32, dev: u64 },
}

// ============================================================
// Case-fold policy — per-mount
// ============================================================

/// How a mount compares directory entries against a lookup
/// component.
///
/// Stored on the mount instance and carried through the namei
/// walker context. POSIX mounts default to [`Sensitive`]; mounts
/// surfaced through Win32 drive letters or case-insensitive volumes
/// use [`InsensitivePreserving`] so the same vnode resolves under
/// both `Foo.txt` and `FOO.TXT` while the directory entry keeps
/// its original casing.
///
/// `vop` chain itself is personality-neutral: lookup always
/// produces the same vnode handle for a given normalized
/// component, regardless of which personality issued the lookup.
/// The case-fold step happens before the dirent comparison —
/// driven by the mount's policy, not the caller's personality.
///
/// [`Sensitive`]: Self::Sensitive
/// [`InsensitivePreserving`]: Self::InsensitivePreserving
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(crate) enum CaseFoldPolicy {
    /// Byte-exact comparison. POSIX default, native saltyfs.
    Sensitive,
    /// Case-insensitive comparison, preserve original casing in
    /// the dirent. Win32 default, case-insensitive mounts, Win32
    /// drive-letter mounts.
    InsensitivePreserving,
}

impl CaseFoldPolicy {
    /// Compare two name components under this policy. Returns
    /// `true` when they refer to the same dirent.
    pub(crate) fn names_equal(self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        match self {
            Self::Sensitive => a == b,
            Self::InsensitivePreserving => a
                .iter()
                .zip(b.iter())
                .all(|(x, y)| ascii_fold(*x) == ascii_fold(*y)),
        }
    }
}

/// ASCII-only case fold (A..Z → a..z). Non-ASCII bytes pass
/// through unchanged — the saltyos namespace is UTF-8 throughout
/// and full Unicode case fold is the responsibility of the
/// mount's case-aware extension.
#[inline]
const fn ascii_fold(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}
