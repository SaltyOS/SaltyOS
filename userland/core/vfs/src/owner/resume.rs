// SPDX-License-Identifier: GPL-2.0-only
//
//! `Resume` — per-PendingOp continuation payload. Stored on every
//! `PendingOp` next to the `OpCore` shared header. Per-domain
//! submodules (saltyfs / netsrv / posix_ttysrv / pager) each
//! extend this enum with their own variants.
//!
//! Routing is *not* done here — that responsibility lives on each
//! `BackendSessionSlot::completion_fn`, which receives the
//! `Resume` alongside the backend-opaque `PendingKindPayload` and
//! the raw completion message. This module provides only the data
//! structures and invariants.

use crate::core::identity::{FsInstanceId, VnodeKey};
use crate::ops::{
    AckReplyIntent, AttrReplyIntent, CreateLeafKind, IoctlReplyIntent, OpenReplyIntent,
    ReadDirReplyIntent, ReadReplyIntent, RenameLinkKind, SetAttrKind, UnlinkKind, VfsOpenSpec,
    WriteReplyIntent,
};
use crate::owner::namei_aux::NameiAuxHandle;
use crate::owner::pending::{WalkCursor, WalkPhase};
use crate::personality::posix::types::{POLLFD_INLINE_MAX, PollFd};
use crate::server::open_object::OpenObjectAnchor;
use crate::server::types::ClientHandle;

/// Networking continuation payload. Carries the identity-stable
/// fields the owner needs to drive a netsrv callback back to a
/// parked client without re-resolving through the per-op inet
/// table.
#[derive(Clone, Copy)]
pub(crate) struct NetResume {
    /// Netsrv-provided connection identifier echoed on the
    /// callback.
    pub conn_id: u32,
    /// Netsrv registration generation at issue time. The callback
    /// gate drops replies whose generation pre-dates the current
    /// netsrv re-registration.
    pub netsrv_gen: u32,
    /// Operation discriminant mirrored from `NET_*` opcodes so the
    /// resume handler can route without re-decoding the reply.
    pub op_type: u8,
}

/// Pseudo-terminal continuation payload. Carries the pty side and
/// badge identity so the pty resume handler can locate the parked
/// reader / writer without walking the pty table a second time.
///
/// `op_type` discriminates which `PTYRESUME_OP_*` arm the
/// completion router takes — open / read / write / ioctl /
/// tcgetattr / tcsetattr each emit a different reply shape.
#[derive(Clone, Copy)]
pub(crate) struct PtyResume {
    pub pty_index: u16,
    pub side: u8,
    pub op_type: u8,
    /// Maximum byte count requested by the client for parked PTY
    /// reads. `VFS_PTY_READY` reuses this to issue the deferred
    /// collect request without re-reading the original IPC message.
    pub max_count: u32,
    pub client_badge: u64,
}

/// Framebuffer / display continuation payload. Carries the FB
/// vnode the request was issued against plus an op-type
/// discriminator the completion router uses to pick the matching
/// reply shape. The reply for `GET_BACKING_MO` carries an MO cap
/// the router forwards to the client; `GET_INFO` returns inline
/// scalar fields; `PRESENT` is an ack with no payload beyond the
/// reply label.
#[derive(Clone, Copy)]
pub(crate) struct FbResume {
    /// FB vnode arena slot — resolves to the `Vnode` whose
    /// `meta.backing_mo` cache the router optionally updates after
    /// `GET_BACKING_MO` completes.
    pub vnode_slot: u32,
    /// Operation discriminant (`FBRESUME_OP_*`).
    pub op_type: u8,
    /// Original POSIX / NT device-control selector when the
    /// completion needs to project one dispdrv reply into multiple
    /// public ioctl shapes. Zero means the op has a single fixed
    /// reply shape.
    pub request: u32,
    /// Client badge captured at issue time so the router can
    /// short-circuit replies whose caller has since closed the fd.
    pub client_badge: u64,
}

/// POSIX poll continuation. The fd set is copied from the inbound
/// wire into fixed-size owner storage before the reply lease is
/// parked, so readiness wakeups never borrow the original IPC
/// buffer. `nfds` is capped by `POLLFD_INLINE_MAX`.
#[derive(Clone, Copy)]
pub(crate) struct PollResume {
    pub client: ClientHandle,
    pub nfds: u8,
    pub entries: [PollFd; POLLFD_INLINE_MAX],
}

/// Final-component terminator the async namei walk feeds into.
///
/// Variants split into two groups:
///
/// 1. **Personality-bipolar terminals** carry a `ReplyIntent`
///    that selects the wire shape (POSIX or NT) without changing
///    the logic helper that runs at the leaf. POSIX dispatch and
///    Win32 dispatch reach the same ops helper through
///    these variants — neither personality is a wrapper of the
///    other.
/// 2. **POSIX-only terminals** cover ops the NT surface does not
///    expose (`chdir`, `getcwd`, exec preflight, the readlink
///    path-bytes reply). Win32 dispatch never produces these.
#[derive(Clone, Copy)]
pub(crate) enum NameiTerminal {
    // ===== Personality-bipolar terminals =====
    /// Open + create-mode applied at the resolved leaf (or against
    /// the parent for `O_CREAT` / `CREATE_NEW`). The ops
    /// helper consumes the `VfsOpenSpec` and the personality reply
    /// dispatcher uses the `OpenReplyIntent` to decide between
    /// POSIX `regs[0] = fd` and NT `IoStatusBlock + handle`.
    Open {
        spec: VfsOpenSpec,
        reply: OpenReplyIntent,
    },
    /// Attribute query at the resolved leaf — POSIX
    /// `stat`/`lstat`/`fstatat`, NT
    /// `NtQueryInformationFile`/`NtQueryAttributesFile` family.
    /// The `AttrReplyIntent` selects which struct shape to pack
    /// (POSIX VAttr layout vs one of the NT
    /// `FILE_*_INFORMATION` classes).
    GetAttr { reply: AttrReplyIntent },
    /// Attribute mutation at the resolved leaf — POSIX
    /// `chmod`/`chown`/`utimes`/path-`truncate`, NT
    /// `NtSetInformationFile(FileBasicInformation)`. Walker
    /// terminal is the leaf itself (no parent mutation), so this
    /// is *not* a `ParentMutation` — chmod/chown/utimes do not
    /// touch the directory entry.
    SetAttr {
        kind: SetAttrKind,
        reply: AckReplyIntent,
    },
    /// Permission probe at the resolved leaf — POSIX
    /// `access`/`faccessat`. NT has no direct surface; Win32
    /// dispatch never produces this variant.
    Access { mode: u32, reply: AckReplyIntent },
    /// Removal: parent + name, single dirent removed. POSIX
    /// `unlink`/`rmdir`, NT `NtDeleteFile` /
    /// `NtSetInformationFile(FileDispositionInformation)`. The
    /// `kind` discriminates whether the leaf must be a directory.
    UnlinkLeaf {
        kind: UnlinkKind,
        reply: AckReplyIntent,
    },
    /// Two-stage walker: rename or hard-link an existing leaf onto
    /// a new (parent, name) pair. POSIX `rename`/`link`, NT
    /// `NtRenameFile` /
    /// `NtSetInformationFile(FileRenameInformation)` /
    /// `NtSetInformationFile(FileLinkInformation)`. The
    /// dual-path state lives in `state.namei_aux[aux_handle]`.
    RenameOrLink {
        kind: RenameLinkKind,
        aux_handle: NameiAuxHandle,
        reply: AckReplyIntent,
    },
    /// New-leaf creation under the resolved parent. POSIX
    /// `mkdir`/`symlink`/`mkfifo`/`mknod`, NT
    /// `NtCreateSymbolicLinkObject`/`NtCreateNamedPipeFile`.
    /// `aux_handle` is `Handle::INVALID` for inline kinds
    /// (`Mkdir`/`Mkfifo`/`Mknod`) and points at the symlink target
    /// bytes for `Symlink`.
    CreateLeaf {
        kind: CreateLeafKind,
        aux_handle: NameiAuxHandle,
        reply: AckReplyIntent,
    },
    // ===== POSIX-only terminals =====
    /// `readlink` — read the target bytes of a symlink leaf and
    /// surface them as the reply payload. NT exposes link-target
    /// queries through `NtQueryInformationFile(FileLinkInformation)`,
    /// which lands on [`Self::GetAttr`] with the matching
    /// [`AttrReplyIntent`]; the dedicated [`Self::Readlink`] only
    /// fires from POSIX dispatch.
    Readlink,
    /// `chdir` — replace the client's recorded cwd vnode and
    /// commit the canonicalised path. NT manages cwd inside the
    /// caller process (no kernel-level chdir), so this terminal
    /// only fires from POSIX.
    Chdir {
        canon_path: [u8; crate::owner::pending::WALK_PATH_MAX],
        canon_len: u16,
    },
    /// `VFS_CANON_PATH` — namei-resolved absolute path emitter
    /// that POSIX exec / `realpath`-equivalent helpers consume.
    /// NT has no direct surface.
    CanonPath {
        canon_path: [u8; crate::owner::pending::WALK_PATH_MAX],
        canon_len: u16,
    },
    /// POSIX exec preflight — `access(X_OK)` followed by
    /// `getattr`. NT exec is a userland concern (CreateProcessW
    /// inside basaltc/win32) so this preflight does not surface
    /// from NT.
    StatForExec,
    /// POSIX `execve` — `access(X_OK)` preflight, then a Regular-file /
    /// `MNT_NOEXEC` policy check and issuance of a non-exec backing
    /// MemoryObject for the resolved binary. Unit variant — the resolved
    /// vnode rides in the walk result.
    OpenForExec,
}

/// Identifies which child-returning compound mutation produced a
/// `FinalOpChild` resume — lets the completion router pick the
/// right reply format.
#[derive(Clone, Copy)]
pub(crate) enum FinalOpKind {
    Create,
    Mkdir,
    Symlink,
}

/// Sub-discriminator for the removal flavour of
/// `FinalOpAckRemoval`.
#[derive(Clone, Copy)]
pub(crate) enum FinalOpRemovalKind {
    Unlink,
    Rmdir,
}

/// Which metadata operation the internal late-pivot state machine
/// is currently waiting on.
#[derive(Clone, Copy)]
pub(crate) enum LatePivotOp {
    Lookup,
    Mkdir,
}

/// Filesystem continuation variants.
///
/// Every variant that produces a personality-visible reply
/// carries a [`crate::personality::reply_intent`] discriminator.
/// The ops helper terminates with a personality-neutral
/// result; the matching `personality::reply::emit_*` dispatcher
/// reads the intent and routes the reply through
/// `personality/posix/reply.rs` or `personality/win32/reply.rs`.
///
/// Each variant captures only generic data (client handle,
/// identity keys, fds, SHM offsets, transfer descriptors,
/// reply intent). Backend-specific parsing / payload extraction
/// lives on `BackendSessionSlot::completion_fn`.
#[derive(Clone, Copy)]
pub(crate) enum FsResume {
    // ===== Personality-bipolar resumes =====
    /// Parked on a plain (non-create) terminal `meta.open` RPC.
    /// The completion router installs the `OpenObject` and
    /// emits the wire reply via `personality::reply::emit_open`
    /// once the backend confirms the open is valid.
    FillOpenReply {
        client: ClientHandle,
        vkey: VnodeKey,
        anchor: OpenObjectAnchor,
        spec: VfsOpenSpec,
        reply: OpenReplyIntent,
    },
    /// Parked while fetching `security.NTACL` before a Win32 open.
    /// The completion router copies the descriptor out of backend
    /// SHM, evaluates it, then re-enters the open helper with the
    /// ACL check marked complete so the terminal `meta.open` can
    /// run normally.
    FillNtAclOpenReply {
        client: ClientHandle,
        vkey: VnodeKey,
        anchor: OpenObjectAnchor,
        spec: VfsOpenSpec,
        reply: OpenReplyIntent,
        desired_access: u32,
    },
    /// Parked on the controlling-tty lookup backing an
    /// `open("/dev/tty")`. The completion installs the OpenObject,
    /// binds the resolved pty to it (so I/O routes to the caller's
    /// ctty), and emits the open — or fails it when the session has
    /// no controlling terminal.
    BindCttyOpen {
        client: ClientHandle,
        vnode_h: crate::core::vnode::VnodeHandle,
        anchor: OpenObjectAnchor,
        spec: VfsOpenSpec,
        action: crate::ops::spec::OpenCreateAction,
        reply: OpenReplyIntent,
    },
    /// Parked on the posix_ttysrv controlling-tty binding dump that
    /// prefixes a tty-bearing init read (`kern.proc.*`,
    /// `/proc/<pid>/stat`). The completion caches the `(sid → tty_dev)`
    /// bindings into the snapshot, then fires the read's first init
    /// query; `decode` joins `tty_dev` locally. Carries no lease — the
    /// client lease lives on the `InitQuerySnapshot` across the chain.
    CttyDump {
        snapshot: crate::arena::handle::Handle<crate::owner::init_rpc::InitQuerySnapshot>,
    },
    /// Parked on the terminal attribute-query RPC. Covers POSIX
    /// `stat`/`lstat`/`fstat`/`fstatat` plus NT
    /// `NtQueryInformationFile` / `NtQueryAttributesFile` /
    /// `NtQueryFullAttributesFile` — the [`AttrReplyIntent`]
    /// selects which struct shape the reply emitter packs.
    FillGetAttrReply {
        client: ClientHandle,
        vkey: VnodeKey,
        reply: AttrReplyIntent,
    },
    /// Parked on a leaf-attribute mutation RPC — POSIX
    /// `chmod`/`chown`/`utimes`/path-`truncate`, NT
    /// `NtSetInformationFile(FileBasicInformation)`.
    FillSetAttrReply {
        client: ClientHandle,
        vkey: VnodeKey,
        reply: AckReplyIntent,
    },
    /// Parked on the terminal permission-probe RPC — POSIX
    /// `access`/`faccessat`. NT does not surface this op.
    FillAccessReply {
        client: ClientHandle,
        vkey: VnodeKey,
        reply: AckReplyIntent,
    },
    /// Parked on a generic mutation whose completion is a plain
    /// ack — POSIX errno=0 or NT IoStatusBlock with `Status=0`.
    AckMutation {
        client: ClientHandle,
        vkey: VnodeKey,
        reply: AckReplyIntent,
    },
    /// Parked on a compound mutation whose completion materialises
    /// a new child vnode on the parent (`create` / `mkdir` /
    /// `symlink` / `mkfifo` / `mknod`). When `spec` is `Some`,
    /// the operation is `O_CREAT` / `NT FILE_CREATE` and the
    /// completion installs an `OpenObject` + fd before emitting;
    /// when `None`, the mutation surfaces as a plain ack.
    FinalOpChild {
        client: ClientHandle,
        parent_vkey: VnodeKey,
        kind_hint: FinalOpKind,
        spec: Option<VfsOpenSpec>,
        open_reply: OpenReplyIntent,
        ack_reply: AckReplyIntent,
        creds_uid: u32,
        creds_gid: u32,
    },
    /// Parked on `unlink` / `rmdir` / `NtDeleteFile` /
    /// `NtSetInformationFile(FileDispositionInformation)`.
    FinalOpAckRemoval {
        client: ClientHandle,
        parent_vkey: VnodeKey,
        removed_child_vkey: VnodeKey,
        kind: FinalOpRemovalKind,
        reply: AckReplyIntent,
    },
    /// Reply-less unlink fired by NT delete-on-close when the
    /// final handle reference drops. Completion only invalidates
    /// caches and releases backend credit.
    DeleteOnClose {
        parent_vkey: VnodeKey,
        removed_child_vkey: VnodeKey,
        kind: FinalOpRemovalKind,
    },
    /// Parked on `rename` / `NtRenameFile` /
    /// `NtSetInformationFile(FileRenameInformation)`.
    FinalOpAckRename {
        client: ClientHandle,
        new_parent_vkey: VnodeKey,
        old_parent_vkey: VnodeKey,
        reply: AckReplyIntent,
    },
    /// Parked on `link` /
    /// `NtSetInformationFile(FileLinkInformation)`.
    FinalOpAckLink {
        client: ClientHandle,
        new_parent_vkey: VnodeKey,
        reply: AckReplyIntent,
    },
    /// Parked on `truncate` /
    /// `NtSetInformationFile(FileEndOfFileInformation)`.
    FinalOpAckTruncate {
        client: ClientHandle,
        file_vkey: VnodeKey,
        fd: i32,
        old_size: u64,
        reply: AckReplyIntent,
    },
    /// Parked on a bulk-read RPC where the client wants the result
    /// inline in the reply's `regs[]` area (short-read fast path).
    /// `shm_offset` is the backend SHM source offset that the
    /// completion router copies from before packing the inline
    /// reply.
    BulkReadStage {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
        fd: i32,
        shm_offset: u64,
        reply: ReadReplyIntent,
    },
    /// Parked on a bulk-read RPC where the client supplied a
    /// destination range inside its registered bulk SHM region.
    /// The completion router copies from the backend SHM at
    /// offset `0` (saltyfs convention — see `saltyfs_read`)
    /// straight into `client_shm_va + client_shm_offset` for
    /// `bytes_read` bytes, then replies with just the length.
    BulkReadStageShm {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
        fd: i32,
        client_shm_offset: u64,
        client_shm_len: u64,
        reply: ReadReplyIntent,
    },
    /// Parked on a bulk-write RPC. The backend reply carries the
    /// committed byte count; the completion router advances the fd
    /// offset only when `fd >= 0` (plain write), leaving positional
    /// writes (`pwrite` / NT explicit byte offset) unchanged.
    BulkWriteStage {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
        fd: i32,
        file_offset: u64,
        requested_len: u64,
        reply: WriteReplyIntent,
    },
    /// Parked on a bulk-readdir RPC.
    BulkReaddirStage {
        client: ClientHandle,
        dir_vkey: VnodeKey,
        fs_id: FsInstanceId,
        fd: i32,
        open_handle: crate::server::types::OpenObjectHandle,
        start_cursor: u64,
        reply: ReadDirReplyIntent,
    },
    /// Parked on a device-control VOP. The completion router
    /// projects the backend-provided raw words through POSIX
    /// ioctl or NT DeviceIoControl reply shape.
    FillIoctlReply {
        client: ClientHandle,
        vkey: VnodeKey,
        /// The originating ioctl command. The completion router needs
        /// it to project a backend reply into the per-command POSIX
        /// shape (e.g. `TIOCGWINSZ` → `struct winsize`,
        /// `FBIOGET_VSCREENINFO` → `struct fb_var_screeninfo`).
        cmd: u32,
        reply: IoctlReplyIntent,
    },
    /// Parked on a step of the async namei walk. The walker's
    /// `NameiTerminal` already carries the personality-aware
    /// reply intent (POSIX or NT), so this variant only needs
    /// the cursor + phase to resume.
    NameiStep {
        client: ClientHandle,
        cursor: WalkCursor,
        phase: WalkPhase,
        terminal: NameiTerminal,
    },

    // ===== POSIX-only resumes =====
    /// Parked on the terminal `readlink` metadata RPC. NT exposes
    /// link-target queries through
    /// `NtQueryInformationFile(FileLinkInformation)`, which lands
    /// on [`Self::FillGetAttrReply`] with the matching attr
    /// intent — this dedicated POSIX entry only fires when the
    /// caller is a POSIX client.
    FillReadlinkReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the exec-preflight `access(X_OK)` metadata RPC.
    /// POSIX-only — NT exec is a userland concern.
    FillStatForExecAccessReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the exec-preflight terminal `getattr` RPC.
    /// POSIX-only.
    FillStatForExecAttrReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the `execve` `access(X_OK)` preflight RPC. On completion
    /// the resolved vnode's exec policy is checked and a non-exec backing
    /// MO is issued + replied. POSIX-only.
    FillOpenForExecAccessReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on a `getxattr` metadata RPC. POSIX-only public
    /// xattr entry points and NT security-descriptor queries can
    /// both consume this through their own reply layer.
    FillXattrGetReply {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
    },
    /// Parked on `NtQuerySecurityObject` while fetching the raw
    /// `security.NTACL` xattr. Missing xattr is not an error here:
    /// the Win32 reply shape returns a zero-length descriptor.
    FillNtSecurityQueryReply {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
    },
    /// Parked on a `listxattr` metadata RPC. The completion router
    /// copies the backend SHM payload before releasing credit.
    FillListXattrReply {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
    },

    // ===== Backend-internal resumes =====
    /// Parked on one step of the internal late-pivot scaffold
    /// builder.
    LatePivot { dir_index: u8, op: LatePivotOp },
}

/// Discriminator for the page-cache-driven backend round-trip
/// the resume should service.
pub(crate) const PAGERRESUME_OP_READ: u8 = 1;
pub(crate) const PAGERRESUME_OP_WRITEBACK: u8 = 2;

/// Resume payload for `OpKind::Pager` ops — backend READ /
/// WRITEBACK round-trips that the pager-event handler fires in
/// response to a kernel `EVENT_TYPE_PAGER_REQUEST` event. Carries
/// enough state to identify the in-flight kernel pager request by
/// `(mo_id, page_idx)` and locate the backing vnode until the backend
/// round-trip lands. The page bytes themselves stage in vfs's read
/// buffer (sync) or the mount SHM ring (async) and are handed to the
/// kernel via `PAGER_SUPPLY_COPY`.
#[derive(Clone, Copy)]
pub(crate) struct PagerResume {
    /// `PAGERRESUME_OP_*` discriminator.
    pub op_type: u8,
    /// Live VnodeHandle the binding keys off. Carried so the
    /// 5-tuple guard on completion can drop replies whose vnode
    /// slot has been recycled.
    pub vnode: crate::core::vnode::VnodeHandle,
    /// Authoritative identity for cache-coherency checks.
    pub vkey: VnodeKey,
    /// Page-aligned file offset (bytes) the backend was asked to
    /// read / write.
    pub page_offset: u64,
    /// Page length in bytes — typically `KERNITE_PAGE_BYTES`. The
    /// wire carries it explicitly so a future huge-page pager
    /// extension plugs in without a resume reshape.
    pub length: u32,
    /// Kernel-issued mo_id from `MO_ATTACH_PAGER`. Echoed back to
    /// the kernel on `PAGER_SUPPLY_COPY` / `PAGER_FAIL` /
    /// `PAGER_WRITEBACK_DONE` so the kernel can match the reply
    /// against the originating `PendingPagerRequest`.
    pub mo_id: u64,
    /// Page index inside the MO (kernel-supplied at fault time;
    /// `record.payload0`).
    pub page_idx: u64,
    /// Pager cancel epoch returned by `PAGER_BEGIN_WRITEBACK`.
    /// Read requests carry 0. Writeback completions echo this
    /// back through `PAGER_WRITEBACK_DONE` so the kernel can
    /// reject stale acks after pager detach / rebind.
    pub writeback_epoch: u64,
    /// Non-zero when this writeback is part of an explicit mmsrv
    /// `MM_MSYNC` / file-backed `MM_MUNMAP` barrier. Completion decrements
    /// the matching VFS barrier before mmsrv is notified.
    pub mmsrv_writeback_token: u64,
}

/// init-query continuation. A parked procfs / sysctl / ctty read is
/// waiting on init's reply (demuxed by kernel `mp_txid`); the handle
/// points at the read's [`InitQuerySnapshot`] which owns the plan, the
/// typed per-step results, and the parked client reply-lease. `stage`
/// is the plan step this `PendingOp`'s reply fills.
///
/// [`InitQuerySnapshot`]: crate::owner::init_rpc::InitQuerySnapshot
#[derive(Clone, Copy)]
pub(crate) struct InitResume {
    pub snapshot: crate::arena::handle::Handle<crate::owner::init_rpc::InitQuerySnapshot>,
    pub stage: u8,
}

/// Top-level resume discriminator. Stored as a field on every
/// `PendingOp`.
#[derive(Clone, Copy)]
pub(crate) enum Resume {
    /// Sentinel installed by `reserve_fs_pending`. The posix
    /// caller is expected to overwrite it via `stamp_resume_ctx`
    /// before returning control to the owner loop. A live
    /// `Placeholder` observed by a completion router indicates a
    /// caller-side bug and gets dropped with a log.
    Placeholder,
    /// Filesystem continuation.
    Fs(FsResume),
    /// Networking continuation.
    Net(NetResume),
    /// Pseudo-terminal continuation.
    Pty(PtyResume),
    /// Framebuffer / display continuation.
    Fb(FbResume),
    /// POSIX `poll(2)` readiness continuation.
    Poll(PollResume),
    /// Page-cache pager continuation — backend RPC fired in
    /// response to a mmsrv pager callback (PAGER_READ /
    /// PAGER_WRITEBACK).
    Pager(PagerResume),
    /// init-query continuation — a parked procfs / sysctl / ctty read
    /// awaiting init's reply on the `KIND_INIT_REPLY` channel.
    Init(InitResume),
}

impl Resume {
    pub(crate) const EMPTY: Self = Resume::Placeholder;
}
