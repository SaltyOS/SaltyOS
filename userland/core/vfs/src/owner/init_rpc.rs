// SPDX-License-Identifier: GPL-2.0-only
//
//! init-query async machine — the no-block transport for VFS→init
//! procfs / sysctl / ctty reads.
//!
//! The VFS owner reactor must never make a blocking `mp_call` to init:
//! init can call back into VFS (during spawn / fork / exec), so a
//! blocking VFS→init query is one side of the init↔VFS reactor
//! deadlock. Instead a read parks an [`InitQuerySnapshot`], issues each
//! init sub-query as a non-blocking `mp_write` carrying a low-range
//! correlation `txid`, and resumes when init's reply lands on the
//! `KIND_INIT_REPLY` channel (a Watch on `init_ep`'s recv side bound to
//! `owner_eq`). Replies are demuxed by the kernel `mp_txid` — init
//! echoes it automatically via `MpReplyTarget::from_ipc_buffer`, so no
//! application-level correlation header is needed (this is distinct from
//! the backend-session path, which keys on a `CorrelationHeader`).
//!
//! A single procfs read may need several sequential init sub-queries
//! (e.g. `/proc/<pid>/stat` = proc_info + proc_times + mem_stats). The
//! snapshot owns the originating client's reply-lease and the typed
//! per-target results across the whole chain; each per-query `PendingOp`
//! only correlates one init round-trip and points back at the snapshot
//! via [`Resume::Init`]. When the plan completes, the snapshot is
//! finalised: the synchronous content generator runs against the
//! collected results and the client reply is sent.
//!
//! Correlation key reuse: `alloc_pending` mints a monotonic low-range
//! [`TxId`] (top bit always clear) and keys the continuation arena by
//! it; that same value is the kernel `mp_txid` on the request, so the
//! reply's `meta.txid` maps straight back via `find_pending_op`.

use trona_kernel::core_types::TronaMsg;
use trona_server::ParkedReply;

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::identity::{BackendNodeId, FsInstanceId, VnodeKey};
use crate::fs::metrics::proc::{ARGV_MAX, ArgvBuf, ProcInfoFull, ProcTimes, SystemProcStats};
use crate::ops::ReadReplyIntent;
use crate::owner::VfsState;
use crate::owner::op::OpKind;
use crate::owner::pending::{PendingOpHandle, TxId, WalkCursor, alloc_pending};
use crate::owner::resume::{InitResume, NameiTerminal, Resume};
use crate::personality::Personality;
use crate::server::consts::MAX_PATH_LEN;
use crate::server::types::ClientHandle;

/// Max init sub-queries chained for one read. `/proc/<pid>/stat` and
/// `/proc/<pid>/status` need the most: proc_info + proc_times +
/// mem_stats = 3; one slot of headroom.
pub(crate) const INIT_PLAN_MAX: usize = 4;

#[inline]
unsafe fn ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

/// One planned init sub-query. `label` is `INIT_GET_PROC_INFO` or
/// `INIT_PGRP_SESSION`; `sub_op` rides `regs[0]`, `arg` rides `regs[1]`
/// (pid / badge). Pagination of variable-length results (argv bytes,
/// per-CPU records) is layered in the completion stage by re-issuing a
/// step with an advancing cursor before advancing `stage`.
#[derive(Clone, Copy)]
pub(crate) struct InitStep {
    pub label: u64,
    pub sub_op: u64,
    pub arg: u64,
}

impl InitStep {
    pub(crate) const NONE: Self = Self {
        label: 0,
        sub_op: 0,
        arg: 0,
    };
}

/// Which procfs read an [`InitReadState::ProcRead`] snapshot serves —
/// selects the finalize formatter. Grows one variant per converted read.
#[derive(Clone, Copy)]
pub(crate) enum ProcReadKind {
    /// `/proc/<pid>/comm`
    Comm,
    /// `/proc/<pid>/stat`
    PidStat,
    /// `/proc/<pid>/status`
    PidStatus,
    /// `/proc/loadavg`
    SysLoadavg,
    /// `/proc/stat` (system-wide)
    SysStat,
    /// `/proc/<pid>/cmdline`
    Cmdline,
}

/// Maximum bytes a `kern.proc.*` sysctl read assembles in one snapshot.
/// Single-value reads (`pathname` / `args` / `pid`) fit easily; the bulk
/// listings (`all` + the filter dirs) page `KinfoProc` records into this
/// buffer and stop appending once it is full (~30 records), bounding the
/// snapshot rather than allocating per-process-count storage.
pub(crate) const SYSCTL_CONTENT_CAP: usize = 4096;

/// `kern.proc` filter-dir selectors — which `KinfoProc` field the filter
/// `<value>` is matched against. `0` means "no filter" (`kern.proc.all`).
pub(crate) const SYSCTL_FILTER_PGRP: u8 = 1;
pub(crate) const SYSCTL_FILTER_TTY: u8 = 2;
pub(crate) const SYSCTL_FILTER_UID: u8 = 3;
pub(crate) const SYSCTL_FILTER_RUID: u8 = 4;
pub(crate) const SYSCTL_FILTER_SESSION: u8 = 5;

/// Max controlling-tty bindings cached per read (≥ posix_ttysrv MAX_PTYS,
/// with headroom). Bounds the `InitQuerySnapshot` ctty cache.
pub(crate) const CTTY_BINDINGS_MAX: usize = 8;

/// Resolve a session's controlling-tty device from the prefetched
/// posix_ttysrv binding cache (`entries` packed `sid | tty_dev << 32`).
/// Returns 0 (no controlling tty) when the session is absent — the
/// procfs / kinfo "no tty" sentinel.
fn ctty_lookup(entries: &[u64], count: u8, sid: u32) -> u64 {
    if sid == 0 {
        return 0;
    }
    let n = (count as usize).min(entries.len());
    for &e in &entries[..n] {
        if (e & 0xFFFF_FFFF) as u32 == sid {
            return e >> 32;
        }
    }
    0
}

/// Whether a read surfaces a controlling-tty device and therefore needs
/// the posix_ttysrv binding dump prefetched before its init query.
fn read_needs_ctty(st: &InitReadState) -> bool {
    matches!(
        st,
        InitReadState::SysValue {
            kind: SysValueKind::KinfoAll | SysValueKind::KinfoFilter | SysValueKind::KinfoSingle,
            ..
        } | InitReadState::ProcRead {
            kind: ProcReadKind::PidStat,
            ..
        }
    )
}

/// Which `kern.proc.*` sysctl read an [`InitReadState::SysValue`] serves —
/// selects the init transport (single query / argv pagination / kinfo
/// page loop) and the finalize formatter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysValueKind {
    /// `kern.proc.pathname.<pid>` — exe path bytes (`GET_EXE_PATH`).
    ExePath,
    /// `kern.proc.args.<pid>` — NUL-separated argv (`GET_ARGV`, paged).
    Argv,
    /// `kern.proc.pid.<pid>` — one bare `KinfoProc` (`GET_KINFO_PROC`).
    KinfoSingle,
    /// `kern.proc.all` — `u32 count + KinfoProc[]` (kinfo page loop).
    KinfoAll,
    /// `kern.proc.{pgrp,tty,uid,ruid,session}.<val>` — filtered
    /// `u32 count + KinfoProc[]` (page loop + local field match).
    KinfoFilter,
}

/// Typed init results accumulated for a procfs read, filled by
/// `decode_into_snapshot` as each planned query replies and rendered by
/// the finalize formatter. Grows one field per result type as read edges
/// are converted.
#[derive(Clone, Copy, Default)]
pub(crate) struct ProcReadResults {
    pub info: Option<ProcInfoFull>,
    pub times: Option<ProcTimes>,
    pub system_stats: Option<SystemProcStats>,
    pub argv: Option<ArgvBuf>,
}

/// Typed per-read result / accumulator state. One variant per read
/// target; the finalize step matches on it to re-enter the matching
/// synchronous content generator. Variant 0 (`None`) is the zeroed
/// sentinel so a freshly `alloc`'d (zeroed) arena slot is a valid value
/// until [`InitQuerySnapshot::EMPTY`] overwrites it.
/// What a ctty session-resolve chains into once init returns the
/// caller's `(sid, pgid)`. The init query is the only blocking step; the
/// pty issue + reply are replayed in `finalize_init_snapshot`.
pub(crate) enum CttyAction {
    /// `VFS_GET_CTTY_DEV`: pty ctty-lookup, then map the pty id to a
    /// synthetic `tty_dev` (`PTYRESUME_OP_CTTY_DEV`).
    GetCttyDev,
    /// `open("/dev/tty")`: pty ctty-lookup, then bind the ctty open with
    /// the prebuilt `BindCttyOpen` resume; `err_intent` frames an error.
    OpenBind {
        resume: Resume,
        err_intent: crate::ops::OpenReplyIntent,
    },
    /// devfs ctty-control ioctl (`TIOCSCTTY` / `TIOCSPGRP` / `TIOCGSID` /
    /// `TIOCNOTTY`): pty ioctl carrying the session, reply projected by
    /// `FillIoctlReply`. Built whole by the devfs vop — these cmds are
    /// POSIX-only, so the reply intent is `PosixIoctl`.
    Ioctl {
        pty_id: u32,
        cmd: u32,
        arg: u64,
        vkey: VnodeKey,
        reply: crate::ops::IoctlReplyIntent,
    },
}

pub(crate) enum InitReadState {
    /// Uninitialised sentinel.
    None,
    /// `/proc/<pid>/exe` and `/proc/self/exe` readlink. Holds the exe
    /// path init returned (`GET_EXE_PATH`) plus the personality the
    /// readlink reply must be framed for.
    ProcExeReadlink {
        personality: Personality,
        path: [u8; MAX_PATH_LEN],
        len: u16,
    },
    /// `/proc/<pid>/exe` readlink used internally while namei follows a
    /// symlink (for example `open("/proc/self/exe")`). The init result
    /// resumes the walk instead of emitting a readlink reply directly.
    ProcExeNameiReadlink {
        client: ClientHandle,
        cursor: WalkCursor,
        terminal: NameiTerminal,
        path: [u8; MAX_PATH_LEN],
        len: u16,
    },
    /// procfs content read served from init data. Carries the read
    /// window (`offset`/`len`) + inline-reply framing (`intent`) and the
    /// typed results the finalize formatter renders into the reply.
    ProcRead {
        kind: ProcReadKind,
        pid: u32,
        offset: u64,
        len: u64,
        intent: ReadReplyIntent,
        results: ProcReadResults,
    },
    /// ctty session resolve (`INIT_PGRP_SESSION`). `sid`/`pgid` are
    /// filled from the reply; `finalize` then issues the pty op named by
    /// `action` and re-parks the client lease on it.
    Ctty {
        client: crate::server::types::ClientHandle,
        action: CttyAction,
        sid: u64,
        pgid: u64,
    },
    /// `/proc` root readdir pid section. The static entries emit
    /// synchronously; once the cursor reaches the pid range the vop parks
    /// here, fetches the pid list (`LIST_PIDS`, inline regs), and
    /// `finalize` emits the single dirent at `cursor` (procfs readdir is
    /// one entry per `getdents`). procfs is POSIX-only, so the reply
    /// framing is fixed to `PosixGetDents`.
    Readdir {
        open_h: crate::server::types::OpenObjectHandle,
        cursor: u64,
        base: u64,
        reply: crate::ops::ReadDirReplyIntent,
        pids: [u32; 32],
        pid_count: u16,
        /// Directory-entry type emitted for each pid child: `DT_DIR` for
        /// `/proc/<pid>` dirs, `DT_REG` for `kern.proc.*` leaf children.
        dtype: u8,
    },
    /// init-backed `kern.proc.*` sysctl read. Pages init for the records
    /// it owns (identity / lifecycle / cred / times), filters locally on
    /// those fields, enriches `vm_size` / `vm_rss` from mmsrv per kept
    /// record, then `finalize` emits the windowed content. `kind` selects
    /// the transport + format; `filter_kind` / `filter_val` apply to the
    /// `KinfoFilter` listings; `content` accumulates across kinfo pages.
    SysValue {
        kind: SysValueKind,
        filter_kind: u8,
        filter_val: u32,
        offset: u64,
        len: u64,
        intent: crate::ops::ReadReplyIntent,
        content: [u8; SYSCTL_CONTENT_CAP],
        content_len: u32,
        count: u32,
        page_off: u32,
        total: u32,
        /// Set when the content buffer filled before every matching record
        /// was appended (more processes than `SYSCTL_CONTENT_CAP` holds);
        /// `finalize` surfaces it via `uwarn!`.
        truncated: bool,
    },
}

/// Parked async state for one VFS→init read. Lives in
/// `VfsState.init_snapshots`; referenced by every in-flight
/// `Resume::Init` for this read.
pub(crate) struct InitQuerySnapshot {
    plan: [InitStep; INIT_PLAN_MAX],
    plan_len: u8,
    stage: u8,
    state: InitReadState,
    /// The originating client's reply endpoint, parked for the lifetime
    /// of the chain. Resumed and consumed exactly once at finalize /
    /// failure.
    reply_lease: Option<ParkedReply>,
    client_id: u32,
    client_badge: u64,
    /// Prefetched posix_ttysrv controlling-tty bindings for a tty-bearing
    /// read, packed `(sid in low 32) | (tty_dev in high 32)`. The
    /// `CttyDump` pre-stage fills this before the init query runs;
    /// `decode` joins `tty_dev` from it. Empty ⇒ records report no tty.
    ctty_entries: [u64; CTTY_BINDINGS_MAX],
    ctty_count: u8,
}

impl InitQuerySnapshot {
    pub(crate) const EMPTY: Self = Self {
        plan: [InitStep::NONE; INIT_PLAN_MAX],
        plan_len: 0,
        stage: 0,
        state: InitReadState::None,
        reply_lease: None,
        client_id: 0,
        client_badge: 0,
        ctty_entries: [0; CTTY_BINDINGS_MAX],
        ctty_count: 0,
    };
}

pub(crate) type InitSnapshotHandle = Handle<InitQuerySnapshot>;

/// Start an async VFS→init read. Parks `reply_lease`, allocates a
/// snapshot, and fires the first sub-query. The caller's vop returns
/// "parked" (does NOT consume the lease) after this. Returns the
/// snapshot handle on success; on allocation / send failure the lease
/// is already consumed with an error reply and `None` is returned.
pub(crate) fn begin_init_read(
    state: &mut VfsState,
    plan: &[InitStep],
    read_state: InitReadState,
    client_id: u32,
    client_badge: u64,
    reply_lease: trona_server::ReplyLease,
) -> Option<InitSnapshotHandle> {
    let Some(h) = state.init_snapshots.alloc() else {
        crate::personality::wire::send_reply_err_typed(
            Personality::Posix,
            reply_lease,
            VfsError::NoMem,
        );
        return None;
    };
    {
        // SAFETY: handle just allocated; slot is live.
        let snap = match state.init_snapshots.get_mut(h) {
            Some(s) => s,
            None => return None,
        };
        *snap = InitQuerySnapshot::EMPTY;
        let n = plan.len().min(INIT_PLAN_MAX);
        snap.plan[..n].copy_from_slice(&plan[..n]);
        snap.plan_len = n as u8;
        snap.state = read_state;
        snap.client_id = client_id;
        snap.client_badge = client_badge;
        snap.reply_lease = Some(reply_lease.park());
    }
    if issue_first_query(state, h).is_none() {
        fail_init_snapshot(state, h, VfsError::Io);
        return None;
    }
    Some(h)
}

/// Like [`begin_init_read`] but for a vop-layer caller that does not yet
/// hold the reply-lease (the vop returns `Parked` and the dispatch layer
/// attaches the lease via [`attach_lease_if_init`]). Allocates the
/// snapshot with no lease, fires sub-query 0, and returns the first
/// per-query `PendingOp` handle — the value the vop returns as
/// `Parked(handle)`.
pub(crate) fn begin_init_read_deferred(
    state: &mut VfsState,
    plan: &[InitStep],
    read_state: InitReadState,
    client_id: u32,
    client_badge: u64,
) -> Option<PendingOpHandle> {
    let h = state.init_snapshots.alloc()?;
    {
        let snap = state.init_snapshots.get_mut(h)?;
        *snap = InitQuerySnapshot::EMPTY;
        let n = plan.len().min(INIT_PLAN_MAX);
        snap.plan[..n].copy_from_slice(&plan[..n]);
        snap.plan_len = n as u8;
        snap.state = read_state;
        snap.client_id = client_id;
        snap.client_badge = client_badge;
        // reply_lease stays None until `attach_lease_if_init`.
    }
    match issue_first_query(state, h) {
        op @ Some(_) => op,
        None => {
            // No lease parked yet; just free the snapshot. The vop
            // surfaces the failure to the client itself.
            let _ = state.init_snapshots.release(h);
            None
        }
    }
}

/// If `op_h` is an in-flight init-query op (`Resume::Init`), park `lease`
/// into its owning snapshot and return `Ok(())`. Otherwise it is a
/// normal backend op — return `Err(lease)` so the caller falls back to
/// its usual `stamp_resume_ctx` park. Each dispatch `Parked` arm calls
/// this first so init-async reads (whose lease lives on the snapshot
/// across the query chain) are handled uniformly.
pub(crate) fn attach_lease_if_init(
    state: &mut VfsState,
    op_h: PendingOpHandle,
    lease: trona_server::ReplyLease,
) -> Result<(), trona_server::ReplyLease> {
    let snap_h = match state.pending_ops.get(op_h) {
        Some(op) => match op.resume {
            Resume::Init(ir) => ir.snapshot,
            // The ctty-dump pre-stage op also owns the read's snapshot,
            // and is the first op for a tty-bearing deferred read — its
            // lease attaches to the snapshot exactly like an init query's.
            Resume::Fs(crate::owner::resume::FsResume::CttyDump { snapshot }) => snapshot,
            _ => return Err(lease),
        },
        None => return Err(lease),
    };
    match state.init_snapshots.get_mut(snap_h) {
        Some(snap) => {
            snap.reply_lease = Some(lease.park());
            Ok(())
        }
        None => {
            // Snapshot gone (unexpected in the single-threaded reactor):
            // consume the lease with an error rather than leak or hang.
            crate::personality::wire::send_reply_err_typed(Personality::Posix, lease, VfsError::Io);
            Ok(())
        }
    }
}

/// Attach a frontend lease for an init-backed readlink that is being consumed
/// by the namei walker, not by the public `readlink(2)` terminal. Converts the
/// snapshot so finalize resumes namei with the target bytes.
pub(crate) fn attach_namei_readlink_if_init(
    state: &mut VfsState,
    op_h: PendingOpHandle,
    client: ClientHandle,
    cursor: WalkCursor,
    terminal: NameiTerminal,
    lease: trona_server::ReplyLease,
) -> Result<(), trona_server::ReplyLease> {
    let snap_h = match state.pending_ops.get(op_h) {
        Some(op) => match op.resume {
            Resume::Init(ir) => ir.snapshot,
            _ => return Err(lease),
        },
        None => return Err(lease),
    };
    match state.init_snapshots.get_mut(snap_h) {
        Some(snap) => {
            let replacement = match &snap.state {
                InitReadState::ProcExeReadlink { path, len, .. } => Some((*path, *len)),
                _ => None,
            };
            let Some((path, len)) = replacement else {
                return Err(lease);
            };
            snap.state = InitReadState::ProcExeNameiReadlink {
                client,
                cursor,
                terminal,
                path,
                len,
            };
            snap.reply_lease = Some(lease.park());
            Ok(())
        }
        None => {
            crate::personality::wire::send_reply_err_typed(Personality::Posix, lease, VfsError::Io);
            Ok(())
        }
    }
}

/// Like [`attach_lease_if_init`], but for the devfs ctty-control ioctl
/// path. The devfs vop parks a `Ctty::Ioctl` snapshot with a placeholder
/// client (the vop has only the caller badge); the dispatch layer —
/// which holds the resolved [`ClientHandle`] — injects it here, then
/// parks the lease. Returns `Err(lease)` for any op that is not a parked
/// `Ctty::Ioctl`, so the caller falls back to its normal ioctl stamp.
pub(crate) fn attach_ctty_ioctl(
    state: &mut VfsState,
    op_h: PendingOpHandle,
    client: crate::server::types::ClientHandle,
    lease: trona_server::ReplyLease,
) -> Result<(), trona_server::ReplyLease> {
    let snap_h = match state.pending_ops.get(op_h) {
        Some(op) => match op.resume {
            Resume::Init(ir) => ir.snapshot,
            _ => return Err(lease),
        },
        None => return Err(lease),
    };
    let snap = match state.init_snapshots.get_mut(snap_h) {
        Some(s) => s,
        None => return Err(lease),
    };
    match &mut snap.state {
        InitReadState::Ctty {
            client: c,
            action: CttyAction::Ioctl { .. },
            ..
        } => *c = client,
        _ => return Err(lease),
    }
    snap.reply_lease = Some(lease.park());
    Ok(())
}

/// Issue the controlling-tty binding dump that prefixes a tty-bearing
/// read, stamping a `CttyDump` resume pointing back at the snapshot. The
/// dump op carries no lease (it lives on the snapshot). Returns the op
/// handle, or `None` if posix_ttysrv is unreachable — the caller then
/// degrades to no-tty by issuing the init query directly.
fn issue_ctty_dump(state: &mut VfsState, snap_h: InitSnapshotHandle) -> Option<PendingOpHandle> {
    let badge = state.init_snapshots.get(snap_h)?.client_badge;
    let h = unsafe { crate::personality::posix::device::issue_pty_ctty_dump(state) }.ok()?;
    let resume = Resume::Fs(crate::owner::resume::FsResume::CttyDump { snapshot: snap_h });
    // Stamp the originating client's badge (from the snapshot) onto the
    // dump op so the client-teardown badge sweep finds + cancels it
    // (`reserve_pending_for_pty` leaves it zero). The client lease lives
    // on the snapshot, so pass no lease here.
    match state.stamp_resume_ctx(h, badge, None, resume) {
        Ok(()) => Some(h),
        Err(_) => {
            let _ = state.pending_ops.release(h);
            None
        }
    }
}

/// Fire the first async query for a freshly set-up snapshot. tty-bearing
/// reads prefetch the posix_ttysrv binding dump first (so `decode` can
/// join `tty_dev` and filters keyed on it work); if the dump cannot be
/// issued (posix_ttysrv down), they degrade to no-tty and go straight to
/// the init query. All other reads issue the init query immediately.
fn issue_first_query(state: &mut VfsState, snap_h: InitSnapshotHandle) -> Option<PendingOpHandle> {
    let needs = state
        .init_snapshots
        .get(snap_h)
        .map(|s| read_needs_ctty(&s.state))
        .unwrap_or(false);
    if needs {
        if let Some(h) = issue_ctty_dump(state, snap_h) {
            return Some(h);
        }
    }
    issue_init_query(state, snap_h, 0)
}

/// Issue plan step `stage`: park a `PendingOp` keyed by a fresh
/// low-range `tx_id` (= the kernel `mp_txid`) carrying a `Resume::Init`
/// pointer back to `snap_h`, then non-blocking-write the request to
/// init. Returns false on alloc / send failure (caller fails the read).
fn issue_init_query(
    state: &mut VfsState,
    snap_h: InitSnapshotHandle,
    stage: u8,
) -> Option<PendingOpHandle> {
    let (label, sub_op, arg, client_id, client_badge) = {
        let snap = state.init_snapshots.get(snap_h)?;
        if stage as usize >= snap.plan_len as usize {
            return None;
        }
        let step = snap.plan[stage as usize];
        (
            step.label,
            step.sub_op,
            step.arg,
            snap.client_id,
            snap.client_badge,
        )
    };

    // init queries carry no backend session and no vnode identity; they
    // are demuxed by kernel txid in `init_reply_complete`, not through
    // `dispatch_pending_reply`'s backend 5-tuple. `OpKind::OpenClose` is
    // the benign no-backend / no-ordering kind.
    let vnode_key = VnodeKey {
        fs_instance_id: FsInstanceId::INVALID,
        backend_id: BackendNodeId::INVALID,
    };
    let Some(op_h) = alloc_pending(
        state,
        OpKind::OpenClose,
        client_id,
        client_badge,
        u32::MAX,
        0,
        vnode_key,
    ) else {
        return None;
    };
    let tx_id = {
        let op = state.pending_ops.get_mut(op_h)?;
        op.resume = Resume::Init(InitResume {
            snapshot: snap_h,
            stage,
        });
        op.core.tx_id
    };

    let mut msg = TronaMsg::zeroed();
    msg.label = label;
    msg.regs[0] = sub_op;
    msg.regs[1] = arg;
    msg.length = 2;
    let init_ep = trona_runtime::client::caps::init_ep().addr();
    // SAFETY: ipc_ctx() is the owner thread's live context; init_ep is a
    // process-lifetime cap. Non-blocking request carrying the low-range
    // correlation txid init echoes on its reply.
    let err = unsafe {
        trona_kernel::ipc::mp_write_request_ctx(ipc_ctx(), init_ep, &raw const msg, tx_id.raw())
    };
    if err != 0 {
        let _ = state.pending_ops.release(op_h);
        return None;
    }
    Some(op_h)
}

/// Demux entry for a reply on the `KIND_INIT_REPLY` channel. `txid` is
/// the kernel `mp_txid` echoed by init; it maps to the per-query
/// `PendingOp`, whose `Resume::Init` points at the snapshot + stage.
/// Decodes the reply into the snapshot's typed result, then issues the
/// next plan step or finalises.
pub(crate) fn init_reply_complete(state: &mut VfsState, txid: u64, reply: &TronaMsg) {
    let tx_id = TxId(txid);
    let Some(op_h) = state.find_pending_op(tx_id) else {
        // Stale — the read was cancelled / the op already reclaimed.
        return;
    };
    let (snap_h, stage) = {
        let op = match state.pending_ops.get(op_h) {
            Some(o) => o,
            None => return,
        };
        match op.resume {
            Resume::Init(ir) => (ir.snapshot, ir.stage),
            // A non-init reply correlated to this txid is a bug / spoof;
            // drop it rather than mis-dispatching.
            _ => return,
        }
    };
    // The per-query op has done its job (correlation); release it. The
    // client reply-lease lives on the snapshot, not this op.
    let _ = state.pending_ops.release(op_h);

    if !decode_into_snapshot(state, snap_h, stage, reply) {
        fail_init_snapshot(state, snap_h, VfsError::Io);
        return;
    }

    // `kern.proc.all` / filter listings drive their own kinfo-page loop:
    // re-issue the next page (reusing plan step 0 with an advanced offset)
    // until the process list is drained or the content buffer is full,
    // bypassing the fixed-plan stage advance below.
    match sysctl_bulk_step(state, snap_h) {
        Some(SysctlBulkStep::Issue(off)) => {
            if let Some(s) = state.init_snapshots.get_mut(snap_h) {
                s.plan[0].arg = off;
            }
            if issue_init_query(state, snap_h, 0).is_none() {
                fail_init_snapshot(state, snap_h, VfsError::Io);
            }
            return;
        }
        Some(SysctlBulkStep::Done) => {
            finalize_init_snapshot(state, snap_h);
            return;
        }
        None => {}
    }

    let (stage_now, plan_len) = {
        let snap = match state.init_snapshots.get_mut(snap_h) {
            Some(s) => s,
            None => return,
        };
        snap.stage = snap.stage.saturating_add(1);
        (snap.stage, snap.plan_len)
    };
    if (stage_now as usize) < plan_len as usize {
        if issue_init_query(state, snap_h, stage_now).is_none() {
            fail_init_snapshot(state, snap_h, VfsError::Io);
        }
    } else {
        finalize_init_snapshot(state, snap_h);
    }
}

/// Completion for the `CttyDump` pre-stage of a tty-bearing read. Caches
/// the posix_ttysrv `(sid → tty_dev)` bindings into the snapshot, then
/// fires the read's first init query. A failed / empty dump leaves the
/// cache empty (records report `tty_dev = 0`), so the read still
/// completes — controlling-tty info is best-effort, never a hard failure.
pub(crate) fn ctty_dump_reply_complete(
    state: &mut VfsState,
    snap_h: InitSnapshotHandle,
    reply: &TronaMsg,
) {
    if reply.label == crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK {
        if let Some(snap) = state.init_snapshots.get_mut(snap_h) {
            let count = (reply.regs[0] as usize)
                .min(CTTY_BINDINGS_MAX)
                .min((reply.length as usize).saturating_sub(1));
            for i in 0..count {
                // Each dump entry: (sid in low 32) | (pty_id in high 32).
                let e = reply.regs[1 + i];
                let sid = e & 0xFFFF_FFFF;
                let pty_id = e >> 32;
                let tty_dev = if pty_id == 0 {
                    trona_protocol::posix_abi::tty::TTY_DEV_CONSOLE
                } else {
                    trona_protocol::posix_abi::tty::TTY_DEV_PTS_BASE + pty_id
                };
                snap.ctty_entries[i] = sid | (tty_dev << 32);
            }
            snap.ctty_count = count as u8;
        }
    }
    // Run the actual read now that the binding cache is populated (or
    // empty): the decode step joins `tty_dev` from it per record.
    if issue_init_query(state, snap_h, 0).is_none() {
        fail_init_snapshot(state, snap_h, VfsError::Io);
    }
}

/// Decode one init reply into the snapshot's typed result for the
/// current target + stage. Returns false on a malformed reply / error
/// label (the read then fails). Grows one arm per read target.
fn decode_into_snapshot(
    state: &mut VfsState,
    snap_h: InitSnapshotHandle,
    stage: u8,
    reply: &TronaMsg,
) -> bool {
    // The plan step's sub-op selects which typed result this reply fills.
    let (sub_op, plan_arg) = match state.init_snapshots.get(snap_h) {
        Some(s) => (s.plan[stage as usize].sub_op, s.plan[stage as usize].arg),
        None => return false,
    };
    if reply.label != trona_protocol::common::TRONA_OK {
        return false;
    }
    let snap = match state.init_snapshots.get_mut(snap_h) {
        Some(s) => s,
        None => return false,
    };
    // Controlling-tty bindings prefetched by the `CttyDump` pre-stage;
    // joined into each record below. Copied out so the `&mut snap.state`
    // match does not alias the snapshot.
    let ctty_entries = snap.ctty_entries;
    let ctty_count = snap.ctty_count;
    match &mut snap.state {
        InitReadState::None => false,
        InitReadState::ProcExeReadlink { path, len, .. }
        | InitReadState::ProcExeNameiReadlink { path, len, .. } => {
            let n = (reply.regs[0] as usize).min(MAX_PATH_LEN);
            // Path bytes pack into regs[1..] as little-endian 8-byte
            // chunks (init `get_exe_path`).
            let src = (&reply.regs[1]) as *const u64 as *const u8;
            // SAFETY: copying `n <= MAX_PATH_LEN` bytes from the reply
            // register tail into the snapshot path buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(src, path.as_mut_ptr(), n);
            }
            *len = n as u16;
            true
        }
        InitReadState::Ctty { sid, pgid, .. } => {
            *sid = reply.regs[0];
            *pgid = reply.regs[1];
            true
        }
        InitReadState::Readdir {
            pids, pid_count, ..
        } => {
            // `LIST_PIDS` packs the active pids inline in `regs[0..length]`.
            let n = (reply.length as usize).min(pids.len());
            for i in 0..n {
                pids[i] = reply.regs[i] as u32;
            }
            *pid_count = n as u16;
            true
        }
        InitReadState::ProcRead { results, .. } => match sub_op {
            trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL => {
                let mut info = ProcInfoFull::from_reply(reply);
                info.tty_dev = ctty_lookup(&ctty_entries, ctty_count, info.sid);
                results.info = Some(info);
                true
            }
            trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES => {
                results.times = Some(ProcTimes {
                    user_time_ns: reply.regs[0],
                    system_time_ns: reply.regs[1],
                    num_threads: reply.regs[2] as u32,
                    start_time_ns: reply.regs[3],
                });
                true
            }
            trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS => {
                results.system_stats = Some(SystemProcStats {
                    procs_total: reply.regs[0] as u32,
                    procs_running: reply.regs[1] as u32,
                    last_pid: reply.regs[2] as u32,
                });
                true
            }
            trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_ARGV => {
                // Paginated argv: this step's `arg` low 32 bits = the page's
                // byte offset; reply regs[0]=total, regs[1]=written this
                // page, regs[2..]=bytes. Accumulate each page into the buf.
                let page_off = (plan_arg & 0xFFFF_FFFF) as usize;
                let total = (reply.regs[0] as usize).min(ARGV_MAX);
                let written =
                    (reply.regs[1] as usize).min(trona_protocol::init::INIT_ARGV_PAGE_BYTES);
                let argv = results.argv.get_or_insert(ArgvBuf::zeroed());
                argv.len = total as u16;
                if page_off < ARGV_MAX && written > 0 {
                    let n = (page_off + written).min(ARGV_MAX) - page_off;
                    // SAFETY: copy `n` bytes from the reply register tail
                    // (regs[2..]) into the argv accumulator at `page_off`;
                    // both `page_off` and `page_off + n` are bounded by
                    // `ARGV_MAX`, the accumulator's length.
                    unsafe {
                        let src = (&reply.regs[2]) as *const u64 as *const u8;
                        core::ptr::copy_nonoverlapping(
                            src,
                            argv.bytes.as_mut_ptr().add(page_off),
                            n,
                        );
                    }
                }
                true
            }
            _ => false,
        },
        InitReadState::SysValue {
            kind,
            filter_kind,
            filter_val,
            content,
            content_len,
            count,
            total,
            ..
        } => match *kind {
            SysValueKind::ExePath => {
                let path_len = (reply.regs[0] as usize).min(SYSCTL_CONTENT_CAP);
                if path_len > 0 {
                    // SAFETY: init packed `path_len` path bytes into regs[1..];
                    // path_len is clamped to content.len() (SYSCTL_CONTENT_CAP).
                    unsafe {
                        let src = (&reply.regs[1]) as *const u64 as *const u8;
                        core::ptr::copy_nonoverlapping(src, content.as_mut_ptr(), path_len);
                    }
                }
                *content_len = path_len as u32;
                true
            }
            SysValueKind::Argv => {
                let page_off = (plan_arg & 0xFFFF_FFFF) as usize;
                let tot = (reply.regs[0] as usize).min(SYSCTL_CONTENT_CAP);
                let written =
                    (reply.regs[1] as usize).min(trona_protocol::init::INIT_ARGV_PAGE_BYTES);
                if page_off < SYSCTL_CONTENT_CAP && written > 0 {
                    let n = (page_off + written).min(SYSCTL_CONTENT_CAP) - page_off;
                    // SAFETY: copy `n` argv bytes from regs[2..] into content at
                    // `page_off`; both bounds are clamped to SYSCTL_CONTENT_CAP.
                    unsafe {
                        let src = (&reply.regs[2]) as *const u64 as *const u8;
                        core::ptr::copy_nonoverlapping(src, content.as_mut_ptr().add(page_off), n);
                    }
                }
                *content_len = tot as u32;
                true
            }
            SysValueKind::KinfoSingle => {
                let mut kp = sysctl_kinfo_from_reply(reply);
                kp.tty_dev = ctty_lookup(&ctty_entries, ctty_count, kp.sid) as u32;
                enrich_kinfo_mem(&mut kp);
                let kp_sz = core::mem::size_of::<trona_protocol::init::KinfoProc>();
                // SAFETY: kp_sz (136) <= content.len() (SYSCTL_CONTENT_CAP).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (&raw const kp) as *const u8,
                        content.as_mut_ptr(),
                        kp_sz,
                    );
                }
                *content_len = kp_sz as u32;
                true
            }
            SysValueKind::KinfoAll | SysValueKind::KinfoFilter => {
                *total = reply.regs[0] as u32;
                if reply.regs[1] == 1 {
                    let mut kp = sysctl_kinfo_from_reply(reply);
                    kp.tty_dev = ctty_lookup(&ctty_entries, ctty_count, kp.sid) as u32;
                    let keep = *kind == SysValueKind::KinfoAll
                        || kinfo_matches_filter(&kp, *filter_kind, *filter_val);
                    if keep {
                        enrich_kinfo_mem(&mut kp);
                        let kp_sz = core::mem::size_of::<trona_protocol::init::KinfoProc>();
                        let at = *content_len as usize;
                        if at + kp_sz <= SYSCTL_CONTENT_CAP {
                            // SAFETY: at + kp_sz <= content.len().
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    (&raw const kp) as *const u8,
                                    content.as_mut_ptr().add(at),
                                    kp_sz,
                                );
                            }
                            *content_len += kp_sz as u32;
                            *count += 1;
                        }
                    }
                }
                true
            }
        },
    }
}

/// Run the synchronous content generator against the collected results
/// and send the client reply. Consumes the parked lease and frees the
/// snapshot. Grows one arm per read target.
fn finalize_init_snapshot(state: &mut VfsState, snap_h: InitSnapshotHandle) {
    // Pull everything the generator needs out under a short borrow, then
    // release the snapshot before emitting (the emit path may re-borrow
    // state).
    let pulled = {
        let snap = match state.init_snapshots.get_mut(snap_h) {
            Some(s) => s,
            None => return,
        };
        let lease = snap.reply_lease.take().map(|p| p.unpark());
        // Move the typed result out (replace with the sentinel).
        let st = core::mem::replace(&mut snap.state, InitReadState::None);
        lease.map(|l| (l, st))
    };
    let _ = state.init_snapshots.release(snap_h);
    let Some((lease, st)) = pulled else {
        return;
    };
    match st {
        InitReadState::None => {
            lease.disarm();
        }
        InitReadState::Ctty {
            client,
            action,
            sid,
            pgid,
        } => {
            let badge = state
                .clients
                .get(client)
                .map(|c| c.client_badge)
                .unwrap_or(0);
            match action {
                CttyAction::GetCttyDev => {
                    match unsafe {
                        crate::personality::posix::device::issue_pty_ctty_lookup(state, sid)
                    } {
                        Ok(h) => {
                            let resume = Resume::Pty(crate::owner::resume::PtyResume {
                                pty_index: 0,
                                side: 0,
                                op_type: crate::owner::pty_completion::PTYRESUME_OP_CTTY_DEV,
                                max_count: 0,
                                client_badge: badge,
                            });
                            if let Err(Some(lease)) =
                                state.stamp_resume_ctx(h, badge, Some(lease), resume)
                            {
                                crate::personality::wire::send_reply_err_for_client(
                                    state,
                                    client,
                                    lease,
                                    VfsError::Io,
                                );
                            }
                        }
                        Err(e) => crate::personality::wire::send_reply_err_for_client(
                            state, client, lease, e,
                        ),
                    }
                }
                CttyAction::OpenBind { resume, err_intent } => {
                    match unsafe {
                        crate::personality::posix::device::issue_pty_ctty_lookup(state, sid)
                    } {
                        Ok(h) => {
                            if let Err(Some(lease)) =
                                state.stamp_resume_ctx(h, badge, Some(lease), resume)
                            {
                                // SAFETY: owner thread; lease consumed once.
                                unsafe {
                                    crate::personality::reply::emit_open(
                                        lease,
                                        err_intent,
                                        Err(VfsError::Io),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            // SAFETY: owner thread; lease consumed once.
                            unsafe {
                                crate::personality::reply::emit_open(lease, err_intent, Err(e));
                            }
                        }
                    }
                }
                CttyAction::Ioctl {
                    pty_id,
                    cmd,
                    arg,
                    vkey,
                    reply,
                } => {
                    match unsafe {
                        crate::personality::posix::device::issue_pty_ioctl(
                            state, pty_id, cmd, arg, sid, pgid,
                        )
                    } {
                        Ok(h) => {
                            let resume =
                                Resume::Fs(crate::owner::resume::FsResume::FillIoctlReply {
                                    client,
                                    vkey,
                                    cmd,
                                    reply,
                                });
                            if let Err(Some(lease)) =
                                state.stamp_resume_ctx(h, badge, Some(lease), resume)
                            {
                                // SAFETY: owner thread; lease consumed once.
                                unsafe {
                                    crate::personality::reply::emit_ioctl(
                                        lease,
                                        reply,
                                        Err(VfsError::Io),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            // SAFETY: owner thread; lease consumed once.
                            unsafe {
                                crate::personality::reply::emit_ioctl(lease, reply, Err(e));
                            }
                        }
                    }
                }
            }
        }
        InitReadState::Readdir {
            open_h,
            cursor,
            base,
            reply,
            pids,
            pid_count,
            dtype,
        } => {
            let mut data = crate::personality::reply::ReaddirReplyData {
                next_cursor: cursor,
                entries_written: 0,
                bytes_written: 0,
                first_entry_ino: 0,
                first_entry_dtype: 0,
                first_entry_name_len: 0,
                first_entry_name: [0u8; crate::personality::reply::READDIR_FIRST_ENTRY_NAME_MAX],
            };
            let idx = cursor.saturating_sub(base) as usize;
            if idx < pid_count as usize {
                let pid = pids[idx];
                let mut nbuf = [0u8; 10];
                let nlen = fmt_u32_dec(pid, &mut nbuf);
                data.first_entry_ino = pid as u64;
                data.first_entry_dtype = dtype;
                data.first_entry_name_len = nlen;
                data.first_entry_name[..nlen].copy_from_slice(&nbuf[..nlen]);
                data.entries_written = 1;
                data.bytes_written = nlen as u32;
                data.next_cursor = cursor + 1;
                if let Some(obj) = state.open_objects.get_mut(open_h) {
                    obj.offset = cursor + 1;
                }
            } else if let Some(obj) = state.open_objects.get_mut(open_h) {
                // Past the last pid: end of directory, cursor unchanged.
                obj.offset = cursor;
            }
            // SAFETY: owner thread; lease consumed exactly once here.
            unsafe {
                crate::personality::reply::emit_readdir_batch(lease, reply, Ok(data));
            }
        }
        InitReadState::ProcExeReadlink {
            personality,
            path,
            len,
        } => {
            // SAFETY: owner thread; lease is the unparked client reply
            // endpoint, consumed exactly once here.
            unsafe {
                crate::personality::reply::emit_readlink_bytes(
                    lease,
                    personality,
                    Ok(&path[..len as usize]),
                );
            }
        }
        InitReadState::ProcExeNameiReadlink {
            client,
            cursor,
            terminal,
            path,
            len,
        } => unsafe {
            crate::core::namei_async::resume_namei_after_readlink(
                state,
                client,
                cursor,
                terminal,
                lease,
                Ok(&path[..len as usize]),
            );
        },
        InitReadState::ProcRead {
            kind,
            pid,
            offset,
            len,
            intent,
            results,
        } => {
            let mut content = [0u8; 2048];
            let content_len = match kind {
                ProcReadKind::Comm => match results.info {
                    Some(info) => crate::fs::procfs::proc_gen_comm(&info, &mut content),
                    None => 0,
                },
                ProcReadKind::PidStat => match results.info {
                    Some(info) => {
                        let pt = results.times.unwrap_or_default();
                        // Per-pid memory comes from mmsrv (its authority),
                        // fetched synchronously here: mmsrv is an
                        // always-replying peer, so this cannot deadlock the
                        // reactor against init.
                        let mem = crate::fs::metrics::per_pid_mem_snapshot(pid).ok();
                        // SAFETY: `proc_gen_stat` writes into the local
                        // `content` buffer via bounds-checked raw ptrs.
                        unsafe {
                            crate::fs::procfs::proc_gen_stat(
                                pid,
                                &info,
                                &pt,
                                mem.as_ref(),
                                &mut content,
                            )
                        }
                    }
                    None => 0,
                },
                ProcReadKind::PidStatus => match results.info {
                    Some(info) => {
                        let pt = results.times.unwrap_or_default();
                        // Per-pid memory comes from mmsrv (its authority),
                        // fetched synchronously here: mmsrv is an
                        // always-replying peer, so this cannot deadlock the
                        // reactor against init.
                        let mem = crate::fs::metrics::per_pid_mem_snapshot(pid).ok();
                        // SAFETY: `proc_gen_status` writes into the local
                        // `content` buffer via bounds-checked raw ptrs.
                        unsafe {
                            crate::fs::procfs::proc_gen_status(
                                pid,
                                &info,
                                &pt,
                                mem.as_ref(),
                                &mut content,
                            )
                        }
                    }
                    None => 0,
                },
                ProcReadKind::SysLoadavg => {
                    let stats = results.system_stats.unwrap_or_default();
                    crate::fs::procfs::proc_gen_loadavg(&stats, &mut content)
                }
                ProcReadKind::SysStat => {
                    let stats = results.system_stats.unwrap_or_default();
                    // SAFETY: `proc_gen_sys_stat` writes into the local
                    // `content` buffer; its per-CPU / clock reads are
                    // synchronous kernel cap invokes.
                    unsafe { crate::fs::procfs::proc_gen_sys_stat(&stats, &mut content) }
                }
                ProcReadKind::Cmdline => {
                    let argv = results.argv.unwrap_or(ArgvBuf::zeroed());
                    crate::fs::procfs::proc_gen_cmdline(&argv, &mut content)
                }
            };
            // Apply the read window: skip `offset`, cap at `len`.
            let off = (offset as usize).min(content_len);
            let n = (content_len - off).min(len as usize);
            // SAFETY: owner thread; lease consumed exactly once here.
            unsafe {
                crate::personality::reply::emit_read_inline(
                    lease,
                    intent,
                    Ok(crate::ops::io::InlineReadResult {
                        data: &content[off..off + n],
                    }),
                );
            }
        }
        InitReadState::SysValue {
            kind,
            offset,
            len,
            intent,
            mut content,
            content_len,
            count,
            truncated,
            ..
        } => {
            if truncated {
                trona_runtime::uwarn!(|lb| {
                    lb.str(
                        b"[VFS] kern.proc.* listing truncated at buffer cap; raise SYSCTL_CONTENT_CAP or move to bulk transport\n",
                    );
                });
            }
            // Bulk listings prefix the assembled records with the u32 count.
            let total_len = match kind {
                SysValueKind::KinfoAll | SysValueKind::KinfoFilter => {
                    content[0..4].copy_from_slice(&count.to_ne_bytes());
                    content_len as usize
                }
                _ => content_len as usize,
            };
            let off = (offset as usize).min(total_len);
            let n = (total_len - off).min(len as usize);
            // SAFETY: owner thread; lease consumed exactly once here.
            unsafe {
                crate::personality::reply::emit_read_inline(
                    lease,
                    intent,
                    Ok(crate::ops::io::InlineReadResult {
                        data: &content[off..off + n],
                    }),
                );
            }
        }
    }
}

/// Format `v` as decimal into `out`, returning the byte length. Renders
/// `/proc/<pid>` directory-entry names in the readdir finalize.
fn fmt_u32_dec(mut v: u32, out: &mut [u8; 10]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = 0;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

/// How to frame an init-read failure reply for the parked client.
enum ErrFraming {
    /// Typed wire error (readlink / generic) for a personality.
    Wire(Personality),
    /// Inline-read error matching the read reply shape.
    Read(ReadReplyIntent),
    /// `open` error (ctty bind).
    Open(crate::ops::OpenReplyIntent),
    /// ioctl error (ctty-control ioctl).
    Ioctl(crate::ops::IoctlReplyIntent),
    /// `VFS_GET_CTTY_DEV` error — framed by the client's wire personality.
    CttyDev(crate::server::types::ClientHandle),
    /// `/proc` readdir error.
    Readdir(crate::ops::ReadDirReplyIntent),
    /// Init-backed readlink failed while namei was following a symlink.
    NameiReadlink {
        client: ClientHandle,
        cursor: WalkCursor,
        terminal: NameiTerminal,
    },
}

/// Fail an in-flight read: send the client an error reply and free the
/// snapshot. Used on alloc / send failure and on decode errors.
pub(crate) fn fail_init_snapshot(state: &mut VfsState, snap_h: InitSnapshotHandle, err: VfsError) {
    let pulled = {
        let snap = match state.init_snapshots.get_mut(snap_h) {
            Some(s) => s,
            None => return,
        };
        let lease = snap.reply_lease.take().map(|p| p.unpark());
        let framing = match &snap.state {
            InitReadState::ProcExeReadlink { personality, .. } => ErrFraming::Wire(*personality),
            InitReadState::ProcExeNameiReadlink {
                client,
                cursor,
                terminal,
                ..
            } => ErrFraming::NameiReadlink {
                client: *client,
                cursor: *cursor,
                terminal: *terminal,
            },
            InitReadState::ProcRead { intent, .. } => ErrFraming::Read(*intent),
            InitReadState::Ctty { client, action, .. } => match action {
                CttyAction::GetCttyDev => ErrFraming::CttyDev(*client),
                CttyAction::OpenBind { err_intent, .. } => ErrFraming::Open(*err_intent),
                CttyAction::Ioctl { reply, .. } => ErrFraming::Ioctl(*reply),
            },
            InitReadState::Readdir { reply, .. } => ErrFraming::Readdir(*reply),
            InitReadState::SysValue { intent, .. } => ErrFraming::Read(*intent),
            InitReadState::None => ErrFraming::Wire(Personality::Posix),
        };
        lease.map(|l| (l, framing))
    };
    let _ = state.init_snapshots.release(snap_h);
    if let Some((lease, framing)) = pulled {
        match framing {
            ErrFraming::Wire(personality) => {
                crate::personality::wire::send_reply_err_typed(personality, lease, err);
            }
            // SAFETY: owner thread; lease consumed exactly once here.
            ErrFraming::Read(intent) => unsafe {
                crate::personality::reply::emit_read_inline(lease, intent, Err(err));
            },
            // SAFETY: owner thread; lease consumed exactly once here.
            ErrFraming::Open(intent) => unsafe {
                crate::personality::reply::emit_open(lease, intent, Err(err));
            },
            // SAFETY: owner thread; lease consumed exactly once here.
            ErrFraming::Ioctl(intent) => unsafe {
                crate::personality::reply::emit_ioctl(lease, intent, Err(err));
            },
            ErrFraming::CttyDev(client) => {
                crate::personality::wire::send_reply_err_for_client(state, client, lease, err);
            }
            // SAFETY: owner thread; lease consumed exactly once here.
            ErrFraming::Readdir(intent) => unsafe {
                crate::personality::reply::emit_readdir_batch(lease, intent, Err(err));
            },
            ErrFraming::NameiReadlink {
                client,
                cursor,
                terminal,
            } => unsafe {
                crate::core::namei_async::resume_namei_after_readlink(
                    state,
                    client,
                    cursor,
                    terminal,
                    lease,
                    Err(err),
                );
            },
        }
    }
}

/// Override the inline-read reply framing on an in-flight `ProcRead`
/// init read. The procfs vop creates the snapshot before the dispatch
/// layer (which alone knows the caller's personality) has run, so it
/// defaults `intent`; the `do_read_fd_inline` `Parked` arm calls this
/// right after `attach_lease_if_init` to record the real
/// [`ReadReplyIntent`]. No-op for non-`ProcRead` reads.
pub(crate) fn stamp_read_intent(
    state: &mut VfsState,
    op_h: PendingOpHandle,
    intent: ReadReplyIntent,
) {
    let snap_h = match state.pending_ops.get(op_h) {
        Some(op) => match op.resume {
            Resume::Init(ir) => ir.snapshot,
            // tty-bearing reads (e.g. `/proc/<pid>/stat`) front-run a
            // `CttyDump` op before the init query, so the intent must be
            // recorded against its snapshot too.
            Resume::Fs(crate::owner::resume::FsResume::CttyDump { snapshot }) => snapshot,
            _ => return,
        },
        None => return,
    };
    if let Some(snap) = state.init_snapshots.get_mut(snap_h) {
        if let InitReadState::ProcRead { intent: slot, .. } = &mut snap.state {
            *slot = intent;
        }
    }
}

/// Read the `KinfoProc` init packed at `regs[INIT_KINFO_PROC_REGS_BASE..]`
/// out of a `GET_KINFO_PROC` / `GET_KINFO_PROC_PAGE` reply.
fn sysctl_kinfo_from_reply(reply: &TronaMsg) -> trona_protocol::init::KinfoProc {
    // SAFETY: init packs size_of::<KinfoProc>() bytes at the reg base; read
    // unaligned to stay correct regardless of register-array layout.
    unsafe {
        core::ptr::read_unaligned(
            (&reply.regs[trona_protocol::init::INIT_KINFO_PROC_REGS_BASE]) as *const u64
                as *const trona_protocol::init::KinfoProc,
        )
    }
}

/// Fill `vm_size` / `vm_rss` on `kp` from mmsrv's per-process snapshot.
/// mmsrv is an always-replying peer (not in the init↔vfs cycle), so this
/// synchronous query is reactor-safe — the join init cannot perform.
fn enrich_kinfo_mem(kp: &mut trona_protocol::init::KinfoProc) {
    if let Ok(mem) = crate::fs::metrics::per_pid_mem_snapshot(kp.pid) {
        kp.vm_size = mem.vm_reserved_bytes;
        kp.vm_rss = mem.vm_resident_pages.saturating_mul(4096);
    }
}

/// Whether `kp` matches a `kern.proc` filter dir's `<value>`. The `tty`
/// selector matches on `tty_dev`, which init does not track (always 0), so
/// `kern.proc.tty.<n>` returns no records unless `<n>` is 0.
fn kinfo_matches_filter(kp: &trona_protocol::init::KinfoProc, filter_kind: u8, val: u32) -> bool {
    match filter_kind {
        SYSCTL_FILTER_PGRP => kp.pgid == val,
        SYSCTL_FILTER_TTY => kp.tty_dev == val,
        SYSCTL_FILTER_UID | SYSCTL_FILTER_RUID => kp.uid == val,
        SYSCTL_FILTER_SESSION => kp.sid == val,
        _ => true,
    }
}

/// Next action for a `kern.proc.all` / filter kinfo-page loop after one
/// page reply: issue the next page, or finalize.
enum SysctlBulkStep {
    Issue(u64),
    Done,
}

/// Drive the kinfo-page loop for `KinfoAll` / `KinfoFilter` snapshots:
/// advance `page_off` and decide whether another `GET_KINFO_PROC_PAGE` is
/// needed (more processes remain and the content buffer has room).
/// Returns `None` for non-bulk states so the caller falls through to the
/// fixed-plan stage advance.
fn sysctl_bulk_step(state: &mut VfsState, snap_h: InitSnapshotHandle) -> Option<SysctlBulkStep> {
    let snap = state.init_snapshots.get_mut(snap_h)?;
    match &mut snap.state {
        InitReadState::SysValue {
            kind,
            page_off,
            total,
            content_len,
            truncated,
            ..
        } if *kind == SysValueKind::KinfoAll || *kind == SysValueKind::KinfoFilter => {
            *page_off += 1;
            let room = (*content_len as usize)
                + core::mem::size_of::<trona_protocol::init::KinfoProc>()
                <= SYSCTL_CONTENT_CAP;
            if *page_off < *total {
                if room {
                    Some(SysctlBulkStep::Issue(*page_off as u64))
                } else {
                    // More processes remain but the content buffer is full.
                    *truncated = true;
                    Some(SysctlBulkStep::Done)
                }
            } else {
                Some(SysctlBulkStep::Done)
            }
        }
        _ => None,
    }
}

/// Park an init-backed `kern.proc.*` sysctl read. `kind` selects the
/// transport + finalize formatter; `pid` targets single-pid reads,
/// `filter_kind` / `filter_val` the `KinfoFilter` selector. Returns the
/// first per-query `PendingOp` handle (the sysctl vop returns it as
/// `Parked`); the dispatch layer attaches the client lease via
/// [`attach_lease_if_init`].
pub(crate) fn begin_sysctl_read(
    state: &mut VfsState,
    kind: SysValueKind,
    pid: u32,
    filter_kind: u8,
    filter_val: u32,
    offset: u64,
    len: u64,
    caller_badge: u64,
) -> Option<PendingOpHandle> {
    use trona_protocol::init::{
        INIT_ARGV_PAGE_BYTES, INIT_GET_PROC_INFO, INIT_GET_PROC_INFO_SUB_GET_ARGV,
        INIT_GET_PROC_INFO_SUB_GET_EXE_PATH, INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC,
        INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC_PAGE,
    };
    // Bulk listings reserve the leading u32 count prefix; single values
    // start empty.
    let content_len = match kind {
        SysValueKind::KinfoAll | SysValueKind::KinfoFilter => 4,
        _ => 0,
    };
    let read_state = InitReadState::SysValue {
        kind,
        filter_kind,
        filter_val,
        offset,
        len,
        intent: crate::ops::ReadReplyIntent::PosixRead,
        content: [0u8; SYSCTL_CONTENT_CAP],
        content_len,
        count: 0,
        page_off: 0,
        total: 0,
        truncated: false,
    };
    let mut steps: [InitStep; INIT_PLAN_MAX] = [InitStep::NONE; INIT_PLAN_MAX];
    let plan: &[InitStep] = match kind {
        SysValueKind::ExePath => {
            steps[0] = InitStep {
                label: INIT_GET_PROC_INFO,
                sub_op: INIT_GET_PROC_INFO_SUB_GET_EXE_PATH,
                arg: pid as u64,
            };
            &steps[..1]
        }
        SysValueKind::Argv => {
            // argv is NUL-separated, capped at ARGV_MAX; page it in fixed
            // steps (pages past the end report 0 bytes written).
            let mut n = 0usize;
            let mut off = 0usize;
            while off < ARGV_MAX && n < INIT_PLAN_MAX {
                steps[n] = InitStep {
                    label: INIT_GET_PROC_INFO,
                    sub_op: INIT_GET_PROC_INFO_SUB_GET_ARGV,
                    arg: ((pid as u64) << 32) | off as u64,
                };
                n += 1;
                off += INIT_ARGV_PAGE_BYTES;
            }
            &steps[..n]
        }
        SysValueKind::KinfoSingle => {
            steps[0] = InitStep {
                label: INIT_GET_PROC_INFO,
                sub_op: INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC,
                arg: pid as u64,
            };
            &steps[..1]
        }
        SysValueKind::KinfoAll | SysValueKind::KinfoFilter => {
            steps[0] = InitStep {
                label: INIT_GET_PROC_INFO,
                sub_op: INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC_PAGE,
                arg: 0,
            };
            &steps[..1]
        }
    };
    begin_init_read_deferred(state, plan, read_state, pid, caller_badge)
}

/// Drop an init read's snapshot: cancel its parked client lease (no
/// reply is sent — the read was aborted or the client is gone) and free
/// the arena slot. Called from `terminate_op_handle` when an in-flight
/// init-query `PendingOp` is cancelled (e.g. by the client-teardown
/// badge sweep, which terminates each in-flight per-query op).
pub(crate) fn drop_snapshot(state: &mut VfsState, snap_h: InitSnapshotHandle) {
    if let Some(snap) = state.init_snapshots.get_mut(snap_h) {
        if let Some(p) = snap.reply_lease.take() {
            p.unpark().cancel();
        }
    }
    let _ = state.init_snapshots.release(snap_h);
}
