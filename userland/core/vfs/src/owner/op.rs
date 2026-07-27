// SPDX-License-Identifier: GPL-2.0-only
//
//! `OpCore` + `OpKind` + reply-slot lifecycle helpers.
//!
//! Single-consume invariant: every `PendingOp.reply_lease` (the
//! [`ReplyLease`] guard wrapping the MessagePipe endpoint that
//! received the request) is consumed *exactly once* — either via
//! [`reply_send`] (success / error reply to the client) or
//! [`reply_drop`] (cancel without emitting a reply). The
//! 5-state cancel machine ([`OpState`]) plus
//! [`CancelDisposition`] guarantees this — every transition out of
//! `Running` / `Queued` / `Completing` lands on exactly one
//! terminal.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

/// 5-state cancel machine. Drives the dependency-graph hooks and
/// the reply-slot single-consume invariant.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpState {
    /// Slot is on the PendingOp arena's free list.
    Free = 0,
    /// Op admitted, waiting on a dependency edge or backend credit.
    /// Backend RPC has not been issued.
    Queued = 1,
    /// Backend RPC issued; waiting on the matching completion.
    Running = 2,
    /// Completion router has the message and is unwinding back into
    /// the caller's reply path. Cancel is too late at this point —
    /// the cancelled marker is honoured but `reply_send` /
    /// `reply_drop` still fires once.
    Completing = 3,
    /// Op terminated. Reply slot has been consumed exactly once via
    /// the disposition recorded in `cancel_disposition`. The slot
    /// will be returned to the free list on the next reclaim sweep.
    Cancelled = 4,
}

/// Cancellation reason. Drives whether the reply slot lands as a
/// real reply ([`CancelDisposition::Cancelled`] sends `EINTR`-class
/// error to the caller) or as a kernel finaliser drop
/// ([`CancelDisposition::Drop`]).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CancelDisposition {
    /// No cancellation in flight.
    None = 0,
    /// Drop: abandon the saved reply endpoint without sending a
    /// public VFS reply. Used for `cancel_for_badge` (client died)
    /// so the client can never observe an actual reply.
    Drop = 1,
    /// Cancelled: send a real reply with `VfsError::Intr` /
    /// `EINTR`. Used for explicit timeout / signal-driven cancels.
    Cancelled = 2,
    /// Server-died: the backend session torn down mid-flight.
    /// Send a real reply with `VfsError::SessionTornDown`.
    ServerDied = 3,
    /// Failed by an internal dependency / ordering predecessor.
    /// The caller supplies the concrete `VfsError`; the terminal
    /// path sends a normal VFS public reply rather than a generic
    /// cancellation.
    Failed = 4,
}

/// High-level operation discriminator. The posix layer extends
/// this as new label arms are added; the saltyfs client drives
/// `BackendOpKind` separately under `OpKind::Read` /
/// `OpKind::Write` / etc.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpKind {
    /// Sentinel: empty slot.
    Empty = 0,
    /// Open / close / dup family — typically synchronous (no
    /// backend round-trip), but the slot is allocated for
    /// uniform reply-slot bookkeeping.
    OpenClose = 1,
    /// Read — async via backend session credit. Distinct from
    /// `Write` so the fsync dependency graph can pin barrier
    /// predecessors to the writer set without false positives
    /// from concurrent reads against the same vnode.
    Read = 2,
    /// Write — async via backend session credit. Pinned as a
    /// PRED_BARRIER predecessor of any subsequent fsync against
    /// the same vnode_key.
    Write = 13,
    /// Directory walk leaf (lookup / stat / readlink etc.) — async
    /// via backend; the namei state machine drives multi-step walks
    /// from a `WalkCursor` stored in the resume payload.
    Namei = 3,
    /// Directory mutation (mkdir / rmdir / rename / link / unlink /
    /// symlink) — async via backend; transactional on the backend
    /// side, single-step on vfs's.
    DirMutate = 4,
    /// Metadata mutation (chmod / chown / utimes / truncate) —
    /// async via backend.
    AttrMutate = 5,
    /// Sync barrier (fsync / fdatasync) — drives a PRED_BARRIER
    /// edge over every outstanding write to the same fd, plus any
    /// in-flight MAP_SHARED writeback through the pager.
    Sync = 6,
    /// Mount / unmount / statvfs.
    MountCtl = 7,
    /// Network-stack frontend (connect / bind / accept / send / recv
    /// / poll / etc.) — async via netsrv backend.
    Net = 8,
    /// Pty / tty path (read / write / ioctl line discipline /
    /// signals via posix_ttysrv).
    Pty = 9,
    /// Page-cache pager handler (PAGER_READ / PAGER_WRITEBACK from
    /// mmsrv) — async via backend.
    Pager = 10,
    /// Framebuffer / display ops (FB_GET_INFO / FB_GET_BACKING_MO /
    /// FB_PRESENT) — async via dispdrv backend. Distinct from
    /// `Pager` because the dispdrv calls are vfs→backend requests
    /// (not mmsrv→vfs callbacks) and from `Pty` because the reply
    /// shape carries a backing MO cap rather than termios bytes.
    Fb = 14,
    /// SHM / pipe / FIFO — typically synchronous on backend
    /// (in-memory) but treated uniformly.
    Shm = 11,
    /// Poll / epoll wait — async via the wait-queue layer; reply
    /// fires when the watched fd's `STATE_READABLE` /
    /// `STATE_WRITABLE` resolves.
    Poll = 12,
}

/// Per-PendingOp shared core. The op-kind-specific resume payload
/// lives next to this in [`crate::owner::pending::PendingOp`] under
/// the [`crate::owner::resume::Resume`] discriminator.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OpCore {
    pub state: OpState,
    pub kind: OpKind,
    pub cancel_disposition: CancelDisposition,
    /// Cancel marker — set independently of `state`. The transition
    /// out of `Running` / `Completing` reads this to pick `send` vs
    /// `drop` of the reply slot.
    pub cancelled: bool,
    /// Caller's `client_id` (badge lower 32 bit).
    pub client_id: u32,
    /// Full inbound badge — used by `cancel_for_badge` on
    /// `STATE_PEER_CLOSED`.
    pub client_badge: u64,
    /// Monotonic per-VFS transaction id. Stamped into the backend
    /// correlation header (final 4 IPC words on every backend RPC)
    /// so completions can be matched against the originating
    /// PendingOp without arena-handle guess-work after slot reuse.
    pub tx_id: crate::owner::pending::TxId,
    /// `live_gen` of the owning backend session at issue time.
    /// Mismatched at completion → drop the reply silently.
    pub backend_session_gen: u32,
    /// Backend session arena index (mount-instance scope).
    pub backend_session_idx: u32,
    /// Vnode key under which the op was issued — survives Arena
    /// slot reuse so a stale completion routed to a freshly
    /// recycled slot is detected and dropped.
    pub vnode_key: crate::core::identity::VnodeKey,
    /// Request-coalescing pointer. When two posix handlers park
    /// on identical backend RPCs (same parent_ino + same name
    /// lookup), the second op stores the first's `tx_id` here and
    /// re-uses the primary's reply at completion time. `INVALID`
    /// for the primary op (or when coalescing isn't applicable).
    pub coalesce_primary_tx: crate::owner::pending::TxId,
    /// Tracks whether this op has reserved a backend-session
    /// credit on `inflight_now`. Reserve sites (the credited
    /// `reserve_*` wrappers) flip this to `true`; the completion
    /// router and the cancel path consult it to decide whether
    /// to release the credit at terminal time. Without an
    /// explicit ownership flag a cancelled queued op (credit
    /// never reserved) would still hand a free credit back to
    /// the session and corrupt `inflight_now` against any
    /// genuinely in-flight reserve.
    pub credit_held: bool,
    /// Caller's personality at issue time — drives the wire format
    /// of the eventual reply. POSIX caller → `errno` reply; Win32
    /// caller → NTSTATUS-shaped reply. Stamped at the same time
    /// as `client_id` so the completion router can pick the right
    /// formatter without a follow-up `clients.get()` lookup
    /// (especially because the client may have exited between
    /// issue and completion, leaving the slot reusable).
    pub personality: crate::personality::Personality,
}

impl OpCore {
    pub(crate) const EMPTY: Self = Self {
        state: OpState::Free,
        kind: OpKind::Empty,
        cancel_disposition: CancelDisposition::None,
        cancelled: false,
        client_id: 0,
        client_badge: 0,
        tx_id: crate::owner::pending::TxId::INVALID,
        backend_session_gen: 0,
        backend_session_idx: u32::MAX,
        vnode_key: crate::core::identity::VnodeKey::NONE,
        coalesce_primary_tx: crate::owner::pending::TxId::INVALID,
        credit_held: false,
        personality: crate::personality::Personality::Posix,
    };
}

/// Consume the saved frontend MessagePipe endpoint by sending the
/// supplied reply `msg` with `reply-marked MP_WRITE`. The lease's `Consumed`
/// transition keeps the debug-build `Drop` guard silent.
pub(crate) fn reply_send(lease: ReplyLease, msg: &TronaMsg) {
    let (target, _epoch) = lease.consume_target();
    if target.is_none() {
        return;
    }
    unsafe {
        let ctx = trona_posix::tls::current_ipc_ctx();
        let buf = if ctx.is_null() {
            core::ptr::null_mut()
        } else {
            (*ctx).ipc_buffer
        };
        let len = core::cmp::min(msg.length as usize, msg.regs.len());
        let _ = trona_server::mp_write_reply_to(buf, target, msg.label, &msg.regs[..len], 0);
    }
}

/// Reply sender that stages one cap in the reply's transfer window.
///
/// `cap` is consumed: the staged slot rides out to the caller on the
/// reply (the kernel `take_ref`s it out of vfs's CSpace), and the
/// `TransferCap` drop reclaims the now-empty source slot. A cap vfs
/// must keep live has to be wrapped with `dup_for_transfer`; only a
/// genuinely transient cap may use `move_for_transfer` /
/// `forward_external`.
/// Returns `true` when the cap reached the caller; `false` if there was no
/// reply target or the cap transfer failed, so the caller can roll back any
/// state it staged for the cap (the `TransferCap` drop reclaims the cap slot
/// either way).
pub(crate) fn reply_send_with_cap(
    lease: ReplyLease,
    msg: &TronaMsg,
    cap: trona_runtime::core::slot_alloc::TransferCap,
) -> bool {
    let (target, _epoch) = lease.consume_target();
    if target.is_none() {
        return false;
    }
    unsafe {
        let ctx = trona_posix::tls::current_ipc_ctx();
        let buf = if ctx.is_null() {
            core::ptr::null_mut()
        } else {
            (*ctx).ipc_buffer
        };
        let len = core::cmp::min(msg.length as usize, msg.regs.len());
        if !buf.is_null() {
            (*buf).caps[0] = cap.slot();
        }
        let r = trona_server::mp_write_reply_to_with_error_fallback(
            buf,
            target,
            msg.label,
            &msg.regs[..len],
            1,
        );
        if !buf.is_null() {
            (*buf).caps[0] = 0;
        }
        if r.primary_error != 0 {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] reply_with_cap: cap transfer failed cap_slot=");
                _lb.hex(cap.slot());
                _lb.str(b" primary=");
                _lb.hex(r.primary_error as u32 as u64);
                _lb.str(b" fallback=");
                _lb.hex(r.fallback_error as u32 as u64);
                _lb.str(b" label=");
                _lb.hex(msg.label);
                _lb.str(b"\n");
            });
            return false;
        }
    }
    true
}

/// Drop the saved endpoint lease without sending a reply. The
/// underlying endpoint is owned by the service, so no cap is deleted
/// here; cancellation only records the single-consume terminal state.
pub(crate) fn reply_drop(lease: ReplyLease) {
    let _ = lease.cancel();
}
