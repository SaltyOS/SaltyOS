// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner-reactor cookie encoding.
//!
//! Re-exports substrate's `(kind: u8 << 56) | (slot: u24 << 32) |
//! (live_gen: u32)` encoding plus the vfs-specific kind constants.
//! Every Watch armed on the owner EQ goes through one of these
//! kinds; the dispatcher decodes the cookie on every fire and
//! routes to the matching handler module.

pub(crate) use trona_server::event_loop::{decode_cookie, encode_cookie};

/// Frontend client master service-EP. The single armed cookie of
/// this kind covers every inbound client RPC; per-caller demux
/// happens via the badge on the inbound MP record.
pub(crate) const KIND_FRONTEND: u8 = 0;

/// Per-mount-instance backend callback. The slot field carries
/// the index into `VfsState.backend_sessions`.
pub(crate) const KIND_BACKEND_SESSION: u8 = 1;

/// File-backed page-fault event published directly by the kernel
/// onto vfs's `OBJ_PAGER`-bound `owner_eq`
/// (`KERNITE_EVENT_TYPE_PAGER_REQUEST`). Single armed cookie; the
/// pager-event handler resolves the kernel-supplied `mo_id` back to
/// the originating vnode + file binding and replies via
/// `PAGER_SUPPLY_COPY` / `PAGER_FAIL`. mmsrv is not on this path.
pub(crate) const KIND_PAGER: u8 = 2;

/// Owner-private timer cookie (page-cache writeback / poll
/// expiry). Single armed cookie.
pub(crate) const KIND_TIMER: u8 = 3;

/// Per-client frontend request MessagePipe. The slot/epoch fields
/// carry the corresponding `ClientState` arena handle.
pub(crate) const KIND_FRONTEND_CLIENT: u8 = 4;

/// init reply channel. Single armed cookie over the recv side of the
/// process's `init_ep` connection: VFS issues procfs / sysctl / ctty
/// queries to init via non-blocking `mp_write` (low-range correlation
/// txid) and parks; init's reply-marked `MP_WRITE` re-arms
/// `STATE_READABLE` here, and the reactor demuxes the reply to its
/// parked continuation by the kernel `mp_txid`. The slot/epoch fields
/// are unused (single channel); correlation is the txid, not the cookie.
pub(crate) const KIND_INIT_REPLY: u8 = 5;

/// mmsrv→VFS explicit MAP_SHARED writeback request channel. mmsrv calls this
/// when `MM_MSYNC` or `MM_MUNMAP` needs VFS, the file-pager owner, to flush
/// dirty file-backed page-cache pages.
pub(crate) const KIND_MMSRV_WRITEBACK: u8 = 6;

/// VFS→mmsrv MAP_SHARED writeback completion channel writability. This is a
/// read-less Watch on the mmsrv endpoint VFS sends `MM_VFS_WRITEBACK_DONE` to;
/// firing it means queued completions can be retried without dropping tokens.
pub(crate) const KIND_MMSRV_WRITEBACK_DONE: u8 = 7;
