//! SaltyOS SaltyFS Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Mounts a SaltyFS partition from blkdrv and serves file read/directory
//! traversal requests over IPC.
//!
//! On-disk format follows docs/design/saltyfs.md exactly.
//! Data transfer to/from blkdrv uses mmsrv SHM.
//!
//! IPC protocol:
//!   Label 1 = BACKEND_OPEN_SESSION:   mount the filesystem
//!   Label 2 = BACKEND_LOOKUP:  MR0=parent_ino, MR1..=name -> MR0=child_ino
//!   Label 3 = BACKEND_READ:    TransferDescriptor-driven (inline or SHM)
//!   Label 4 = BACKEND_READDIR: MR0=dir_ino, MR1=cursor -> entries + EOF flag
//!   Label 5 = BACKEND_STAT:    MR0=ino -> stat info
//!   Label 6 = BACKEND_GETINFO: -> total/free blocks, label
//!   Label 16 = BACKEND_WRITE:  TransferDescriptor-driven (inline or SHM)
//!
//! Startup caps are role-based. System caps come from `trona_runtime::client::caps::*()`;
//! the service-local `blkdrv_ep` dependency is resolved through the
//! `trona_runtime::local_cap!` macro declared below.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod alloc;
mod block;
mod btree;
#[allow(dead_code)]
mod casefold_table;
mod consts;
mod crc;
mod handlers;
mod name;
mod session;
mod types;
mod worker;
mod xattr;

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_kernel::uapi;
use trona_protocol::common::{TRONA_INVALID_OPERATION, TRONA_IO_ERROR, TRONA_OK};
use trona_protocol::correlation::*;
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::posix::TRONA_STALE;
use trona_protocol::vfs::backend::*;
use trona_runtime::core::slot_alloc::OwnedCap;

use consts::*;
use types::Superblock;

const CAP_SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;

// Service-local cap: `Require=blkdrv-ep.socket` in `saltyfs.service`
// (Provider=blkdrv, Alias=blkdrv_ep). Init hashes `"saltyfs:blkdrv_ep"`
// into a LOCAL_ROLE id when building the startup cap_table.
trona_runtime::local_cap!(pub(crate) blkdrv_ep = "saltyfs:blkdrv_ep");

// VFS backend-callback caps live on per-session `SessionSlot` records
// in `SESSION_TABLE` (`saltyfs/src/session.rs`); there is no daemon-
// global callback endpoint anymore. `backend_callback()` resolves
// the live slot's `callback_ep` for the legacy single-session
// reply paths (the reactor's correlated-reply routing, worker direct-completion).

/// Resolve the live session's `callback_ep` from `SESSION_TABLE`.
/// Used by the reactor's correlated-reply routing (main.rs) and
/// `build_open_session_completion` / worker reply paths (worker.rs)
/// to address the current backend callback endpoint. In capacity-1
/// transitional mode this returns the first `Live` slot's
/// `callback_ep`; once multi-slot is wired, callers must pass the
/// slot index resolved from the request's session_id instead.
#[inline]
pub(crate) fn backend_callback() -> u64 {
    if let Some(idx) = session::current_live() {
        if let Some(slot) = session::slot(idx) {
            return slot.callback_ep.as_ref().map(|c| c.as_raw()).unwrap_or(0);
        }
    }
    0
}

/// Size of the per-saltyfs receive-slot arena. Each VFS restart consumes
/// one slot (the old `BACKEND_CALLBACK_EP` cap is `cnode_delete`-ed but
/// its slot stays in the arena's "past"). The arena absorbs:
///   * one cap per live multi-mount session (`SALTYFS_SESSION_SLOTS`)
///     for the BACKEND_OPEN_SESSION callback cap landing,
///   * one cap per in-flight async request (`SALTYFS_MAX_INFLIGHT`)
///     for `TRANSFER_KIND_MO` payload caps that arrive on
///     BACKEND_WRITE / BACKEND_READ before the worker maps + drops
///     them, and
///   * 32 slots of slack for restart-rebind churn (the old per-call
///     cap stays in the arena's "past" until the slot rolls back
///     around).
///
/// saltyfs is `Restart=always` so a misconfigured cap-rate would
/// just re-spawn with a fresh arena — but we size the arena large
/// enough that no realistic burst exhausts it.
const RECV_SLOT_COUNT: u64 = 256;

/// Receive-slot arena for IPC cap transfer. Initialised in `main` before
/// entering the server loop; armed and recycled by the helper API in
/// `trona_server::recv_slot`.
pub(crate) static mut RECV_SLOTS: trona_server::recv_slot::RecvSlotArena =
    trona_server::recv_slot::RecvSlotArena::new_empty();

// ======================================================================
// Global state
// ======================================================================

static mut MOUNTED: bool = false;
/// Mount-wide read-only flag. Set by `block::check_features` when the
/// image carries unknown `compat_ro_flags`, or by an explicit
/// `SALTYFS_MOUNT_RO` request. When true, all mutating handlers short-circuit
/// with `TRONA_READONLY` and no dirty blocks should ever accumulate.
static mut READONLY: bool = false;
static mut SB: Superblock = unsafe { core::mem::zeroed() };
static mut BLOCK_SIZE: u64 = DEFAULT_BLOCK_SIZE;
static mut BLK_SHM_ID: u64 = 0;
static mut CURRENT_SESSION_ID: u32 = 0;
static mut NEXT_SESSION_ID: u32 = 1;

/// Block cache: LRU-ish (just track block numbers, evict oldest)
static mut CACHE_BLOCK_NR: [u64; CACHE_SLOTS] = [u64::MAX; CACHE_SLOTS];
static mut CACHE_AGE: [u32; CACHE_SLOTS] = [0; CACHE_SLOTS];
static mut CACHE_TICK: u32 = 0;
static mut CACHE_DIRTY: [bool; CACHE_SLOTS] = [false; CACHE_SLOTS];

/// Next inode number to allocate
static mut NEXT_INO: u64 = 2;

/// Superblock dirty flag — set when `next_inode_seq` is updated, cleared after
/// `write_superblock()` flushes it to disk.
pub(crate) static mut SB_DIRTY: bool = false;

/// Bitmap block allocator
static mut BITMAP_CACHE: [[u8; 4096]; BITMAP_CACHE_SLOTS] = [[0; 4096]; BITMAP_CACHE_SLOTS];
static mut BITMAP_CACHE_BLOCK: [u64; BITMAP_CACHE_SLOTS] = [u64::MAX; BITMAP_CACHE_SLOTS];
static mut BITMAP_CACHE_DIRTY: [bool; BITMAP_CACHE_SLOTS] = [false; BITMAP_CACHE_SLOTS];
static mut BITMAP_BLOCK_COUNT: u64 = 0;
static mut ALLOC_HINT: u64 = 0;

// VFS-SaltyFS SHM mapping state lives on per-session `SessionSlot`
// records (`session::live_shm_region()`); there is no daemon-global
// SHM-mapped flag anymore.
/// Internal-only reply label used to tell the owner loop that a worker
/// accepted the request and will emit the real completion later. Must not
/// collide with wire-visible protocol labels such as `TRONA_OK == 0`.
const DEFERRED_REPLY_LABEL: u64 = u64::MAX;

fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

fn decode_request_correlation(msg: &TronaMsg) -> Option<CorrelationHeader> {
    let words = [
        msg.regs[CORRELATION_HEADER_REG_START],
        msg.regs[CORRELATION_HEADER_REG_START + 1],
        msg.regs[CORRELATION_HEADER_REG_START + 2],
        msg.regs[CORRELATION_HEADER_REG_START + 3],
    ];
    let header = CorrelationHeader::decode_words(words);
    if header.class != CORRELATION_CLASS_FS
        || header.backend != CORRELATION_BACKEND_SALTYFS
        || header.kind != CORRELATION_KIND_REQUEST
        || header.token == 0
    {
        return None;
    }
    Some(header)
}

fn stamp_completion_correlation(reply: &mut TronaMsg, request: CorrelationHeader) {
    let words = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        ..request
    }
    .encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = words[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    // Most handlers set a small reply.length for their own payload; raise
    // it so the kernel's length-bounded register copy includes the four
    // header words at MR28..=MR31. Without this, VFS's
    // `decode_fs_completion_header` sees zeros and drops the completion.
    ensure_correlation_wire_length(&mut reply.length);
}

/// Stamp a completion correlation header that flags the reply as a
/// stale-incarnation miss: the caller sent `request_seq` for `(ino,
/// seq=caller)` but the live inode now carries a different `seq`,
/// meaning the inode has been freed and recycled since the caller last
/// saw it. VFS translates the flag to `VfsError::Stale → ESTALE` on
/// POSIX or `ERROR_STALE_LINK` on Win32.
///
/// `request` must be the originating request's correlation header
/// (`class` / `backend` / `session` / `opcode` / `token` preserved);
/// this helper flips `kind` to `COMPLETION` and OR's
/// `CORRELATION_F_STALE_INCARNATION` into `flags`.
fn stamp_stale_incarnation_completion(reply: &mut TronaMsg, request: CorrelationHeader) {
    let header = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        flags: request.flags | CORRELATION_F_STALE_INCARNATION,
        ..request
    };
    let words = header.encode_words();
    // Same wire-length raise as `stamp_completion_correlation` — the
    // stale-incarnation flag is useless if the header itself does not
    // survive the kernel's length-bounded register copy.
    ensure_correlation_wire_length(&mut reply.length);
    reply.regs[CORRELATION_HEADER_REG_START] = words[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
}

/// Check if a request's declared `request_seq` still matches the live
/// inode's sequence. Returns `true` when the request is stale (the
/// inode has been reallocated since the caller took its handle); the
/// caller should short-circuit and stamp
/// `CORRELATION_F_STALE_INCARNATION` on the reply via
/// [`stamp_stale_incarnation_completion`].
///
/// `request_seq == 0` is the "opt-out" sentinel — legacy paths that do
/// not thread the seq through yet pass 0 and this check passes
/// unconditionally. Callers that need stale protection must stamp a
/// non-zero seq (via `stamp_saltyfs_async_request(.., seq)`).
pub(crate) fn is_request_stale(request_seq: u32, live_seq: u32) -> bool {
    request_seq != 0 && request_seq != live_seq
}

// ======================================================================
// Name service registration
// ======================================================================

fn register_namesrv() {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"saltyfs";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let Some(publish_tc) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] No service client ep to publish\n");
        });
        return;
    };
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.slot());
    }
    msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    msg.length = (REGISTER_FLAGS_REG + 1) as u64;
    unsafe {
        let mut reply = TronaMsg::zeroed();
        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        drop(publish_tc);
        if err != 0 || reply.label != TRONA_OK {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[saltyfs] namesrv registration failed\n");
            });
        }
    }
}

// ======================================================================
// Server main loop
// ======================================================================

/// Cookie for the service pipe's `STATE_READABLE` Watch (kind 0).
const SALTYFS_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Reactor dispatcher. Each VFS-backend request runs the backend op under
/// `BLOCK_LOCK`; the reply is then routed — a `DEFERRED_REPLY_LABEL` reply is
/// left for a worker to push, a correlated reply is pushed on the backend
/// callback EP, and an uncorrelated reply goes back on the service pipe.
struct SaltyfsDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
}

impl trona_server::event_loop::EqDispatcher for SaltyfsDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let badge = meta.badge;
        // Acquire `BLOCK_LOCK` before any accessor on the process-global
        // cache / bitmap / superblock / blkdrv SHM scratch. Released before the
        // reply is routed so the writeback worker can drain its queue.
        worker::BLOCK_LOCK.lock();

        // badge low 32 bits = caller's client_id per the cross-broker
        // badge layout (see `trona_server::badge`). Saltyfs daemon does
        // not differentiate per-client today; multi-mount session work
        // (BACKEND_OPEN_SESSION) will consume this when it lands.
        let _client_id = trona_server::badge::client_id_of(badge);
        let label = msg.label;
        // Stale-incarnation pre-check: for opcodes that target a specific
        // inode (every op that puts the primary ino in regs[0]), peek the
        // live inode and compare its sequence against the caller's stamped
        // `request_seq`. A divergence means the caller's cached node handle
        // refers to a since-freed-and-recycled inode, and the request is
        // short-circuited with `CORRELATION_F_STALE_INCARNATION`. Ops that
        // do not carry a node identity (`BACKEND_OPEN_SESSION`,
        // `BACKEND_CLOSE_SESSION`, `BACKEND_GETINFO`, `BACKEND_SHM_SETUP`)
        // skip the check; legacy callers that stamp `request_seq == 0`
        // opt out via the zero sentinel.
        let stale_reply: Option<TronaMsg> = {
            let node_targeted = matches!(
                label,
                BACKEND_LOOKUP
                    | BACKEND_READ
                    | BACKEND_READDIR
                    | BACKEND_STAT
                    | BACKEND_CREATE
                    | BACKEND_MKDIR
                    | BACKEND_UNLINK
                    | BACKEND_RMDIR
                    | BACKEND_RENAME
                    | BACKEND_TRUNCATE
                    | BACKEND_WRITE
                    | BACKEND_SYMLINK
                    | BACKEND_READLINK
                    | BACKEND_LINK
                    | BACKEND_CHMOD
                    | BACKEND_CHOWN
                    | BACKEND_SETATTR
                    | BACKEND_GETXATTR
                    | BACKEND_SETXATTR
                    | BACKEND_REMOVEXATTR
                    | BACKEND_LISTXATTR
            );
            if !node_targeted {
                None
            } else if let Some(header) = decode_request_correlation(msg) {
                // Primary slot: regs[0] holds the primary inode for every
                // node-targeted op. `request_seq == 0` opts out of the
                // incarnation check for that slot.
                let primary_stale = if header.request_seq == 0 {
                    false
                } else {
                    let ino = msg.regs[0];
                    let live_seq = match handlers::get_inode(ino) {
                        Some(inode) => inode.sequence,
                        None => 0,
                    };
                    is_request_stale(header.request_seq, live_seq)
                };
                // Secondary slot: only BACKEND_RENAME (new_parent at
                // regs[2]) and BACKEND_LINK (new_parent at regs[1])
                // stamp a non-zero `request_seq_secondary`. All other
                // node-targeted ops leave it at the zero opt-out
                // sentinel and this branch is a no-op.
                let secondary_stale = if primary_stale || header.request_seq_secondary == 0 {
                    false
                } else {
                    let secondary_ino = match label {
                        BACKEND_RENAME => msg.regs[2],
                        BACKEND_LINK => msg.regs[1],
                        _ => 0,
                    };
                    if secondary_ino == 0 {
                        false
                    } else {
                        let live_seq_secondary = match handlers::get_inode(secondary_ino) {
                            Some(inode) => inode.sequence,
                            None => 0,
                        };
                        is_request_stale(header.request_seq_secondary, live_seq_secondary)
                    }
                };
                if primary_stale || secondary_stale {
                    if secondary_stale && !primary_stale {
                        trona_runtime::uwarn!(|_lb| {
                            _lb.str(b"[saltyfs] stale secondary inode for op=");
                            _lb.hex(label);
                            _lb.str(b"\n");
                        });
                    }
                    let mut r = TronaMsg::zeroed();
                    r.label = TRONA_STALE;
                    stamp_stale_incarnation_completion(&mut r, header);
                    Some(r)
                } else {
                    None
                }
            } else {
                None
            }
        };
        let reply = if let Some(r) = stale_reply {
            r
        } else {
            match label {
                BACKEND_OPEN_SESSION => {
                    // Capture the backend_callback EP that VFS transfers with
                    // this OPEN_SESSION. Every OPEN_SESSION carries exactly one
                    // cap (see vfs/src/fs/saltyfs_client/vfsops.rs::saltyfs_mount
                    // — both async and sync paths pre-stage the cap via
                    // `ipc::set_send_cap_ctx`); stale caps from a prior session
                    // are `cnode_delete`-ed here before replacement, so a VFS
                    // restart cannot leave saltyfs holding a dead endpoint.
                    //
                    // Cap-count trust: `capture_transferred_cap` reads
                    // the kernel-published `received_cap_count` from the
                    // IPC buffer's reserved area and returns `None` when
                    // no cap was actually transferred, so a malformed
                    // sender that promised a cap but did not stage one
                    // is rejected here without ever installing the
                    // ghost slot.
                    let incoming = unsafe {
                        let arena = &mut *(&raw mut RECV_SLOTS);
                        trona_server::recv_slot::capture_transferred_cap(ipc_ctx(), arena)
                            .unwrap_or(0)
                    };

                    // Off-owner mount: when the request carries a
                    // correlation header and a worker is live, enqueue
                    // the mount on the worker so the saltyfs owner can
                    // accept other traffic while superblock read +
                    // bitmap scan + feature negotiation run in the
                    // background. The worker pushes the reply via
                    // `backend_callback()` using the correlated-reply
                    // pattern — identical to `ReadBlocks`.
                    let reply = if worker::worker_running() {
                        if let Some(_) = decode_request_correlation(msg) {
                            let correlation_words = [
                                msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 1],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 2],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 3],
                            ];
                            let mount_flags = if msg.length >= 1 { msg.regs[0] } else { 0 };
                            let reply_ep = backend_callback();
                            unsafe {
                                worker::submit_or_run(worker::WorkerJob {
                                    tx_id: worker::next_tx_id(),
                                    kind: worker::WorkerJobKind::OpenSession {
                                        reply_ep,
                                        mount_flags,
                                        correlation_words,
                                    },
                                });
                            }
                            let mut deferred = TronaMsg::zeroed();
                            deferred.label = DEFERRED_REPLY_LABEL;
                            deferred
                        } else {
                            handlers::handle_mount(msg)
                        }
                    } else {
                        handlers::handle_mount(msg)
                    };

                    // After `handle_mount` (or the worker's mount path)
                    // installs a Live slot in `SESSION_TABLE`, dual-stash
                    // the captured callback cap onto it. While the global
                    // `BACKEND_CALLBACK_EP` and the per-slot `callback_ep`
                    // coexist (capacity-1 transitional), every readout
                    // converges on the same value; the global is the
                    // legacy alias that `backend_callback()` still
                    // returns.
                    if incoming != 0 {
                        session::set_live_callback_ep(incoming);
                    }
                    reply
                }
                BACKEND_CLOSE_SESSION => handlers::handle_close_session(msg),
                BACKEND_LOOKUP => handlers::handle_lookup(msg),
                BACKEND_READ => {
                    // Off-owner read: if the request is correlated (VFS
                    // stamped a CorrelationHeader) and a worker is live,
                    // enqueue the read on the worker's submit ring and
                    // return the "deferred" sentinel. The worker reads
                    // blocks from disk, stamps a completion header, and
                    // pushes the reply via `backend_callback()` exactly
                    // like `push_async_complete` would. The owner loop
                    // never blocks on blkdrv I/O for a read.
                    if worker::worker_running() {
                        if let Some(_) = decode_request_correlation(msg) {
                            let correlation_words = [
                                msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 1],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 2],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 3],
                            ];
                            let transfer = trona_protocol::vfs::backend::TransferDescriptor::decode_regs([
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG],
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG + 1],
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG + 2],
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG + 3],
                        ]);
                            let reply_ep = backend_callback();
                            unsafe {
                                worker::submit_or_run(worker::WorkerJob {
                                    tx_id: worker::next_tx_id(),
                                    kind: worker::WorkerJobKind::ReadBlocks {
                                        reply_ep,
                                        ino: msg.regs[0],
                                        file_offset: msg.regs[1],
                                        transfer_kind: transfer.kind,
                                        transfer_offset: transfer.offset,
                                        transfer_length: transfer.length,
                                        correlation_words,
                                    },
                                });
                            }
                            // Return the internal deferred sentinel so the
                            // owner loop skips both async-push and
                            // mp_write_reply_read, then jumps straight to mp_read_ctx.
                            let mut deferred = TronaMsg::zeroed();
                            deferred.label = DEFERRED_REPLY_LABEL;
                            deferred
                        } else {
                            handlers::handle_read(msg)
                        }
                    } else {
                        handlers::handle_read(msg)
                    }
                }
                BACKEND_READDIR => handlers::handle_readdir(msg),
                BACKEND_STAT => handlers::handle_stat(msg),
                BACKEND_GETINFO => handlers::handle_getinfo(),
                BACKEND_CREATE => handlers::handle_create(msg),
                BACKEND_MKDIR => handlers::handle_mkdir_fs(msg),
                BACKEND_UNLINK => handlers::handle_unlink_fs(msg),
                BACKEND_RMDIR => handlers::handle_rmdir_fs(msg),
                BACKEND_RENAME => handlers::handle_rename_fs(msg),
                BACKEND_TRUNCATE => handlers::handle_truncate_fs(msg),
                BACKEND_SHM_SETUP => handlers::handle_shm_setup(msg),
                BACKEND_WRITE => {
                    // Hybrid-1 deferred dispatch: when the request
                    // carries a correlation header and the worker is
                    // live, snapshot the payload off the inbound regs
                    // (inline) or capture the SHM offset / MO cap
                    // (Ring / Mo), submit a `WriteBlocks` job, and
                    // return the deferred sentinel. The worker calls
                    // `execute_write_locked`, drives the cache +
                    // superblock flush so the direct completion send
                    // marks a commit boundary, and ships the reply
                    // through `backend_callback()`. Sync fallback
                    // for legacy uncorrelated callers stays on
                    // `handlers::handle_write`.
                    if worker::worker_running() {
                        if let Some(_) = decode_request_correlation(msg) {
                            let correlation_words = [
                                msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 1],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 2],
                                msg.regs
                                    [trona_protocol::correlation::CORRELATION_HEADER_REG_START + 3],
                            ];
                            let transfer = trona_protocol::vfs::backend::TransferDescriptor::decode_regs([
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG],
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG + 1],
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG + 2],
                            msg.regs[trona_protocol::vfs::backend::BACKEND_RW_REQ_DESCRIPTOR_REG + 3],
                        ]);
                            let slot_idx = session::slot_idx_for_msg(msg).unwrap_or(0) as u32;
                            let live_gen = session::slot(slot_idx as usize)
                                .map(|s| s.live_gen)
                                .unwrap_or(0);
                            // Capture an inbound MO cap when the wire
                            // discriminator promised one. `capture_transferred_cap`
                            // returns `None` when the kernel reports zero
                            // staged caps, so a sender that signalled
                            // `TRANSFER_KIND_MO` but failed to attach the
                            // cap collapses to a null OwnedCap, which the
                            // worker rejects with `OUT_OF_RANGE`. Inbound
                            // caps that arrived under non-MO wire kinds
                            // (e.g. a misbehaving sender) are dropped by
                            // OwnedCap::drop before the arm exits.
                            let captured_cap: OwnedCap = unsafe {
                                let arena = &mut *(&raw mut RECV_SLOTS);
                                let raw = trona_server::recv_slot::capture_transferred_cap(
                                    ipc_ctx(),
                                    arena,
                                )
                                .unwrap_or(0);
                                OwnedCap::adopt_received(raw)
                            };
                            let payload = match transfer.kind {
                                trona_protocol::vfs::backend::TRANSFER_KIND_INLINE => {
                                    // Drop any spurious inbound cap; OwnedCap::drop
                                    // calls delete_and_free (NOT_FOUND on
                                    // null slot is silently discarded).
                                    drop(captured_cap);
                                    let len = transfer.length.min(
                                        trona_protocol::vfs::backend::INLINE_TRANSFER_WIRE_MAX,
                                    );
                                    let mut bytes = [0u8; 160];
                                    unsafe {
                                        let src = &raw const msg.regs[
                                        trona_protocol::vfs::backend::BACKEND_WRITE_INLINE_PAYLOAD_REG
                                    ] as *const u8;
                                        for i in 0..len as usize {
                                            bytes[i] = *src.add(i);
                                        }
                                    }
                                    worker::WritePayload::Inline { len, bytes }
                                }
                                trona_protocol::vfs::backend::TRANSFER_KIND_SHM => {
                                    // Drop any spurious inbound cap.
                                    drop(captured_cap);
                                    worker::WritePayload::Ring {
                                        offset: transfer.offset,
                                        len: transfer.length,
                                    }
                                }
                                trona_protocol::vfs::backend::TRANSFER_KIND_MO => {
                                    worker::WritePayload::Mo {
                                        cap: captured_cap,
                                        len: transfer.length,
                                    }
                                }
                                _ => {
                                    // Unknown transfer kind — drop the cap and
                                    // produce a zero-length inline payload so the
                                    // worker surfaces OUT_OF_RANGE.
                                    drop(captured_cap);
                                    worker::WritePayload::Inline {
                                        len: 0,
                                        bytes: [0u8; 160],
                                    }
                                }
                            };
                            let reply_ep = backend_callback();
                            unsafe {
                                worker::submit_or_run(worker::WorkerJob {
                                    tx_id: worker::next_tx_id(),
                                    kind: worker::WorkerJobKind::WriteBlocks {
                                        reply_ep,
                                        slot_idx,
                                        live_gen,
                                        ino: msg.regs[0],
                                        file_offset: msg.regs[1],
                                        payload,
                                        correlation_words,
                                    },
                                });
                            }
                            let mut deferred = TronaMsg::zeroed();
                            deferred.label = DEFERRED_REPLY_LABEL;
                            deferred
                        } else {
                            handlers::handle_write(msg)
                        }
                    } else {
                        handlers::handle_write(msg)
                    }
                }
                BACKEND_SYMLINK => handlers::handle_symlink(msg),
                BACKEND_READLINK => handlers::handle_readlink(msg),
                BACKEND_LINK => handlers::handle_link(msg),
                BACKEND_CHMOD => handlers::handle_chmod(msg),
                BACKEND_CHOWN => handlers::handle_chown(msg),
                BACKEND_SETATTR => handlers::handle_setattr(msg),
                BACKEND_GETXATTR => xattr::handle_getxattr(msg),
                BACKEND_SETXATTR => xattr::handle_setxattr(msg),
                BACKEND_REMOVEXATTR => xattr::handle_removexattr(msg),
                BACKEND_LISTXATTR => xattr::handle_listxattr(msg),
                BACKEND_FSYNC => handlers::handle_fsync(msg),
                _ => {
                    let mut r = TronaMsg::zeroed();
                    r.label = TRONA_INVALID_OPERATION;
                    r
                }
            }
        };

        // Dispatch dirty-block writeback to the worker thread after
        // mutating operations. The worker keeps blkdrv IPC off the
        // owner's critical path. If the worker is not running (spawn
        // failed at startup, or running under a config that disables
        // it) `submit_or_run` falls back to a synchronous flush so
        // correctness is preserved. Stale-incarnation-rejected requests
        // never touched the on-disk state, so their label-match arm is
        // skipped here.
        //
        // `BACKEND_WRITE` is excluded here: the Hybrid-1 deferred
        // path performs cache + superblock flush inside its own
        // worker job (see `worker::build_write_blocks_outcome`),
        // so the direct completion send marks a real commit
        // boundary. Re-enqueuing FlushCache / FlushSuperblock here
        // would race with the in-flight write job and risk
        // surfacing the wire reply before the bytes are durable.
        let is_mutating = matches!(
            label,
            BACKEND_CREATE
                | BACKEND_MKDIR
                | BACKEND_UNLINK
                | BACKEND_RMDIR
                | BACKEND_RENAME
                | BACKEND_TRUNCATE
                | BACKEND_SYMLINK
                | BACKEND_LINK
                | BACKEND_CHMOD
                | BACKEND_CHOWN
                | BACKEND_SETATTR
                | BACKEND_SETXATTR
                | BACKEND_REMOVEXATTR
        );
        if is_mutating && reply.label != TRONA_STALE {
            unsafe {
                worker::submit_or_run(worker::WorkerJob {
                    tx_id: worker::next_tx_id(),
                    kind: worker::WorkerJobKind::FlushCache,
                });
                worker::submit_or_run(worker::WorkerJob {
                    tx_id: worker::next_tx_id(),
                    kind: worker::WorkerJobKind::FlushSuperblock,
                });
            }
        }

        // Drain any status-only completions the worker has posted while
        // we were handling this request. Deferred read/mount replies are
        // sent directly by the worker after it drops `BLOCK_LOCK`;
        // writeback/checksum jobs still use this owner-facing ring so
        // `close_session` can surface aggregate failure.
        unsafe {
            let _ = worker::drain_completion_statuses();
        }

        let request_correlation =
            decode_request_correlation(msg).filter(|header| header.opcode as u64 == label);
        let mut reply = reply;
        // Only re-stamp the completion header for non-stale replies.
        // Stale replies already carry a correlation header with
        // `CORRELATION_F_STALE_INCARNATION` set by
        // `stamp_stale_incarnation_completion`; re-stamping via
        // `stamp_completion_correlation(..request)` would wipe the
        // flag because the flag is derived from the reply's state,
        // not the request's.
        if let Some(header) = request_correlation {
            if reply.label != TRONA_STALE {
                stamp_completion_correlation(&mut reply, header);
            }
        }

        // `close_session` must not race with outstanding writeback or
        // deferred direct-send completions. Release `BLOCK_LOCK` before
        // draining so the worker can make progress, then reacquire it
        // and tear the session down only after every in-flight job is
        // gone. If drain/final teardown reported failure, downgrade the
        // reply to `TRONA_IO_ERROR` so the client sees a non-zero close
        // status instead of a false success.
        if label == BACKEND_CLOSE_SESSION && reply.label == TRONA_OK {
            worker::BLOCK_LOCK.unlock();
            let drain_status = unsafe { worker::drain_pending() };
            worker::BLOCK_LOCK.lock();
            let finalize_status = handlers::finalize_close_session();
            if drain_status != 0 || finalize_status != 0 {
                // Preserve correlation-header bytes (already stamped
                // above) and the reply-length convention; only rewrite
                // the label so the client sees a non-zero close.
                reply.label = TRONA_IO_ERROR;
                reply.length = 0;
                reply.regs[0] = 0;
            }
        }

        // Release the block lock before entering the outer IPC wait so
        // the writeback worker can drain its submit ring while we park
        // for the next VFS request.
        worker::BLOCK_LOCK.unlock();

        // Route the reply; the EventLoop owns the next receive. `request_correlation`
        // and the stamped `reply` were computed above under `BLOCK_LOCK`.
        // SAFETY: `ipc_ctx()` is this thread's IPC context.
        unsafe {
            if reply.label == DEFERRED_REPLY_LABEL {
                // Deferred — a worker pushes the correlated completion later via
                // the backend callback EP.
            } else if request_correlation.is_some() {
                let ep = backend_callback();
                if ep == 0 {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(
                            b"[saltyfs] async completion dropped -- backend_callback EP missing\n",
                        );
                    });
                } else {
                    let err = ipc::mp_write_ctx(ipc_ctx(), ep, &raw const reply);
                    if err != 0 {
                        trona_runtime::uerror!(|_lb| {
                            _lb.str(b"[saltyfs] async completion send failed err=");
                            _lb.hex(err as u64);
                            _lb.str(b" ep=");
                            _lb.hex(ep);
                            _lb.str(b"\n");
                        });
                    }
                }
            } else {
                let _ = ipc::mp_write_reply_ctx(ipc_ctx(), self.recv_ep, &raw const reply);
            }
        }
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // Cycle the receive-slot arena before the next MP_READ so a transferred
        // cap lands in a fresh slot. SAFETY: single-threaded reactor owns RECV_SLOTS.
        unsafe {
            (&mut *(&raw mut RECV_SLOTS)).recycle_for_next_recv(ipc_ctx(), CAP_SELF_CSPACE);
        }
        true
    }

    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(self.watch_cap),
            trona_kernel::core_types::CapRef::flat(self.recv_ep),
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
            SALTYFS_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

fn server_loop() -> ! {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[saltyfs] Entering reactor\n");
    });
    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();

    // Self-provision the reactor's EventQueue + Watch from rsrcsrv.
    let eq = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_EVENT_QUEUE as u64,
        4,
    );
    let watch = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_WATCH as u64,
        0,
    );
    let (eq, watch) = match (eq, watch) {
        (Some(eq), Some(watch)) => (eq, watch),
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[saltyfs] reactor EventQueue/Watch alloc failed\n");
            });
            loop {
                trona_kernel::syscall::yield_now();
            }
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();

    // Arm the service pipe's READABLE edge onto the reactor EQ.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        SALTYFS_SERVICE_COOKIE,
    );

    core::mem::forget(eq);
    core::mem::forget(watch);

    let dispatcher = SaltyfsDispatcher {
        recv_ep,
        watch_cap,
        eq_cap,
    };
    let mut reactor = trona_server::event_loop::EventLoop::new(eq_cap, dispatcher);
    loop {
        // SAFETY: `ctx` is this thread's IPC context.
        unsafe {
            let _ = reactor.run_iteration(ctx);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[saltyfs] SaltyFS Server starting\n");
    });

    // Set up SHM from blkdrv
    if !block::setup_blk_shm() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] Failed to set up blkdrv SHM -- cannot operate\n");
        });
    }

    // Set up block cache
    if !block::setup_cache() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] Failed to set up block cache\n");
        });
    }

    // Auto-mount on startup
    if !block::read_superblock() {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[saltyfs] No SaltyFS partition found -- running without mount\n");
        });
    } else {
        unsafe {
            *(&raw mut MOUNTED) = true;
        }
        alloc::init_bitmap();

        // Bitmap consistency check: verify used_blocks matches actual bitmap.
        // Skip the correcting write path when mounted read-only.
        let actual_used = alloc::count_used_blocks();
        let sb_used = unsafe { (*(&raw const SB)).used_blocks };
        if actual_used != sb_used {
            let ro = unsafe { *(&raw const READONLY) };
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[saltyfs] WARN: bitmap mismatch: sb.used_blocks=");
                _lb.dec(sb_used);
                _lb.str(b" actual=");
                _lb.dec(actual_used);
                if ro {
                    _lb.str(b" (read-only; not correcting)\n");
                } else {
                    _lb.str(b" (correcting)\n");
                }
            });
            if !ro {
                unsafe {
                    (*(&raw mut SB)).used_blocks = actual_used;
                }
                block::write_superblock();
            }
        }

        if unsafe { (*(&raw const SB)).next_inode_seq == 0 } {
            block::legacy_upgrade_next_inode_seq();
            block::write_superblock();
        } else {
            unsafe {
                *(&raw mut NEXT_INO) = (*(&raw const SB)).next_inode_seq;
            }
        }
    }

    // Register with name service; unit_mgr observes the publish event as readiness.
    register_namesrv();

    // Spawn the writeback worker so the owner loop does not block on
    // blkdrv IPC for dirty-block and superblock flushes. Failure to
    // spawn leaves the owner in single-threaded mode — `submit_or_run`
    // detects that and falls back to a synchronous in-line flush.
    unsafe {
        let cfg = trona_runtime::thread::SpawnConfig::for_runtime_thread();
        if !worker::spawn_worker(cfg) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[saltyfs] writeback worker unavailable\n");
            });
        }
    }

    // Reserve and arm the receive-slot arena. Used by the
    // `BACKEND_OPEN_SESSION` dispatch arm in `server_loop` to capture the
    // VFS backend_callback EP via `trona_server::recv_slot::capture_transferred_cap`.
    // Must run after the slot allocator is live (crt/rtld startup ensured
    // that before `main`) and before the first receive.
    unsafe {
        let arena = &mut *(&raw mut RECV_SLOTS);
        let allocator = trona_server::recv_slot::SlotAllocator {
            alloc_consecutive: trona_runtime::core::slot_alloc::slot_alloc_consecutive_cb,
            invoke_depth: trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
        };
        if !arena.init_with_allocator(allocator, RECV_SLOT_COUNT) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[saltyfs] FATAL: recv-slot arena allocation failed\n");
            });
            return -1;
        }
        arena.arm_first(ipc_ctx(), CAP_SELF_CSPACE);
    }

    // Enter server loop
    server_loop()
}
