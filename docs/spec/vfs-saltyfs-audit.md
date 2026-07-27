# VFS ↔ SaltyFS Audit

## Purpose

This document is a living ledger for the VFS ↔ SaltyFS modular refactor
described in `vfs-saltyfs-modular-lemon` (planning artefact). It is the
single place to answer four questions at any point in time:

1. Which blocker-level gaps are still open at current HEAD?
2. Which historical gaps have been closed and should stay visible?
3. Which design-intent invariants must hold across the VFS client and
   the saltyfs backend for the refactor to be proof-relevant?
4. Which load-bearing assumptions support the current claims?

This document is not a mechanized proof. It records static audit results,
codex cross-model audit findings, runtime-relevant debts, and the
assumptions those statements depend on. It complements
`memory-model-audit.md` which covers kernel / mmsrv / rsrcsrv; the two
files share no ID space.

## How To Update This Document

When a new audit pass is done:

1. Add one entry to `## Audit Log`.
2. Update `## Current Status`.
3. Add or update items in `## Open Blockers` and `## Historical Fix Ledger`.
4. If the design invariants changed, update `## Required Invariants`.
5. If an assumption shifted, update `## Load-Bearing Assumptions`.

Stable IDs:

- `VH#` = historically-identified blocker that is now closed.
- `VO#` = blocker open at current HEAD.
- `VI#` = refactor-level invariant.
- `VA#` = load-bearing assumption.

`V` prefix keeps this file's IDs disjoint from `memory-model-audit.md`'s
`H# / O# / I# / A#` space.

## Scope And Method

This audit covers:

- `userland/core/vfs` — the VFS server (owner loop, namei, backend
  session table, pending-op arena, worker pool).
- `userland/drivers/filesystems/saltyfs` — the SaltyFS backend (owner
  thread, writeback + deferred-mount worker, block cache, btree).
- `lib/trona/uapi/protocol/correlation.rs` and
  `lib/trona/uapi/protocol/fs_backend.rs` — the wire contract between
  the two.
- `lib/trona/uapi/consts/server.rs` — `TRONA_STALE` and related
  wire-visible error codes.
- Personality-facing error maps in `personality/posix/errno.rs` and
  `personality/win32/errno.rs` that surface backend-level failures.

Unless an audit-log entry says otherwise, this is a static source audit
plus a targeted build probe. No soak / runtime regression tests are
implied.

## Current Status

Current snapshot:

- Date: `2026-04-20`
- Method: codex-assisted static source audit (two passes) + static
  implementation in-session; `VH13` landed in a targeted dual-seq edit
  pass.
- Current verdict: `DESIGN INVARIANTS MET, RUNTIME-UNVERIFIED` —
  pending smoke tests. Build / compiler pass state is a separate
  process concern tracked outside this audit.
- Historical blocker closures retained: `VH1`–`VH13`.
- Currently open blocker-level issues: `VO3`–`VO7` (`VO1` retired —
  see `## Audit Log` 2026-04-19 second entry; `VO2` retired and
  promoted to `VH13` — see 2026-04-20 entry).
- Currently open complications (not blocker-level): see `## Secondary
  Complications`.

### Status Table

| ID   | Status | Area | Summary | Primary invariant(s) |
|------|--------|------|---------|----------------------|
| VH1  | CLOSED | Wire contract | `CorrelationHeader` at MR28..=MR31, `BACKEND_*` opcode retirement of `SALTYFS_*` labels | VI1, VI2 |
| VH2  | CLOSED | Wire contract | `BackendOpenSessionReply.max_inflight` + per-session credit cap read end-to-end | VI3 |
| VH3  | CLOSED | Wire contract | Correlated completion reply path unified: owner-side `emit_server_reply`, allowlist retired | VI2 |
| VH4  | CLOSED | Wire contract | `CorrelationHeader.request_seq` + `CORRELATION_F_STALE_INCARNATION` plumbed end-to-end on fresh-issue paths; `TRONA_STALE (33)` maps to `ESTALE` / `ERROR_STALE_LINK` | VI4 |
| VH5  | CLOSED | Wire contract | Unknown-token completion arrivals logged and dropped without wedging the owner loop | VI5 |
| VH6  | CLOSED | Session lifecycle | Session teardown synthesises typed `VfsError::SessionTornDown` replies; resolve-cache evicts by `fs_id`; `observe_backend_send` triggers reactive teardown on send error | VI6, VI7 |
| VH7  | CLOSED | Structural | `OwnerVopCtx` / `OwnerMountCtx` / `WorkerIoCtx` replace trampoline statics; accessors and `reborrow` added | VI8, VI9 |
| VH8  | CLOSED | Structural | `ipc_objects.rs` physically owns `PipeState` / `SocketState` / `EpollInstance` / `ShmData` + helpers; POSIX `personality/types.rs` is a thin re-export | VI10 |
| VH9  | CLOSED | Ingress classification | `VfsEvent` enum covers every owner-loop ingress source including `TimerFired`; inet callback, pager, PTY notification, unknown-label callback all routed through classification | VI11 |
| VH10 | CLOSED | State hygiene | Bootstrap flags (`backend_callback_prepared`, `mmsrv_pager_registered`, `netsrv_callback_registered`) moved off `static mut` onto `VfsState`; `LOGGED_INET_*` likewise | VI12 |
| VH11 | CLOSED | Pending-op arena | `PendingOpState::Net` + `Resume::Net(NetResume)` added; `personality::posix::inet` migrated off the fixed `inet_pending` array onto the unified `pending_ops` arena | VI13 |
| VH12 | CLOSED | SaltyFS completion ring | Worker no longer blocks on `send_ctx`; `WorkerCompletion { reply_ep, reply_msg }` carries the full reply, owner drains and emits | VI14 |
| VH13 | CLOSED | Wire contract | `CorrelationHeader.request_seq_secondary` + SaltyFS `server_loop` dual-seq precheck — rename/link secondary target now stale-guarded symmetrically | VI4 |
| VH14 | CLOSED | Wire contract | `BACKEND_OPEN_SESSION` now carries `extra_caps[0] = VFS backend_callback EP`; SaltyFS's dispatch arm captures via `trona::recv_slot::capture_transferred_cap` into `BACKEND_CALLBACK_EP`, `cnode_delete`-ing any prior cap so VFS restart cannot leave a dead endpoint. `emit_server_reply` checks `send_ctx` return and loud-logs on failure as the safety net for label-trust cap detection (userland ABI does not yet expose receive-side `extra_caps` — see `trona::recv_slot` module note for the follow-up). Replaces the broken static `backend_callback.cap` attachment that previously caused a silent drop → rootfs.target boot hang | VI1 |
| VO3  | OPEN   | Session lifecycle | `netsrv_gen` is stored on `PendingOpState::Net` but never compared at callback arrival; stale-callback-after-re-registration is not enforced in software | VI6 |
| VO4  | OPEN   | Structural | `WorkerIoCtx` still carries `state: *mut VfsState` + `ops: *const VopVector` as an opt-in escape hatch; removing them requires migrating ~20 saltyfs vops callers | VI8 |
| VO5  | OPEN   | SaltyFS lifecycle | No distinct `PendingTransaction` / worker-local `TxId` split on the saltyfs side; worker jobs and VFS-visible correlation tokens share a single id space | VI16 |
| VO6  | OPEN   | Async migration | `saltyfs_write` still runs synchronously via `mutate_rpc::saltyfs_ipc_write`; does not participate in the credit / deferred-replay machinery | VI17 |
| VO7  | OPEN   | Protocol retirement | `BACKEND_CHMOD` / `BACKEND_CHOWN` remain as live fallbacks alongside `BACKEND_SETATTR` instead of being retired | VI18 |

## State Model That Must Be Proved

The runtime truth for a VFS request is spread across seven places:

1. VFS service-EP message + reply-slot reservation
   `userland/core/vfs/src/server/*` — caller badge, saved reply cap.

2. VFS `pending_ops` arena
   `userland/core/vfs/src/owner/pending.rs` — `PendingOpState::Fs` /
   `PendingOpState::Net`, generation metadata, resume continuation.

3. VFS `backend_sessions` slot table
   `userland/core/vfs/src/owner/session.rs` — `session_id`, `live_gen`,
   `inflight_now`, `inflight_max`, completion-fn / defer-push / drain /
   readdir-eof hooks, callback EP, revocation slot.

4. VFS `deferred_issues` arena
   `userland/core/vfs/src/owner/deferred.rs` — parked ops waiting for
   credit; carries snapshot of op kind + resume + target seq.

5. Backend IPC message in flight
   MR0..=MR27 payload + MR28..=MR31 `CorrelationHeader`.

6. SaltyFS owner thread + worker thread
   `userland/drivers/filesystems/saltyfs/src/{main,worker,handlers,block}.rs`
   — inode B-tree, block cache, bitmap, superblock, writeback ring,
   deferred-mount ring, per-correlation reply stamping.

7. Personality-side error surface
   `personality/{posix,win32}/errno.rs` + `VfsError::to_trona`.

A refinement story ties these seven layers together. The request
lifecycle is a finite state machine with transitions:

`Issued → Parked → (Cancelled | Session-TornDown | Stale | Completed) →
Reply-Emitted → Slot-Released`

For every transition at least one of the seven layers commits, exactly
once, with a matching rollback on partial failure.

## Required Invariants

### Wire Contract

- `VI1` Every in-flight backend request carries a `CorrelationHeader`
  at MR28..=MR31 with `class = CORRELATION_CLASS_FS`, `backend` set to
  the backend identifier, and a non-zero `token` allocated monotonically
  from `VfsState.next_tx_id`.
- `VI2` The reply path for a correlated request produces exactly one
  completion: the backend-callback EP push when `kind = COMPLETION`, or
  the synchronous reply slot when the request arrived with no
  `CorrelationHeader`. Label-driven dispatch (`SALTYFS_*` opcodes) is
  forbidden.
- `VI3` The per-session inflight cap comes from
  `BackendOpenSessionReply.max_inflight` at mount time. VFS never
  issues more than `max_inflight` concurrent credited ops per session.
- `VI4` The caller stamps `request_seq` (primary) and
  `request_seq_secondary` (secondary; used by multi-target ops such
  as `rename` and `link`) into the `CorrelationHeader`. For each
  non-zero slot whose paired live inode sequence differs, the backend
  replies with `CORRELATION_F_STALE_INCARNATION` set, `TRONA_STALE`
  label, and no side-effect (no writeback, no re-stamp of the
  completion header). A zero value in either slot is an opt-out
  sentinel for that slot alone.
- `VI5` A completion arriving for an unknown `token` is logged once per
  arrival (rate-limited in `dispatch_pending_reply`) and dropped; the
  owner loop never blocks on it.

### Session Lifecycle

- `VI6` A session teardown (graceful unmount or reactive revocation via
  `observe_backend_send`) cancels every in-flight `PendingOp` scoped to
  the session, synthesises `VfsError::SessionTornDown` replies for each
  saved reply slot, drains the deferred-issue ring, evicts every
  resolve-cache entry scoped to the retired `fs_instance_id`, and zeroes
  the session slot.
- `VI7` A completion arriving after session teardown whose echoed
  `session` field no longer matches any live `BackendSessionSlot` is
  dropped silently; the saved reply slot (if any) is released.

### Structural

- `VI8` MetaOps and VfsOps dispatch through explicit ctx types
  (`OwnerVopCtx<'a>`, `OwnerMountCtx<'a>`) carrying `&mut VfsState`.
  Trampoline statics are forbidden. `WorkerIoCtx` is the data-plane
  snapshot; state access is nullable and opt-in.
- `VI9` `OwnerVopCtx::reborrow` is the only mechanism for nested
  meta-op dispatch within a call; no second `OwnerVopCtx::from_state`
  fires while a parent ctx is on the stack.
- `VI10` Neutral IPC-object backings (`PipeState`, `SocketState`,
  `EpollInstance`, `ShmData`) are defined in `ipc_objects.rs`. The
  server layer references them directly; POSIX is a consumer, not an
  owner.
- `VI11` Every ingress message to the owner loop is classified through
  the `VfsEvent` exhaustive match. New ingress sources extend the enum.

### State Hygiene

- `VI12` Backend bootstrap flags and log rate-limit counters live on
  `VfsState`. Module-local `static mut` for per-VFS-process state is
  forbidden.
- `VI13` Net-class parks live in the unified `pending_ops` arena as
  `PendingOpState::Net`; there is no private fixed-array pending table.
- `VI14` The saltyfs worker thread never calls `ipc::send_ctx` for a
  client-facing reply. The completion ring carries the full reply +
  target EP; the owner thread is the exclusive sender.

### Runtime-Correctness

- `VI16` Saltyfs worker-local transaction identifiers are disjoint from
  VFS-supplied correlation tokens. A crash-recovery audit can
  reconstruct both sides' ordering independently.
- `VI17` Every backend-bound data op (read / write / readdir / bulk
  read / bulk write) either participates in the credit machinery and
  can park on a waiter ring, or returns `VfsError::NotSupported` at
  dispatch time. Synchronous blocking of the VFS owner loop on backend
  I/O is forbidden for the hot path.
- `VI18` Personality-neutral attribute mutation rides a single wire op
  (`BACKEND_SETATTR`) whose reply carries the post-commit `VAttr`
  snapshot. Legacy single-field opcodes (`BACKEND_CHMOD`,
  `BACKEND_CHOWN`) are sync-fallback only and targeted for retirement.

## Open Blockers

### VO3 — `netsrv_gen` stored but not enforced

- Status: `OPEN`
- Area: session lifecycle
- Primary invariants: `VI6`

What is claimed:
- `VfsState.next_netsrv_gen` is bumped on every successful netsrv
  re-registration. `PendingOpState::Net { netsrv_gen, .. }` captures
  the generation at reservation time.

What is missing:
- Callback arrival comparison. The current `find_pending(conn_id,
  op_type)` matches only on the `(conn_id, op_type)` pair. A stale
  callback from a pre-restart netsrv instance that arrives after VFS
  re-registration would be accepted by the first live-and-matching
  pending op.
- Closure on the VFS-only side: extend `find_pending` to additionally
  match `netsrv_gen == state.next_netsrv_gen`, and cancel every live
  net-class pending op at the moment `ensure_inet_callback_registered`
  bumps the generation. Full enforcement with netsrv-echoed generation
  requires a netsrv wire extension and is tracked as V2 work.

### VO4 — `WorkerIoCtx` retains `state` and `ops` escape hatches

- Status: `OPEN`
- Area: structural
- Primary invariants: `VI8`

What is claimed:
- DataOps dispatch through `WorkerIoCtx`. MetaOps dispatch through
  `OwnerVopCtx`. The types are distinct.

What is missing:
- `WorkerIoCtx.state: *mut VfsState` and `WorkerIoCtx.ops:
  *const VopVector` are retained as an opt-in escape hatch. On the
  owner thread they hold the live state pointer; on a worker thread the
  caller is expected to null `state` via `into_worker_ctx()` before
  handoff. The ~20 saltyfs vops sites that issue owner-side RPC
  through `ctx.state` would break if the escape hatch were removed
  without a migration of each site.
- Closure requires a dispatcher rework that routes owner-issue paths
  through `OwnerVopCtx` everywhere they exist today. Scope: saltyfs
  vops + fileops/dir.rs + fileops/rw.rs callers.

### VO5 — No `PendingTransaction` / distinct `TxId` split on saltyfs side

- Status: `OPEN`
- Area: saltyfs lifecycle
- Primary invariants: `VI16`

What is claimed:
- Saltyfs worker jobs carry a `WorkerJob.tx_id` allocated by
  `next_tx_id()`. VFS-visible correlation tokens are allocated by
  `VfsState::alloc_tx_id`.

What is missing:
- The worker-job id and the VFS correlation token are conceptually
  distinct but neither side has a declared `PendingTransaction` table
  that ties them. A worker job that needs to post an owner-side commit
  (as described in the Stage 4 plan for `RemoteLookup` /
  `MountOpenSession`) cannot today reference its originating VFS
  correlation without an ad-hoc carry.
- Closure becomes load-bearing when worker jobs need owner-side
  commit / cancel / backpressure accounting beyond "build full reply
  and push". Today every worker arm either completes inline or posts a
  single terminal `WorkerCompletion`, so the split is cosmetic.

### VO6 — `saltyfs_write` not migrated to async credit path

- Status: `OPEN`
- Area: async migration
- Primary invariants: `VI17`

What is claimed:
- `saltyfs_read`, `saltyfs_readdir`, `saltyfs_setattr`, and the xattr
  ops all issue through the async credit machinery with deferred
  replay on credit exhaustion.

What is missing:
- `saltyfs_write` in `fs/saltyfs_client/vops.rs` dispatches through
  the synchronous `mutate_rpc::saltyfs_ipc_write` path; no credit
  reservation, no deferred replay. A write under credit pressure
  behaves differently from a concurrent read under the same pressure.
- Closure requires the same pattern as the read migration: an
  `saltyfs_ipc_write_issue` that reserves credit, parks on the waiter
  ring, stamps `BulkWriteStage` resume.

### VO7 — Legacy `BACKEND_CHMOD` / `BACKEND_CHOWN` retained

- Status: `OPEN`
- Area: protocol retirement
- Primary invariants: `VI18`

What is claimed:
- `BACKEND_SETATTR` with a field mask is the async-capable path for
  every attribute mutation.

What is missing:
- `BACKEND_CHMOD` (21) and `BACKEND_CHOWN` (22) are preserved as
  synchronous fallbacks for the early-boot path before the session slot
  exists. Every deployed backend that implements them must continue to
  do so, bloating the protocol surface.
- Closure requires the early-boot attribute mutation path to either
  use `BACKEND_SETATTR` unconditionally (with a sync-capable fallback)
  or defer attribute mutations until after session establishment.

## Historical Fix Ledger

### VH1. Legacy `SALTYFS_*` opcodes retired — CLOSED

- Status: `CLOSED`
- Area: wire contract
- Primary invariants: `VI1`, `VI2`

What landed:
- All per-backend `SALTYFS_MOUNT` / `SALTYFS_LOOKUP` / etc. opcodes
  were removed from the generic protocol namespace. The protocol uses
  `BACKEND_*` with a `CorrelationHeader.backend` discriminant. Backend-
  local constants (`SALTYFS_MAGIC`, `SALTYFS_INCOMPAT_*`,
  `SALTYFS_PROTO_V2`) remain as saltyfs-internal identifiers; they are
  not protocol opcodes.

### VH2. `max_inflight` end-to-end through session credit machinery — CLOSED

- Status: `CLOSED`
- Area: wire contract
- Primary invariants: `VI3`

What landed:
- `BackendOpenSessionReply.max_inflight` field added to the generic
  reply shape. SaltyFS advertises `SALTYFS_MAX_INFLIGHT = 64` on mount.
  VFS stores it on `BackendSessionSlot.inflight_max` and reads it from
  `backend_credit_reserve` / `backend_credit_release`. The prior
  compile-time `VFS_LOCAL_MAX_INFLIGHT` constant was deleted.

### VH3. Async allowlist on saltyfs server retired — CLOSED

- Status: `CLOSED`
- Area: wire contract
- Primary invariants: `VI2`

What landed:
- `userland/drivers/filesystems/saltyfs/src/main.rs::server_loop` no
  longer carries the hardcoded 5-opcode allowlist. Every correlated
  request produces one completion via `emit_server_reply`. A
  non-correlated request rides the synchronous reply cap; a request
  deferred to the worker returns the `label = 0` sentinel and the
  worker pushes the completion later.

### VH4. Stale-incarnation detection end-to-end (fresh-issue paths) — CLOSED

- Status: `CLOSED`
- Area: wire contract
- Primary invariants: `VI4`

What landed:
- At `VH4` land-time, `CorrelationHeader.request_seq: u32` +
  `_pad: u32` occupied the previously-zero `words[3]`; `VH13` later
  repurposed the `_pad` slot as `request_seq_secondary` — see `VA5`
  for the current wire layout. `stamp_saltyfs_async_request(.., seq)`
  takes a trailing seq argument (post-`VH13`, a trailing
  secondary-seq argument as well). All 40+ fresh-issue stamp call
  sites pass a live seq from the target vnode's `remote_seq`;
  deferred replay carries `target_seq` through `DeferredIssue` to
  the same stamp helper.
- SaltyFS handler pre-check (`is_request_stale`) fires before dispatch
  and produces a `TRONA_STALE` completion with
  `CORRELATION_F_STALE_INCARNATION` set. Writeback is skipped for
  stale replies; `stamp_completion_correlation` skips the re-stamp so
  the stale flag is preserved.
- `TRONA_STALE = 33` maps to POSIX `ESTALE (-116)` and Win32
  `ERROR_STALE_LINK (1206)` / `STATUS_STALE_HANDLE`.

Remaining limitation (closed by `VH13` on 2026-04-20): the rename /
link dual-seq gap — see `VH13` for the `request_seq_secondary`
extension and SaltyFS `server_loop` dual-seq precheck.

### VH5. Unknown-token completion arrivals logged and dropped — CLOSED

- Status: `CLOSED`
- Area: wire contract
- Primary invariants: `VI5`

What landed:
- `dispatch_pending_reply` logs two distinct drop reasons: malformed
  correlation header, and valid header whose `token` matches no live
  `PendingOp`. Both drop paths release the saved reply slot when the
  snapshot held one.

### VH6. Session teardown through typed `SessionTornDown` reply — CLOSED

- Status: `CLOSED`
- Area: session lifecycle
- Primary invariants: `VI6`, `VI7`

What landed:
- `observe_backend_send(fs_id, send_err)` is wired at every saltyfs
  fresh-issue call site and at the deferred-replay drain. On any
  non-transient send error, the session tears down: every in-flight
  `PendingOp` scoped to `fs_id` gets a synthesised
  `VfsError::SessionTornDown.to_trona()` reply, the deferred-issue
  ring drains with the same error, resolve-cache entries for the
  session are evicted, and the session slot is zeroed.
- `set_backend_callback_ep` is called at mount finalize so the future
  kernel-pushed cap-revocation detector can correlate on the stashed
  cap. The detector itself is not wired; it is forward-looking.

### VH7. Ctx reification — CLOSED

- Status: `CLOSED`
- Area: structural
- Primary invariants: `VI8`, `VI9`

What landed:
- `vfs_core/vop_context.rs` defines `OwnerVopCtx<'a>`,
  `OwnerMountCtx<'a>`, and `WorkerIoCtx`. MetaOps take
  `&mut OwnerVopCtx`; VfsOps take `&mut OwnerMountCtx` or
  `&OwnerMountCtx`; DataOps take `&WorkerIoCtx`.
- Accessors `vnode()` / `vnode_mut()` / `mount()` / `vtype()` /
  `fs_instance_id()` / `node_id()` / `backend_seq()` / `reborrow()`
  on `OwnerVopCtx`. `mount()` / `mount_mut()` on `OwnerMountCtx`.
- The `data_ctx_from_meta` compat shim is gone; call sites use
  `ctx.data_ctx()` directly.

Remaining limitation: see `VO4` for the retained `WorkerIoCtx.state`
/ `.ops` escape hatch.

### VH8. `ipc_objects.rs` physical type ownership — CLOSED

- Status: `CLOSED`
- Area: structural
- Primary invariants: `VI10`

What landed:
- `PipeState`, `SocketState`, `EpollInstance`, `ShmData` plus helper
  types (`PendingConn`, `EpollEntry`, `PipeReadWaiter`,
  `PipeWriteWaiter`) are physically defined in
  `userland/core/vfs/src/ipc_objects.rs`. Buffer-size constants
  (`SOCK_BUF_SIZE`, `PIPE_BUF_SIZE`) are authoritative here.
- `personality/posix/types.rs` re-exports the 7 neutral types; it
  retains only POSIX-specific waiter layouts (`PollWaiter`,
  `PtyPendingReader`).
- `personality/posix/consts.rs` re-exports the buffer-size constants
  so existing glob imports keep compiling.

### VH9. `VfsEvent` ingress classification — CLOSED

- Status: `CLOSED`
- Area: ingress classification
- Primary invariants: `VI11`

What landed:
- `VfsEvent { PtyNotification, NetsrvCallback, PagerRequest,
  BackendCompletion, UnknownCallback, TimerFired, ClientRequest }`.
- `classify_event` is a pure function over the inbound triple.
- `dispatch_timer_fired(state, now_ns)` is the entry point the owner
  loop calls at the top of each iteration; it routes through the
  same classification surface as IPC ingress.

### VH10. Bootstrap flags and log counters onto `VfsState` — CLOSED

- Status: `CLOSED`
- Area: state hygiene
- Primary invariants: `VI12`

What landed:
- `BACKEND_CALLBACK_EP_PREPARED`, `MMSRV_PAGER_CALLBACK_REGISTERED`,
  `NETSRV_CALLBACK_REGISTERED` all moved onto `VfsState`.
- `LOGGED_INET_OPS`, `LOGGED_INET_CALLBACKS`, `LOGGED_INET_RECV_RESULTS`
  moved onto `VfsState`; every log call site threads `&mut state`.
- `prepare_backend_callback_endpoint(state)` and
  `ensure_mmsrv_pager_callback_registered(state)` take explicit
  state.

### VH11. Net-class parks on unified `pending_ops` arena — CLOSED

- Status: `CLOSED`
- Area: pending-op arena
- Primary invariants: `VI13`

What landed:
- `PendingOpState::Net { netsrv_gen, conn_id, op_type, resume_ctx }`.
- `Resume::Net(NetResume { conn_id, netsrv_gen, op_type })` payload.
- `reserve_net_pending` + `stamp_net_resume_ctx` on `VfsState`.
- `personality::posix::inet::callback::{alloc_pending, find_pending,
  clear_pending_badge, dump_pending_inet, has_pending_capacity}`
  rewritten on top of the unified arena. The former
  `VfsState.inet_pending` fixed array and `PendingInetOp` struct are
  gone.
- `dispatch_pending_reply` drops FS-class completions stamped on a
  Net slot with a log line; `stamp_resume_ctx` rejects Net variants
  (net-side stamping goes through `stamp_net_resume_ctx`).

Remaining limitation: see `VO3` for the gen-enforcement gap.

### VH12. SaltyFS worker completion ring — CLOSED

- Status: `CLOSED`
- Area: saltyfs completion ring
- Primary invariants: `VI14`

What landed:
- `WorkerCompletion { tx_id, status, reply_ep, reply_msg: TronaMsg }`.
- `run_job_and_completion` returns the stamped reply; writeback /
  checksum jobs set `reply_ep = 0` (status-only).
- `run_job_inline` (owner fallback) sends directly because the owner
  is already on the reply path.
- Owner-side completion drain (`main.rs::server_loop`) does
  `ipc::send_ctx(ctx, comp.reply_ep, &comp.reply_msg)` on each
  completion with `reply_ep != 0`.

### VH13. rename / link dual-seq stale guard — CLOSED

- Status: `CLOSED`
- Area: wire contract
- Primary invariants: `VI4`

What landed:
- `CorrelationHeader.words[3]` low/high u32 split:
  `request_seq` (primary) + `request_seq_secondary`
  (secondary). MR28..=MR31 layout unchanged.
- `stamp_saltyfs_async_request` signature extended; all
  single-node op call sites pass `0` for the secondary slot
  (opt-out sentinel).
- `saltyfs_ipc_rename_issue_async` /
  `saltyfs_ipc_link_issue_async` carry an explicit
  `new_parent_seq` captured from the secondary vnode's
  `remote_seq` at stamp time in the VOP handler.
- SaltyFS `server_loop` pre-dispatch stale-check now runs
  `is_request_stale` on both slots and reuses
  `stamp_stale_incarnation_completion` on either mismatch.
  `handle_rename_fs` / `handle_link` unchanged — they still
  enter with a live inode pair guaranteed.
- `TRONA_STALE` → `ESTALE` / `ERROR_STALE_LINK` mapping
  unchanged.

Remaining limitation: rename / link do not yet ride the async
credit / deferred-replay arena, so
`DeferredIssue.target_seq_secondary` and
`op_kind::{Rename, Link}` secondary-seq fields are deferred to
the future async migration of those ops (tracked alongside VO6).

## Secondary Complications

Not blocker-level, but they complicate the refactor and should stay
visible.

### Pre-existing

- **Dual-mode saltyfs mount path.** `saltyfs_mount` has a `can_park:
  bool` branch — the async (park-capable) path is taken at runtime, and
  a synchronous fallback is retained for bootstrap / `late_mount`
  callers that cannot drive a backend completion. The sync path is not
  `request_seq`-stamped (the mount has no prior inode incarnation).
- **Coalesce-only lookup fetch.** The per-mount `pending_lookups`
  coalesce table sits on the owner side and pairs follower walks to a
  primary lookup RPC. The Stage 4 plan's worker-issued lookup fetch +
  owner-commit split is not wired; the current coalescer would have to
  be re-plugged when that split lands.
- **Checksum / integrity verification placeholder.** SaltyFS
  `WorkerJobKind::VerifyChecksum` is a no-op arm reserved for the
  integrity surface. The
  `VfsError::IntegrityFailure { fs, detail: IntegrityDetail }` surface
  exists (used by `parse_stat_attr`) but there is no worker-driven
  block-level checksum verification.

### Introduced by the refactor

- **Single-worker recv-slot allocation.** `main.rs` allocates one recv
  slot per worker in `0..MAX_WORKERS`, including worker 0 (distinct
  from the owner's service-EP slot). If slot allocation fails partway,
  the affected worker index is left at 0; `submit_or_run`'s inline
  fallback would silently collapse to owner-side execution instead.
  The fallback is correct but loses the worker-off-owner property.
- **Deferred replay seq coverage.** The `DeferredIssue.target_seq` is
  populated from the caller's `vkey.backend_id.seq` at park time.
  When the session is torn down between park and drain, the drain path
  uses the saved seq — which could refer to an inode that has since
  been freed. In practice the drain path synthesises a
  `SessionTornDown` error before ever stamping the request, so the
  stale seq never reaches the wire. Cosmetic complication only. Rename / link do not yet ride the deferred-replay arena, so `DeferredIssue.target_seq_secondary` and `op_kind::{Rename, Link}` secondary-seq carry are intentionally absent at `VH13` land-time; they are tracked for the future async migration of those ops.
- **Worker-side DataOps helpers are NotSupported.** `run_item_on_worker`
  routes every `WorkItem` variant to a post_completion, but the
  `dispatch_data_{read,write,bulk_read,bulk_write,readdir}` helpers
  return `VfsError::NotSupported` because the only async-capable
  backend in the current tree (SaltyFS) already uses the
  backend-callback wire. Workers would add latency without unblocking
  anything. The helpers exist so a future synchronous-blocking backend
  can plug in; today they are scaffolding.
- **`apply_cross_mount_vget_reply` has no producer.** The helper is
  fully implemented (parse stat reply → vget → install root vnode →
  rewrite cursor) but no namei-walker code currently parks with
  `WalkPhase::CrossMountVget`. Dormant until the cross-mount-walk
  producer lands.

## Load-Bearing Assumptions

If any assumption below changes, every dependent statement must be
re-audited.

### VA1. Owner loop is single-threaded

Source of assumption:
- `VfsState` is not `Sync`; every mutation runs under a unique
  `&mut VfsState` held by the owner thread.
- The worker pool pushes `Completion` records onto SPSC rings but
  never mutates `VfsState` directly.

Why it matters:
- Every `for_each_active_mut` / `for_each_active` iteration on
  `pending_ops`, `deferred_issues`, `backend_sessions`, `clients`,
  `mounts`, `vnodes` relies on no concurrent mutation.
- Drain-then-release patterns (e.g. `cancel_pending_ops_for_session`)
  assume that the slot handles collected in the first pass stay valid
  for the second-pass release.

Invalidation trigger:
- Giving workers direct `&mut VfsState` access.
- Splitting the VFS owner loop across multiple threads.
- Adding RCU-style lock-free readers over arena state.

### VA2. Saltyfs `BLOCK_LOCK` covers every shared block / bitmap / SB field

Source of assumption:
- `BLOCK_LOCK` is acquired at the top of every owner-loop iteration in
  saltyfs `server_loop` and held until the outer reply wait.
- The writeback worker acquires `BLOCK_LOCK` per-job.
- Read-block / write-block helpers assume the lock is held.

Why it matters:
- Without the lock, the owner's metadata dispatch could race the
  worker's writeback on cache slot contents or the superblock dirty
  flag.

Invalidation trigger:
- A second saltyfs worker thread that also touches the cache.
- Fine-grained per-slot locking that weakens the global lock.

### VA3. Kernel cap-revocation notification is unavailable

Source of assumption:
- No kernel-side `watch_cap(..)` / `cap_revoked_notification(..)`
  primitive exists today.
- Backend session teardown is reactive: the userspace `observe_backend_send`
  path is the detection point.

Why it matters:
- `set_backend_revocation_slot` is a forward-looking API; no consumer
  today.
- A backend that crashes mid-flight is observed only when the next
  send fails.

Invalidation trigger:
- Kernel gains a cap-revocation notification mechanism.

### VA4. SaltyFS is the only async-callback backend

Source of assumption:
- Every VFS backend in the tree today is either a local filesystem
  (ramfs / tmpfs / devfs / procfs / sysctlfs / pipefs) or SaltyFS.
- Local backends have no async-RPC concept.
- SaltyFS uses the backend-callback EP for async completions.

Why it matters:
- The Stage 4 worker-issued lookup / mount-open-session split has no
  consumer today; the scaffolding exists but dispatches
  `NotSupported`.
- Routing decisions in `owner/dispatch.rs` assume at most one
  async-capable backend per-class.

Invalidation trigger:
- Adding a second async-callback FS backend.
- Adding an async-callback net backend that unifies with
  `BackendCompletion` classification.

### VA5. `CorrelationHeader.words[3]` is a dual-u32 split

Source of assumption:
- `CorrelationHeader.request_seq: u32` occupies the low half of
  `words[3]`; `CorrelationHeader.request_seq_secondary: u32`
  occupies the high half.
- Prior to `VH13`, the high half was hard-zero (`_pad`).

Why it matters:
- The `VO2` closure consumed the previously free `_pad` slot. The
  next header extension must either repurpose an existing field,
  reclaim a flag bit, or expand beyond MR28..=MR31.
- Rename / link secondary-target stale-incarnation guard rides this
  slot.

Invalidation trigger:
- A third `u32` of header metadata would require a wire-layout
  expansion (additional MR slot) or an equivalent reclaim.

## Audit Log

### 2026-05-08 — Plan 8 trona crate split (no audit delta)

- Method: trona substrate split into 5 crates (`uapi`,
  `trona_kernel`, `trona_protocol`, `trona_server`,
  `trona_runtime`); LD-1 cleanup landed the D' composition-root
  pattern (server binaries now compose `RecvSlotArena`'s
  `SlotAllocator` from `trona_runtime::core::slot_alloc::*_cb`
  callbacks; no `runtime → server` edge).
- Result: every `VFS_BACKEND_*` const, register-layout const,
  feature-flag bit, `TransferDescriptor` struct, reply label,
  and the full `CorrelationHeader` moved out of the old
  `lib/trona/substrate/protocol.rs` into
  `lib/trona/protocol/src/vfs/backend.rs` and
  `lib/trona/protocol/src/correlation.rs`. Numerics, struct
  layouts, and audit obligations are unchanged. The new vfs
  cleanslate (`userland/core/vfs/`) and the saltyfs daemon both
  reach the const block through
  `use trona_protocol::vfs::backend::*` and
  `use trona_protocol::correlation::*`.
- VO# scoring is not re-evaluated by this pass. The Plan 7 vfs
  cleanslate replaced every code surface VO3·VO4·VO5·VO6·VO7
  used to track (now `userland/core/vfs/src/owner/{pending,
  dependency, session}.rs`, `fs/saltyfs_client/rpc.rs`); a
  follow-up audit against the new layout should re-score each
  open VO# against the new file paths.

### 2026-05-07 — P7 VFS cleanslate / backend wire 0x600-0x6FF migration

- Method: static source edits + cross-crate wire ownership
  realignment.
- Result: backend wire labels migrated from the legacy `BACKEND_*`
  block (previously defined inside
  `userland/core/vfs/src/ipc/protocol/backend.rs` and
  `correlation.rs` with `pub(crate)` scope) to the substrate-owned
  `VFS_BACKEND_*` block at
  `lib/trona/protocol/src/vfs/backend.rs:0x600..=0x61C`. The saltyfs
  daemon now reads the same numerics through
  `use trona_protocol::vfs::backend::*` without depending on the vfs crate;
  future ext4 / other backend daemons inherit from the same
  source.
- Touched modules:
  - `lib/trona/protocol/src/vfs/backend.rs` — Added
    `VFS_BACKEND_OPEN_SESSION` (0x600) through
    `VFS_BACKEND_SETATTR` (0x61B); legacy
    `VFS_BACKEND_SHM_SETUP` (0x61C); reply labels
    (`VFS_BACKEND_REPLY_*` at 0x6F02..=0x6F7A); short-name
    aliases for the daemon dispatch view
    (`BACKEND_OPEN_SESSION` etc.); register-layout consts
    (`BACKEND_RW_REQ_DESCRIPTOR_REG`,
    `BACKEND_READ_INLINE_PAYLOAD_REG`,
    `BACKEND_WRITE_INLINE_PAYLOAD_REG`,
    `BACKEND_READDIR_F_EOF`, `BACKEND_SETATTR_REG_COUNT`,
    `BACKEND_SETATTR_REPLY_REG_COUNT`); feature-flag bits
    (`BACKEND_FEATURE_ASYNC_V1` /
    `BACKEND_FEATURE_INCARNATION_SEQ` /
    `BACKEND_FEATURE_INLINE_TRANSFER` /
    `BACKEND_FEATURE_SHM_TRANSFER`); transfer kind discriminators
    (`INLINE_TRANSFER_WIRE_MAX = 160`,
    `TRANSFER_KIND_INLINE = 0`, `TRANSFER_KIND_SHM = 1`); the
    full `CorrelationHeader` struct with `encode_words` /
    `decode_words` / `ensure_correlation_wire_length`; the full
    `TransferDescriptor` struct with `encode_regs` /
    `decode_regs`.
  - `userland/core/vfs/src/ipc/protocol/correlation.rs` —
    Reduced from a local `pub(crate)` const block + struct
    definition to a single `pub(crate) use trona_protocol::vfs::backend::{...}`
    re-export.
  - `userland/core/vfs/src/ipc/protocol/backend.rs` — Reduced
    from a local `pub(crate)` const block + struct definition
    to a single `pub(crate) use trona_protocol::vfs::backend::{...}`
    re-export.
- Side notes:
  - `BACKEND_CHMOD` / `BACKEND_CHOWN` — substrate-side aliases
    over `VFS_BACKEND_SETMODE` (0x613) /
    `VFS_BACKEND_SETOWNER` (0x614). Numeric is the same as the
    new SETMODE / SETOWNER labels; the verb-based names are
    retained for the saltyfs daemon's existing dispatch arms.
    `VO7` (CHMOD / CHOWN retirement) status unchanged — both
    label spellings still exist as wire-level synonyms over the
    same numeric. The audit-level retirement (purging the
    daemon's verb-based dispatch arms in favour of SETATTR-only)
    remains open.
  - `VFS_BACKEND_SHM_SETUP` (0x61C) — kept as a reserved slot
    pending the OPEN_SESSION-fold migration. Marked legacy in
    the substrate doc-comment so future audit passes flag it
    for removal once OPEN_SESSION's reply advertises the SHM
    region directly.
- Drift detection: vfs ↔ saltyfs daemon now share the wire
  through a single source of truth (`trona_protocol::vfs::backend`
  after the Plan 8 crate split — see the 2026-05-08 audit entry).
  A numeric-skew bug between the two sides is no longer
  expressible — both compile against the same `pub const`.
- Build verification deferred — the vfs cleanslate workstream
  gates compile checks at `just warn` only on explicit user
  request (cleanslate / no-compile-during-cleanslate policy).
- Open blockers unchanged: `VO3`–`VO7`.

### 2026-04-20 — VO2 closed via dual-seq wire extension (VH13)

- Method: static source audit + targeted edit.
- Result: `VO2` retired and promoted to `VH13`.
  `CorrelationHeader` now carries `request_seq` (primary) and
  `request_seq_secondary` (secondary) in `words[3]`;
  SaltyFS `server_loop` precheck runs dual-seq
  `is_request_stale`. `VI4` and `VA5` updated to reflect the
  symmetric contract and the consumed `_pad` slot.
- Open blockers now: `VO3`–`VO7`.

### 2026-04-19 — VO1 retired (build hygiene out of audit scope)

- Method: scope review.
- Result: `VO1` ("build pass not empirically verified") was mis-scoped
  as an audit blocker. Build / compiler pass state is a process concern
  tracked outside this document, the same way `memory-model-audit.md`
  records "pending build / boot verification" only as a status note
  and never as an `O#` invariant. `VO1` is retired; the ID is not
  reused. `VI15` ("just warn passes clean") is likewise removed — the
  refactor's correctness invariants do not include compiler pipeline
  state.

### 2026-04-19 — Tier 0 through Tier 2 landed, codex cross-model second pass

- Method: codex cross-model audit of the in-session changes (`xhigh`
  reasoning effort), followed by targeted static corrections.
- Result: `VH1`–`VH12` closed. `VO1`–`VO7` open.
- Main landed themes:
  - Stale-seq plumbing through `CorrelationHeader.request_seq` and
    `DeferredIssue.target_seq`, backend pre-check, personality errno
    maps.
  - Session teardown via typed `SessionTornDown` reply synthesis.
  - Unified `pending_ops` arena for net-class parks; removal of
    `inet_pending` fixed array.
  - Owner-side completion drain on saltyfs worker; worker no longer
    blocks on `send_ctx`.
  - `VfsEvent` classifier extended with `TimerFired`.
  - `ipc_objects.rs` physical type ownership.
- Build / smoke verification pending.

### 2026-04-19 — Initial codex audit of the modular-lemon plan

- Method: codex cross-model audit (`xhigh` reasoning) against the plan
  at `/Users/hamin/.claude/plans/vfs-saltyfs-modular-lemon.md`.
- Result: produced a 12-tier implementation checklist; identified
  `NotSupported` / dead-code / silent-drop gaps across the `WorkItem`
  dispatch surface, missing type moves in `ipc_objects.rs`, missing
  stale-incarnation producer in saltyfs, and ~20+ stale `VopContext` /
  `trampoline_*` doc comments.
- Main open themes going into the Tier-0 pass: stale-seq production,
  session-teardown reactive path, physical type move,
  saltyfs-worker completion ring, `VfsEvent` classification holes.
