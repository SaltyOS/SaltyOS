# VFS

The VFS server brokers every filesystem RPC for every userspace
process. Clients reach it through `caps::vfs_ep()` (a lazy
namesrv lookup); backends (saltyfs / netsrv / posix_ttysrv /
blkdrv / dispdrv) talk to it through their own per-mount-instance
backend session.

## Topology

* **Frontend.** Single master service-EP MP_CORE. namesrv mints
  a copy of the send side per client with `BADGE_AS_CALLER` so
  every inbound record carries the client's `client_id` in the
  badge's lower 32 bit. The owner reactor's cookie kind for
  this source is `0`.
* **Backend.** Per-mount-instance MP_CORE pair. vfs holds the
  send-side and a callback recv-side; the callback recv-side is
  Watched on the owner EQ with cookie kind `1`. Each mount
  carries a separate `BackendSessionSlot` so a single saltyfs
  daemon serving two mount points has two independent sessions
  (independent `live_gen`, independent SHM ring, independent
  fsync ordering domain).
* **Pager.** Single MP_CORE pair owned by vfs's pager handler.
  vfs registers the send-side with mmsrv via
  `MM_REGISTER_VFS_PAGER` at boot; mmsrv calls the matching
  recv-side back when a file-backed page fault needs vfs to fill
  the page. Cookie kind `2`.
* **Timer.** Owner-private timer cap on the same EQ for page-
  cache writeback, poll expiry, and the reclaim sweep. Cookie
  kind `3`.

The owner thread is the single `VfsState` mutator. Workers are
short-lived assistants that drive blocking `BACKEND_*` RPCs;
they receive raw pointers (`Arena::raw_ptr` guarded by
`flight_count`) and never touch the arena directly.

## Wire labels

Four blocks under `lib/trona/substrate/protocol.rs`:

* `0x500..=0x5DF` — public client-facing labels (`VFS_OPEN`,
  `VFS_READ`, ..., `VFS_REGISTER_BULK_SHM`).
* `0x5E0..=0x5EF` — admin tier (per-client control capabilities),
  driven only by init.
* `0x600..=0x6FF` — backend RPCs vfs initiates (`BACKEND_LOOKUP`,
  `BACKEND_READ`, ..., `BACKEND_FSYNC`).
* `0x700..=0x7FF` — pager callback (`PAGER_READ`,
  `PAGER_WRITEBACK`, `PAGER_INVALIDATE`, `PAGER_RELEASE`,
  `PAGER_REGISTER`).

Each public label has a matching reply label in the
`0x5F00..=0x5FFF` error block (see `vfs_error_to_public_reply`).

### Admin tier (per-client control capabilities)

init owns every VFS client's lifecycle. Authority and target identity
ride on a control cap's badge (`TAG(0xC) | ROOT | epoch(43b) |
slot(16b)`, encoded by `trona_protocol::control`); the fork FD-table
clone and the exec `FD_CLOEXEC` sweep are init-driven admin verbs,
never reachable on the public client endpoint.

| Label | Hex | Authority | Notes |
|---|---|---|---|
| `VFS_BIND_CLIENT_SELF` | 0x5E0 | client (own badge) | A spawned process binds its request MP, adopting the `ClientState` init pre-created for its `client_id` |
| `VFS_DEREGISTER_CLIENT` | 0x5E1 | per-client cap (`MP_WRITE`) | Tear-down; the badge names the client |
| `VFS_ADMIN_REGISTER_CLIENT` | 0x5E2 | ROOT control cap | Pre-creates the client, mints + returns the per-client control cap |
| `VFS_ADMIN_CLONE_FDS` | 0x5E3 | per-client cap (two-step) | Clone the parent FD table into the child; child pinned via `VFS_ADMIN_CLONE_SET_PARTNER` |
| `VFS_ADMIN_CLONE_SET_PARTNER` | 0x5E4 | per-client cap (step 1) | Records the child as the pending clone partner under a nonce |
| `VFS_ADMIN_EXEC_SWEEP` | 0x5E5 | per-client cap | Drop the client's `FD_CLOEXEC` descriptors after the exec point of no return |

**Bind adoption.** init pre-registers each VFS client at spawn
(`VFS_ADMIN_REGISTER_CLIENT`) and holds the returned control cap. The
process later binds with `VFS_BIND_CLIENT_SELF`: vfs adopts the matching
pre-created `ClientState` (keyed by `client_id`) and attaches the
process's request MP. A process init did not pre-register (e.g. one that
booted before vfs and so declares no `vfs:process-client` interface)
falls back to creating a fresh client on bind. The client-facing
`VFS_CLONE_FDS` / `VFS_CLIENT_EXEC` labels — which an unprivileged client
could once invoke against another process — are removed.

## PendingOp invariants

Every async backend RPC reserves a `PendingOp` slot that records
the 5-tuple `(tx_id, client_id, reply_mp_recv,
backend_session_gen, vnode_stable_key)`. The completion router
validates all five before resuming the caller:

* `tx_id` matches the correlation header echoed back by the
  backend.
* `client_id` matches the cookie that resumed the dispatch
  loop.
* `reply_mp_recv` is the message-pipe receive side captured at op
  reservation time; completions reply through that endpoint and stale
  endpoints are rejected by the generation checks below.
* `backend_session_gen` matches the session slot's current
  `live_gen` (mismatch ⇒ stale incarnation, silent drop).
* `vnode_stable_key` matches the vnode the op was issued
  against; stale completions arriving after vnode reclaim are
  dropped.

The reply slot itself is consumed exactly once via
`send_saved_reply` (success / typed error to caller),
`drop_saved_reply` (kernel-finaliser cancel — caller sees a
kernel-side error), or `cancel_for_badge` (peer disappeared).

## Dependency graph

`PendingOp` carries a `predecessors` array plus a barrier
counter. Two edge kinds:

* `PRED_TX` — strict happens-after. Used for saltyfs RENAME's
  dual-locking sequence, link chains, and the MAP_SHARED
  writeback → fsync chain.
* `PRED_BARRIER` — N predecessors must all complete before the
  successor unblocks. Fsync gathers every in-flight WRITE plus
  every outstanding writeback against its target vnode as
  predecessors.

`first_error` propagates through the graph: when a predecessor
completes with an error, the successor records that error in
its `aggregate_error` slot, and on unblock the successor either
issues its backend RPC (no error) or fails immediately with the
predecessor's error (so a fsync that depends on a failed write
returns the write's error to the client).

## Backend session teardown

Four-step ordering — invariant for every backend session:

1. Advance the session's `live_gen` so future PendingOp issues
   on this slot abort.
2. `watch_cancel(callback_watch)` and `watch_cancel(pager_watch)`
   — kernel purges stale records from the owner EQ ring.
3. Cancel every PendingOp tagged with this session's slot
   index; the saved reply endpoints become drop-only.
4. Release the callback caps the backend held (cap_count =
   send + recv + pager_callback).

The order is fixed: step 1 must precede step 2 (no in-flight
publish after the gen advance), and step 3 must precede step 4
(reply endpoints still need a live cap until canceled).

## Page cache

`PageCacheEntry` slots in `state.page_cache` track every
file-backed page mmsrv currently shares with a client process.
Each entry records the source `(vnode, page_offset)` plus the
frame mmsrv loaned vfs and the `Clean / Dirty / Writeback`
state. mmsrv drives `PAGER_READ` on miss, `PAGER_WRITEBACK` on
dirty-page eviction, and `PAGER_INVALIDATE` on file truncation;
vfs replies with the requested frame (or completes the
writeback) and updates the cache entry's state.

Eviction is LRU. The owner reactor's idle tick walks the LRU
list tail-first and reclaims clean entries; dirty entries
trigger a `PAGER_WRITEBACK` round-trip and stay on the list
until the writeback completes. fsync's `PRED_BARRIER` collects
every outstanding writeback for its target vnode so the reply
is held until durability is observed.

## fd table

Each `ClientState` carries a [`SegmentedSlotTable<OpenObject>`].
Three parallel anon-mapped arrays per segment: handle, free-list
next pointer, and a personality-neutral flag byte.

The flag byte has no built-in meaning. POSIX interprets bit 0 as
`FD_CLOEXEC` (drives the cloexec sweep at exec time);
Win32 (and any future personality) is free to assign its own
meaning. The two personalities never coexist in the same
process so the bits do not collide.

Storage scales by segment doubling — no fixed cap on fds per
client and no fixed cap on segment count. Each new segment
doubles the previous one's size; allocation eventually fails on
mmap ENOMEM rather than on a declared ceiling.

## Personality split

Each `ClientState` carries a `Personality` discriminator. Two
values today:

- `Personality::Posix` — POSIX wire (S_IF\* mode, dirent layout,
  sigset, sockaddr_\*, AT_\* openat flags, case-sensitive UTF-8
  names, symlink hop limit 40).
- `Personality::Win32` — Win32 NT wire (FILE_ATTRIBUTE_\*,
  ACCESS_MASK / GENERIC_\*, drive letters, `\\?\`-prefixed
  extended-length paths, UNC `\\server\share`, DOS reserved
  names, case-insensitive name lookup with case preservation).

`Personality::DEFAULT = Posix`. The vnode core stays
personality-neutral so the same node is observable from either
personality.

### Label-range routing

The 0x500..=0x5FF VFS_PUBLIC block is partitioned along
personality lines:

| label range     | personality | dispatch entry           |
|-----------------|-------------|--------------------------|
| 0x500..=0x53F   | Posix       | `personality::posix`     |
| 0x540..=0x57F   | Win32       | `personality::win32`     |
| 0x580..=0x5BF   | (any)       | neutral fileops handler  |
| 0x5C0..=0x5FF   | reserved    | `NotSup`                 |

A request whose label range and the client's `Personality`
disagree returns `NotSup` — a Win32 process cannot smuggle a
POSIX wire shape through a Win32 slot, and vice versa. The
neutral window (0x580..=0x5BF) carries the labels the two
personalities share without translation (close / dup /
fork-clone of fd-table state); both personalities reach those
through the same `fileops::*::handle` entry.

### Personality stamping path

`ensure_client(badge, client_id)` allocates the slot at
`Personality::DEFAULT`. The first observed RPC's label range
selects the actual personality:

- 0x500..=0x53F first contact — slot stays at `Posix` (default
  unchanged; no stamp churn for the common case).
- 0x540..=0x57F first contact — slot flips to `Win32`. Any
  subsequent POSIX-range label from the same client lands in
  the `NotSup` mismatch arm.

The first-contact rule means an explicit register-personality
RPC is not required for either personality; the wire range
itself is the source of truth. A future
`VFS_REGISTER_CLIENT_PERSONALITY` RPC may be added if a client
needs to assert personality before its first I/O (e.g. to
control the namei case-folding mode), but the present model
covers every observed wire path.

### Bit-position alignment

The fd-table's per-slot flag byte (see "fd table" above) is
deliberately personality-neutral. POSIX `FD_CLOEXEC = 0x01` and
Win32 `HANDLE_FLAG_INHERIT = 0x01` claim the same bit position
with inverted polarity:

- POSIX: bit set → exec closes; bit clear → exec inherits.
- Win32: bit clear → child inherits; bit set → child does not
  inherit.

Same on-disk bit, opposite ABI semantics. A handle inherited
across the multi-personality fork path (once that lands) sees
the matching ABI semantics with no translation — the underlying
byte never changes; only the projecting personality reinterprets it.

### Module map

| Module                              | Owns                        |
|-------------------------------------|-----------------------------|
| `personality::Personality`          | Discriminator enum, default |
| `personality::posix::consts`        | O_\* / S_IF\* / AT_\* / SEEK_\* / MAP_\* / PROT_\* / MS_\* / SCM_\* / MSG_\*, `POSIX_FD_CLOEXEC` |
| `personality::posix::types`         | `Stat`, `Statvfs`, `Dirent`, `PollFd`, `EpollEvent`, `Sigset`, `Sockaddr*`, `IoVec`, `MsgHdr`, `CmsgHdr` |
| `personality::posix::file`          | `mode_t`, umask, `posix_perm_check`, sticky-bit / SGID inheritance, SUID strip on write |
| `personality::posix::poll`          | `POLL*` / `EPOLL*` masks, `EPOLL_CTL_*`, `EPOLL_CLOEXEC`, `project_pollmask` |
| `personality::posix::signals`       | `SIG*`, `SA_*`, `SigAction`, `FaultKind → Signo`, `default_action` |
| `personality::posix::namei`         | POSIX path policy: absolute / `..` / AT_FDCWD / symlink hop cap, `WalkPolicy::from_at` |
| `personality::posix::inet`          | sockaddr decode/encode, `cmsg_*` walk, SCM_RIGHTS / SCM_CREDENTIALS classifiers |
| `personality::posix::dispatch`      | 0x500..=0x53F label fan-out → fileops |
| `personality::win32::consts`        | GENERIC_\* / FILE_SHARE_\* / FILE_ATTRIBUTE_\* / STATUS_\*, `WIN32_HANDLE_FLAG_INHERIT` |
| `personality::win32::types`         | `LargeInteger`, `UnicodeString`, `ObjectAttributes`, `IoStatusBlock`, `FileBasicInformation`, `FileStandardInformation`, `SecurityAttributes` |
| `personality::win32::namei`         | Win32 path classification: drive letter / `\\?\` / UNC / DOS reserved |
| `personality::win32::drives`        | A:..=Z: drive table, current-drive selector |
| `personality::win32::dispatch`      | 0x540..=0x57F label fan-out (skeleton; per-handler wiring lands as PE callers reach vfs) |
