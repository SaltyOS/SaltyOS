# SaltyFS Backend Wire — Hybrid-1 Transfer + Multi-Session

This document is the canonical specification of the wire between the
VFS owner reactor (frontend) and the saltyfs daemon (backend) for
bulk data transfer (BACKEND_READ / BACKEND_WRITE / BACKEND_READDIR
/ xattr round-trips) and per-mount-instance session management. It
supersedes the prior single-session SHM-region scheme.

The on-disk format and every metadata RPC stay unchanged. This
specification covers only the data-plane transport and the session
lifecycle that fronts it.

## 1. TransferDescriptor (4-register)

`trona_protocol::vfs::backend::TransferDescriptor` rides at
`regs[BACKEND_RW_REQ_DESCRIPTOR_REG..+TransferDescriptor::REG_COUNT]`
(= regs[4..8]) on every BACKEND_READ / BACKEND_WRITE request.

| Reg slot | Field      | Meaning                                                                |
|----------|------------|------------------------------------------------------------------------|
| 4        | `kind`     | `TRANSFER_KIND_INLINE=0` / `TRANSFER_KIND_SHM=1` / `TRANSFER_KIND_MO=2` |
| 5        | `flags`    | Reserved — must be zero. Non-zero is rejected by the daemon.           |
| 6        | `offset`   | For `SHM`, byte offset into the per-session SHM ring. Zero otherwise.  |
| 7        | `length`   | Payload length in bytes.                                               |

`TransferDescriptor::encode_regs()` packs all four words; senders
that fail to pack `desc[2]` / `desc[3]` produce a malformed request
and the daemon decodes a zero-byte payload window.

## 2. Hybrid-1 Size Threshold

Frontend issuers select `kind` by payload size:

| Payload `length`     | Wire `kind`             | Carrier                                       |
|----------------------|-------------------------|-----------------------------------------------|
| `0 < len ≤ 160 B`    | `TRANSFER_KIND_INLINE`  | regs[8..28] (20 register slots × 8 bytes)     |
| `161 B ≤ len ≤ 4 KiB`| `TRANSFER_KIND_SHM`     | per-session SHM ring sub-region (one slot)    |
| `len > 4 KiB`        | `TRANSFER_KIND_MO`      | per-RPC anonymous MemoryObject as `caps[0]`   |

`INLINE_TRANSFER_WIRE_MAX = 160` matches the available inline window
(reg slot 8 through reg slot 27, leaving regs 28-31 for the
correlation header).

When the SHM ring is saturated and `len ≤ 4 KiB`, the frontend
falls through to `TRANSFER_KIND_MO`. There is no daemon-side
backpressure signal — the size-class selection is final at send
time.

## 3. Per-session SHM ring

Each `BackendSessionSlot` owns a 64 KiB SHM region carved out of the
`VFS_SHM_VADDR + slot_idx × SALTYFS_SHM_REGION_BYTES` window. The
region is partitioned as 16 × 4 KiB sub-region slots:

| Constant                       | Value         | Source                                              |
|--------------------------------|---------------|-----------------------------------------------------|
| `SALTYFS_SHM_REGION_BYTES`     | 64 KiB        | `saltyfs/src/consts.rs`                             |
| `SALTYFS_RING_SLOT_BYTES`      | 4 KiB         | `vfs/src/fs/saltyfs_client/types.rs`                |
| `SALTYFS_RING_SLOT_COUNT`      | 16            | `vfs/src/fs/saltyfs_client/types.rs`                |

Frontend ring management lives on `SaltyfsMountData`:

* `ring_bitmap: u16` — bit `i` is set iff sub-region `i` is leased
  to an in-flight `BACKEND_WRITE`.
* `ring_cursor: u8` — search hint for the next allocation. Allocation
  cycles forward from the cursor and rolls modulo
  `SALTYFS_RING_SLOT_COUNT` so back-to-back writes do not stall on
  the same slot.

`MountData::ring_alloc()` returns the slot index on success; the
issuer copies the source bytes into
`shm_vaddr + slot_idx × SALTYFS_RING_SLOT_BYTES` before issuing the
request. On reply the completion router calls
`MountData::ring_free(slot_idx)` — the slot index is recoverable
from `transfer.offset / SALTYFS_RING_SLOT_BYTES`.

Daemon-side bounds checks consult `SessionSlot::shm_bytes` (the
per-session region size advertised on `BACKEND_OPEN_SESSION`). The
legacy `VFS_SHM_PAGES = 256` constant described a single 1 MB
window and is no longer load-bearing.

## 4. MO Transfer ABI (`TRANSFER_KIND_MO`)

`MM_MO_CREATE = 0x415` (mmsrv self-tier label) — caller asks mmsrv
to retype an anonymous MO out of its frame pool. Wire:

```
request:  regs[0] = length (page-aligned by mmsrv)
          regs[1] = flags (reserved, must be zero)
reply:    label   = TRONA_OK
          caps[0] = mo_cap   (caller-owned)
```

mmsrv stamps the caller's `client_idx` as the MO owner so the MO is
reclaimed when the client exits. The MO is `length` bytes rounded
up to page granularity.

VFS frontend write path (`vfs/src/fs/saltyfs_client/vops.rs::retype_mo_for_write`):

1. `MM_MO_CREATE(length, 0)` → `mo_cap`.
2. `MM_MMAP(kind=MO, hint=0 (auto), size=aligned, prot=R+W, flags=0,
   mo_offset=0; caps[0]=mo_cap)` → `mapped_va`.
3. `memcpy(src → mapped_va, length)`.
4. `MM_MUNMAP(mapped_va, aligned)` — frontend's mapping is done.
5. Cap survives in the frontend's CSpace; `saltyfs_ipc_write_issue`
   stages it into `caps[0]` for the BACKEND_WRITE send and drops it
   inline post-send (`cnode_delete` + `slot_free`). The kernel
   `cnode_copy`'d the cap into the daemon's receive slot at send
   time, so the sender's slot is redundant on success.

Daemon side (`saltyfs/src/worker.rs::WritePayload::Mo`):

1. `capture_transferred_cap` lifts the inbound cap off the receive
   slot arena (main.rs BACKEND_WRITE arm).
2. Worker validates `cap != 0 && len ≤ MO_STAGING_SIZE` (1 MiB).
3. `MM_MMAP(kind=MO, hint=MO_STAGING_VADDR, size=aligned_len,
   prot=R, flags=FIXED, mo_offset=0; caps[0]=cap)` — daemon-private
   staging window. mmsrv `cnode_move`s the cap into its stable slot.
4. `execute_write_locked` reads through the staging window.
5. Cache + superblock flush — commit boundary for the direct reply.
6. `MM_MUNMAP(MO_STAGING_VADDR, aligned_len)`.
7. `cnode_delete` on the now-empty source slot (no-op, kept as a
   belt-and-braces release).

The single staging window is safe because `BLOCK_LOCK` serialises
WriteBlocks job execution.

## 5. BACKEND_OPEN_SESSION + Per-mount-instance Session Slot

`saltyfs/src/session.rs` carries the daemon-side session table:

```
SALTYFS_SESSION_SLOTS = 64
SessionState ::= Empty | Live | Closing
SessionSlot {
    state, session_id, live_gen,
    callback_ep, callback_watch, callback_cookie,
    shm_id, shm_region_mo, shm_vaddr, shm_bytes,
    max_inflight,
}
```

Lookup helpers — `find_live_by_id`, `alloc_slot`, `current_live`,
`slot_shm_vaddr(idx) = VFS_SHM_VADDR + idx × SALTYFS_SHM_REGION_BYTES`,
`live_shm_region_for_msg(msg)`, `slot_idx_for_msg(msg)`. Inbound
correlated requests carry the 32-bit `session` field in the
correlation header; the daemon resolves it to a slot via
`find_live_by_id`.

`BACKEND_OPEN_SESSION` reply (regs):

| Reg | Field                      |
|-----|----------------------------|
| 0   | `session_id`               |
| 1   | `root_node` (BackendNodeId) |
| 2   | `feature_bits`             |
| 3   | `root_ino`                 |
| 4   | `max_inflight`             |
| 5   | `SALTYFS_SHM_REGION_BYTES` (per-session SHM size hint) |

The reply also carries the daemon's `callback_ep` cap as `caps[0]`
so the frontend can send completions back to the right slot.

## 6. Close-session 4-step Teardown

When the frontend issues `BACKEND_CLOSE_SESSION`, the daemon:

1. `slot.state = Closing`.
2. `slot.live_gen += 2` — even-bump invalidates queued work.
3. `WATCH_CANCEL` on `callback_watch` (if armed).
4. Drop `BLOCK_LOCK`, `drain_pending()` — wait for in-flight + queued
   jobs to exit. Queued WriteBlocks jobs detect the gen bump under
   `BLOCK_LOCK` and self-suppress (no completion sent).
5. Reacquire `BLOCK_LOCK`, `MM_SHM_DESTROY` the SHM region (id-based
   destruction, not cap drop), `cnode_delete` on `callback_ep`,
   `SessionSlot::empty()`.

Pager-attached MOs are torn down by the kernel via `cancel_epoch`
cascade — saltyfs does not need to scan MOs at close time.

## 7. Cancel Semantics

A `WorkerJobKind::WriteBlocks` job captures
`(slot_idx, session_id, live_gen)` at submit time. When the worker
runs the job:

1. Acquire `BLOCK_LOCK`.
2. Re-read `SESSION_TABLE[slot_idx].live_gen`.
3. If captured generation does not match, the session has been
   closed (or recycled) since submission — the job returns
   `WorkerOutcome::Status(0)` without sending a completion. Any
   MO cap the payload carried is `cnode_delete`'d to recycle the
   receive-slot arena entry.
4. Otherwise execute `execute_write_locked` + flushes + direct
   reply. In-flight (already-running) writes are not rolled back;
   the close path's `drain_pending()` waits for them to finish.

This makes BACKEND_WRITE cancellation lock-free for queued work and
drain-based for in-flight work.

## 8. Flush Ordering

`WorkerJobKind::WriteBlocks` performs `cache_flush_all()` and
`flush_superblock_if_dirty()` between `execute_write_locked` and
the direct completion send. The owner's per-mutating-op generic
flush enqueue in `main.rs` skips `BACKEND_WRITE` — the worker's
own flush already provides a real commit boundary. Re-enqueuing
would race with the in-flight write job and risk surfacing the
wire reply before the bytes are durable.

`fsync` continues to use the dependency-graph `PRED_BARRIER` edge
in the VFS pending arena rather than a per-call flush.

## 9. RECV_SLOT_COUNT Sizing

`saltyfs/src/main.rs::RECV_SLOT_COUNT = 256` —
`SALTYFS_SESSION_SLOTS (64) + SALTYFS_MAX_INFLIGHT (64) + slack 32`.
Each session may hold one in-flight callback cap; in-flight write
jobs may carry an MO cap; arena ring rotation past mark_kept needs
breathing room. 256 covers the worst case without ring stalls.

## 10. Daemon staging-window cap

`MO_STAGING_VADDR = 0x5300_0000` — single 1 MiB region in the
daemon's vspace where inbound MOs are mapped. `MO_STAGING_SIZE =
1 MiB` caps any single BACKEND_WRITE / BACKEND_READ payload — larger
writes are rejected with `KERNITE_ERR_OUT_OF_RANGE`. Frontends
that need to write more than 1 MiB chunk across multiple
BACKEND_WRITEs (no per-call cap negotiation; the cap is a
daemon-private detail).

Single-window suffices because writes serialise under `BLOCK_LOCK`.
