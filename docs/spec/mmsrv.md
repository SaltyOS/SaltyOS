# mmsrv — memory server

## Role

mmsrv owns:
1. A buddy frame allocator over the `mmsrv-pool` untyped seed.
2. MemoryObject lifecycle (retype, refcount, COMMIT/DECOMMIT/CLONE/RESIZE).
3. Per-client RegionTable (`RegionId`, `BackingDescriptor`, `MappedRegion`).
4. VSpace mapping coordination via `KERNITE_INV_VSPACE_*`.
5. Fault dispatcher: every user TCB's fault MP recv side fans into a
   single fault EQ via Watch (cookie = `(client_id<<32) | tcb_id`).
   PAGE_FAULT (anon) and OOM-recoverable are resolved in-place;
   everything else forwards to init via `INIT_REPORT_FAULT` and
   drops the fault token (kernel reaps the TCB).
6. shm support.
7. File-backed mmap routing: vfs registers its pager EP via
   `MM_REGISTER_VFS_PAGER` at boot; mmsrv stores the cap and forwards
   every file-backed page fault to vfs through `PAGER_SUPPLY_PAGE` /
   `PAGER_BEGIN_WRITEBACK` / `PAGER_EVICT_PAGE` (see `docs/spec/vfs.md`).

## Threading

Main reactor TCB drains the service EQ (init-only and self-only
labels). Fault dispatcher TCB drains the fault EQ. Lock order:
`client_table` → `ClientState.policy_lock` → `mo_registry` →
`frame_alloc`. Region publication uses `txn::commit_swap` under the
owning client's policy_lock.

## IPC surface

### admin tier (per-client control capabilities)

Authority and target identity both ride on the control cap's badge
(`TAG(0xC) | ROOT | epoch(43b) | slot(16b)`, encoded by `trona_protocol::control`).
`MM_REGISTER_CLIENT` is the only verb authorized by the per-server **ROOT**
control cap (held only by init); it allocates the `ClientState`, mints a
**per-client** control cap, and returns it in the reply. Every other admin verb
is invoked on that per-client cap — invoking it *is* both the authorization and
the client selector, so mmsrv accepts no trusted `client_id` integer on the
admin path. Two-operand verbs (fork, cross-client stage) use a two-step
transactional invoke: a `*_SET_PARTNER` step pins the secondary operand under a
nonce, then the operate step consumes the matching pending partner. Consume-once
is the replay guard; the slot-epoch re-check is the ABA guard. init mints the
ROOT cap from mmsrv's master-EP send; mmsrv mints the per-client caps from a
GRANT-bearing copy of that same send delivered to it under `ROLE_SERVICE_CLIENT_EP`.

| Label | Hex | Authority | Notes |
|---|---|---|---|
| `MM_REGISTER_CLIENT` | 0x400 | ROOT control cap | Allocates `ClientState`, mints + returns the per-client control cap; arms Watch over per-client MP recv (cookie=client_id) |
| `MM_DEREGISTER_CLIENT` | 0x401 | per-client cap (`MP_WRITE`) | Tear-down; bumps the slot epoch so a recycled slot's stale cap fails closed |
| `MM_FORK_VSPACE` | 0x402 | per-client cap (two-step) | `FORK_RANGE` per region (anon = COW pair, file-backed-RO = share); child pinned via `MM_FORK_SET_PARTNER` |
| `MM_FORK_SET_PARTNER` | 0x409 | per-client cap (step 1) | Records the child as the pending fork partner under a nonce |
| `MM_REGISTER_FAULT_PIPE` | 0x403 | per-client cap | Per-TCB fault MP recv binding; arms Watch on fault EQ with cookie=(client_id<<32\|tcb_id) |
| `MM_STAGE_IMAGE_REGION` | 0x404 | per-client cap (two-step for cross-client src) | Stages an image region into the dest VSpace; cross-client source pinned via `MM_STAGE_SET_SOURCE`, `EXEC_MO_SRC` is single-step |
| `MM_STAGE_SET_SOURCE` | 0x40D | per-client cap (step 1) | Records the source client as the pending stage partner under a nonce |
| `MM_BEGIN_EXEC_REPLACE` | 0x405 | per-client cap | Opens an exec-replace transaction → `txn_id` |
| `MM_COMMIT_EXEC_REPLACE` | 0x406 | per-client cap | Swaps in the new VSpace |
| `MM_ABORT_EXEC_REPLACE` | 0x407 | per-client cap | Rolls back the pending exec-replace |

`MM_BIND_CLIENT_SELF` (0x408) is the client-side counterpart: a freshly spawned
process binds its own request MP to the `ClientState` init pre-created for it.

### self-only tier (per-client MP, cookie = client_id is the identity)

| Label | Hex | Notes |
|---|---|---|
| `MM_MMAP` | 0x410 | Anon / file-backed mmap |
| `MM_MUNMAP` | 0x411 | Tear single region |
| `MM_MPROTECT` | 0x412 | Update PROT_* on a region |
| `MM_BRK` | 0x413 | Heap watermark set |
| `MM_SBRK` | 0x414 | Heap watermark adjust |
| `MM_SHM_CREATE` | 0x420 | Create posix shm region |
| `MM_SHM_MAP` | 0x421 | Map an existing shm region |
| `MM_FILE_MMAP` | 0x430 | File-backed mmap. mmsrv allocates a file-backed MO; subsequent page faults route to vfs through the registered pager EP. |
| `MM_PREFAULT_RANGE` | 0x440 | Pre-commit pages in a region |
| `MM_GET_SYSTEM_MEMINFO` | 0x4F0 | procfs / sysinfo backing |

### vfs-only tier (single boot-time registration, vfs ↔ mmsrv pager wire)

| Label | Hex | Caller | Notes |
|---|---|---|---|
| `MM_REGISTER_VFS_PAGER` | 0x441 | vfs (boot) | vfs hands mmsrv the recv-side of its pager MP. mmsrv keeps the cap and routes every file-backed page fault through `PAGER_SUPPLY_PAGE` / `PAGER_BEGIN_WRITEBACK` / `PAGER_EVICT_PAGE` (Pager block 0x2C0..=0x2C7). |

## Fault topology

Every user TCB has its own fault MP send side (`TCB_SET_FAULT_PIPE`).
recv side lives in mmsrv. The fault EQ Watches each recv side with a
cookie packing both `client_id` (high 32 bits) and `tcb_id` within
the client (low 32 bits). The dispatcher resolves the victim from
the cookie alone — it does not depend on the IPC `record.badge`,
which means fault delivery is resilient to badge-propagation issues.

Fault reply semantics (`kernite/src/ipc/fault.rs`):

- `reply-marked MP_WRITE(KERNITE_OK)` = victim resumes at faulting RIP.
- non-OK reply, malformed reply, or closed fault pipe = arch handler
  escalates `begin_destroy`.

mmsrv replies `KERNITE_OK` only when it has actually committed a page
(recoverable PAGE_FAULT, recoverable OOM). For everything else it
forwards `INIT_REPORT_FAULT` to init and sends a non-OK reply.

## `MM_MPROTECT` constraints

- Base and length must be page-aligned, non-zero, and fully contained by
  a single `MappedRegion`.
- Cross-region `mprotect` ranges are rejected; callers must split per region.
- Requests that do not change the containing region's protection are no-ops.
- mmsrv updates kernel PTE flags first, then publishes region metadata as
  head/middle/tail records so future fault handling sees the same
  permissions as the kernel.
- Split records preserve the original backing object and adjust
  page/file/device offsets for the subrange.
