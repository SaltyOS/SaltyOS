# mmsrv Authorization Audit

## Purpose

This document tracks proof-relevant authorization gaps in the mmsrv
public IPC surface. It is a sibling of `memory-model-audit.md`, scoped
to **who may call which mmsrv endpoint against whose client record**
rather than to PMM / MO / VSpace invariants.

It answers:

1. Which mmsrv endpoints carry an implicit cross-client privilege?
2. Which of those validate the caller against the target?
3. Which historically-known gaps are closed, and which are still open?
4. What load-bearing assumptions does the current badged-`mmsrv_ep`
   distribution rest on?

This document is not a mechanized proof. It records static audit
results plus architecture notes.

## How To Update This Document

When a new audit pass lands:

1. Add one entry to `## Audit Log`.
2. Update `## Current Status`.
3. Add or update items in `## Open Blockers` and `## Historical Fix
   Ledger`.
4. If the proof obligations changed, update `## Required Invariants`.

Stable IDs mirror `memory-model-audit.md`:

- `H#` — historically-identified blocker that is now closed.
- `O#` — blocker that is open at current HEAD.
- `I#` — proof-relevant authorization invariant.
- `A#` — load-bearing assumption.

## Scope And Method

This audit covers the subset of `userland/core/mmsrv` IPC labels that
take a `target_badge` distinct from the caller. The pure "client
operates on itself" labels (`MM_MMAP`, `MM_MPROTECT`, …) are out of
scope — their authorization is implicit in the caller-badge check
already built into `find_client_by_badge(caller_badge)`.

Unless an audit-log entry says otherwise, this is a static source
audit only. No build, boot, or runtime repro is implied.

## Current Status

Current snapshot:

- Date: `2026-05-04`
- Method: static source audit; ABI rewrite
- Current verdict: `RESOLVED BY DESIGN` — the kernite Fuchsia-style
  edge rewrite removed every cross-client opcode from mmsrv's wire,
  so the H/O proof obligations no longer have a wire surface to
  enforce against.
- Open blockers: none.
- Historical closures: `H1`, `H2`, `H3`, `H4`, `O1`, `O2`, `O3`.

### Status Table

| ID | Status | Endpoint | Summary | Primary invariant(s) |
|---|---|---|---|---|
| H1 | RESOLVED BY DESIGN (2026-05-04) | `MM_ALLOC_STACK_REGION` / `MM_FREE_STACK_REGION` | Both opcodes deleted in the 2026-05-04 ABI rewrite. Stack provisioning is now done inline by the child via `MM_MMAP(MAP_GROWSDOWN)` against its own per-client MP. | A1, A2 |
| H2 | RESOLVED BY DESIGN (2026-05-04) | `MM_DEREGISTER` | Renamed to `MM_DEREGISTER_CLIENT` and gated to the init-only tier (`INIT_PRIV_BADGE_FROM_MMSRV`). Self-deregister has no wire surface; init owns lifecycle. | A1, A2 |
| H3 | RESOLVED BY DESIGN (2026-05-04) | Cross-client opcode cluster (11 labels) | Every label deleted. The current ABI has zero opcodes that take a `target_badge` distinct from the per-client MP's badge. mmsrv enforces self-only by construction (the per-client MP recv side is the identity). | A1, A2 |
| H4 | RESOLVED BY DESIGN (2026-05-04) | `MM_REGISTER` | Renamed to `MM_REGISTER_CLIENT`, init-only tier. The wire takes `(client_id, vspace_cap, request_mp_recv)` — no caller-supplied badge. | A1, A3 |
| O1 | RESOLVED BY DESIGN (2026-05-04) | Cross-client read paths | Deleted alongside H3. mmsrv's only wire surface that touches another client is `MM_FORK_VSPACE`, which init alone can call (init-only tier badge gate). | A1 |
| O2 | RESOLVED BY DESIGN (2026-05-04) | Stack reservation cross-client | Stack mappings are anon regions in the caller's own vspace. There is no shared stack reservation table any more. | A1 |
| O3 | RESOLVED BY DESIGN (2026-05-04) | Badge squatting on `MM_REGISTER` | Init owns every `client_id` allocation (`alloc_client_id`); badges are mint-time stamps under init's control. No userland process can squat. | A1, A3 |

## State Model That Must Be Proved

mmsrv holds three kinds of cross-client state:

1. Per-client metadata (`MmClient`) — badge, pid, VSpace cap,
   region / reservation slabs, watermarks (`heap_base`,
   `heap_current`, `mmap_hint`), `registrant_badge`.
2. Per-region metadata (`MappedRegion`) — base, length, prot,
   `region_type`, `BackingDescriptor`, optional `reservation` link,
   stack-only fields (`stack_allocator_badge`,
   `guard_reservation_id`).
3. Kernel-side VmArea state reachable through the stored `vspace_cap`.

Authorization proof obligations define who may read or mutate each
category. Both categories (1) and (3) are currently exposed to any
holder of a badged `mmsrv_ep` via cross-client opcodes.

## Required Invariants

### Authorization Invariants

- `I1` Every mmsrv opcode that takes a `target_badge` distinct from
  the caller must verify one of the following:
  - `caller_badge == target_badge` (self-operation), OR
  - `caller_badge == target_client.registrant_badge` (the registrant
    that published the target), OR
  - the caller is a named system authority with a documented
    broadcast right (currently none).

- `I2` `MM_REGISTER` may only succeed when the caller has an explicit
  right to seed a client record for the requested badge. Enforced at
  HEAD via the registrant-mismatch check that closed `H4`; see
  the matching `A3` for the load-bearing assumption.

- `I3` Per-region authorization (e.g. `stack_allocator_badge`) is an
  **additive** gate on top of `I1`. It narrows a cross-client right
  (granted by `I1`) down to a specific caller. The region gate alone
  is insufficient; both must hold.

### Derived Invariants (from `memory-model-audit.md`)

The historical authorization gaps interacted with the memory-model
invariants by opening writer paths that broke them. The fixes
recorded under `H2`–`H4` close those paths:

- `H2` restored `I11` (`MmClient` publication atomicity):
  third-party `MM_DEREGISTER` can no longer tear a live client
  down behind the registrant's back.
- `H3` restored `I2`, `I21`, `I22`: third-party mutations of
  VmArea state and `REGION_STACK` extents are gated by
  `enforce_target_authorization` / `enforce_fork_authorization`.
- `H4` closed the `MM_REGISTER` squatting / DoS path; without the
  registrant-mismatch reject, a hostile process could force
  `TRONA_ALREADY_EXISTS` on a legitimate service's
  `MM_REGISTER`.

## Open Blockers

None — see the Historical Fix Ledger for `H2` / `H3` / `H4` which
formerly tracked `O1` / `O2` / `O3`.

## Historical Fix Ledger

### H1. Stack-region cross-client hole — CLOSED (2026-04-19)

`MM_ALLOC_STACK_REGION` and `MM_FREE_STACK_REGION` previously
accepted any `(caller, target)` pair. An attacker could overwrite a
victim's VSpace with a stack mapping they owned, then tear it down
through the matching free opcode.

Resolution landed alongside the stack provisioning redesign:

- New field `MmClient.registrant_badge` (`userland/core/mmsrv/src/types.rs`),
  populated by `handle_mm_register` from `caller_badge`.
- New field `MappedRegion.stack_allocator_badge`, populated by
  `handle_mm_alloc_stack_region` from `caller_badge`.
- Both alloc and free now gate on
  `caller_badge == target_badge || caller_badge == dst_client.registrant_badge`
  before touching any state.
- Free additionally requires either an exact per-region allocator
  match (for supervisor-allocated stacks) or the registrant path
  (for `posix_mmap(MAP_STACK)`-origin stacks whose
  `stack_allocator_badge == 0`).
- Fork preserves `stack_allocator_badge` and the new
  `guard_reservation_id` back-link so the gate survives fork; see
  H3 below for the cross-client cluster fix and the matching
  reservation remap in `ForkPlan::finalize_back_links`.

See `docs/spec/memory-model-audit.md` invariants `I21`–`I24` for the
memory-model side of the same fix.

### H2. `MM_DEREGISTER` accepts any caller — CLOSED (2026-04-29)

`handle_mm_deregister` now calls
`enforce_target_authorization(client, caller_badge)` before tearing
the client down. The helper accepts the request only when
`caller_badge == client.badge` (self-deregister) or
`caller_badge == client.registrant_badge` (the
supervisor that registered the client). Any other caller receives
`TRONA_INSUFFICIENT_RIGHTS`.

### H3. Cross-client opcode cluster — CLOSED (2026-04-29)

Every cross-client opcode (`MM_MPROTECT_TARGET`, `MM_MAP_WINDOW`,
`MM_UNMAP_WINDOW`, `MM_PREFAULT_RANGE`, `MM_MAP_BATCH`,
`MM_ALLOC_INITRD_COPY`, `MM_ALLOC_BOOTINFO_COPY`,
`MM_COPY_FROM_CLIENT_REGION`,
`MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION`,
`MM_ALLOC_TYPED_COPY_FROM_CLIENT_REGION`) calls
`enforce_target_authorization` at handler entry; `MM_FORK_REGIONS`
calls the dual-client variant `enforce_fork_authorization`.

`MM_UNMAP_WINDOW`'s wire grew an explicit `target_badge` field
(`regs[0]`) so the handler can resolve the client whose region the
window points at.

### H4. `MM_REGISTER` badge squatting — CLOSED (2026-04-29)

`handle_mm_register` rejects re-registration of a badge previously
held by a different registrant: it calls `find_any_client_by_badge`
(searches inactive slots too) and returns
`TRONA_INSUFFICIENT_RIGHTS` when the prior `registrant_badge` does
not match `caller_badge`. The first-registrant wins; a hostile
process cannot squat on init's badge or recycle a freed slot under
a different identity.

## Load-Bearing Assumptions

### A1. mmsrv exposes a per-client MP — the MP recv side IS the client identity

Every process receives a private MP_PAIR with mmsrv at spawn time.
mmsrv's service EQ Watches every per-client MP recv side; the
matching `cookie = client_id` becomes the authorization context for
every label that arrives on it. There is no `target_badge` field on
any self-only label — the MP itself is the identity and the kernel
`MP_READ` boundary defends against spoof.

### A2. The Watch cookie is set by mmsrv at register time

mmsrv installs the `client_id` cookie when init calls
`MM_REGISTER_CLIENT`. The kernel writes that cookie on every
EventRecord raised by that MP becoming readable. A client cannot
forge a cookie it does not own — `MP_REGISTER_CLIENT` is on the
init-only tier, so only init can install a Watch with a cookie of
its choosing.

### A3. Badges are allocated by init only (`MM_REGISTER_CLIENT` is init-only)

`MM_REGISTER_CLIENT` lives on the init-only tier; mmsrv rejects any
caller whose `record.badge` is not `INIT_PRIV_BADGE_FROM_MMSRV`. No
sibling process can ever stamp a client_id, so badge squatting has
no surface.

## Audit Log

### 2026-05-08 — Plan 8 LD-1 cleanup (no authz delta)

- Method: trona crate split land (D' composition-root pattern).
- Result: no authorization surface change. LD-1 moved the
  `RecvSlotArena` adapter out of `trona_runtime` and into each
  server binary's composition root, so the `runtime → server` edge
  the original split implicitly carried is gone. `mmsrv` now
  composes its own `SlotAllocator` from
  `trona_runtime::core::slot_alloc::slot_alloc_consecutive_cb` +
  `_invoke_depth_cb` and feeds it to `RecvSlotArena::init_with_allocator`.
  The wire that H/O obligations enforce against is identical before
  and after the cleanup.
- No re-opening: `H1·H2·H3·H4·O1·O2·O3` remain `RESOLVED BY DESIGN`.

### 2026-05-04 — ABI Rewrite (RESOLVED BY DESIGN)

- Method: ABI rewrite alongside the core-userland rebuild.
- Result: every H/O blocker became unrepresentable in the new wire
  layout. mmsrv now exposes only:
  * Self-only tier on per-client MP recv (no target_badge on any
    label; MP recv side is the identity).
  * Init-only tier on master service-EP MP gated by
    `INIT_PRIV_BADGE_FROM_MMSRV` (`MM_REGISTER_CLIENT`,
    `MM_DEREGISTER_CLIENT`, `MM_FORK_VSPACE`,
    `MM_REGISTER_FAULT_PIPE`).
- Closed: H1, H2, H3, H4, O1, O2, O3.

### 2026-04-19 — Initial Sweep

- Method: static source audit triggered by the stack provisioning
  redesign's third-party review. The auditor flagged
  `MM_ALLOC_STACK_REGION` cross-client access, which was closed; the
  same review surfaced the cluster of unaddressed cross-client
  opcodes and the unauthenticated `MM_REGISTER` path that this
  document now tracks.
- Result: `H1` closed; `O1`, `O2`, `O3` recorded as open.
- Main landed fix themes: `registrant_badge` field on `MmClient`,
  per-region `stack_allocator_badge`, allocator + registrant gate on
  the two stack-region opcodes, allocator-badge replication across
  fork, `MM_MUNMAP` self-teardown path that permits pthread stack
  reclaim.

### 2026-05-06 — ABI sweep

- Method: the kernite Fuchsia-style edge rewrite reaches mmsrv.
  The new ABI removes every `target_badge` cluster opcode and
  collapses cross-client wire to four init-only labels
  (`MM_REGISTER_CLIENT` / `MM_DEREGISTER_CLIENT` / `MM_FORK_VSPACE` /
  `MM_REGISTER_FAULT_PIPE`).
- Result: `H1·H2·H3·H4` and `O1·O2·O3` are **resolved by design** —
  the wire surface that allowed cross-client operations no longer
  exists. Self-tier identity is established by per-client request MP
  ownership: each child holds a distinct kernel cap minted by
  `RSRC_ALLOC_MP_PAIR`, the kernel cap system blocks any other
  process from invoking it, and mmsrv's service EQ Watch cookie
  carries the pre-registered `client_id` for dispatch routing only
  (badge is unused — `RSRC_ALLOC_MP_PAIR` results carry badge=0).
- New rule: the only bootstrap-bind exception inside the 0x40x
  admin tier is `MM_BIND_CLIENT_SELF`. Any future admin-only label
  sets `require_admin(badge == INIT_PRIV_BADGE_FROM_MMSRV)`
  explicitly.
- `MM_FORK_VSPACE` accepts an `exclude_vas` array so init can
  preserve regions in the child's address space that must not COW
  from the parent — currently used only for the cap-table region at
  `CHILD_CAP_TABLE_VA`.
