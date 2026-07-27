# Memory-Model Audit

## Purpose

This document is a living ledger for proof-relevant memory-model work in
SaltyOS. It is meant to answer four questions at any point in time:

1. What state machine would a seL4-style proof need to refine?
2. What invariants must hold across PMM / MO / VSpace / mmsrv / rsrcsrv?
3. Which blocker-level issues are still open at current HEAD?
4. Which historically-known gaps have already been fixed?

This document is not a mechanized proof. It records static audit results,
historical fixes, currently-open proof blockers, and the assumptions those
statements depend on.

## How To Update This Document

When a new audit pass is done:

1. Add one entry to `## Audit Log`.
2. Update `## Current Status`.
3. Add or update items in `## Open Blockers` and `## Historical Fix Ledger`.
4. If the proof obligations changed, update `## Required Invariants`.

Stable IDs:

- `H#` = historically-identified blocker that is now closed.
- `O#` = blocker that is open at current HEAD.
- `I#` = proof-relevant invariant.
- `A#` = load-bearing assumption.

## Scope And Method

This audit covers:

- `kernite` PMM / MO / VSpace / paging
- `mmsrv`
- `rsrcsrv`

Unless an audit-log entry says otherwise, this is a static source audit only.
No build, boot, or runtime repro is implied.

## Current Status

Current snapshot:

- Date: `2026-04-19`
- Method: static source audit only
- Current verdict: `PROOF BLOCKERS CLOSED` (pending build / boot verification)
- Historical blocker closures retained: `H1-H10`
- Current blocker-level issues: none

### Status Table

| ID | Status | Area | Summary | Primary invariant(s) |
|---|---|---|---|---|
| H1 | CLOSED | VSpace map/fork metadata | Mapping metadata reservation made atomic before commit | I2, I7, I8 |
| H2 | CLOSED | MO reverse maps | `reverse_maps` gained a synchronization domain and destroy walk protocol | I2, I3 |
| H3 | CLOSED | PMM free semantics | `pmm_free` now proves unmapped-before-free locally via `map_count` | I4 |
| H4 | CLOSED | mmsrv mirror state | Userspace region mirror gained transactional publication / rollback | I5, I10, I11, I14 |
| H5 | CLOSED | rsrcsrv quota sizing | Kernel and rsrcsrv share one object sizing function | I6, I9, I13 |
| H6 | CLOSED | COW resolve syscall path | `resolve_cow_with_frame` routes through `cow_install_atomic`; child MO backing is established as part of the same transaction | I17 |
| H7 | CLOSED | COW pooled fast path | COW pool frames are retagged `KernelPrivate{CowPool}` at donation and drained on VSpace teardown; kernel holds lifetime | I18 |
| H8 | CLOSED | MO radix tree access | `resolve_page_depth` / `is_local_committed` read `pages` under `commit_lock`; parent chain walked per-MO without cross-nesting | I19 |
| H9 | CLOSED | COW fast paths | Both `handle_cow_fault` and `handle_cow_fault_pooled` delegate to `cow_install_atomic`; radix commit failure rolls back PTE/PMM | I17 |
| H10 | CLOSED | VSpace teardown | `free_pdpt_recursive` / `free_pd_recursive` call `pmm_free(KernelPrivate{PageTable})` after releasing the self-mapping ref | I20 |

## State Model That Must Be Proved

The implementation spreads memory truth across five places:

1. PMM per-frame state
   `kernite/src/mm/frame.rs`
   `FrameOwner`, `map_count`, and frame flags.

2. MemoryObject state
   `kernite/src/cap/memory_object.rs`
   radix tree entries plus `reverse_maps`.

3. VSpace state
   `kernite/src/mm/vspace.rs`
   hardware PTEs plus `VmArea` Maple tree metadata.

4. mmsrv state
   `userland/core/mmsrv/src/types.rs`
   per-client `MmRegion[]` policy state.

5. rsrcsrv state
   `userland/core/rsrcsrv/src/main.rs`
   untyped source pools, owner quotas, and handle metadata.

For a proof, these cannot merely be "usually consistent". They need one
refinement story with explicit state transitions between:

`PMM <-> MemoryObject <-> VSpace <-> mmsrv <-> rsrcsrv`

## Required Invariants

At minimum, the following must hold.

### Core Ownership And Mapping Invariants

- `I1` Every physical frame has exactly one semantic owner in PMM.
- `I2` Every present MO-backed PTE is represented by a matching `VmArea`
  span and a matching MO `ReverseMapEntry`.
- `I3` Every `ReverseMapEntry` points to a live VSpace and a still-valid VA
  range.
- `I4` `pmm_free()` is called only after the last mapping reference is gone.
- `I5` mmsrv region metadata is a refinement of kernel `VmArea` state, not a
  competing second truth.
- `I6` rsrcsrv quota accounting must upper-bound, and ideally exactly match,
  actual kernel object memory usage.

### Structural And Error-Cleanliness Invariants

- `I7` No two `VmArea`s in one VSpace overlap.
- `I8` `map_mo` / `fork_range` error paths leave no residual child-side PTE,
  `VmArea`, or reverse-map mutations attributable to the failed call.
- `I9` Kernel object sizing used by retype and quota accounting comes from one
  shared source of truth.
- `I10` Fork is child-atomic: success fully publishes child state, failure
  leaves the child in pre-call state.
- `I11` `MmClient` publication is atomic at the document's abstraction level:
  no partially-swapped region/scalar state becomes observable.
- `I12` Policy code and kernel-VM code stay separated by an explicit layering
  boundary.
- `I13` Quota cost is idempotent: alloc-time charge equals free-time refund.
- `I14` Every kernel-side install performed by transactional fork is journaled
  exactly once before any later fallible step.

### Assumption-Coupled And Caveat Invariants

- `I15` mmsrv publication holds the owning client's
  `Mutex<ClientPolicyInner>` around `txn::commit_swap`; the
  historic single-threaded simplification is retired by `A2`
  (mmsrv now runs a main reactor and a fault dispatcher
  concurrently). Readers either see the staged region table or
  the published one, never a half-installed mix, because the
  swap point is the mutex-protected `commit_swap`.
- `I16` Fork dedup preserves aliasing only within the bounded dedup table
  design; above the bound it degrades to a documented caveat, not a clean proof
  story.

### Current-Head Blocking Invariants

- `I17` After any COW-resolution path, the installed present PTE must
  correspond to a backing entry in the child MO radix tree and PMM owner state
  must agree with that child MO.
- `I18` If the kernel stores a raw physical address obtained from a `Frame`
  capability, it must also hold a kernel-side lifetime claim or rehome
  ownership before userspace can revoke the original capability.
- `I19` Any read of `MemoryObject.pages` that can race with commit/remove/grow
  must either hold `commit_lock` or use a separately-proved lock-free
  publication protocol.
- `I20` Every PMM-allocated page-table frame for a user VSpace must eventually
  return to PMM via `pmm_free(...)` with the matching owner tag.

### Stack-Provisioning Invariants

Introduced by the stack provisioning redesign (2026-04-19). The
authoritative stack is the single full-span `REGION_KIND_STACK` VmArea
in the thread's VSpace; the TCB fields are a cache re-verified against
the VmArea on every update.

- `I21` For every live user TCB with `user_stack_min != 0`, the TCB's
  VSpace contains exactly one VmArea with `region_kind = REGION_KIND_STACK`
  covering `[user_stack_min, user_stack_top)`, backed by one MemoryObject
  whose capacity is at least `(user_stack_top - user_stack_min) / PAGE_SIZE`
  pages. The MO may carry additional unmapped capacity beyond the
  VmArea span (e.g. when pthread picks a non-power-of-two
  `stack_size` and the MO is rounded up to the next retype size class)
  — only the pages covered by the VmArea are reachable through the
  mapping. *Enforcer:* `TCB_SET_STACK_BOUNDS` re-validates the VmArea
  span, `region_kind`, and `mo.page_count >= expected_pages` under
  `VSpace.lock` before committing the TCB cache; spawn / fork /
  `pthread_create` are the only call sites that reach this syscall.

- `I22` For every live user TCB with `user_stack_guard_bottom != 0`,
  the range `[user_stack_guard_bottom, user_stack_min)` has no VmArea,
  no present or demand PTE, and no MO `ReverseMapEntry` pointing into
  it. *Enforcer:* the provisioning sequence (init spawn path and
  mmsrv's `MM_ALLOC_STACK_REGION`) maps only the reserve range; the
  guard hole is defined by absence. Fork replicates the parent's
  stack VmArea into the child at the same coordinates, preserving
  this property.

- `I23` Every present PTE inside a `REGION_KIND_STACK` VmArea has
  `FrameOwner::MoData { mo, page_idx }` with `mo` equal to **the VmArea's
  backing MO or one of its COW ancestors** reachable through
  `cow_parent` raw pointers (kernel-internal `*mut MemoryObject`,
  pinned by `KernelObject.ref_count` — see the "COW Lifetime
  Invariants" section). The
  literal "backing MO" form of this invariant is re-established on
  first write through `cow_install_atomic` (H6/H9), which retags the
  new frame with `MoData { mo: child_mo, page_idx }`. *Enforcer:* the
  stack map sequence uses `VSPACE_MAP_MO` with `VSPACE_FLAG_DEMAND`;
  the legacy `vspace_map(OBJ_FRAME, …)` path is not reachable for
  stack pages. The demand-fault path (`handle_demand_fault`) preserves
  `MoData` with the VmArea's MO when promoting a demand PTE. Fork
  produces a child VmArea pointing at a COW child MO whose present
  pages transitively resolve through the parent chain — the ancestor
  form of this invariant covers the shared-frame window, and COW
  resolution (`cow_install_atomic`) restores the literal form.

- `I24` `TCB_SET_STACK_BOUNDS` is accepted only on
  `ThreadState::Inactive`. Running/Ready/Blocked TCBs cannot have
  their stack bounds altered. *Enforcer:* the syscall rejects non-
  `Inactive` states with `Busy`; fork resumes the child only after
  publishing bounds.

- `I25` An MO page committed from a caller-supplied untyped (`MO_COMMIT`
  with `ut_cap != 0`, tagged `PHYS_TAG_UNTYPED` in the MO radix) has
  `FrameOwner::MoData { mo, page_idx }` as its live PMM owner and records
  the exact carving source in `FrameMeta::source_ut`. `VSPACE_MAP_MO`,
  COW snapshot retagging, and panic diagnostics therefore see the real
  owner, while MO destroy / `mo_decommit` route the page back to the
  source untyped by `source_ut`. The source untyped carries an outstanding
  MO-page count and an internal refcount pin, so reset/reap cannot recycle
  the source before the MO releases the page. *Enforcer:* `MO_COMMIT`
  uses `pmm_transfer_with_source`; release paths use
  `release_resident_data_page`; `UntypedMemory::reset_state` refuses
  while `mo_page_refs != 0`.

## Open Blockers

None at current HEAD. The five blockers O1–O5 that were open on 2026-04-17
have all landed; see `H6`–`H10` in the Historical Fix Ledger.

## Historical Fix Ledger

These are blocker-level issues that were historically real and are still
important to track, but are considered closed by the current implementation.

### H1. Mapping happened before metadata registration - CLOSED

- Status: `CLOSED`
- Area: VSpace map/fork metadata
- Primary invariants: `I2`, `I7`, `I8`

What landed:

- overlap gate before metadata mutation;
- maple reservation before insert;
- reverse-map reservation ticket before commit;
- infallible metadata commit after successful reservation.

Result:

Map/fork metadata no longer relies on post-hoc rollback symmetry to repair
late-stage allocator failure.

### H2. `MemoryObject::reverse_maps` had no synchronization domain - CLOSED

- Status: `CLOSED`
- Area: MO reverse-map integrity
- Primary invariants: `I2`, `I3`

What landed:

- dedicated `MemoryObject::rmap_lock`;
- explicit lock order `VSpace.lock -> MO.rmap_lock -> FRAME_LOCK`;
- snapshot + re-validate destroy walk to avoid inversion.

Result:

Reverse-map mutation and observation now have a named synchronization domain,
and destroy no longer needs to violate global lock ordering.

### H3. PMM free did not prove "unmapped before free" - CLOSED

- Status: `CLOSED`
- Area: PMM safety
- Primary invariants: `I4`

What landed:

- `FrameAllocator::free_internal` panics on non-zero `map_count`;
- `map_count` widened to `u32`;
- free-time diagnostics now report the failing frame and owner tag.

Result:

PMM now enforces "unmapped before free" locally instead of assuming higher
layers got it right.

### H4. mmsrv kept a second memory truth and preserved partial fork state - CLOSED

- Status: `CLOSED`
- Area: userspace VM mirror / fork publication
- Primary invariants: `I5`, `I10`, `I11`, `I14`

What landed:

- transactional `mmsrv::txn` rollback guard;
- staged region-table publication;
- atomic commit-swap of region/scalar state;
- layering split between policy and kernel-VM code.

Result:

The userspace mirror is now explicitly transactional instead of being an
independent best-effort state machine.

### H5. rsrcsrv quota accounting was not a refinement of kernel bytes - CLOSED

- Status: `CLOSED`
- Area: quota sizing
- Primary invariants: `I6`, `I9`, `I13`

What landed:

- shared `object_alloc_bytes` sizing helper;
- compile-time kernel size assertions;
- cached `cost_bytes` for idempotent refund;
- removal of ad hoc rsrcsrv object-size logic.

Result:

Kernel retype and rsrcsrv quota accounting now derive object byte cost from one
shared source of truth.

### H6. `resolve_cow_with_frame` published PTEs without establishing child-MO backing - CLOSED

- Status: `CLOSED`
- Area: COW resolve syscall path
- Primary invariants: `I17`

What landed:

- new `VSpace::cow_install_atomic` helper (Reserve BUSY → Publish
  PTE+TLB+PMM mapping-refs → Finalize radix → Commit-point
  `pmm_set_owner(MoData)`) under `MO.commit_lock`;
- `resolve_cow_with_frame` delegates to the helper; the child MO is
  resolved via the VSpace Maple tree before any allocation;
- `syscall_vspace_cow_resolve` is an **always-consume donation**: inside
  one CAP_LOCK critical section it revokes the Frame cap and retags the
  PMM owner to `KernelPrivate{CowPool}`, then calls the helper. Success
  flips it to `MoData`. Failure returns the phys to PMM via
  `pmm_free(CowPool)`. A post-install revoke would have let CDT's
  `reclaim_child_range` overwrite the `MoData` tag back to
  `UntypedReserved` and panic the next owner-mismatch check — the
  donation-style ordering avoids this.

Result:

Every successful COW resolve exits with the `(PTE, MO radix, PMM
owner)` triple all pointing at the new frame. External observers
(commit_lock not held) only ever see pre-call or post-call states.
ABI trade-off (recorded here for transparency): the Frame cap is
consumed on every invocation, including failure. Retry requires the
caller to allocate a fresh frame.

### H7. COW scratch pool had no kernel-held lifetime claim - CLOSED

- Status: `CLOSED`
- Area: COW pooled fast path
- Primary invariants: `I18`

What landed:

- new `KernelMetaKind::CowPool` variant with per-subkind accounting;
- `VSPACE_SET_COW_POOL` / `VSPACE_REPLENISH_COW_POOL` revoke each
  donated Frame cap and retag the backing frame to
  `KernelPrivate{CowPool}` under CAP_LOCK + FRAME_LOCK;
- `VSpace::cleanup` drains un-consumed pool entries via
  `pmm_free(KernelPrivate{CowPool})` before page-table teardown.

Result:

Pool entries are owned by the kernel for their full lifetime. Deletion
or revocation of the originating Frame capability cannot reclaim the
phys out from under the kernel.

### H8. `resolve_page_depth` read `pages` outside its writers' synchronization domain - CLOSED

- Status: `CLOSED`
- Area: MO radix reader synchronization
- Primary invariants: `I19`

What landed:

- `resolve_page_depth` and `is_local_committed` acquire `commit_lock`
  around every `pages.get` — per MO, never nested across two MOs.
- `self.cow_parent` is read inside `self.commit_lock` so the
  **`cow_parent` slot value** observed by the reader is coherent with
  respect to the lazy-collapse writer.
- The lazy-collapse branch of `MemoryObject::destroy` now writes
  `remaining.cow_parent` under `remaining.commit_lock`, closing the
  torn-field read/write race on the field itself.
- The lingering writer sites in `syscall_mo_resize`, `map_demand_*`,
  and the map-path flatten step now acquire `commit_lock` around
  `commit_page` / `pages.remove`.
- `MemoryObject::commit_lock` docstring and the global lock-ordering
  comment in `kernite/src/mm/mod.rs` now declare `commit_lock` at the
  same nesting depth as `rmap_lock` (disjoint), with explicit
  `commit_lock → ut.alloc_lock → FRAME_LOCK` ordering downstream.

Result:

Every reader of `MemoryObject.pages` observes a state produced under
the same lock the writers hold, and the `cow_parent` field itself is
read/written coherently.

**Scope of the `cow_parent` guarantee.** The `commit_lock` guard
serializes the **write** of `cow_parent`. The walker
(`resolve_page_depth`) uses a hand-over-hand pin protocol: it
`increment_refcount`s the next parent under the current MO's
`commit_lock` before releasing the lock, then `release_object`s the
previous link outside the lock. This keeps a kernel-internal
reference on the next link so the reaper / lazy-collapse cannot
finalize that parent (or rewire its `cow_parent`) while the walker
steps onto it. The previous "slot deref + `A1` (kernel objects never
freed)" argument has been **superseded** by the pin protocol: see
the "COW Lifetime Invariants" section. `A1` no longer holds in
general (the reaper does reclaim MO carved blocks); `cow_parent`
safety now flows entirely from refcount pins.

Returned `phys` values remain live for the caller's `VSpace.lock`
window via `H3`'s `map_count >= 1` invariant when the caller already
holds an active mapping; first-mapping callers are addressed in the
same caveats section.

### H9. COW fast paths ignored radix-commit failure after publishing a PTE - CLOSED

- Status: `CLOSED`
- Area: COW fast-path atomicity
- Primary invariants: `I17`

What landed:

- `handle_cow_fault` and `handle_cow_fault_pooled` both delegate to
  `cow_install_atomic`; the helper's Reserve step uses
  `RadixTree::reserve_slot(BUSY)` so radix-alloc failure returns the
  frame to PMM without ever touching PTE or PMM owner state;
- `write_entry` failure rolls back the BUSY reservation;
- `RaceLost` (another CPU already resolved) is reflected back to the
  fault handler as "continue", with the donated / allocated frame
  released with its current tag (`KernelPrivate{General}` or
  `KernelPrivate{CowPool}`).

Result:

No COW fast path can leave a present PTE pointing at a page the child
MO has not committed. Failure paths are transactional across all three
domains.

### H10. User VSpace page-table frames leaked on teardown - CLOSED

- Status: `CLOSED`
- Area: VSpace teardown
- Primary invariants: `I20`

What landed:

- `free_pdpt_recursive` / `free_pd_recursive` call
  `pmm_free(KernelPrivate{PageTable})` on each PDPT, PD, and PT frame
  after the self-mapping ref is released via `pmm_release_mapping`;
- PML4 / aarch64 L0 root continue to be owned by the parent untyped
  carve and are intentionally skipped;
- applies unchanged on both x86_64 and aarch64 (the teardown helpers
  share one arch-generic 4-level walk).

Result:

User VSpace destruction returns every allocated page-table frame to
PMM. The page-table population counter and the `KernelPrivate{PageTable}`
tag are now a faithful refinement of actual reclamation behaviour.

## Secondary Proof Complications

Not blocker-level, but they complicate a mechanized proof and should stay
visible. Grouped by origin.

### Pre-existing

- **COW parent lifetime.** Child MOs reference their parent through an
  internal cap slot and a manually-maintained refcount instead of a
  uniform CDT-managed lifetime.
- **Multiple mapping views.** A single region is tracked in three places:
  PMM `map_count`, kernel `VmArea` / `ReverseMapEntry`, and userspace
  `MmRegion`. Consistency is invariant-level, not structural.
- **Bounded fork dedup.** `DEDUP_MAX = 16` caps alias preservation; beyond
  that the guarantee degrades to a documented caveat.

### Introduced by H6–H10

- **Intermediate radix nodes on `write_entry` failure.** `cow_install_atomic`
  removes the BUSY leaf on rollback but does not compact intermediate
  nodes allocated during Reserve. Memory accounting only; readers see
  the slot as uncommitted, and MO teardown frees the nodes.
- **Pool depth drift on `RaceLost`.** `handle_cow_fault_pooled` consumes
  the pool entry before calling `cow_install_atomic`. A `RaceLost` frees
  the consumed frame via `pmm_free(CowPool)` without emitting a
  notification-ring entry, so mmsrv sees the deficit only at the next
  replenish. Correctness-neutral (another CPU already committed) but
  counter-visible.
- **First-mapping caller lifetime.** `resolve_page_depth`'s returned
  phys has `map_count >= 1` only for callers already holding a mapping
  to the page. First-mapping callers (map-syscall initial install) must
  finish the PTE install inside the same `VSpace.lock` window; otherwise
  concurrent unmap from other VSpaces could drop `map_count` to zero
  and free the frame. All current callers satisfy this, but the window
  is narrow rather than absent. A tighter claim (incrementing
  `map_count` inside `resolve_page_depth`) is tracked as follow-up.
- **`cow_parent` slot-reuse window — closed.** Previously the walker
  released `commit_lock` and then dereferenced a cap slot whose live
  cap might have been freed in the gap, falling back on `A1` (kernel
  objects never freed) plus a `MemoryObject` type-check for safety.
  `cow_parent` is now a kernel-internal `*mut MemoryObject` instead of
  a cap slot, and the walker pins each next parent (via
  `increment_refcount`) before releasing the current MO's
  `commit_lock`. The reaper cannot finalize a pinned parent, so the
  slot-reuse window does not exist. See the "COW Lifetime Invariants"
  section for the full pin protocol.
- **`handle_cow_fault` behavior change.** When the faulting VA has a
  COW-bit PTE but the Maple-tree VMA lookup does not yield a backing
  MO, the function now returns `Err(VSpaceError::NotMapped)` instead
  of the previous silent-success path (which was itself the `O1`
  bug). This is intentional and necessary for `I17`, but any
  user-visible code that relied on the silent-success behavior will
  now see the fault dispatcher's error path (SIGSEGV-equivalent). The
  existing `test_runner` `fork` / `mmap` modules exercise COW; a
  `just run` pass is the empirical check that no legitimate caller
  regresses.

## Load-Bearing Assumptions

If any assumption below changes, every dependent statement in this document must
be re-audited.

### A1. Kernel objects are never freed or reused during system lifetime

Source of assumption:

- kernel objects are carved from untyped memory;
- backing bytes are not reused during normal object destruction paths.

Why it matters:

- raw `*mut VSpace` / `*mut KernelObject` identity is used in reverse-map and
  destroy logic;
- snapshot + re-validate reasoning depends on pointer stability;
- ABA is ruled out by design rather than by generation tagging.

Invalidation trigger:

- any future object-memory reuse path;
- any typed-object free-and-reallocate design;
- any move away from monotonic untyped-backed object storage.

### A2. mmsrv has two cooperating threads (main reactor + fault dispatcher)

Source of assumption:

- 2026-05-04 ABI rewrite. The fault dispatcher TCB drains
  per-TCB fault MPs from a separate fault EQ; the main reactor
  drains init-only / self-only MPs from the service EQ.

Why it matters:

- `I10` and `I11` cannot rely on single-threading any more.
  Publication uses per-client `Mutex<ClientPolicyInner>` plus
  `txn::commit_swap` while holding that mutex — readers either see
  the staged or the committed region table, never a torn one.
- Lock order is strict:
  `client_table: RwLock<Vec<ClientState>>` →
  `ClientState.policy_lock: Mutex` →
  `mo_registry: Mutex` → `frame_alloc: Mutex`. The fault
  dispatcher's per-TCB entries Mutex and backoff_queue are
  dispatcher-only sub-locks below the policy_lock, never above.

Invalidation trigger:

- adding a third producer that mutates `ClientState` outside the
  per-client policy_lock;
- introducing a wait-free / RCU publication on top of the existing
  staged-swap, without removing the mutex (mixing the two creates
  torn reads).

## Audit Log

### 2026-04-19 - Stack Provisioning Redesign

- Method: static source audit of the stack redesign.
- Result: no new blockers; `H1`-`H10` unchanged.
- New invariants: `I21`-`I24` (stack VmArea / TCB cache / guard-hole / Inactive gating).
- Main landed fix themes:
  full-span reserve MO + demand PTE + unmapped guard hole, high-VA
  stack slot, `TCB_SET_STACK_BOUNDS (0x84)` + `MM_ALLOC_STACK_REGION (0xAB)`,
  removed `handle_stack_growth_fault`, `.service` `[Memory]` section.
- Build / boot verification pending.

### 2026-04-17 - Close of O1-O5

- Method: static source audit + targeted code walkthrough of the landed
  `cow_install_atomic` primitive and its three fault-path callers.
- Result: `O1`-`O5` closed, recorded as `H6`-`H10`.
- Main landed fix themes:
  atomic 3-way COW transaction (PTE / MO radix / PMM owner), kernel-owned
  COW scratch pool via `KernelPrivate{CowPool}`, radix reader /
  writer synchronization via `commit_lock`, user-VSpace page-table
  reclamation.
- Build / boot verification pending — recorded as a near-term obligation.

### 2026-04-17 - Follow-up Static Audit On Current HEAD

- Method: static source audit only
- Result: current HEAD is not proof-ready
- Recorded blockers: `O1-O5`
- Main regression themes:
  COW materialization, raw frame lifetime, radix synchronization, page-table
  reclamation

### Historical Baseline - Original Five Blockers Closed

- Method: static audit plus code review of landed fixes
- Result: `H1-H5` closed
- Main landed fix themes:
  metadata reservation, reverse-map locking, PMM free hardening,
  mmsrv transactionality, quota sizing SSOT

## COW Lifetime Invariants (post `cow_parent` decoupling)

- **`MemoryObject.cow_parent` is a kernel-internal `*mut MemoryObject`,
  not a cap slot.** Lifetime is governed by `KernelObject.ref_count`:
  `mo_clone` calls `increment_refcount(parent)` once, and the matching
  `release_object(parent)` is invoked exactly once on
  `MemoryObject::destroy` (or transferred to a remaining child in the
  lazy-collapse rewire). mmsrv's user-cap delete on a parent MO drops
  only its own cap reference; descendant child MOs continue to pin
  the parent through the kernel-internal link.
- **`resolve_page_depth` walker uses a hand-over-hand pin protocol.**
  While holding the current MO's `commit_lock`, the walker calls
  `increment_refcount` on `cur_mo.cow_parent` before releasing the
  lock, then drops the previous link's ref outside the lock. The
  walker never holds two `commit_lock`s at once and always carries
  exactly 0 or 1 outstanding refs, so the reaper / lazy-collapse can
  never invalidate a link the walker is mid-step on.
- **Destroy is reaper-only.** `MemoryObject::destroy`'s lazy-collapse
  branch never calls `parent_mo.destroy()` directly; instead it calls
  `release_object(parent)` and lets the deferred-cleanup queue run
  the destructor under `CAP_LOCK`. This eliminates nested destroy
  contexts and aligns with the reaper module's documented
  `release_object → enqueue_reap` boundary.

## Fork Transaction Invariants (post `VSPACE_FORK_RANGE` all-or-nothing)

- **`VSPACE_FORK_RANGE` is all-or-nothing per chunk.** The kernel
  pre-reserves child page-table nodes (`ensure_tables_for_range`),
  pre-reserves rmap tickets and maple-tree split slots, then runs the
  per-page PTE flip + child install loop with no failure paths
  (post-reserve `write_entry` cannot fail). The forward call writes
  a bitmap of `writable→COW` transitions into a caller-supplied
  rollback buffer; the bitmap is the only state
  `VSPACE_UNDO_FORK_RANGE` needs to restore the parent side
  precisely. Each chunk covers at most `MAX_FORK_PAGES = 8192` pages.
- **`VSPACE_UNDO_FORK_RANGE` is symmetric and all-or-nothing.** mmsrv's
  `RollbackDelta` stashes the rollback buffer per chunk; on
  transaction failure (any later chunk or region failing) it replays
  each chunk's undo, restoring parent VmArea ownership
  (`parent_shadow_mo → old_mo`, merging the VmArea split if
  present), restoring parent PTEs to writable for the bitmap-marked
  pages, and tearing down child PTEs / child VmArea in the chunk
  range.
- **Parent VmArea split.** When a chunk is a left-aligned subset of
  a larger parent VmArea, the kernel splits V into `V_chunk` (owned
  by `parent_shadow_mo`) and `V_right` (still owned by `old_mo`).
  mmsrv forks regions in chunk order, so right-aligned and
  strict-interior cases are not produced by the policy layer and are
  rejected by the kernel as `InvalidArgument`.
- **mmsrv `ParentRegionStage` mirrors `RegionStage` for the parent
  side.** A full copy of `parent.regions` is allocated at fork start;
  per-chunk `mo_cap` updates land in the staged copy, never on the
  live table. `commit_swap_pair` swaps both parent and child region
  tables in a single critical section. Post-commit cleanup releases
  every distinct old `mo_cap` whose region now references
  `parent_shadow_mo`, with linear pre-dedup so each cap is checked
  at most once.

## 2026-05-06 — Concurrency model update

- **A2 revision.** mmsrv now runs two cooperating threads (a main
  service-tier reactor on the per-client request MP fan-in EQ and a
  dedicated fault dispatcher on the fault EQ). Lock order is strict
  `client_table` → `ClientPolicyInner` → `mo_registry` → `frame_alloc`
  with the fault dispatcher's `entries` Mutex and `backoff_queue` as a
  separate sub-order under the dispatcher TCB. `txn::commit_swap_pair`
  runs under the owning client's `policy_lock` so a fork transaction
  is serialized against any concurrent self-tier RPC from the same
  client.
- **Watch-cookie identity model.** The fault dispatcher and the
  service-tier dispatcher both rely on `KERNITE_INV_WATCH_REGISTER`
  cookies to identify which client/TCB triggered an event:
  - service tier: cookie = `client_id` (registered at
    `MM_REGISTER_CLIENT` time).
  - fault tier: cookie = `(client_id << 32) | tcb_id_in_client`
    (registered at `MM_REGISTER_FAULT_PIPE` time).

  No badge is consulted on either tier. Per-client MP ownership
  through the kernel cap system is the authorisation guarantee;
  the ABI explicitly avoids minting per-client badges
  on `RSRC_ALLOC_MP_PAIR` results.
- **Fork exclude list.** `MM_FORK_VSPACE` accepts an `exclude_vas`
  array; matching parent regions are skipped when iterating
  `KERNITE_INV_VSPACE_FORK_RANGE`. init uses this to preserve the
  child cap-table region so a fresh frame can be staged at the same
  VA without colliding with a COW'd inherit.
