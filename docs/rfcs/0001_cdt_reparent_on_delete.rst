======================================================
RFC-0001: Re-parent CDT children on capability delete
======================================================

:Status: Implemented
:Areas: Kernel; Capabilities
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-21
:Description: Reclaim a forked child's root CNode on teardown by re-parenting a deleted slot's CDT children onto its own parent instead of re-rooting them; fixes the resource-server untyped-pool exhaustion (err = 0x5) cascade.

Problem Statement
=================

SaltyOS carves every kernel object from untyped memory and never frees it
explicitly. An object's storage is reclaimed only when the object's reference
count reaches zero and the reaper returns its block to the owning untyped's
free list. The resource server (``rsrcsrv``) owns a fixed
global untyped authority (32 MiB, subdivided into 4 MiB arena chunks) and
satisfies every process's retypes from a shared free list with per-owner quota
accounting; ``init`` retypes the per-process spawn bundle through it.

Under sustained ``fork``/``exec``/``exit`` load — the ``test_fork``,
``test_sched_race``, and ``test_vfs_stress_mt`` stress paths — child spawn
began to fail permanently after a few hundred cycles. ``alloc_bundle`` substep
#2, the child's root CNode retype and the single largest carve in the bundle
(``size_bits = 12``: 4096 slots, 128 KiB), returned ``err = 0x5``
(``OUT_OF_MEMORY``). Once that began, every subsequent fork-based test failed
(``test_vfs_stress_mt``, ``test_win32_console_stress``, ``test_saltyfs``,
``test_dns``, ``test_sse``). The kernel frame allocator still reported tens of
thousands of free frames at the moment of failure, so this was not global
memory exhaustion: the leak was confined to ``rsrcsrv``'s untyped authority.

This RFC does **not** address the other, independent test failures present at
the same time (shm ``MAP_SHARED`` mmap, path-based ``execve``,
``/dev/urandom``); those have separate root causes and are tracked separately.
It also does not change general untyped accounting.

Summary
=======

When ``init`` spawns a child it seeds the child's own root CNode with
capabilities to the child's own TCB, VSpace, and CSpace at the well-known self
slots (``CAP_SELF_TCB``, ``CAP_SELF_VSPACE``, ``CAP_SELF_CSPACE``). The
``CAP_SELF_CSPACE`` copy makes the CNode hold a capability to *itself*.
``cnode_copy`` increments the CNode object's reference count, so this
self-capability pins the count at >= 1 permanently; the destructor that would
sweep the CNode's slots — and thereby delete the self-capability — runs only at
reference count 0. The cycle has no breaker.

Teardown could not break it either, because ``delete_capability`` *re-rooted* a
deleted slot's CDT children. When ``init`` deleted its own copy of the child's
CNode capability, the surviving self-capability was promoted to a CDT root, so
the resource server's subsequent revoke of the child's birth capability — which
walks the CDT subtree — could no longer reach it.

The fix is a single kernel change: ``delete_capability`` now **re-parents**
ordinary derived children onto the deleted slot's own parent (keeping them
inside the revoke-reachable subtree) instead of re-rooting them. The
existing teardown sequence then reaches and deletes the re-parented
self-capabilities, the reference count falls to zero, the reaper runs, and the
child CNode's 128 KiB block returns to the pool. There is no userland or ABI
change.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- A child process's root CNode, TCB, and VSpace MUST be reclaimable on process
  exit, returning their backing to the resource server's pool.
- The fork-hardening property MUST be preserved: a capability pinned in transit
  (an in-flight IPC carrier) must still detach to a CDT root on delete — not
  re-parent — so that a slot reused beneath it cannot be revoked out from under
  the transfer.
- The capability-derivation-tree (CDT) invariants MUST hold: the CDT stays
  acyclic, and every live *ordinary* derived capability stays reachable from an
  ancestor for revocation (revoke-reachability). Capabilities pinned in transit
  are the deliberate exception — they detach to a root.
- The fix MUST NOT require any userland or ABI change.

Design
======

Background: derivation, reference counts, and reclamation
---------------------------------------------------------

Capabilities form a derivation tree (the CDT, equivalent to seL4's Mapping
Database). Copying or minting a capability inserts the new slot as a CDT child
of its source and increments the target object's reference count. Reclamation
is reference-count driven: ``release_object`` enqueues an object for the reaper
only when its count transitions to zero; the reaper then runs the object's
destructor (for a CNode, a sweep that deletes every contained capability),
unlinks the object from its parent untyped's child list, and returns its block
to the free list.

The well-known self slots (``CAP_SELF_TCB``, ``CAP_SELF_VSPACE``,
``CAP_SELF_CSPACE``) are part of the process ABI: every process reaches its own
TCB, address space, and capability space through fixed slots in its root CNode.
``init``'s ``seed_self_caps`` installs them when it builds a child.

The self-reference cycle
------------------------

Seeding ``CAP_SELF_CSPACE`` copies the child's root-CNode capability *into the
child's own root CNode*. The CNode now contains a capability to itself, and the
copy increments the CNode's reference count. Because the only code that deletes
that self-capability is the CNode's own destructor — which runs only at
reference count 0 — the self-capability holds the count at >= 1 and the
destructor never runs. The CNode can never start to reap.

Why re-rooting stranded the self-capability
-------------------------------------------

On exit the kernel runs ``drop_owned_caps`` (which deletes ``init``'s
bundle-capability copies, including its copy of the child's CNode capability)
and then ``rsrc_owner_exited`` (which revokes the child's birth capability held
by ``rsrcsrv`` as a back-reference). Revocation walks the CDT subtree of the
birth capability.

Deleting ``init``'s copy invoked ``delete_capability``, which called
``reroot_children``: the deleted slot's children were detached to CDT roots
(their parent link cleared). The child's self-capability — formerly derived
under the birth-capability subtree via ``init``'s copy — therefore became a
root, outside the subtree the back-reference revoke traverses. The revoke could
not reach it, the reference count stayed >= 1, the CNode was never reaped, its
parent untyped's child list stayed non-empty (so the chunk could not be reset),
and its block was never returned to the free list. Each fork leaked one 128 KiB
CNode; the 32 MiB authority was exhausted after a few hundred forks, and the largest
carve (substep #2) was the first to fail.

The fix: re-parent instead of re-root
-------------------------------------

``delete_capability`` now calls ``reparent_children``. Ordinary derived
children are re-linked onto the deleted slot's own parent (their grandparent
in the derivation tree), so they remain within that ancestor's revoke-reachable
subtree rather than becoming roots. (If the deleted slot is itself a CDT root,
its ordinary children stay roots — there is no ancestor to attach them to; that
does not arise on the teardown path above, where ``init``'s copy is derived
under the resource server's birth capability.) Capabilities pinned in
transit are still detached to a root via ``detach_to_root``, preserving the
fork-hardening guarantee.

With re-parenting, the child's self-capabilities remain reachable from
``rsrcsrv``'s back-reference after ``init``'s copy is deleted, so
``rsrc_owner_exited``'s revoke deletes them. The reference count then falls to
zero, the reaper runs the CNode (and, transitively, the TCB and VSpace it
pinned), and the block returns to the pool.

Why the reaper machinery was left unchanged
-------------------------------------------

The deferred-reclamation machinery already existed and was correct:
``release_object``'s scheduler-reference deferral, ``Tcb::cleanup`` releasing
the thread's internal CSpace/VSpace pins, and ``destroy_object``'s CNode
slot-sweep. The only defect was the orphaned, un-deleted self-capabilities. The
fix therefore targets the existing revoke path rather than introducing new
teardown machinery.

Implementation
==============

A single kernel change in ``kernite/src/cap/cdt.rs``: ``delete_capability``
calls ``reparent_children`` where it previously called ``reroot_children``. The
``delete()`` doc comment in ``kernite/src/cap/cnode.rs`` was updated to describe
the new behaviour. No ``init``, userland, or ABI change.

Performance
===========

Negligible. Re-parenting relinks the same CDT pointers that re-rooting did —
O(number of direct children of the deleted slot) — with no new allocation and
no additional lock.

Ergonomics
==========

No interface change. The fix removes a latent resource leak that previously
surfaced only under sustained fork load. Correct teardown is now the default
with no new caller obligation.

Backwards Compatibility
=======================

No source or ABI/wire change. The capability-invocation interface, object
layouts, and ``init``'s spawn protocol are unchanged.

Security Considerations
=======================

Revoke-reachability is a security invariant: a capability orphaned from its
ancestor's CDT subtree cannot be revoked, so the authority it carries cannot be
withdrawn. The previous re-root behaviour silently produced unrevocable
self-capabilities on every process teardown. Re-parenting restores the
invariant that every live *ordinary* derived capability remains revocable by an
ancestor; capabilities pinned in transit are the deliberate exception and become
roots by design.

Testing
=======

- ``test_runner`` improved from 13 to 16 passing modules after the fix; the
  five fork-cascade failures were no longer gated by spawn exhaustion.
- The ``test_sched_race`` storms (fork/exit, yield, VSpace-teardown) exercise
  hundreds of teardown cycles per run.
- ``just warn`` is clean on x86_64.
- Validated by a QEMU boot of the full ``test_runner`` suite (the empirical
  "done" gate).

Documentation
=============

``kernite/src/cap/cnode.rs``'s ``delete()`` doc comment was updated to state
that ordinary children re-parent on delete while transit-pinned children detach
to a root.

Drawbacks, Alternatives, and Unknowns
=====================================

Two alternatives were considered (and, for A, partially implemented) before
settling on re-parenting:

- **Approach A** — ``init`` deletes the self slots before exit. Userland
  explicitly deletes slots 0/1/2 of the child's CNode on teardown. Rejected as
  incomplete: a process can copy or move its self-capability into another slot,
  which would still pin the CNode and prevent the reap from starting; an
  ``init``-side sweep of the fixed slots cannot see those.
- **Approach C** — a privileged kernel "destroy CSpace" operation. A new
  operation that recursively sweeps and deletes every slot of a child's root
  CNode, independent of the object reference count. Rejected as over-engineered:
  the reaper machinery already exists and is correct, so a new primitive
  duplicates existing behaviour to work around a single CDT bug.
- **Approach #2** — re-parent on delete (chosen). Repairs the *existing*
  resource-server revoke path with one local CDT change that aligns with seL4's
  MDB semantics. A single path, no new primitive, and no userland change.

**Unknown:** whether the child's self-TCB (slot 0) and self-VSpace (slot 1)
capabilities strand their own backing by the same mechanism, or are freed only
transitively once the CNode is reaped. The fix reclaims them in practice
(13 -> 16), but a dedicated audit of each self-slot's reclamation path remains
open.

Prior Art and References
========================

- **seL4** — ``src/object/cnode.c``'s ``emptySlot`` relinks a deleted slot's
  CDT predecessor and successor so derived children stay reachable, and
  ``cteRevoke`` traverses that chain. seL4's Mapping Database (MDB) is the
  direct model for the re-parent semantics adopted here.
