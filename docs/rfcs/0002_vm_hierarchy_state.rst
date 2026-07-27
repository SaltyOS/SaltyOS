=============================================================
RFC-0002: VmHierarchyState, a per-COW-tree serialization lock
=============================================================

:Status: Implemented
:Areas: Kernel; Memory
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-21
:Description: Introduce a per-COW-tree VmHierarchyState kernel object whose lock serializes every structural copy-on-write operation, closing the shm MAP_PRIVATE snapshot races F2 and F3 by construction and replacing the global COW topology lock.

Problem Statement
=================

A ``MAP_PRIVATE`` mapping, a clone, a snapshot, and a fork each create a tree
of ``MemoryObject`` instances related by copy-on-write (COW). Structural operations on
that tree — attaching a child, downgrading a parent's pages to read-only COW,
splitting a mapping on partial unmap, collapsing on destroy — must be
serialized against each other and against page faults. Two SMP races followed
from the absence of a single serializer:

- **F2** — a downgrade-to-COW walk racing a partial unmap that splits the
  mapping out from under it (downgrade walk versus unmap split).
- **F3** — the snapshot *freeze window*: between publishing a child snapshot
  and write-protecting the parent, a concurrent parent write can mutate a page
  the child already shares, so the snapshot observes a value it should not.

These are lock-ordering and serialization races; they surface only under
``--smp >= 2``. The pre-existing locking (a global ``COW_TOPOLOGY_LOCK`` plus
per-object ``commit_lock`` / ``rmap_lock`` and hand-over-hand pins) did not
serialize the structural operations cleanly, so correctness rested on fragile
per-path arguments.

This RFC does **not** fix TLB coherence. After a downgrade write-protects a
parent's PTEs, a remote CPU with a stale writable TLB entry can still write the
frozen frame until it processes the shootdown IPI; that residual *TLB tail* is
pre-existing and is addressed by separate, future work (see *Drawbacks,
Alternatives, and Unknowns*).

Summary
=======

Introduce a per-COW-tree kernel object, ``VmHierarchyState`` (object type 25).
Every ``MemoryObject`` in one COW tree shares a single ``VmHierarchyState``;
its lock nests **outside** ``VSpace.lock`` and serializes every structural
operation on that tree — snapshot, clone, fork, downgrade, fault resolution,
unmap split, and destroy. Because conflicting operations now serialize on the
tree lock, F2 and F3 are closed by construction, and the global
``COW_TOPOLOGY_LOCK`` is removed.

The state object is a capability: userland (``mmsrv``) retypes it from untyped
memory and passes it into snapshot/clone/fork, consistent with SaltyOS's rule
that every kernel object is retyped from untyped. A bounded ``RangeChangeList``
on the object pre-positions a seam for future coalesced and synchronous TLB
shootdown without changing today's correctness.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- F2 and F3 MUST be closed by construction (serialization), not by per-path
  reasoning about which interleavings are reachable.
- The lock MUST be per-COW-tree, not global, so independent trees do not
  serialize against one another.
- Holding the tree lock across TLB shootdowns MUST be deadlock-free; this relies
  on ``tlb_shootdown`` being fire-and-forget (it sends an IPI and does not wait
  for an acknowledgement).
- The tree lock MUST keep an acyclic lock order: no ``CAP_LOCK``, object
  release/reap, scheduler operation, or event-queue/wake may run under the tree
  lock. Such effects are deferred until after the lock is dropped.
- The state object MUST be a capability provisioned by userland (retyped from
  untyped), like every other kernel object.

Design
======

The copy-on-write tree
----------------------

``MAP_PRIVATE``, clone, snapshot, and fork link ``MemoryObject`` instances into a tree
(parent, shadow, child) connected by copy-on-write. A structural operation
mutates the shape of this tree or the COW state of its pages. The unit of
serialization is the tree, not the individual object: a snapshot of one parent
and a concurrent unmap of a sibling child must agree on a single order.

The hierarchy-state object
--------------------------

``VmHierarchyState { header, lock, bound, rcl }`` is a small kernel object
modeled on the existing ``MessagePipeCore`` pattern, with
``ObjectType::VmHierarchyState = 25``. Each ``MemoryObject`` gains a
``hierarchy_state: AtomicPtr<VmHierarchyState>`` and a ``hierarchy_bind_lock``.
The objects of one COW tree all point at the same ``VmHierarchyState``; a
standalone (un-bound) object has a null ``hierarchy_state`` and serializes on
its own ``hierarchy_bind_lock`` instead.

Lock ordering
-------------

The tree lock nests **outside** ``VSpace.lock``. The kernel lock-order document
(``kernite/src/mm/mod.rs``) records ``VmHierarchyState.lock (per COW tree)``
ahead of ``VSpace.lock``. The acyclicity invariant is explicit: nothing that
could re-enter the capability or scheduler subsystems — ``CAP_LOCK``,
``release_object``, a wake, a reschedule, or the reaper — runs under the tree
lock. Each such effect is recorded and performed after the lock is released.

The bind protocol
-----------------

To bind a set of objects into one tree, the kernel takes each object's
``hierarchy_bind_lock`` in address order, then the state's ``lock``, then
publishes ``hierarchy_state`` and takes a per-object reference, performs the
structural change under the tree lock, and finally runs the deferred releases
after unlock. Address-ordered acquisition plus an identity check (rejecting a
candidate equal to the source, which would otherwise appear twice in the sorted
list) keeps the protocol deadlock-free.

F3: closing the snapshot freeze window
--------------------------------------

The snapshot freeze sequence is move, retag, **downgrade the parent, then
attach the child** — in that order. Write-protecting the parent's PTEs *before*
the child becomes visible closes the PTE-level window in which a parent write
could mutate a page the child already shares. (The residual TLB tail is out of
scope; see below.)

Fault handling: the drop-revalidate dance
-----------------------------------------

A page-fault handler cannot hold ``VSpace.lock`` while acquiring the outer tree
lock without inverting the order. Handlers use a *drop-revalidate dance*: under
``VSpace.lock`` they discover and pin the fault's tree state (or the standalone
object), drop ``VSpace.lock``, acquire the tree lock, re-look-up the VMA, and
revalidate before acting. The demand-fault path takes the tree lock over the
whole fault, so correctness follows by construction rather than from an argument
that resolution and supply cannot interleave. Because ``tlb_shootdown`` is
fire-and-forget, holding the tree lock across shootdowns is deadlock-free.

Removing the global topology lock
---------------------------------

With the tree lock serializing structural operations, the global
``COW_TOPOLOGY_LOCK`` is removed, along with redundant hand-over-hand pins and
an inline re-validation in the map path that the tree lock makes unnecessary.

RangeChangeList: coalesced TLB invalidation
-------------------------------------------

A bounded accumulator, ``rcl``, on the state object records ``(vspace, va)``
pairs for the operations that run under the tree lock — downgrade, converge,
destroy teardown, the multi-page unmap split, and a bound single-page unmap.
Only the remote (cross-CPU IPI) shootdown is deferred this way; the local
``invlpg`` is always immediate. The accumulated entries are drained to a local
buffer under the lock and flushed, coalesced, after the lock is dropped — except
that if the accumulator fills (``RCL_CAP`` = 16) mid-walk it flushes immediately
while the tree lock is still held. The single-page page-fault paths keep their
immediate per-page shootdown. This post-unlock flush is the integration seam for
future synchronous / quarantine shootdown.

Userland provisioning of the state object
-----------------------------------------

Snapshot, clone, and fork of a standalone-parent tree require a
``VmHierarchyState`` capability. ``mmsrv`` provisions it
(``alloc_vm_hierarchy_state``: allocate a slot, retype
``OBJ_VM_HIERARCHY_STATE`` from untyped, pass it as an argument, and drop the
caller's copy after the call). When the source tree is already bound (a chained
snapshot or a clone that adopts an existing tree), the kernel adopts the
existing state and leaves the passed capability for the caller to reclaim — so
``mmsrv`` provisions uniformly without tracking whether the source is bound.

Implementation
==============

The work landed in phases: the object and its retype/finalize plumbing; the
snapshot freeze reorder; the fault drop-revalidate dance; unmap-split and
destroy under the tree lock with the global topology lock removed; migration of
the ``MemoryObject``-capability syscalls; uniform binding for the pager, clone,
and fork paths; the ``RangeChangeList``; and finally the userland provisioning
and the compile gate.

A pitfall: silent-miss type decoders
------------------------------------

Adding an ``ObjectType`` is mostly compile-checked: an exhaustive ``match``
will not build with a variant missing. The one site that silently mis-handles a
new type is the raw-number decoder in ``syscall_untyped_retype`` (a
``match raw & 0xFF { ... _ => InvalidArgument }``). Type 25 hit the wildcard, so
every retype of it failed, ``mmsrv``'s provisioning returned ``None``, and every
fork failed with ``OUT_OF_MEMORY`` (``err = 0x5``). The fix added the
``25 => VmHierarchyState`` decoder arm. Lesson: when adding an ``ObjectType``,
audit wildcard / raw-number decoders, which the discriminant-versus-uapi size
assertions do not cover.

Performance
===========

The lock is per-COW-tree, so independent trees never contend. For the multi-page
structural operations, ``RangeChangeList`` coalesces what were per-page
shootdowns into one post-unlock flush; single-page fault paths stay immediate.
The per-tree memory cost is one ``VmHierarchyState`` object
(``KERNITE_VM_HIERARCHY_STATE_BYTES`` = 312 bytes), allocated once per tree.

Ergonomics
==========

Userland must provision the hierarchy-state capability for snapshot, clone, and
fork. ``mmsrv`` encapsulates this in ``alloc_vm_hierarchy_state``, mirroring its
existing watch-pool retype. The kernel's adopt-the-existing-state behaviour for
an already-bound tree lets ``mmsrv`` provision uniformly without tracking the
source's bound state.

Backwards Compatibility
=======================

This is a kernel and UAPI change, applied in lockstep with the one userland
caller (``mmsrv``):

- A new object type ``OBJ_VM_HIERARCHY_STATE = 25``.
- ``MO_SNAPSHOT`` and ``MO_CLONE`` take the state capability as an added
  argument (``MO_CLONE`` is now three arguments); ``vspace_fork_range`` packs
  the state capability into the high 32 bits of its first argument.
- ``KERNITE_VM_HIERARCHY_STATE_BYTES`` = 312 (a 48-byte base plus 264 bytes for
  the ``RangeChangeList``).

No POSIX or Win32 personality-visible interface changes; ``mmap``, ``fork``, and
the snapshot/clone surface seen by applications are unchanged.

Security Considerations
=======================

The races corrupt ``MAP_PRIVATE`` snapshot isolation: F3 lets a snapshot share a
page that the parent then mutates, leaking the parent's later writes across the
private-copy boundary. Closing F2 and F3 by construction restores the integrity
guarantee that a private snapshot observes a stable, isolated view of its source
at the instant it was taken. The residual TLB tail (below) is a known,
pre-existing gap in that guarantee under ``--smp >= 2`` until synchronous
shootdown lands.

Testing
=======

- A concurrent regression test, ``test_shm_snapshot_f3_race`` (Test 4d), was
  added: a writer thread repeatedly stores to a shared parent page while the
  main thread takes ``MAP_PRIVATE`` snapshots and asserts each is stable. It is
  meaningful only under ``--smp >= 2`` — the sequential case cannot exhibit F3,
  because the snapshot syscall (including the downgrade) completes before the
  next instruction runs.
- ``just warn`` is clean on both x86_64 and aarch64.
- QEMU-verified after fixing the type-25 decoder regression: fork succeeds and
  the suite advances.

Documentation
=============

``kernite/src/mm/mod.rs``'s lock-ordering document was updated to place
``VmHierarchyState.lock (per COW tree)`` ahead of ``VSpace.lock`` and to state
the acyclicity invariant (no capability, release, wake, or scheduler operation
under the tree lock).

Drawbacks, Alternatives, and Unknowns
=====================================

- **Keep the global topology lock.** The previous design used a single global
  ``COW_TOPOLOGY_LOCK``. Rejected: a global lock serializes every COW tree
  against every other, and it still required per-path arguments for the fault
  and snapshot orderings.
- **Argue fault correctness per path.** For the demand-fault path, an argument
  that resolution and supply cannot race was considered. Rejected in favour of
  taking the tree lock over the whole fault, which is correct by construction
  and far easier to audit.
- **Known limitation: the TLB-coherence tail.** The tree lock fixes lock
  ordering, not TLB coherence. Because ``tlb_shootdown`` is fire-and-forget, a
  remote CPU with a stale writable TLB entry can write a just-frozen page (F3) or
  a just-freed frame (the same tail exists in ``evict_clean_page``) until it
  processes the IPI. This is pre-existing and is closed only by synchronous
  shootdown with frame quarantine; the ``RangeChangeList`` post-unlock flush is
  the pre-positioned seam for that future work.
- **Unknown: single-page unmap batching.** A bound single-page unmap is already
  wired into the ``RangeChangeList`` seam, but because it shoots down a single
  page, batching there yields no coalescing today; only the future synchronous
  path will make the seam pay off.

Prior Art and References
========================

- **Zircon (Fuchsia)** — ``VmHierarchyState`` is Zircon's shared state object
  for a VMO hierarchy; the per-tree lock and the name are taken from it.
- **Linux** — ``dup_mmap`` performs fork copy-on-write per-VMA. SaltyOS binds
  fork per region (per ``MemoryObject``), matching the per-mapping / per-VMO
  fork granularity of both Linux and Zircon.
