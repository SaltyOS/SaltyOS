=============================================================
ADR-0001: Borrowed-frames sources as COW-break source pages
=============================================================

:Status: Implemented
:Areas: kernite mm (fault path); mmsrv (exec staging, mmap)
:Authors: Hamin Sung
:Reviewers: MiniMax M3
:Date: 2026-06-27
:Supersedes: none
:Depends: docs/rfcs/0004_exec_memory_object_primitives.rst (``MO_CLONE_RANGE``),
  docs/rfcs/0009_capability_bounded_wx.rst (borrowed-frames MoKind as a valid
  ``MO_CLONE_RANGE`` parent; writable data as a private COW child).
:Description: Extend the kernel fault-path COW break to recognise
  borrowed-frames MO pages as a safe copy source, and revert mmsrv's writable
  data run back to a private ``MO_CLONE_RANGE`` child of the exec / code MO
  (RFC-0009's design), replacing the eager-copy workaround another session
  applied to unblock boot.

Context
=======

SaltyOS's code MemoryObjects for initrd-resident libraries (``ldtrona-elf.so``,
``libc.so``, etc.) are *borrowed-frames MOs*: their pages live in the immortal
initrd device-untyped, are never owned/committed/evicted/freed by the MO, and
are populated once via ``populate_borrowed``. The design treats them as a
valid ``MO_CLONE_RANGE`` parent so a writable data child can be bound over a
sub-range and break privately on first write — the same lazy sharing model
that disk-backed code MOs get from the page cache.

Two paths in the kernel actually need to honour that:

- **Map path** (``VSPACE_MAP_MO``, ``kernite/src/syscall/vspace.rs:3355``) —
  calls ``effective_page_source_locked`` to classify the source, honours the
  ``borrowed: true`` flag (``vspace.rs:3499``: only rejects non-borrowed
  device-MEM), and installs a COW PTE for inherited parent frames
  (``vspace.rs:3467-3543``). Correct.
- **Fault path** (``handle_cow_fault`` / ``handle_cow_fault_pooled`` in
  ``kernite/src/mm/vspace.rs``) — gates the break with
  ``cow_copy_source_is_data_page(old_phys)`` (``vspace.rs:3992``), a
  phys-only filter that accepts ``MoData``-owned frames and non-device
  ``UntypedReserved`` frames and rejects everything else. Because borrowed
  frames live in a *device* untyped, the filter returns ``false`` and the
  fault propagates as ``VSpaceError::NotCow`` → mmsrv IPC → an unresolved
  fault. **A first write to any COW PTE whose source is a borrowed frame
  loops indefinitely.**

The fault path was the only outlier. The explicit ``cow_break_for_write``
(``cap/memory_object.rs:1335``) already handles borrowed sources correctly —
it discards the ``borrowed`` flag from ``resolve_page_depth_locked`` and
copies bytes regardless. ``MO_WRITE`` is gated by a ``BorrowedFrames``
self-check on the *target* MO (``syscall/mo.rs:1145``), which is unrelated to
the source-classification gate.

Past workaround (rejected)
--------------------------

A previous session hit the boot-time expression of the bug — ``ldtrona-elf.so``
``self_relocate`` writing ``.data`` at offset ``0x46000``, triggering a COW
fault on a borrowed-frames parent and looping — and worked around it by
changing mmsrv's DATA run from ``MO_CLONE_RANGE`` (the design) to an eager
anon copy via ``copy_file_pages_into_private_mo`` (``dispatch.rs:2144``).
That unblocked boot but:

- diverged from the RFC-0009 design (writable data must be a private COW
  child of the code MO; the borrowed-frames parent is the WHOLE POINT of
  initrd sharing);
- left the *runtime* mmap path (``handle_mmap_mo_private``,
  ``mmap.rs:738``) still using ``MO_CLONE``, so any rtld-driven load of an
  initrd-resident DSO would hit the same hang;
- did not address the kernel-side root cause: the fault-path filter.

The eager-copy helper is preserved for the use cases that genuinely need it
(boundary carve pages, BSS tail).

Decision
========

Two coupled changes:

1. **Kernel fault path: chain-aware source classification** (``vspace.rs``).
   Replace ``cow_copy_source_is_data_page(phys) -> bool`` with
   ``cow_break_source_locked(child_mo, mo_page_idx) -> Option<u64>``. The
   new helper:

   - calls ``effective_page_source_locked`` (the single source of truth for
     "what backs this page") under the per-tree ``VmHierarchyState`` lock;
   - returns ``Some(phys)`` for ``Resident { borrowed: true, .. }`` (any
     borrowed-frames source — the new case);
   - returns ``Some(phys)`` for ``Resident { borrowed: false, .. }`` only if
     the phys passes the legacy filter (a true device-MEM frame must not be
     touched);
   - returns ``None`` for ``Pager { .. } | Zero | Failed`` — no resident frame
     to copy from; the caller falls through to the pager or mmsrv IPC.

   The legacy phys-based filter is split out into
   ``phys_is_touchable_data_page`` (``vspace.rs:4056``) so the borrowed and
   non-borrowed cases share the same check by composition.

   Both call sites (``handle_cow_fault`` at ``vspace.rs:4246``,
   ``handle_cow_fault_pooled`` at ``vspace.rs:4534``) use the helper's
   returned ``src_phys`` for **both** the gate and the byte-copy source. The
   pool path additionally resolves ``src_phys`` *before* consuming the pool
   entry, so a rejection leaves the pool intact. PTE ``old_phys`` is no
   longer passed across the helper boundary — a single chain walk under the
   tree lock is the only authority.

2. **mmsrv: restore the COW data child** (``dispatch.rs`` + ``mmap.rs``).
   The exec-staging DATA run is now published via a new
   ``stage_exec_cow_data`` helper (``dispatch.rs:2421``) that:

   - retypes a fresh anon child MO sized to the run (``file_pages *
     KERNITE_PAGE_BYTES``);
   - binds it as a ``MO_CLONE_RANGE`` sub-range child of the exec MO (mmsrv
     holds ``READ`` on the source and ``WRITE`` on the child, satisfying the
     primitive's rights contract);
   - publishes the COW child as a mapped region via ``MappingPlan`` with
     ``fork_policy: InheritCow``, ``BackingDescriptor::Anon { mo_offset: 0
     }``, ``mo_offset_pages: 0`` (the child is sized to the run);
   - emits a trailing BSS region as a fresh demand-zero anon (matching
     ``stage_exec_materialize``'s tail).

   Both ``handle_stage_exec_mo`` and ``handle_stage_provided_mo_region``
   route ``STAGE_IMAGE_KIND_DATA`` through this helper. ``STAGE_FLAG_EXEC_MATERIALIZE``
   now means specifically "TEXT/RODATA boundary carve" — DATA always takes
   the COW path regardless of the flag, which is what the design actually
   says.

   ``handle_mmap_mo_private`` (``mmap.rs:738``) gets the same treatment for
   ``MMAP_KIND_MO``: the child MO is bound via ``MO_CLONE_RANGE`` over the
   mapped sub-range, and the install size is ``pages * KERNITE_PAGE_BYTES``
   (sub-range only) — the kernel resets ``child.page_count`` to the sub-range
   on bind, so the smaller install saves an untyped chunk reservation. The
   ``MMAP_KIND_SHM_MO`` branch is unchanged: ``H`` still freezes the whole
   source, so it stays at ``full_size``.

Consequences
============

Positive
--------

- **Restored RFC alignment.** Writable data is once again a private
  ``MO_CLONE_RANGE`` child of the code MO; the borrowed-frames parent is
  honoured as a ``MO_CLONE_RANGE`` parent in every layer (map, fault,
  explicit break). The ``MO_CLONE_RANGE`` primitive is exercised by both
  exec staging and runtime mmap.
- **Cross-instance sharing.** Unmodified ``.data`` pages of initrd-resident
  libraries stay shared between every process that maps them. Reads through
  the COW PTE point at the borrowed frame until the first write.
- **Runtime DSO path fixed.** rtld loading an initrd DSO via
  ``MMAP_KIND_MO, MM_FLAG_PRIVATE`` no longer hangs — its COW child is a
  valid ``MO_CLONE_RANGE`` of a borrowed-frames parent, and the fault path
  can break it.
- **Memory efficiency.** mmsrv install sizing on the MO branch uses the
  sub-range size; SHM hidden-parent install is unchanged.

Negative
--------

- **Hot-path overhead.** Every COW fault now walks the MO chain
  (``effective_page_source_locked``) instead of a single ``pmm_lookup``.
  The walk is bounded by the tree's depth (RFC-0002 acyclicity invariant),
  typically one or two MO levels. The same walk is already on the map path,
  so the fault path is now in line with it rather than qualitatively
  different.

Neutral
-------

- The eager-copy helper ``copy_file_pages_into_private_mo`` stays for the
  TEXT/RODATA boundary-carve path and the trailing BSS path; both are
  unaffected.
- **Single source of truth.** Callers must use the helper's returned phys for
  both the gate and the copy. Two-source confusion (PTE phys vs chain phys)
  is no longer expressible.

Rejected alternatives
=====================

- **Eager anon for all DATA** (the previous-session workaround). Unblocks
  boot, leaves runtime DSO exposed, diverges from the design. The kernel
  limitation is hidden behind a workaround rather than fixed.
- **Detect borrowed sources in mmsrv and route them through eager copy.**
  Same divergence; doesn't fix the kernel; requires every mmsrv path that
  binds COW children of code MOs to special-case the source kind.
- **Forbid binding COW children of borrowed-frames MOs at all.** Defeats the
  purpose of the borrowed-frames MoKind as a shared read-only mapping with
  deferred private COW breaks; regresses initrd-resident code sharing.

Implementation
==============

- ``kernite/src/mm/vspace.rs``

  - new ``phys_is_touchable_data_page`` (split-out legacy filter,
    ``vspace.rs:4056``);
  - new ``cow_break_source_locked`` (chain-aware gate returning
    ``Option<u64>``, ``vspace.rs:4025``);
  - ``handle_cow_fault`` uses ``src_phys`` from the helper for the copy and
    for ``cow_install_atomic``'s ``retag_from`` argument (``vspace.rs:4246``);
  - ``handle_cow_fault_pooled`` resolves ``src_phys`` before consuming the
    pool entry (``vspace.rs:4534``).

- ``userland/core/mmsrv/src/dispatch.rs``

  - new ``stage_exec_cow_data`` (``dispatch.rs:2421``) — exec-staging
    COW data child;
  - ``handle_stage_exec_mo`` DATA arm redirects to it
    (``dispatch.rs:1853``);
  - ``handle_stage_provided_mo_region`` DATA arm redirects to it
    (``dispatch.rs:1980``).

- ``userland/core/mmsrv/src/mmap.rs``

  - ``handle_mmap_mo_private`` ``MMAP_KIND_MO`` branch uses
    ``MO_CLONE_RANGE`` with a sub-range-sized child install
    (``mmap.rs:776-868``);
  - ``MMAP_KIND_SHM_MO`` branch unchanged.

Locking
=======

The tree-lock precondition is enforced by the existing dance:

- ``discover_fault_lock`` (``vspace.rs:4123``) pins the per-tree
  ``VmHierarchyState`` before the fault path enters the tree lock;
- both call sites acquire the tree lock under IRQs-disabled before calling
  the helper (``vspace.rs:4142``, ``vspace.rs:4391``);
- revalidation of ``child_mo.hierarchy_state == tree_state`` happens before
  the helper call (``vspace.rs:4234``, ``vspace.rs:4431``);
- the helper's internal chain walk briefly takes each ancestor's
  ``commit_lock`` (``memory_object.rs:1174``) and releases it before
  returning; outer (tree) → inner (commit_lock) order is preserved.

mmsrv holds ``STATE_LOCK`` throughout ``stage_exec_cow_data`` (no blocking
I/O); the trailing revalidation is therefore redundant in steady state but
matches the existing ``stage_exec_materialize`` discipline and provides
defence-in-depth.

Verification
============

- ``just warn``: layering-check ok; full clean rebuild; 230/230 build steps;
  no new warnings introduced.
- Boot smoke (out of scope for this ADR): the authors separately verified
  ``just run --headless --smp 2`` reaches mmsrv / namesrv / logsrv, and
  SMP race coverage via the existing ``handle_cow_fault_pooled`` race-lost
  / sibling converge path.
