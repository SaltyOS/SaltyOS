=====================================================================
ADR-0007: MAP_FIXED replacement semantics and POSIX-conformant munmap
=====================================================================

:Status: Implemented
:Areas: mmsrv (mmap, txn, dispatch); trona protocol ``mm`` wire flags;
  trona runtime client ``mm`` flag translation; test_runner ``test_mmap``
:Authors: Hamin Sung
:Reviewers: GLM 5.2, GPT 5.5
:Date: 2026-06-29
:Supersedes: none
:Depends: ``lib/trona/protocol/src/mm.rs`` (single source of truth for
  ``MM_MMAP`` flag bits); mmsrv's ``park_vfs_writeback_group`` writeback
  park/resume model (``userland/core/mmsrv/src/mmap.rs``); the per-client
  region index ``ClientVm::regions_index`` (``userland/core/mmsrv/src/
  client.rs``).
:Description: Make ``MAP_FIXED`` POSIX-conformant in mmsrv — it now
  replaces every mapping (full or partial) overlapping the requested
  range, writeback-aware for shared-dirty pages — distinguish it from
  ``MAP_FIXED_NOREPLACE`` (fail with ``EEXIST`` on overlap) via a new
  wire bit, and make ``munmap`` POSIX-conformant (multi-region,
  hole-tolerant) by sharing one range-teardown primitive.

Context
=======

``test_runner`` ``test_mmap`` "Test 7: MAP_FIXED replacement" and
"Test 8: partial-overlap MAP_FIXED" failed. The root cause was that mmsrv
treated ``MAP_FIXED`` like ``MAP_FIXED_NOREPLACE``.

Two compounding defects
-----------------------

1. **MAP_FIXED rejected overlaps.** Each mmap handler's ``MAP_FIXED`` arm
   called ``range_is_free(vm, hint, size, image_res)`` and replied
   ``KERNITE_ERR_ALREADY_MAPPED`` (0x14, errno ``EEXIST``) when the target
   range overlapped an existing mapping. POSIX ``MAP_FIXED`` must instead
   discard/overwrite every mapping (full or partial) in the range.

2. **The same gap lived in munmap.** ``handle_munmap`` called
   ``txn::unmap`` exactly once. ``txn::unmap`` finds the single region
   containing ``base`` and requires the requested range to be fully inside
   that one region (multi-region ranges → ``EINVAL``; an address with no
   region → ``NOT_FOUND``). Separately, the writeback walker
   ``walk_file_backed_flush_segments`` returned ``NOT_FOUND`` on a hole
   before teardown was reached. POSIX ``munmap`` must remove/split every
   region in an arbitrary range and treat holes as no-op success.

Wire flag collapse
------------------

The client's ``mmsrv_flags_from_posix`` collapsed both POSIX flags into a
single bit::

    if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 { out |= MM_FLAG_FIXED }

so the server could not tell "replace" from "fail-on-overlap" even after
the teardown logic was fixed. A distinct wire bit was required.

Decision
========

A single shared range-teardown primitive, applied to both MAP_FIXED
replacement and munmap, plus a new wire bit and a writeback-aware
park/resume continuation for replacement.

Patch 1 — Wire bit + flag single-source-of-truth
------------------------------------------------

- ``lib/trona/protocol/src/mm.rs`` adds
  ``pub const MM_FLAG_FIXED_NOREPLACE: u64 = 1 << 4;`` (bits 0=FIXED,
  1=GROWSDOWN, 2=LAZY, 3=PRIVATE; bit 4 free). It is always accompanied by
  ``MM_FLAG_FIXED`` (NOREPLACE implies fixed placement).
- mmsrv's local ``FLAG_FIXED / FLAG_GROWSDOWN / FLAG_LAZY`` aliases are
  replaced with protocol-const imports (mirroring how ``FLAG_PRIVATE`` was
  already imported), and ``MM_FLAG_FIXED_NOREPLACE`` is imported as
  ``FLAG_FIXED_NOREPLACE``. The protocol file is the one true location;
  no value is duplicated in mmsrv.
- ``lib/trona/runtime/src/client/mm.rs`` ``mmsrv_flags_from_posix`` splits
  the two POSIX flags: ``MAP_FIXED_NOREPLACE`` →
  ``MM_FLAG_FIXED | MM_FLAG_FIXED_NOREPLACE``; plain ``MAP_FIXED`` →
  ``MM_FLAG_FIXED`` only. ``MAP_LAZY`` / ``MAP_PRIVATE`` arms unchanged.

Patch 2 — Shared teardown primitive ``txn::force_unmap_range``
--------------------------------------------------------------

New ``pub(crate) unsafe fn force_unmap_range`` (``txn.rs``) removes every
mapping overlapping ``[base, base + pages*PAGE)``. It loops, re-querying
after each mutation (no iterator held across ``&mut vm``)::

    loop {
        let Some(id) = range_overlaps_mapping(vm, base, end - base)
            else { return Ok(()) };          // holes or done => success
        let (r_base, r_end) = { vm.region(id) } -> (base, va_end);  // scoped
        let isect_base = max(base, r_base);
        let isect_end  = min(end,  r_end);
        let isect_pages = (isect_end - isect_base) / PAGE;
        txn::unmap(vm, isect_base, isect_pages, vspace, self_vm,
                   mo_registry, frames)?
    }

``txn::unmap``'s single-region containment check always passes because the
intersection is by construction a sub-range of ``[r_base, r_end)``. A
whole region takes ``txn::unmap``'s whole branch (drops the guard
reservation when present); a strict head/tail/middle overlap is split by
``split_region``; a pure-middle overlap (region straddles the range) yields
before+after fragments. Reservations that are not regions (image
reservations, plain reservations) are untouched.

Borrow rule: the ``vm.region(id)`` borrow ends (scoped block) before the
``&mut vm`` call; ``iter_regions()`` is never held across a mutation.
Partial overlap over a *guarded stack* region is rejected by
``split_region`` (``EINVAL``) — consistent with how ``mprotect`` and
partial ``munmap`` already treat guarded stacks; whole-overlap of a
guarded stack takes the whole branch and correctly drops the guard.

Patch 3 — Hole-tolerant writeback walk
--------------------------------------

``walk_file_backed_flush_segments`` now iterates regions overlapping
``[vaddr, end)`` and skips holes instead of returning ``NOT_FOUND`` (it
previously errored when ``find_region(cur)`` missed or when
``cur < region.base``). ``msync`` over a hole becomes a no-op success
(its ``Ok(false)`` arm already replies ``TRONA_OK``); ``munmap`` over a
range with holes reaches teardown instead of erroring.

Patch 4 — POSIX-conformant munmap
---------------------------------

``handle_munmap``'s inline ``Ok(false)`` arm and the
``VFS_WRITEBACK_OP_MUNMAP`` arm of ``finish_vfs_writeback_group`` call
``txn::force_unmap_range`` instead of ``txn::unmap``. ``munmap`` now
handles multi-region ranges, partial overlaps across several regions, and
holes as no-op success.

Patch 5 — Per-kind install helpers (extracted, behavior-identical)
------------------------------------------------------------------

Each handler's post-placement install tail is extracted into a free
function callable from both the synchronous replace path and the resume
path:

- ``install_anon`` — from ``handle_mmap`` after ``va_base``.
- ``install_mo_shared_from_stable(stable_mo_slot, ...)`` — shared MO tail;
  builds the ``MappingPlan`` with ``FileBacked`` backing adopting an
  already-moved stable cap.
- ``install_mo_private_from_source(...)`` — private MO path; seeds the COW
  child via ``MO_CLONE`` from a stable source slot instead of the
  ephemeral receive slot.
- ``install_device_from_slot(...)`` — device mapping install.

A ``CapSlotCleanup`` enum plus ``delete_preserved_cap`` and
``cleanup_mmap_fixed_replace_ctx`` centralise cap freeing on every error
path so a preserved MO/device cap never leaks.

Patch 6 — MAP_FIXED replacement in the three arms
-------------------------------------------------

In each handler's ``flags & FLAG_FIXED != 0`` block (after alignment/bounds
checks), the ``range_is_free`` rejection is replaced by::

    if flags & FLAG_FIXED_NOREPLACE != 0 {
        if !range_is_free(vm, <span>, <size>, <image_res>) {
            reply ALREADY_MAPPED; return;        // EEXIST preserved
        }
        va_base = hint;
    } else {
        // POSIX MAP_FIXED: replace.
        <move any incoming ephemeral cap to a stable slot>   // MO + device
        match park_vfs_writeback_group(buf, state, client_idx, hint, size,
                MS_SYNC, VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE,
                VfsWritebackContinuation::MmapFixedReplace(ctx)) {
            Ok(true)  => return,                 // parked; resume later
            Ok(false) => force_unmap_range(...)? ; <install_*>(),
            Err(code) => { cleanup_preserved_cap(); reply code; return; }
        }
    }

The MO and device paths receive the caller's cap in the per-IPC receive
slot, which is gone after a park. For the fixed-replace path that cap is
``cnode_move``\ d into a stable slot **before** ``park_vfs_writeback_group``
and carried in the resume context; both the synchronous ``Ok(false)`` path
and the resume install from the stable slot. Non-replace / NOREPLACE /
auto-place paths keep their original cap-move location.

Patch 7 — Resume continuation for ``MMAP_FIXED_REPLACE``
--------------------------------------------------------

- ``const VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE: u8 = 3`` (after MUNMAP=1,
  MSYNC=2).
- ``MmapFixedReplaceCtx`` (kind discriminant + hint/size/prot/flags/image
  fields + the preserved stable slot + reply target) is carried by
  ``PendingVfsWritebackGroup`` via a ``VfsWritebackContinuation`` enum
  (``Munmap | Msync | MmapFixedReplace(MmapFixedReplaceCtx)``), so every
  resume path is uniform.
- ``park_vfs_writeback_group`` takes the continuation (``Munmap`` /
  ``Msync`` for the existing callers) and writes it into the allocated
  group record before returning ``Ok(true)``.
- ``finish_vfs_writeback_group`` adds the third arm: re-validate client
  epoch (reuse the MUNMAP arm's ``INVALID_OPERATION`` guard; on mismatch
  defensively free the preserved cap); ``force_unmap_range`` (dirty pages
  already flushed); dispatch to the matching ``install_*`` helper from the
  context; reply via ``send_mmap_result_to_target`` (parked target). On
  teardown or install error, free the preserved cap then reply the code.

Patch 8 — State-aware handlers + dispatch
-----------------------------------------

``handle_mmap`` / ``handle_mmap_mo`` / ``handle_mmap_device`` now take
``client_idx: u32, state: &mut ServerState`` (they previously took
``&mut ClientState`` / ``&mut ClientVm``) so they can call
``park_vfs_writeback_group``. ``dispatch.rs`` routes ``MM_MMAP`` through
the state-aware handler, before the per-client mutable borrow — the same
shape ``handle_munmap`` / ``handle_msync`` already use. The
``state`` ↔ ``vm`` borrows are temporal (park returns before the handler
touches ``vm`` again).

Consequences
============

Positive
--------

- ``MAP_FIXED`` now replaces overlapping mappings (full and partial),
  matching POSIX. Test 7 (full replace) and Test 8 (partial replace) pass.
- ``MAP_FIXED_NOREPLACE`` continues to fail with ``EEXIST`` on overlap,
  now distinguished from ``MAP_FIXED`` by an explicit wire bit; the new
  collision test guards against regressing the two flags back into one.
- ``munmap`` is POSIX-conformant: multi-region ranges, partial overlaps
  across several regions, and holes (no-op success). The new Test 4b
  covers multi-region and hole ranges.
- Shared-dirty replacement is correct: dirty ``MAP_SHARED`` pages in the
  replaced range are flushed via the existing writeback park/resume
  before teardown. The new Test 9 (``MAP_SHARED`` ``MAP_FIXED`` with file
  offset) exercises this path.
- One teardown primitive serves both MAP_FIXED replacement and munmap;
  the single-region/hole bugs in ``munmap`` are closed by the same change
  that fixes ``MAP_FIXED``.
- mmsrv's local flag aliases are gone; the protocol file is the single
  source of truth for every ``MM_FLAG_*`` bit, so future drift is a
  compile error.

Negative
--------

- The three mmap handlers are now ``&mut ServerState``-based and route
  through dispatch before the per-client borrow. The control flow is
  heavier than the old synchronous ``range_is_free`` check, and the
  park/resume continuation plus per-kind install helpers are the bulk of
  the diff.
- The resume path is reached only when the *replaced* mapping is
  dirty-shared ``FileBacked``. It is required for POSIX correctness but is
  not exercised by the common (anonymous / private) replace cases.

Neutral
-------

- ``txn::unmap`` is unchanged; ``force_unmap_range`` composes it. The
  whole-region guard-reservation drop and the ``split_region`` semantics
  are reused verbatim.
- ``walk_file_backed_flush_segments``'s contract change (hole-tolerant)
  also makes ``msync`` over a hole a no-op success, which is more
  POSIX-correct than the prior ``NOT_FOUND``.

Rejected alternatives
=====================

- **Single-region-only MAP_FIXED replacement (pass Test 7/8, skip the
  rest).** Would leave ``MAP_FIXED`` non-conformant for multi-region
  ranges and leave the ``munmap`` multi-region/hole bugs untouched. The
  shared primitive is the correct shape; applying it to ``munmap`` too is
  the same work, not more.
- **Keep collapsing ``MAP_FIXED`` and ``MAP_FIXED_NOREPLACE`` into one
  bit.** Once plain ``MAP_FIXED`` replaces, ``NOREPLACE`` would also
  replace instead of failing with ``EEXIST``. A distinct wire bit is
  required for both to be correct simultaneously.
- **Make the replaced range's writeback synchronous.** The vfs writeback
  is asynchronous (``MP`` messages). Correctness requires the existing
  park/resume; there is no synchronous shortcut.
- **Detect and special-case shared-dirty replacement in ``release_region_backing``
  instead of the park/resume flow.** ``release_region_backing`` for
  ``FileBacked`` drops the cap; it does not flush dirty pages. Routing
  through ``park_vfs_writeback_group`` reuses the proven munmap/msync
  writeback path.
- **Per-kind resume via re-dispatching the whole handler in "resume
  mode".** Rejected in favour of extracted install helpers: explicit,
  auditable, and the synchronous and resume paths share one install
  function per kind.

Implementation
==============

- ``lib/trona/protocol/src/mm.rs`` — adds ``MM_FLAG_FIXED_NOREPLACE``
  (``1 << 4``).
- ``lib/trona/runtime/src/client/mm.rs`` — ``mmsrv_flags_from_posix``
  splits ``MAP_FIXED`` / ``MAP_FIXED_NOREPLACE``.
- ``userland/core/mmsrv/src/txn.rs`` — adds ``force_unmap_range``
  (re-query loop over ``range_overlaps_mapping`` → ``txn::unmap`` on the
  per-region intersection).
- ``userland/core/mmsrv/src/mmap.rs``

  - replaces local ``FLAG_*`` aliases with protocol imports; adds the
    ``FLAG_FIXED_NOREPLACE`` alias;
  - adds ``VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE``, ``MmapFixedReplaceCtx``,
    ``VfsWritebackContinuation``; threads the continuation through
    ``park_vfs_writeback_group`` and ``PendingVfsWritebackGroup``;
  - ``CapSlotCleanup``, ``delete_preserved_cap``,
    ``cleanup_mmap_fixed_replace_ctx`` for error-path cap freeing;
  - install helpers ``install_anon``, ``install_mo_shared_from_stable``,
    ``install_mo_private_from_source``, ``install_device_from_slot``;
  - the three ``MAP_FIXED`` arms (``handle_mmap`` / ``handle_mmap_mo`` /
    ``handle_mmap_device``) gain the NOREPLACE-vs-replace dispatch and the
    writeback-aware teardown-then-install;
  - ``walk_file_backed_flush_segments`` becomes hole-tolerant;
  - ``handle_munmap`` and ``finish_vfs_writeback_group`` use
    ``force_unmap_range``;
  - ``finish_vfs_writeback_group`` gains the ``MmapFixedReplace`` resume
    arm and ``send_mmap_result_to_target``;
  - the handlers become ``client_idx`` + ``state``-based.
- ``userland/core/mmsrv/src/dispatch.rs`` — routes ``MM_MMAP`` through the
  state-aware handler before the per-client mutable borrow.
- ``userland/tests/test_runner/src/test_mmap.rs`` — Test 4b (multi-region
  and hole ``munmap``), the ``MAP_FIXED_NOREPLACE`` collision assertion
  (expects ``EEXIST`` and an undisturbed existing mapping), and Test 9
  (``MAP_SHARED`` ``MAP_FIXED`` with file offset, exercising the writeback
  park/resume path). Tests 7 and 8 are unchanged.

Verification
============

- ``just warn``: full layering-check + clean recompile, no new warnings
  from the touched files.
- ``test_runner`` ``test_mmap`` (QEMU, serial):

  - Test 7 (full ``MAP_FIXED`` replace) → ``PASS``;
  - Test 8 (partial-overlap ``MAP_FIXED``) → ``PASS``;
  - Test 4b (multi-region and hole ``munmap``) → ``PASS``;
  - ``MAP_FIXED_NOREPLACE`` collision → ``EEXIST``, existing mapping
    untouched → ``PASS``;
  - Test 9 (``MAP_SHARED`` ``MAP_FIXED`` with file offset) → ``PASS``.

- The author separately verified ``just run`` reaches the test output and
  confirmed the above cases pass; the implementation was produced via
  delegated execution (codex / GPT 5.5) and reviewed by GLM 5.2.
