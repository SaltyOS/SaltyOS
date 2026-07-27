=====================================================================
ADR-0006: PE spawn/exec layout, init self-expand, and ldsrv PE adopt
=====================================================================

:Status: Implemented
:Areas: libtrona runtime slot allocator; libtrona loader common PE
  planner; libtrona protocol ldsrv comments; userland core init
  supervisor (lifecycle, boot_core, mm_ipc, ldsrv_adopt, spawn plan);
  userland core ldsrv resolve
:Authors: Hamin Sung
:Reviewers: GPT 5.5, MiniMax M3
:Date: 2026-06-28
:Supersedes: none
:Depends: ``kernite/include/uapi/uapi.rs`` slot allocator kernel ABI;
  ``lib/trona/runtime/src/spawn/layout.rs`` VmClientLayout contract;
  ``lib/trona/protocol/src/ldsrv.rs`` LDSRV_ADOPT_OBJECT wire format
:Description: Repair the PE spawn/exec layout contract, give init a
  working CSpace self-expansion path with a pinned quota, harden the
  runtime slot allocator's lazy-bind against exhaustion, split the
  spawn receive window between ldsrv and other services, and prewarm
  the ldsrv cache with PE files so first PE ``resolve_main`` is a
  cache hit.

Context
=======

The Stage-3 boot test programs (``hello_pe``, ``console_stress_pe``,
``vfs_stress_pe``, fork/exec stress) failed mid-run because four
distinct bugs compounded. None of them were in the kernel proper; they
sat at the init/ldsrv/mmsrv seam.

Bug 1 — every PE image misclassified as non-PE
-------------------------------------------------

``userland/core/init/src/supervisor/lifecycle.rs`` had a typo at the PE
detection site::

    image_bytes[0] == b'M' && image_bytes[1] == b'M'

PE magic is ``MZ``, not ``MM``. Every PE binary therefore fell through
to the ELF branch, where ``loader::elf::parse`` rejected the leading
bytes with ``KERNITE_ERR_INVALID_ARGUMENT``. There was also a private
``fn is_pe_header`` in the same file and a separate ``detect_format``
inside ``loader::pe.rs`` — three magic checks, three different sites.

Bug 2 — PE exec layout missing the rtld span
--------------------------------------------

``compute_exec_layout_pe`` passed ``0`` as the interpreter span and
only ``[kernel32_span]`` as preloaded DSOs. ``load_pe_program_via_mmsrv``
passed **both** the ``ldtrona-pe.so`` interpreter and ``kernel32.dll``.
The planner and the loader had drifted; every PE ``execve`` registered
an ``VmClientLayout`` whose ``interpreter_*`` window was empty, so
mmsrv had nowhere to map the PE rtld at runtime.

Bug 3 — init had no CSpace self-expansion
-----------------------------------------

Init's slot allocator handed out slots from a fixed startup envelope
(~80 usable above the kernel-installed range). Every ``spawn`` consumes
``RECEIVE_WINDOW_SIZE = 18`` slots from the receive window; ``fork``
inherits the parent's proc record but the lifecycle pipeline still
allocates a 14-slot window per call. ``fork/exec`` stress overruns the
envelope fast, and ``fatal_slot_alloc`` (``slot_alloc.rs``) just spins
``yield_now`` forever with no log.

Init had never called ``enable_self_expand`` or
``reserve_expand_temp_slot``. The first ``RSRC_ALLOC(OBJ_CNODE)`` on
init's behalf would have created an OwnerTable entry with ``bytes_max=0``
(no cap, default). A later admin call setting init's quota to a finite
value would silently close the door mid-test.

Bug 4 — slot allocator lazy-binds inside the exhaustion path
------------------------------------------------------------

``alloc_object_recorded`` and ``alloc_mp_pair_recorded`` both have an
``if authority_ep == 0 { caps::rsrcsrv_ep() ... }`` block. That getter
issues ``NAMESRV_LOOKUP("rsrcsrv")`` — which allocates slots for the
request MP and arms a Watch. Calling it from inside
``slot_alloc_consecutive``'s exhaustion retry is exactly the
deadlock-on-exhaustion path: the caller has no free slots and the
fix-up itself needs slots.

Bug 5 — receive window over-allocates for non-ldsrv services
------------------------------------------------------------

``RECEIVE_WINDOW_SIZE = 18`` was a single constant. The ldsrv-only
adopt + exec-control MP pairs added 4 slots, but only ldsrv ever used
those 4. Every other service spawned and then left 4 slots leak in
its receive window. The cap-table lint did not catch this because the
constant was used uniformly; the drift was silent.

Bug 6 — ldsrv's PE cache only fills at first resolve
----------------------------------------------------

``userland/core/init/src/supervisor/ldsrv_adopt.rs`` skipped every PE
file::

    if bytes.len() < 4 || bytes[..4] != ELF_MAGIC {
        continue;
    }

The first ``RESOLVE_MAIN`` for a PE binary always paid the full
``relayout_pe`` cost: read PE headers from the VFS-backed MO,
``mo_create`` an anonymous memory-image, ``mmap_mo`` R/W, copy each
section, ``munmap``, confer EXECUTE. The cold-cache path is fine for
sporadic exec but is a wasted round-trip on every boot.

Decision
========

Patch 1 — PE correctness
------------------------

- Canonical helper in ``userland/core/init/src/supervisor/loader/pe.rs``::

      #[inline]
      pub fn is_pe_header(bytes: &[u8]) -> bool {
          bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z'
      }

- ``detect_format`` and ``compute_spawn_layout`` both delegate to
  ``is_pe_header``. The local copy in ``lifecycle.rs`` is deleted.
- New shared ``pe::compute_pe_layout`` planner replaces the duplicated
  body of ``compute_spawn_layout_pe`` and is the one true source for
  both spawn and exec. ``compute_exec_layout_pe`` delegates to it.
  Drift between spawn and exec is now a compile error.

Patch 2a — init self-expand + quota pin
---------------------------------------

- New bootstrap slot constant ``SLOT_SELF_EXPAND_TEMP`` in
  ``internal_slots.rs``, registered into ``install_skip_range`` at
  ``stage_a_read_kernel_handoff`` so the allocator never vends it.
- New ``wire_init_self_expand`` in ``boot_core.rs`` runs immediately
  after ``spawn_rsrcsrv`` returns, and performs three steps in order:

  1. ``rsrcsrv_set_quota_unbounded(rsrcsrv_ep)`` — pins init's aggregate
     byte cap to ``u64::MAX`` via ``LABEL_SET_QUOTA`` with the admin
     badge ``RSRCSRV_ADMIN_BADGE`` (rsrcsrv's admin-class gate passes;
     admit still records against init's OwnerTable row).
  2. ``reserve_expand_temp_slot(SLOT_SELF_EXPAND_TEMP)``.
  3. ``enable_self_expand(rsrcsrv_ep, INIT_OWNER_ID)``.

- The first ``slot_alloc`` that exhausts init's startup envelope
  triggers ``try_self_expand_locked`` (``slot_alloc.rs``), which issues
  ``RSRC_ALLOC(OBJ_CNODE)`` against this endpoint. Expansion is
  **lazy** — no eager pre-install at boot.

Patch 2b — slot allocator lazy-bind hardening
---------------------------------------------

The three inline ``if authority_ep == 0 { caps::rsrcsrv_ep() ... }``
blocks (``alloc_object_recorded``, ``alloc_mp_pair_recorded``,
``free_record``) are rewritten so the lazy getter runs only when the
allocator has free slots::

    let resolved = if cached != 0 {
        cached  // eager path: ROLE_RSRCSRV_CLIENT weak symbol
    } else if slot_alloc_remaining() > 0 {
        crate::client::caps::rsrcsrv_ep().addr()
    } else {
        0
    };

On exhaustion (``slot_alloc_remaining() == 0``), the allocator reports
``Exhausted`` rather than calling ``caps::rsrcsrv_ep()`` and recursing
into the slot path that is already exhausted. ``free_record`` takes the
strict form: refuse the call on exhaustion so callers can decide
between failing the operation vs. carrying the record id to a later
release.

A new public introspection helper ``expansion_state()`` returns
``(remaining, authority_ep_set, handler_set, expansion_count,
expand_base, expand_limit)`` for the diagnostic.

Patch 2c — improved fatal diagnostic
------------------------------------

``fatal_slot_alloc`` prints the full expansion-state snapshot once,
then re-prints at a power-of-two cadence (``tick & (tick-1) == 0``)
so a long-running hang does not flood the log. The first minute logs
~12 lines; every subsequent doubling keeps the long-hang log
readable. The constant power-of-two check is preferable to "every 1M
yields" because the diagnostic line carries the actual count, which is
more useful than the period.

Patch 3 — receive window split (no alias)
-----------------------------------------

``RECEIVE_WINDOW_SIZE = 18`` is replaced by two purpose-specific
constants in ``spawn/plan.rs``::

    pub const RECEIVE_WINDOW_BASE: u64 = 14;            // every spawn
    pub const RECEIVE_WINDOW_LDSRV_EXTRA: u64 = 4;     // ldsrv-only

**No** ``RECEIVE_WINDOW_SIZE`` / ``RECEIVE_WINDOW_MAX`` compatibility
alias. Either would invite future drift back to "use the constant"
which is the bug class we are eliminating. ``plan.receive_window_size()``
is the only legitimate consumer; ``phase_alloc_bundle`` binds the
value into a local ``window_count`` once and threads it through both
the alloc and the failure cleanup::

    let window_count = plan.receive_window_size();
    let receive_base = slot_alloc_consecutive_or_idle(window_count, ...);
    ...
    unsafe { delete_and_free_receive_window(receive_base, window_count); }

The ``+14`` and ``+16`` offsets inside the ldsrv branch
(``receive_base + 14`` for the adopt pair, ``receive_base + 16`` for
the exec-control pair) stay literal — adding a named
``LDSRV_ADOPT_OFFSET`` constant would re-introduce the drift risk.

Patch 4a — common PE memory-image planner
-----------------------------------------

New module ``lib/trona/loader/common/pe/memory_image.rs`` exports a
struct-return planner with a bounded ``MAX_COPIES = 32`` array. The
planner takes a ``&[u8]`` PE file slice, validates the headers, and
returns the copy list. **No IPC, no MO**. Callers compose the planner
with their own MO read/write path.

The planner enforces invariants shared by both ``ldsrv::resolve::
relayout_pe`` (resolve-time) and ``init::ldsrv_adopt::adopt_object_pe``
(boot-time cache prewarm): the two paths cannot drift because they
use the same correctness predicates.

Patch 4b — PE adopt in init, init-local mm_ipc wrappers
-------------------------------------------------------

The init-side ``adopt_object_pe`` runs after mmsrv is up. Init does
**not** use ``trona_runtime::client::mm::{mo_create, mmap_mo, munmap}``
because those resolve ``mmsrv_ep()`` from the runtime weak symbol —
which is 0 for init (init's mmsrv endpoint is its own self-tier
``state.caps.mmsrv_self_mp``, not a published service-EP cap).

Two init-local wrappers are added to ``mm_ipc.rs``:

- ``mm_mo_create_self(state, length, flags) -> Result<OwnedCap, i32>``
  issues ``MM_MO_CREATE`` on ``mmsrv_self_mp`` and adopts the cap
  into the receive slot.
- ``mm_mmap_mo_self(state, mo_cap, size, prot, mo_offset, fixed)
  -> Result<u64, i32>`` issues ``MM_MMAP kind=MMAP_KIND_MO`` on
  ``mmsrv_self_mp``, transfers the MO cap, returns the mapped VA.

``mm_munmap_self`` already existed and is reused. With these wrappers,
init's PE adopt path becomes: plan copy list from the common helper,
``mm_mo_create_self`` → ``mm_mmap_mo_self`` → copy sections from
initrd bytes → ``mm_munmap_self`` → ``mo_mark_executable_ref`` →
``LDSRV_ADOPT_OBJECT``. Original PE file bytes are the content
identity — they match what ldsrv's ``confer_and_cache`` would hash
on first resolve, so the adopt hits cache before any exec.

ldsrv's ``relayout_pe`` in ``userland/core/ldsrv/src/resolve.rs`` is
also rewritten on top of ``plan_memory_image`` so the two PE memory-image
paths share the same planner.

Patch 4c — protocol comment clarification
-----------------------------------------

``LDSRV_ADOPT_OBJECT`` in ``lib/trona/protocol/src/ldsrv.rs`` documents
that ``caps[0]`` may be either a borrowed-frames code MO (ELF adopt)
**or** an anonymous memory-image code MO (PE adopt). Register layout
is unchanged; the comment now matches what the wire actually carries.

Consequences
============

Positive
--------

- ``hello_pe``, ``console_stress_pe``, ``vfs_stress_pe``, and
  fork/exec stress all run to completion against the Stage-3 QEMU
  image. ``test_fork`` survives the 64-zombie ``waitpid`` drain.
- Init's CSpace is no longer a fixed-size resource. Self-expansion
  caps at ``MAX_CSPACE_EXPANSIONS × 1024`` slots, more than enough for
  the test programs.
- Non-ldsrv spawns now use 14 slots, not 18. With ~5 spawns per
  test plus the patch 2a expansion budget, the boot pipeline
  comfortably covers all the test programs.
- The slot allocator's lazy-bind can no longer deadlock on
  exhaustion. The runtime weak symbol is the eager path; the lazy
  NAMESRV_LOOKUP runs only when there is room for its own slot needs.
- ldsrv's PE cache is warm at boot; the first PE exec in the test
  programs is a cache hit.
- Two PE memory-image paths share a planner; future invariants
  (e.g. bounds checks) only need to be added once.

Negative
--------

- Init's slot allocator holds the slot allocator's spinlock across the
  in-process RSRC_ALLOC IPC for self-expansion. The lock is per-process
  and uncontended in normal boot, but a contention hot-spot is
  possible if a sibling userland calls ``slot_alloc`` while init is
  expanding. This is acceptable because the only sibling callers are
  children init just spawned, and they do not race with init's own
  allocator until they have their own ``slot_alloc_init_from_layout``
  call.
- The init-local mm_ipc wrappers duplicate the wire-level knowledge
  of ``MM_MO_CREATE`` / ``MM_MMAP``. ldsrv and vfs already have their
  own helpers. If a future refactor moves these into ``trona_runtime::
  client::mm``, the wrappers must move with them.
- The PE planner's bounded ``MAX_COPIES = 32`` rejects PEs with more
  than ~30 sections. No production PE in the repo hits this; future
  PEs that do will need a follow-up to heap-allocate the array.

Rejected alternatives
=====================

- **Add a public helper ``alloc_object_recorded_with_caps`` and
  refactor three call sites to use it.** This is what the original
  plan suggested. It does not actually fix bug 4 because the lazy
  bind still happens inside the helper — the helper's structure
  makes the fix more visible but the runtime invariant is the same.
  The inline refactor (read weak symbol, conditional lazy fallback)
  is clearer and easier to audit than a helper indirection.
- **Keep ``RECEIVE_WINDOW_MAX = 18`` as a convenience alias.**
  Adding any alias invites future drift back to "use the constant"
  which is the bug class Patch 3 eliminates. The only legitimate
  consumer is ``plan.receive_window_size()``; phase.rs threads the
  count through a local variable.
- **Patch 4b with Cargo.toml / new crate.** Out of scope per the
  original task constraints. The common helper lives in the existing
  ``trona_loader`` crate's ``common/pe/`` subtree.
- **Implement PE adopt in ldsrv by adopting initrd bytes directly.**
  ldsrv runs after mmsrv but has no access to init's initrd MO — the
  initrd is registered as init's ``state.caps.initrd_va``, and ldsrv
  cannot read it as a regular file. PE adopt must happen on init's
  side, before init moves the ExecAuthority to ldsrv.
- **Eager self-expand pre-install.** A single sub-CNode install at
  boot was considered. Rejected: it surfaces no protocol drift that
  the lazy path does not already surface, and it doubles the slot
  footprint of a freshly-booted system with no children.

Implementation
==============

- ``userland/core/init/src/supervisor/loader/pe.rs`` — adds
  ``is_pe_header``, refactors ``detect_format``, adds the shared
  ``compute_pe_layout``.
- ``userland/core/init/src/supervisor/lifecycle.rs`` — fixes the
  ``MM`` typo, deletes the local ``is_pe_header``, refactors
  ``compute_spawn_layout_pe`` and ``compute_exec_layout_pe`` to share
  the planner.
- ``userland/core/init/src/internal_slots.rs`` — adds
  ``SLOT_SELF_EXPAND_TEMP = 256``.
- ``userland/core/init/src/supervisor/boot.rs`` — registers
  ``SLOT_SELF_EXPAND_TEMP`` in the boot skip range, calls
  ``wire_init_self_expand`` after ``spawn_rsrcsrv``.
- ``userland/core/init/src/supervisor/boot_core.rs`` — adds
  ``wire_init_self_expand``, ``rsrcsrv_set_quota_unbounded``, and the
  init quota pin constant.
- ``userland/core/init/src/supervisor/mm_ipc.rs`` — adds
  ``mm_mo_create_self`` and ``mm_mmap_mo_self`` init-local wrappers
  for the self-tier mmsrv endpoint.
- ``userland/core/init/src/supervisor/ldsrv_adopt.rs`` — adds the
  PE adopt branch via ``adopt_object_pe``, updates the file doc
  comment to describe both ELF and PE adopt paths.
- ``userland/core/init/src/supervisor/spawn/plan.rs`` — replaces
  ``RECEIVE_WINDOW_SIZE`` with ``RECEIVE_WINDOW_BASE`` and
  ``RECEIVE_WINDOW_LDSRV_EXTRA``; adds
  ``BootstrapPlan::receive_window_size()``.
- ``userland/core/init/src/supervisor/lifecycle/phase.rs`` —
  ``delete_and_free_receive_window`` takes an explicit ``count``;
  ``phase_alloc_bundle`` binds ``window_count`` once and threads it
  through.
- ``lib/trona/runtime/src/core/slot_alloc.rs`` — adds
  ``expansion_state()``; rewrites the three lazy-bind blocks to read
  the weak symbol first and only fall back when the allocator has
  free slots; improves ``fatal_slot_alloc`` with state snapshot +
  power-of-two cadence.
- ``lib/trona/loader/common/pe/memory_image.rs`` — new struct-return
  planner with bounded copy array.
- ``lib/trona/loader/common/pe/mod.rs`` — registers the new module.
- ``userland/core/ldsrv/src/resolve.rs`` — ``relayout_pe`` rewritten
  on top of ``plan_memory_image``.
- ``lib/trona/protocol/src/ldsrv.rs`` — extends the
  ``LDSRV_ADOPT_OBJECT`` doc comment to describe the anonymous
  memory-image MO form (PE adopt).

Testing
=======

Expected behavioral checks against the Stage-3 QEMU image:

- ``[INIT] self-expand wired: ep=<addr> temp=<256> quota=unbounded``
  appears once in the boot log.
- ``[ldtrona-pe] loaded: kernel32.dll`` appears repeatedly during the
  PE test programs (``vfs_stress_pe``, ``console_stress_pe``).
- ``test_vfs_stress_mt``, ``test_win32_console_stress``, ``test_fork``
  (64-zombie drain), ``test_sched_race``, ``test_exec``, and
  ``test_pthread`` all print ``PASS``.
- No ``[slot_alloc] FATAL:`` line appears in the boot log.

Build verification: ``just build`` produces the initrd and disk image
without warnings from the touched files; ``just warn`` runs the full
layering-check + clean recompile.
