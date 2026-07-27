=================================================================
RFC-0010: Unified VA Layout Plan and Image-Reservation Invariant
=================================================================

:Status: Implemented
:Areas: libtrona runtime (``spawn/layout``); init (spawn, fork, exec,
  stack startup block); mmsrv (client layout state, image reservations,
  exec-replace commit, exec staging validation); rtld (runtime DSO load
  window); mmsrv control IPC (full layout metadata on register and
  exec-replace)
:Authors: Hamin Sung
:Reviewers: MiniMax M3, GPT 5.5
:Date: 2026-06-28
:Depends: ``docs/rfcs/0009_capability_bounded_wx.rst`` (image reservations,
  code-object envelope model, ``resolve_library`` self-bootstrapping)
:Supersedes: none
:Description: Make ``VmLayoutPlan`` the single authority for every
  process VA window and teach mmsrv to store, validate, fork, atomically
  replace, and stage against that layout. Image reservations become
  first-class mappings inside the planned runtime DSO window;
  ``mmap_limit`` remains only the anonymous mmap allocator ceiling, not
  a bound on loader-owned image envelopes. The interpreter and preloaded
  DSO closure live in the high DSO arena (``DSO_LOAD_BASE_START`` and up)
  so the anonymous mmap window in low VA can grow to its full default
  ceiling without colliding with code.

Problem Statement
=================

SaltyOS keeps policy outside the kernel, so userland must be precise about
the virtual-address contract it gives each process. Today the contract is
split across three places:

- ``lib/trona/runtime/src/spawn/layout.rs`` owns many fixed addresses and
  the current ``VmLayoutPlan`` type.
- ``userland/core/init/src/supervisor/lifecycle.rs`` still registers
  children with hard-coded ``DEFAULT_CHILD_HEAP_*`` and
  ``DEFAULT_CHILD_MMAP_*`` values.
- ``userland/core/mmsrv/src/client.rs`` stores only scalar heap/mmap
  watermarks, and ``exec`` swaps the VM/VSpace without replacing those
  watermarks.

That split produced the current path-exec failure. A process created by
service spawn gets its DT_NEEDED closure pre-mapped by init. A process created
by path ``execve`` gets only the main image and interpreter; its runtime
linker later resolves ``libtrona.so`` through ``ldsrv`` and maps it through
``MM_RESERVE_IMAGE`` plus fixed ``MM_MMAP`` image runs.

The image reservation is valid: ``resolve_image_reservation`` checks the
reservation id, owner badge, image purpose, fixed-placement requirement, and
``r.base..r.end`` containment. But the fixed ``MM_MMAP`` branch then applies
the client's ``mmap_limit`` anyway. Runtime DSOs live in the high DSO arena
near ``DSO_LOAD_BASE_START``; the registered ``mmap_limit`` is still the low
anonymous-mmap ceiling, so mmsrv rejects the mapping as out of range.

The failure is a symptom of a broader invariant leak:

- the anonymous mmap allocator window and the runtime image-load window are
  different VA regions, but they share one scalar bound;
- the startup block already has ``dso_window_base`` / ``dso_window_size``, and
  rtld already consumes them, but init writes ``0, 0``;
- ``MM_RESERVE_IMAGE`` has its own reservation bounds, but reservation
  installation does not currently make the DSO window an explicit parent
  policy;
- ``exec`` creates a new address space while retaining the old client's
  heap/mmap placement metadata;
- mmsrv does not see the layout's image windows at all and cannot validate
  staged regions against them — the loader's word is law.

This RFC fixes the model rather than applying a narrow exception. The rule is:
one planned layout enters mmsrv with the process, and every later placement
decision — anonymous mmap, image reservation, exec staging — is validated
against that layout. The interpreter and preloaded DSO closure live in the
high DSO arena so the anonymous mmap window in low VA can grow to its full
default ceiling; the ``elf_code`` window stays in low VA next to the heap
floor since the main image is loaded before any anonymous mapping exists.

Status and Scope
================

This remains an RFC, not an ADR. It changes the intended shape of the process
layout contract and the mmsrv control protocol. The implementation should land
as one coherent layout change, not as a local ``mmap_limit`` patch.

The RFC is intentionally larger than the immediate ``test_exec`` failure:

- service spawn, fork, and exec all receive or inherit a full layout;
- the interpreter and preloaded DSO closure land in the high DSO arena
  (``DSO_LOAD_BASE_START`` and up); the anonymous mmap window in low VA
  grows up to ``DEFAULT_CHILD_MMAP_LIMIT`` without colliding with code;
- runtime DSO placement is a named planned window in the high arena;
- mmsrv's exec transaction commits layout metadata atomically with the staged
  VM and VSpace;
- mmsrv validates every staged ``dst_va`` against the layout's image windows
  during the transaction — loader runs that land outside ``elf_code`` /
  ``interpreter`` / ``preloaded_dsos`` are rejected before any kernel mapping
  happens;
- image reservations are validated as sub-allocations of the planned DSO
  window;
- direct fixed mmap is constrained by both bounds of the mmap allocator
  window (``hint >= mmap_base && end <= mmap_limit``) when no image
  reservation is named.

Requirements
============

- ``VmLayoutPlan`` MUST be the single source of truth for a process's
  user-visible VA windows: heap, anonymous mmap, runtime DSO image window,
  stack, startup IPC/cap-table windows, loader scratch, initrd, and fixed
  init/mmsrv self-VM windows.
- mmsrv MUST store the process layout as structured state, not as unrelated
  heap/mmap scalars.
- ``MM_REGISTER_CLIENT`` MUST install the full layout for a fresh process,
  including the three image windows (``elf_code``, ``interpreter``,
  ``preloaded_dsos``) so staging validation has something to check against.
- ``fork`` MUST inherit the parent's current layout exactly, including heap
  break and mmap hint/cursor.
- ``exec`` MUST compute a new layout for the replacement image and commit it
  atomically with the new ``ClientVm`` and VSpace cap. On abort, the old
  layout remains live.
- ``mmap_limit`` MUST constrain only anonymous auto-placement and direct fixed
  mappings that do not name an image reservation. Direct fixed mappings are
  bounded on both sides: ``hint >= layout.mmap_base && end <= layout.mmap_limit``.
- ``MM_RESERVE_IMAGE`` MUST create an image reservation only inside the
  process's planned runtime DSO/image window, and only if the envelope does not
  overlap an existing mapping or reservation.
- Fixed image-run mappings with ``regs[6] != 0`` MUST be checked against their
  reservation envelope and ordinary overlap rules, not against
  ``mmap_limit``.
- Every staged region in an exec transaction (and in the equivalent
  service-spawn live VM path) MUST land inside one of the layout's image
  windows (``elf_code`` / ``interpreter`` / ``preloaded_dsos``). Stacks
  (``STAGE_FLAG_STACK``) and plain anon runs (``STAGE_IMAGE_KIND_NONE``)
  are exempt — they live in the stack band and the mmap band respectively.
- The startup block MUST pass the planned runtime DSO window to rtld for every
  process. Static images still receive a non-empty runtime DSO window so the
  registered layout has one uniform shape.
- The compile-time layout guard MUST cover both fixed windows and the default
  dynamic windows. Runtime layout construction MUST reject non-default layouts
  that collide.
- The interpreter and preloaded DSO closure MUST live in the high DSO arena
  (``DSO_LOAD_BASE_START`` and up), so the anonymous mmap window in low VA
  can use the full default ceiling. Loader code MUST NOT assign ad hoc DSO
  bases outside the planner.
- Kernel syscall ABI is unchanged. The mmsrv control protocol changes.

Design
======

Layout data model
-----------------

``VmLayoutPlan`` becomes the complete process VA plan. It keeps the existing
image and stack fields and adds the windows mmsrv needs to enforce placement:

::

    pub struct VmLayoutPlan {
        pub ipc_buf: VmRegion,
        pub cap_table: VmRegion,
        pub elf_code: VmRegion,            // low VA — main image
        pub interpreter: VmRegion,         // high DSO arena
        pub preloaded_dsos: VmRegion,      // high DSO arena
        pub runtime_dso_window: VmRegion,  // high DSO arena tail
        pub heap_window: VmRegion,         // low VA
        pub mmap_window: VmRegion,         // low VA
        pub stack: VmRegion,
        pub scratch: VmRegion,
        pub initrd: VmRegion,
        pub stack_top: u64,
        pub stack_spec: StackLayoutSpec,
    }

``VmRegion`` remains ``base + size``. ``VmRegion::zero()`` means "this window
does not exist for this process".

The wire + runtime layout record includes all six allocator windows plus the
three image windows so mmsrv can enforce placement and validate staged runs:

::

    pub struct VmClientLayout {
        // Allocator windows (low VA → high VA, ordered by base).
        pub heap_base: u64,
        pub heap_limit: u64,
        pub mmap_base: u64,
        pub mmap_limit: u64,
        pub dso_base: u64,
        pub dso_limit: u64,
        // Image windows — used by mmsrv to validate exec staging.
        // A zero base/limit pair ("both zero") means "no image of this
        // kind for this process" (static image, no interpreter, no
        // DT_NEEDED closure). The three windows are independent: any
        // subset can be zero while the others are populated.
        pub elf_code_base: u64,
        pub elf_code_limit: u64,
        pub interpreter_base: u64,
        pub interpreter_limit: u64,
        pub preloaded_base: u64,
        pub preloaded_limit: u64,
    }

``VmLayoutPlan::client_layout()`` derives this record. mmsrv stores it in
``ClientState`` as one field, alongside the mutable cursors:

- ``heap_current`` starts at ``heap_base`` and changes through ``brk``.
- ``mmap_hint`` starts at ``mmap_base`` and changes through mmap placement.
- ``layout`` holds the immutable base/limit contract for the current image.

This keeps the stable layout contract separate from allocator cursors. The
image windows are part of the immutable contract so they survive every
allocator-cursor change without re-derivation.

Window placement
----------------

The planner owns these decisions. The two arenas are deliberately disjoint:

- **Low VA** holds the main image (``elf_code``), the loader scratch page, the
  initrd CPIO window, the heap window, and the anonymous mmap window. Nothing
  in this arena is mmap'd by mmsrv as a runtime loader image.
- **High DSO arena** (``DSO_LOAD_BASE_START`` and up) holds the interpreter,
  preloaded DSO closure, runtime DSO window, and the user stack below
  ``STACK_TOP_ANCHOR``. mmsrv's ``MM_RESERVE_IMAGE`` places runtime code
  envelopes here.

Per-window decisions:

- Main executable (``elf_code``):

  - ET_DYN with ``PT_INTERP`` loads at ``ELF_CODE_BASE`` in low VA.
  - ET_EXEC or static direct images keep their declared load address, after
    validation against the fixed windows.

- Interpreter and preloaded DSOs:

  - allocated in the **high DSO arena** beginning at ``DSO_LOAD_BASE_START``;
  - the interpreter lands at ``DSO_LOAD_BASE_START``; the preloaded closure
    follows, with each DSO offset by its own span plus a guard page
    (``DSO_LOAD_BASE_STRIDE``) so a single DSO never straddles a partially-
    rounded span boundary;
  - laid out by the planner; the resolver only returns spans + names;
  - no loader code assigns ad hoc DSO bases outside the planner.

- Runtime DSO window:

  - begins after the highest preloaded interpreter/DSO image plus a guard
    page, or at ``DSO_LOAD_BASE_START`` when the image is static and has no
    interpreter/preloaded DSO image;
  - ends at the lower of ``DEFAULT_RUNTIME_DSO_LIMIT`` and the concrete stack
    guard bottom for this plan;
  - is never empty in a registered client layout;
  - this is the parent window for every ``MM_RESERVE_IMAGE`` and for rtld's
    ``lib_load_addr`` / ``lib_load_limit``.

- Heap window:

  - starts after low-VA code/scratch/initrd regions and at least
    ``DEFAULT_CHILD_HEAP_BASE``;
  - ends before the anonymous mmap window;
  - size grows naturally now that interp / preloaded DSOs are out of low VA.

- Anonymous mmap window:

  - starts at the greater of ``DEFAULT_CHILD_MMAP_BASE`` and the
    collision-safe value derived from the actual low-VA plan;
  - ends at ``DEFAULT_CHILD_MMAP_LIMIT`` unless the profile provides a
    smaller policy limit;
  - if the computed base reaches or exceeds the limit, layout construction
    fails instead of silently widening the window;
  - must end below ``DSO_LOAD_BASE_START`` so it never collides with the
    high arena.

- Stack:

  - remains anchored near the top of user VA through ``StackLayoutSpec``;
  - its guard and reserve are part of the same plan validation pass;
  - the runtime DSO window is capped below the stack guard bottom, so
    runtime image reservations cannot collide with the stack reserve or guard.

The previous ``compute_mmap_base(plan, heap_base)`` helper becomes an internal
step of ``compute_mmap_window``. It returns ``[base, DEFAULT_CHILD_MMAP_LIMIT)``
and fails when ``base >= limit`` or when ``base`` would reach the high arena.

Mmsrv placement semantics
------------------------

The mmsrv placement rules become explicit. Every dispatch path consumes the
same ``layout`` (``VmClientLayout``) and every reject path surfaces a
``LayoutError`` whose ``wire_code`` matches the failure mode (range out of
range vs. argument shape).

- Auto ``MM_MMAP`` uses ``layout.mmap_base..layout.mmap_limit`` through
  ``place_va``.
- Direct fixed ``MM_MMAP`` with ``regs[6] == 0`` is accepted only when
  ``hint >= layout.mmap_base && end <= layout.mmap_limit`` and the range is
  free. ``hint < layout.mmap_base`` is rejected with the same error code as
  ``end > layout.mmap_limit`` — they are the same kind of "outside the
  allocator window" violation.
- Image ``MM_MMAP`` with ``regs[6] != 0`` is accepted only when:
  - the reservation exists;
  - it has ``ReservationPurpose::Image``;
  - its owner badge matches the caller;
  - the mapping is fixed;
  - ``hint..end`` lies inside the reservation;
  - the range is free except for that reservation.
- Device mappings do not accept image reservations. Their fixed form remains a
  direct fixed mapping and stays under the mmap-window check unless a future RFC
  defines a separate device-MMIO window.
- Exec-staging runs (``MM_STAGE_IMAGE_REGION`` with
  ``STAGE_FLAG_EXEC_TXN``) land in the pending exec VSpace. Before any kernel
  mapping, mmsrv validates that ``[dst_va, dst_va + mem_size)`` lies inside one
  of the layout's image windows:
  - ``elf_code_base..elf_code_limit`` for the main image;
  - ``interpreter_base..interpreter_limit`` for ``/lib/ldtrona-elf.so`` (or
    ``/lib/ldtrona-pe.so`` for PE processes);
  - ``preloaded_base..preloaded_limit`` for the DT_NEEDED closure.
  The same rule applies to live-VM staging for service spawn (where the
  ``ClientState::layout`` of the spawning child carries the same windows).
  Stacks (``STAGE_FLAG_STACK``) and plain anon runs
  (``STAGE_IMAGE_KIND_NONE``) are exempt — they live in the stack band and
  the mmap band respectively, not in any image window.

``range_is_free`` remains load-bearing. It checks region overlap and
reservation overlap. For image runs it skips exactly the containing image
reservation and still rejects every other overlap. The image-window check
runs before ``range_is_free`` so a misrouted loader run never reaches the
slab.

Image reservations
------------------

``MM_RESERVE_IMAGE(base, bytes)`` is upgraded from "pure bookkeeping" to
"bookkeeping under the current layout":

- ``base`` and ``bytes`` must be page-aligned and non-zero;
- ``base..end`` must lie inside ``layout.dso_base..layout.dso_limit``;
- the range must not overlap any live mapping or reservation;
- the reservation is installed as ``ReservationPurpose::Image`` with the
  caller's badge.

This makes the reservation the parent bounds-check source for runtime images.
The later image-run mappings are sub-allocations of that reservation. They do
not consult the anonymous mmap ceiling.

Startup and rtld
----------------

The startup block already contains:

- ``SaltyOSStartupLayoutV1.dso_window_base``
- ``SaltyOSStartupLayoutV1.dso_window_size``

and both ELF and PE rtld already consume a non-zero window. Init must stop
writing ``0, 0`` and instead pass ``plan.runtime_dso_window`` into
``build_startup_block``.

The runtime linker uses this window as the candidate range for
``resolve_startup_dependencies`` and ``dlopen``. Static images have no startup
rtld consumer, but mmsrv still registers the same non-empty window; an empty
runtime DSO window is an invalid ``MM_REGISTER_CLIENT`` layout.

Spawn, fork, and exec
---------------------

Service spawn:

1. init resolves the image geometry and any bootstrap DSO closure **before**
   ``realize_process`` runs — the binary is read from the initrd, the
   interpreter is parsed, the DT_NEEDED closure is recursively resolved, and
   ``compute_vm_layout`` produces the full ``VmLayoutPlan`` (with image
   windows in the high DSO arena);
2. ``plan.client_layout()`` derives the wire + runtime ``VmClientLayout``;
3. ``MM_REGISTER_CLIENT`` sends the derived layout, including the three
   image windows so mmsrv can validate later staging runs;
4. ``phase_stage` reuses the same spans to call ``plan_for_closure`` —
   because the spans match what was registered, the loader's derived
   ``VmLayoutPlan`` is bit-for-bit identical to the one already in mmsrv;
5. ``compose_*`` plumbs ``plan.runtime_dso_window`` into the startup block;
6. mmsrv validates all subsequent mappings against the registered layout,
   including exec-style staging runs that land in the live VM.

Fork:

1. mmsrv clones the parent's ``ClientVm`` as it does today;
2. mmsrv copies the parent's layout and mutable cursors;
3. the child starts with identical placement state, matching the inherited
   VM. ``client_layout()`` is the parent's ``client_layout()`` verbatim —
   the child sees the same image windows the parent saw, so any later
   staging run the child itself drives (none today, but future
   ``dlopen``-style paths may) stays within the parent's contract.

Exec:

1. the caller resolves the executable through its own VFS authority and
   passes the exec MemoryObject to init, per RFC-0006 and RFC-0009;
2. init parses the replacement image and computes a new ``VmLayoutPlan``
   (with image windows in the high DSO arena — ``elf_code`` is set even
   for path-exec, since the loader stages the main image as part of the
   transaction);
3. ``MM_BEGIN_EXEC_REPLACE`` receives the new VSpace cap, exec MO cap, and
   the new ``VmClientLayout`` (all twelve fields);
4. mmsrv stores that layout in ``PendingExecVm.pending_layout`` next to
   the staged ``ClientVm``;
5. staging calls install regions into the pending VM and validate against
   the pending layout's image windows — any ``dst_va`` outside
   ``elf_code`` / ``interpreter`` / ``preloaded_dsos`` is rejected before
   any kernel mapping happens;
6. ``MM_COMMIT_EXEC_REPLACE`` atomically swaps the live VM, VSpace cap,
   layout, ``heap_current``, and ``mmap_hint``;
7. abort drops the pending VM, pending VSpace, exec MO, and pending
   layout without touching the live process.

This is the point where the current "no wire change" assumption is
deliberately discarded. The ideal design needs the mmsrv control wire to
carry the full layout metadata — including image windows — so mmsrv can
validate both anonymous placement and loader staging against one shared
contract.

Protocol changes
================

``MM_REGISTER_CLIENT`` grows from:

::

    regs[0] = client_id
    regs[1] = pid
    regs[2] = heap_base
    regs[3] = heap_limit
    regs[4] = mmap_base
    regs[5] = mmap_limit

to:

::

    regs[0]  = client_id
    regs[1]  = pid
    regs[2]  = heap_base
    regs[3]  = heap_limit
    regs[4]  = mmap_base
    regs[5]  = mmap_limit
    regs[6]  = dso_base
    regs[7]  = dso_limit
    regs[8]  = elf_code_base
    regs[9]  = elf_code_limit
    regs[10] = interpreter_base
    regs[11] = interpreter_limit
    regs[12] = preloaded_base
    regs[13] = preloaded_limit

``MM_BEGIN_EXEC_REPLACE`` grows from a cap-only request to:

::

    regs[0]  = heap_base
    regs[1]  = heap_limit
    regs[2]  = mmap_base
    regs[3]  = mmap_limit
    regs[4]  = dso_base
    regs[5]  = dso_limit
    regs[6]  = elf_code_base
    regs[7]  = elf_code_limit
    regs[8]  = interpreter_base
    regs[9]  = interpreter_limit
    regs[10] = preloaded_base
    regs[11] = preloaded_limit
    caps[0]  = new_vspace
    caps[1]  = exec_mo

The reply remains ``txn_id``. ``MM_COMMIT_EXEC_REPLACE`` and
``MM_ABORT_EXEC_REPLACE`` keep their current request shape.

Both layout-consuming entry points (``handle_register_client`` and
``handle_begin_exec_replace``) consume the layout through
``VmClientLayout::validate`` and surface ``LayoutError::wire_code`` on
rejection: construction-side range failures are ``OUT_OF_RANGE``; malformed
wire values and parent-arena violations are ``INVALID_ARGUMENT``. No "fail open
to INVALID_ARGUMENT" anymore; the caller can distinguish "your layout overlaps
mine" from "your layout is malformed".

The kernel ABI and the public rtld startup ABI do not change; the DSO window
fields already exist in ``SaltyOSStartupLayoutV1``.

Implementation Outline
=====================

``lib/trona/runtime/src/spawn/layout.rs``

- Move child heap defaults out of init's ``spawn/plan.rs`` into the shared
  layout module.
- Extend ``VmLayoutPlan`` with heap, mmap, cap-table, and runtime DSO windows.
- Add ``VmClientLayout`` and ``VmLayoutPlan::client_layout``.
- Place ``interpreter`` and ``preloaded_dsos`` in the **high DSO arena**
  (``DSO_LOAD_BASE_START`` and up) so the anonymous mmap window in low VA
  can use the full default ceiling. ``elf_code`` stays in low VA.
- Replace direct DSO-base arithmetic in init's loader with layout helpers
  that assign interpreter, preloaded DSO, and runtime DSO-tail windows.
- Extend ``assert_vm_windows_disjoint`` so the default heap/mmap/DSO
  windows are checked against fixed windows at compile time. The DSO-arena
  / stack-anchor ceiling check lives in a separate top-level ``const _``.
- Add runtime validation for computed plans, returning an invalid layout
  instead of saturating through collisions.
- ``VmClientLayout::validate`` enforces the parent-arena rule: the runtime DSO
  window and high image windows must lie inside the high DSO arena,
  ``elf_code`` must stay in low VA, and any partially-populated image window
  (``base == 0, limit != 0``) is rejected.

``userland/core/init/src/supervisor/loader``

- Make ELF/PE image loading return or consume a ``VmLayoutPlan`` rather than
  recomputing stack/image geometry in separate helpers.
- ``dso::resolve`` returns spans + names only; per-DSO ``load_base`` /
  ``entry_pc`` are stamped by ``dso::assign_bases`` from the planner's
  already-allocated ``plan.interpreter`` / ``plan.preloaded_dsos`` windows
  (it does **not** recompute those windows — single source of truth).
- ``plan_for_closure`` runs ``compute_vm_layout`` + ``assign_bases`` and
  returns the plan.
- Pass ``plan.runtime_dso_window`` into ``stack::compose*`` and
  ``build_startup_block``.
- PE startup uses the same DSO window plumbing as ELF.
- Drop the unused ``child_vspace: u64`` parameter from ``load_program_via_mmsrv``,
  ``load_image_via_mmsrv``, and ``load_pe_program_via_mmsrv``; the destination
  VSpace is reached through ``dst_client_id`` (mmsrv resolves the cap from its
  client table).

``userland/core/init/src/supervisor/lifecycle.rs``

- ``compute_spawn_layout`` reads the service binary from the initrd, runs
  the same plan the loader runs (without staging), and returns the layout
  derived from ``plan.client_layout()``.
- ``handle_spawn`` calls ``compute_spawn_layout`` **before**
  ``realize_process`` so ``MM_REGISTER_CLIENT`` registers the layout-derived
  contract, not a parallel set of constants. The loader's
  ``plan_for_closure`` in ``phase_stage`` reuses the same spans and
  produces a bit-for-bit identical plan.
- ``handle_fork`` reads the parent's ``ProcessRecord::layout`` (no fallback
  to constants — a missing parent layout is a programming error).
- For exec, compute the replacement layout before ``MM_BEGIN_EXEC_REPLACE``
  and pass the derived layout (with image windows) in that request.
- ``compute_exec_layout_elf`` / ``compute_exec_layout_pe`` are the canonical
  exec-side layout helpers and are reused for any future call site that
  needs an exec-style layout without going through ``realize_process``.

``userland/core/mmsrv/src/client.rs``

- Replace ``heap_base``, ``heap_limit``, ``mmap_base``, ``mmap_limit``
  scalar fields with ``layout: VmClientLayout`` plus mutable
  ``heap_current`` and ``mmap_hint``.
- Extend ``PendingExecVm`` with ``pending_layout`` (full twelve fields).
- ``commit_exec_txn`` swaps the pending layout and resets cursors from it.
- Fork inheritance copies the full layout plus cursors.

``userland/core/mmsrv/src/mmap.rs``

- ``place_va`` uses ``client.layout.mmap_base..client.layout.mmap_limit``.
- Anon/MO fixed branches apply both bounds (``hint >= mmap_base`` AND
  ``end <= mmap_limit``) when ``image_reservation.is_none()``.
- Device mappings stay under the mmap-window check (no image-reservation
  path).
- ``handle_reserve_image`` validates against ``layout.dso_base`` /
  ``layout.dso_limit`` and calls the overlap checker before installing the
  reservation.

``userland/core/mmsrv/src/dispatch.rs``

- Parse the larger ``MM_REGISTER_CLIENT`` layout record (twelve u64s).
- Parse the larger ``MM_BEGIN_EXEC_REPLACE`` request (twelve u64s + two
  caps) and store the pending layout.
- Use ``VmClientLayout::validate`` and surface ``LayoutError::wire_code``
  on reject (out-of-range for arena / ordering errors, invalid-argument for
  shape errors).
- Every staging path (``MM_STAGE_IMAGE_REGION`` in all three modes:
  cross-client, ``EXEC_MO_SRC``, ``PROVIDED_MO``) validates
  ``[dst_va, dst_va + mem_size)`` against the layout's image windows
  before any kernel mapping. Stacks and ``STAGE_IMAGE_KIND_NONE`` are
  exempt (they live in the stack band and mmap band respectively).

Invariants
==========

- Every process has exactly one current ``VmClientLayout`` in mmsrv.
- Every exec transaction has either no pending layout or a pending layout
  paired with its pending VM and VSpace.
- The interpreter and preloaded DSO closure live in the high DSO arena
  (``DSO_LOAD_BASE_START`` and up); the anonymous mmap window in low VA
  ends below ``DSO_LOAD_BASE_START``.
- ``mmap_hint`` is a cursor inside ``layout.mmap_base..layout.mmap_limit``.
- ``heap_current`` is a cursor inside ``layout.heap_base..layout.heap_limit``.
- Every image reservation lies inside ``layout.dso_base..layout.dso_limit``.
- Every image-run mapping with ``regs[6] != 0`` lies inside its image
  reservation.
- No direct fixed mmap without an image reservation can escape the mmap
  window on either side (``hint < mmap_base || end > mmap_limit``).
- No staged ``MM_STAGE_IMAGE_REGION`` run lands outside
  ``layout.elf_code`` / ``layout.interpreter`` / ``layout.preloaded_dsos``
  (modulo the stack and ``STAGE_IMAGE_KIND_NONE`` exemptions).
- Forked children inherit layout and cursors from the parent, not defaults.
- Exec commit swaps layout and address space together.
- mmsrv surfaces ``LayoutError::wire_code`` on every layout rejection, so
  callers can tell "your layout overlaps mine" from "your layout is
  malformed".
- The loader never assigns an ad hoc DSO base; every load base comes from
  ``plan.interpreter`` / ``plan.preloaded_dsos`` (single source of truth).

Rejected Alternatives
=====================

*Only gate ``mmap_limit`` on ``regs[6] == 0``.* This fixes the observed
``test_exec`` failure, but leaves image reservations unparented by a planned
window and leaves exec with stale placement metadata.

*Keep the mmsrv wire unchanged.* Impossible for the ideal model. A replacement
image needs replacement layout metadata. Without carrying it through
``MM_BEGIN_EXEC_REPLACE``, commit can only keep the old layout.

*Raise ``mmap_limit`` for exec.* This conflates anonymous mmap with image
loading and lets the gap allocator hand out addresses across the high DSO
arena. The loader window should be separate.

*Clamp rtld runtime loads under ``mmap_limit``.* That defeats the architecture:
rtld and DSOs intentionally live in a dedicated high-VA arena, not in the
anonymous mmap pool.

*Have init pre-map every DT_NEEDED object for path-exec.* This makes
path-exec depend on init resolving runtime library policy. The caller/rtld/ldsrv
path introduced by RFC-0009 should remain the steady-state code-loading path.

*Model runtime DSO loads as anonymous mmap.* Rejected because a loaded DSO is a
code-object image with teardown, W^X, and capability-derived protection
requirements. It needs an image reservation, not a generic anonymous region.

Backwards Compatibility
=======================

The public process ABI is unchanged. ``SaltyOSStartupLayoutV1`` already has the
DSO window fields and rtld already handles them.

The mmsrv control protocol changes. All in-tree callers are init/mmsrv-owned
and must be updated in the same change. There is no stable external mmsrv
client ABI to preserve.

Security Considerations
=======================

This RFC does not grant executable authority. RFC-0009 remains the W^X and
code-authority boundary: executable pages come from execute-bearing code MOs
and cap-derived mapping ceilings.

The layout change improves confinement:

- arbitrary fixed mappings remain bounded by the mmap window;
- runtime code images are bounded by the DSO/image window;
- image reservations cannot be created over unrelated mappings or reserved
  ranges;
- exec cannot accidentally keep stale placement limits from the old image.

Testing
=======

- ``just fmt-check``.
- ``just build``.
- ``just warn``.
- ``just run --headless --smp 2``.
- ``just run --headless --smp 4`` if any scheduler, fault, or IPC timing code is
  touched during implementation.
- ``just cross-hello`` and ``just cross-hello-cpp`` are not required by the
  layout contract itself, but should be run if the startup block, rtld, or
  sysroot-visible loader behavior changes.

Positive coverage:

- service spawn still boots and reaches all core services;
- the loader's plan and the mmsrv-registered layout are bit-for-bit
  identical for every spawned child (verified at register time by
  ``VmClientLayout::validate``);
- fork inherits parent layout, mmap hint, and heap cursor exactly;
- path ``execve("/bin/vfs_stress_elf", ...)`` loads ``libtrona.so`` at
  runtime and passes ``test_exec`` Test 1;
- missing-path exec still fails with the existing expected error;
- PE startup receives the same DSO window metadata and does not regress;
- core services (namesrv, rsrcsrv, mmsrv) register with the layout their
  Stage C/D/E loader actually used, not with a parallel set of constants.

Negative coverage:

- direct fixed ``MM_MMAP`` without an image id whose ``hint < mmap_base``
  is rejected with the same error as ``end > mmap_limit``;
- direct fixed ``MM_MMAP`` whose ``end > mmap_limit`` is rejected;
- ``MM_RESERVE_IMAGE`` outside the DSO window is rejected;
- ``MM_RESERVE_IMAGE`` overlapping an existing mapping is rejected;
- ``MM_RESERVE_IMAGE`` overlapping another reservation is rejected;
- image-run mapping outside its reservation is rejected;
- image-run mapping with an id owned by another client is rejected;
- ``MM_STAGE_IMAGE_REGION`` whose ``dst_va`` lies outside
  ``layout.elf_code`` / ``layout.interpreter`` / ``layout.preloaded_dsos``
  is rejected before any kernel mapping happens;
- partially-populated wire layout (``elf_code_base == 0`` while
  ``elf_code_limit != 0``) is rejected with ``InvalidElfCodeWindow``;
- an image window that crosses its parent arena or the concrete per-plan DSO
  ceiling is rejected;
- exec abort leaves the old layout and cursors intact.

Prior Art and References
========================

- **RFC-0009 capability-bounded W^X** introduced the code-object envelope model:
  a runtime image is mapped from rights-attenuated code MO caps into an image
  reservation, and ``MM_UNMAP_IMAGE`` tears the envelope down. RFC-0010 makes the
  VA parent of that envelope explicit.
- **Fuchsia VMAR** uses explicit virtual-memory address regions and validates
  fixed mappings against the selected region rather than a process-wide mmap
  ceiling. SaltyOS's DSO/image window is the same shape at mmsrv scale:
  reserve a named VA subrange, then map fixed image runs inside it.
- **seL4 / Genode-style userland address-space construction** keeps address
  layout policy outside the kernel. The kernel enforces object and mapping
  authority; userland owns the layout contract. SaltyOS follows that model by
  making init and mmsrv responsible for the plan.
- **Linux process layout** keeps heap, mmap, stack, executable, vDSO, and shared
  library placement as distinct layout concerns. Linux may randomize them, but
  it does not treat the anonymous mmap ceiling as the universal bound for every
  loader mapping.
- **GHC RTS memory-map controls** are a practical precedent for reserving or
  biasing large VA arenas for runtime loader/allocation needs. The lesson is the
  same: special runtime image/allocation arenas should be explicit, not hidden
  behind a generic mmap cursor.

Reference links:

- Fuchsia ``zx_vmar_allocate``:
  https://fuchsia.dev/reference/syscalls/vmar_allocate
- Fuchsia ``zx_vmar_map``:
  https://fuchsia.dev/reference/syscalls/vmar_map
- seL4 mapping tutorial:
  https://docs.sel4.systems/Tutorials/mapping.html
- Linux ``randomize_va_space``:
  https://docs.kernel.org/admin-guide/sysctl/kernel.html#randomize-va-space
- Linux ``mmap_rnd_bits``:
  https://docs.kernel.org/admin-guide/sysctl/vm.html#mmap-rnd-bits
- GHC RTS options:
  https://downloads.haskell.org/ghc/latest/docs/users_guide/runtime_control.html
