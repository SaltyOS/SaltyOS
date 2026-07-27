================================================================
ADR-0004: Run planner splits BSS-only pages into ZeroFill runs
================================================================

:Status: Implemented
:Areas: libtrona loader (``common::elf::run_plan``;
  ``rtld::image_sink``); init supervisor loader
  (``userland/core/init/src/supervisor/loader/elf.rs``,
  ``boot_image.rs``); mmsrv image-run mapping
  (``map_image_run_mo`` / ``map_image_run_anon``)
:Authors: Hamin Sung
:Reviewers: MiniMax M3
:Date: 2026-06-28
:Supersedes: none
:Depends: ``docs/rfcs/0006_execve_caller_memory_object.rst`` (text / rodata
  shared, data private COW, bss demand-zero),
  ``docs/rfcs/0009_capability_bounded_wx.rst`` (data as private ``R-W``
  COW child, code MO as the executable authority),
  ``docs/rfcs/0010_unified_vm_layout_plan.rst`` (image reservation parent
  policy for runtime DSOs),
  ``docs/adrs/0003_runtime_image_mmap_kind.rst`` (image kind on the
  runtime image-map wire).
:Description: The ELF run planner must never emit a single
  ``RunSource::PrivateFromCodeMo`` run whose ``run.bytes`` span extends
  past the source code MemoryObject's pages. The planner splits every
  pure BSS page — a page where the segment's ``p_filesz`` ends at or
  before the page start — out of the private file-extent run into its
  own ``RunSource::ZeroFill`` run inside the same image reservation.
  The boundary page (where ``p_memsz > p_filesz`` mid-page) stays inside
  the private run with ``file_bytes`` clamping the clone range to the
  file extent; its in-page BSS tail is zeroed by the rtld image-sink
  after the map, preserving the existing semantics. PE does not need
  the fix because the ldsrv memory-image MO already covers BSS.

Context
=======

The bug surfaced as a runtime linker failure on every dynamically
linked program once ``execve`` reached the runtime-DT_NEEDED path::

    [ldtrona-elf] failed to load DT_NEEDED: libtrona.so stage=image-map-run
    [ldtrona] FATAL: ELF dependency load failed

The stage name ``image-map-run`` (mapped to
``LoadError::ImageMapRunFailed`` in
``lib/trona/loader/rtld/elf/object.rs:402``) is the rtld image-sink's
``SinkError::MapRun`` arm in
``lib/trona/loader/rtld/image_sink.rs:142``. The failure was at the
per-run ``MM_MMAP`` step, not at the ldsrv resolve step: ``ldsrv``
returned a valid ``READ|EXECUTE`` code MemoryObject, ``plan_elf``
consumed its program headers and produced a ``RunPlan``, and
``image_sink::place_image`` had already reserved the image envelope
via ``MM_RESERVE_IMAGE``. Only the per-run mapping into that envelope
rejected.

Root cause
----------

The planner's ``PendingRun::can_extend``
(``lib/trona/loader/common/elf/run_plan.rs:148``) only rejected the
single case ``run_has_gap && page_has_file`` — a private run that had
already crossed past its file extent could not fold in another
file-backed page. It did not reject the complementary case
``page_has_file == false`` — a private run could fold in a pure BSS
page after the file extent. The result was one
``RunSource::PrivateFromCodeMo { mo_offset_pages, file_bytes }`` run
whose ``run.bytes`` covered both the file extent and the BSS pages
that followed it.

``image_sink::place_image`` then forwarded that run verbatim to
``mm::map_image_run_mo(run.va, run.bytes, …, mo_offset_pages*PAGE, …)``
(``lib/trona/loader/rtld/image_sink.rs:131-142``). mmsrv's
``handle_mmap_mo_private`` rejected it because
``mo_offset_pages + run.bytes / PAGE > source_pages``
(``userland/core/mmsrv/src/mmap.rs:885-888``), returning
``KERNITE_ERR_OUT_OF_RANGE``. The kernel's ``MO_CLONE_RANGE`` primitive
enforces the same bound at the kernel boundary
(``kernite/src/syscall/mo.rs:489-494``) — neither side may clone pages
the parent MO does not own.

For ELF, the source code MO carries the file bytes of the resolved
object. It does not include BSS. Whether the backing is an initrd
borrowed-frames MO (built by ldsrv at Stage 0/1, ADR-0001) or a VFS
pager-backed MO (built on first use for disk-only objects, RFC-0009
§"Disk-only objects"), the MO is sized to ``ceil(p_filesz / PAGE)``
pages. The BSS pages beyond ``p_filesz`` are a property of the running
process's address space, not of the file. The bug was therefore a
planner-level violation of:

- RFC-0006 §"Mapping the image": "text and read-only segments shared
  from the MemoryObject's pages, the writable data segment as a
  private copy-on-write sub-range, and bss as demand-zero".
- RFC-0009 §"Concrete mechanism: mmsrv map an image into a reserved
  envelope": "materializes privately any partly-writable / partly-BSS
  boundary page and trailing BSS".

Why init's path was incidentally correct
----------------------------------------

Init's ``MmsrvSink`` and ``MmsrvProvidedSink``
(``userland/core/init/src/supervisor/loader/elf.rs:84-118, 186-215``)
route ``PrivateFromCodeMo`` through ``STAGE_FLAG_EXEC_MATERIALIZE``
(``elf.rs:96``) to mmsrv's ``stage_exec_materialize``
(``userland/core/mmsrv/src/dispatch.rs:2339``), which already splits
``file_pages`` from ``bss_pages`` on its side and emits a separate
anon region for the trailing BSS. So init's loader path silently
absorbed the buggy planner output — at the cost of one extra
materialise-with-zero-tail IPC per private run instead of an explicit
``ZeroFill`` run. The rtld path had no such buffer: it called
``mm::map_image_run_mo`` directly with ``run.bytes``, so the bug
surfaced immediately as a kernel-side range violation.

Decision
========

Modify ``PendingRun::can_extend`` in
``lib/trona/loader/common/elf/run_plan.rs`` so a private run extends
only over pages that have file content:

.. code-block:: rust

    fn can_extend(&self, info: &PageClass, page_va: u64) -> bool {
        if page_va != self.end_va() || self.prot != info.prot || self.clean != info.clean {
            return false;
        }
        if !self.clean {
            if info.file_end_va <= page_va {
                return false;          // pure BSS → new ZeroFill run
            }
            if self.file_end_va < self.end_va() {
                return false;          // run has gap → no later file-backed page
            }
        }
        true
    }

``info.file_end_va`` is already the highest file-backed VA within the
page (computed in ``classify_page``,
``lib/trona/loader/common/elf/run_plan.rs:80-132``); the new check is
just "this page carries any file bytes". ``PendingRun::extend``,
``PendingRun::finish``, the ``Run`` and ``ImageRunKind`` types, and
``RunSource::ZeroFill`` all stay unchanged.

Effects on run shape
--------------------

- A run of fully-file-backed pages (the common case) stays a single
  ``PrivateFromCodeMo { mo_offset_pages, file_bytes == run.bytes }``.
  The ``MO_CLONE_RANGE`` now fits the source MO exactly because
  ``mo_offset_pages + pages == ceil(p_filesz / PAGE) == source_pages``.
- A boundary page at the end of a private run (segment's
  ``p_memsz > p_filesz`` mid-page) stays inside the private run with
  ``file_bytes = file_end_va - start_va < run.bytes``. The image-sink's
  existing ``if file_bytes < run.bytes { write_bytes }`` path
  (``image_sink.rs:147-155``) zero-fills the in-page tail after the
  map; for RoData it maps temporarily ``R-W``, zeroes, and
  ``mprotect``s back to ``R--`` (``image_sink.rs:156-162``). Unchanged.
- A pure BSS page (where the segment's ``p_filesz`` ends at or before
  the page start) now starts a new pending run whose ``finish`` falls
  through the existing ``file_bytes == 0`` branch
  (``run_plan.rs:196-202``) and emits ``RunSource::ZeroFill`` with
  ``ImageRunKind::Bss`` (writable) or ``RoData`` (read-only). The
  image-sink routes ``ZeroFill`` through ``mm::map_image_run_anon``
  (``image_sink.rs:96-99``), which mmsrv maps as a fresh anonymous MO
  inside the same image reservation
  (``lib/trona/runtime/src/client/mm.rs:646``,
  ``userland/core/mmsrv/src/mmap.rs:611-628, 1274-1281``).

RFC alignment
-------------

- **RFC-0006.** Text / rodata shared from the source MO, data a private
  copy-on-write sub-range, trailing bss demand-zero. The split makes
  the third clause literal at the run level rather than implicit in
  ``memsz - filesz`` of a single run.
- **RFC-0009.** Data as a private ``R-W`` COW child of the code MO;
  the boundary carve remains inside the private run, the trailing BSS
  becomes a distinct demand-zero region.
- **RFC-0010.** Image reservations are the parent policy for runtime
  image envelopes; the new ``ZeroFill`` run lives inside the same
  reservation. mmsrv's ``MM_RESERVE_IMAGE`` validation
  (``mmap.rs:1274-1281``) and the run's ``MM_MMAP`` image-reservation
  check (``mmap.rs:611-628``) apply unchanged.

PE does not need the fix: ``lib/trona/loader/common/pe/run_plan.rs``
emits ``PrivateFromCodeMo { file_bytes: bytes }`` for writable runs
(``pe/run_plan.rs:135-145``), and ldsrv hands the linker a
memory-image MO whose ``image_size`` already includes BSS zeros. Every
writable run's ``file_bytes == run.bytes``, so the ``MO_CLONE_RANGE``
fits the source MO exactly. ``MAX_PE_RUNS = 128`` was already adequate.

Run-buffer sizing: the worst case grows from ``N`` private runs to
``N`` private runs + ``N`` ``ZeroFill`` runs (each BSS tail becomes
one). Bumped from 64 to 128 to match ``MAX_PE_RUNS`` and leave
comfortable headroom for the most complex plausible PIEs.

Consequences
============

Positive
--------

- **DT_NEEDED DSO loading works.** rtld's ``load_object_into``
  (``lib/trona/loader/rtld/elf/object.rs:614``) reaches relocation;
  the ``[ldtrona-elf] failed to load DT_NEEDED: libtrona.so
  stage=image-map-run`` log line no longer appears. Combined with
  ADR-0002 (init owns the ldsrv EP) and ADR-0003 (runtime image-map
  carries image kind), the path-exec chain now runs end to end.
- **Plan's ``file_bytes`` is honest.** Every ``PrivateFromCodeMo``
  run's ``file_bytes`` describes a window that fits inside the source
  MO; mmsrv's range check at ``mmap.rs:885-887`` and the kernel's
  ``MO_CLONE_RANGE`` check at ``mo.rs:489-494`` pass by construction
  rather than by coincidence.
- **init's path becomes simpler.** After the planner fix, each emitted
  run is self-consistent: a ``PrivateFromCodeMo`` carries
  ``file_bytes == run.bytes`` for fully-file-backed runs, and a
  separate ``ZeroFill`` run carries the BSS tail. Each
  ``MM_STAGE_IMAGE_REGION`` call now describes one shape rather than
  two, removing the planner-side reliance on mmsrv's
  ``stage_exec_materialize`` to compensate.
- **No new IPC, no new wire code, no new MM call.** ``RunSource::ZeroFill``,
  ``ImageRunKind::Bss``, ``map_image_run_anon``, and
  ``stage_exec_anon_region`` already existed.

Negative
--------

- **More runs per image.** A PT_LOAD with ``p_memsz > p_filesz`` that
  previously emitted one private run now emits one private run + one
  ``ZeroFill`` run. The buffer bump (64 → 128) absorbs this; the IPC
  fan-out (one extra ``MM_STAGE_IMAGE_REGION`` per BSS tail) is
  negligible.
- **Comment churn.** ``MAX_RTLD_RUNS``, ``MAX_IMAGE_RUNS``,
  ``MAX_BOOT_RUNS``, and the ``can_extend`` doc-comment needed updates
  to reflect the new run shape.

Neutral
-------

- **RoData boundary page still in private run.** A non-writable
  PT_LOAD with ``p_memsz > p_filesz`` is a valid ELF construct; the
  boundary page is still handled by the existing
  ``file_bytes < run.bytes`` path in the image-sink, which the RoData
  branch maps temporarily writable, zeroes, and ``mprotect``s back to
  ``R--``. Any follow-on pure-BSS pages become ``ZeroFill`` runs
  carrying ``ImageRunKind::RoData`` (because ``finish``'s existing
  ``file_bytes == 0`` branch maps no-W to RoData) and are mapped
  ``R--`` directly by ``map_image_run_anon``.
- **PE path unchanged.** ``pe::run_plan.rs`` emits
  ``PrivateFromCodeMo { file_bytes: bytes }`` for writable runs;
  ``image_sink``'s ``map_image_run_mo`` for those runs fits the
  memory-image MO's pages exactly. ``MAX_PE_RUNS = 128`` was already
  adequate.
- **``PendingRun::extend`` / ``PendingRun::finish`` unchanged.** The
  semantics of "private run, file_bytes, zero the in-page tail" are
  preserved exactly; only the page-level extend rule changes.

Rejected alternatives
======================

- **Fix the bug in the image-sink: have it split the run internally
  before calling ``map_image_run_mo``.** Larger surface: the sink
  would need to know where to split (last fully-file-backed page vs.
  boundary page) and emit a second ``map_image_run_anon`` call. The
  planner already has the per-page classification data; doing the
  split there keeps the sink a stateless pass-through and reuses the
  existing ``RunSource::ZeroFill`` path.
- **Extend ``map_image_run_mo`` to accept a ``file_bytes`` parameter
  and have mmsrv do the file-pages + anon-tail split in one call.**
  Larger still: requires a new wire register, a new mmsrv dispatch
  path, and complicates ``range_is_free`` (two backing MOs per call).
  The two existing primitives (``map_image_run_mo`` and
  ``map_image_run_anon``) cover the two halves cleanly.
- **Make the source code MO carry the BSS pages too (eagerly
  zero-fill on resolve).** Defeats the purpose of the code MO: a
  ``READ|EXECUTE`` file-backed object should reflect the file, not the
  process's intended address-space layout. PE's memory-image MO is
  the exception, not the rule, and even there the memory-image is
  constructed at ldsrv's well-defined point (with section RVAs already
  padded), not at every resolve.
- **Pass ``file_bytes`` only, not ``run.bytes``, and have mmsrv reject
  the run if ``run.bytes > file_bytes`` with a synthesised
  zero-fill sub-region.** Re-introduces the old ambiguity — what does
  the unwritten VA hold? — and pushes BSS placement to a single run
  whose source MO range underspecifies the mapped VA. The split makes
  the model explicit at the run level.
- **Detect "the file is smaller than the run" in mmsrv from the
  ``KERNITE_INV_MO_GET_SIZE`` reply and synthesise a separate
  zero-fill sub-region on the fly.** Requires mmsrv to know the run's
  intended ``file_bytes``, which the wire currently doesn't carry.
  Either grows the wire or requires a new mmsrv-side query per run;
  the planner-side split is strictly smaller.

Implementation
==============

- ``lib/trona/loader/common/elf/run_plan.rs``

  - ``PendingRun::can_extend`` — new rule rejects a pure BSS page
    (``info.file_end_va <= page_va``) before the existing gap-and-file
    rule; doc-comment updated to explain both rules with file
    references to ``userland/core/mmsrv/src/mmap.rs:885`` and
    ``kernite/src/syscall/mo.rs:489``.
  - No other changes (``PendingRun::extend``,
    ``PendingRun::finish``, ``PendingRun::emit_run``, the ``Run`` and
    ``ImageRunKind`` types, ``RunSource::ZeroFill``, and the
    ``carves`` flow all unchanged).

- ``lib/trona/loader/rtld/elf/object.rs``

  - ``MAX_RTLD_RUNS``: 64 → 128; doc-comment rewritten to describe the
    worst case (two runs per PT_LOAD) and reference the planner rule.

- ``userland/core/init/src/supervisor/loader/elf.rs``

  - ``MAX_IMAGE_RUNS``: 64 → 128; doc-comment rewritten to describe
    the worst case and reference ``MAX_PE_RUNS``.

- ``userland/core/init/src/supervisor/loader/boot_image.rs``

  - ``MAX_BOOT_RUNS``: 64 → 128; doc-comment rewritten to describe
    the worst case and reference ``MAX_IMAGE_RUNS`` /
    ``MAX_PE_RUNS``.

No changes to:

- ``lib/trona/loader/rtld/image_sink.rs`` — ``map_image_run_mo`` +
  boundary-page ``write_bytes`` + RoData ``mprotect`` back-path is
  correct for the new run shape.
- ``lib/trona/loader/common/image.rs`` — ``RunSource::PrivateFromCodeMo``
  doc semantics ("clone prefix, zero the in-page tail") still match.
- ``lib/trona/loader/common/pe/run_plan.rs`` — PE memory-image MO
  already covers BSS.
- ``userland/core/mmsrv/src/mmap.rs`` — kernel / MO range checks stay
  strict; the new ``ZeroFill`` runs ride the existing
  ``map_image_run_anon`` path.
- ``kernite/src/syscall/mo.rs`` — ``MO_CLONE_RANGE`` range check stays
  strict.
- Wire / protocol / mmsrv control IPC — unchanged.

Verification
============

- ``just warn``: layering-check ok; full clean rebuild; no new
  warnings introduced. The cap-discipline lint accepts the planner
  change (``__trona_cap_*`` access sites are untouched) and the init
  ``compute_spawn_layout`` / ``plan_for_closure`` reuse path stays
  bit-for-bit identical to the pre-fix baseline.
- ``just run`` (path exec via VFS, runtime test_runner Test 1 —
  ``TEST_EXEC``): ``libtrona.so`` and ``libc.so`` load from VFS,
  ``ldtrona-elf`` reaches the entry-point handoff, ``TRONA-TLS
  init_main`` runs, and ``TEST_EXEC Test 1: PASS`` is reported::

      [TEST_EXEC] Test 1: execve ELF via vfs path
      [ldtrona-elf] loaded from vfs: libtrona.so
      [ldtrona-elf] loaded from vfs: libc.so
      [ldtrona-elf] startup via trona_runtime_install
      [ldtrona-elf] handoff to entry 0x400000011000
      [TRONA-TLS] init_main: block=0x4000040cf040 tcb=0x4000040d0040 tp=0x4000040d0040
      [TEST_EXEC] Test 1: PASS

  This is the test that previously failed with::

      [ldtrona-elf] failed to load DT_NEEDED: libtrona.so stage=image-map-run
      [ldtrona] FATAL: ELF dependency load failed

  Per ``[MMSRV] client registered id=0x6a pid=84 … dso=0x40000c192000
  ..0x7ffff7dff000``, the new process's mmsrv layout matches the
  registered one — the runtime DSO window covers the DSO arena as
  RFC-0010 requires, so ADR-0002's ldsrv EP resolution, ADR-0003's
  image-kind-on-the-wire, and this ADR's planner split compose cleanly.
