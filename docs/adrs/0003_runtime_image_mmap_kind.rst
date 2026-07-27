============================================================
ADR-0003: Runtime image mmap carries image kind
============================================================

:Status: Implemented
:Areas: libtrona protocol/runtime/loader; mmsrv mmap; loader image metadata
:Authors: Hamin Sung
:Reviewers: GPT 5.5
:Date: 2026-06-28
:Supersedes: none
:Depends: ``docs/rfcs/0010_unified_vm_layout_plan.rst``,
  ``docs/rfcs/0009_capability_bounded_wx.rst``,
  ``lib/trona/protocol/src/mm.rs`` (``MM_MMAP``),
  ``userland/core/mmsrv/src/mmap.rs`` (self-tier mmap handling),
  ``userland/core/mmsrv/src/dispatch.rs`` (stage-time image-region handling).
:Description: Runtime DSO image-run mappings must carry the concrete image
  kind (TEXT, RODATA, DATA, BSS) on the ``MM_MMAP`` wire alongside the image
  reservation id. The reservation id proves placement in the RFC-0010 DSO
  image area; the image kind selects the region type, maximum protection,
  fork policy, and backing descriptor. Without the kind, the runtime loader
  path can validate the address span but still collapse image runs into
  generic mmap semantics.

Context
=======

RFC-0010 gives dynamically loaded images a dedicated DSO virtual-address
range. Runtime image-run mappings are identified by a non-zero image
reservation id: mmsrv validates such mappings against the image reservation
instead of the ordinary mmap limit, and ``MM_UNMAP_IMAGE`` tears down the
whole image by reservation id.

That was only half of the contract. The stage-time loader path already
passes image kind through ``MM_STAGE_IMAGE_REGION`` and mmsrv uses it to
publish correct memory metadata:

- TEXT is a shared executable image region and RODATA is a shared-library
  read-only region, both with bounded maximum protection.
- DATA is a private COW image region.
- BSS is a private demand-zero image region.

The runtime self-tier path, however, only passed the image reservation id in
``MM_MMAP``. That let mmsrv validate that a run belonged to a DSO reservation,
but it did not tell mmsrv whether the run was TEXT, RODATA, DATA, or BSS.
As a result, the runtime path had to infer semantics from source shape and
protection flags. That inference is not stable:

- ``PROT_READ`` can be ordinary mmap data or RODATA.
- ``MM_FLAG_PRIVATE`` describes source mechanics, not image identity.
- DATA and BSS both need private semantics, but they do not have the same
  source backing.
- A reservation id alone cannot pick ``region_type``, ``max_prot``,
  ``fork_policy``, or ``BackingDescriptor``.

The concrete symptom that exposed the drift was a runtime loader failure
reported as::

    [ldtrona-elf] failed to load DT_NEEDED: libtrona.so stage=image-map-run
    [ldtrona] FATAL: ELF dependency load failed

At that point library lookup had already reached ldsrv. The remaining
failure was in runtime image-run mapping, where the runtime loader and mmsrv
did not share enough metadata to preserve the same image semantics that the
stage-time path already had.

Decision
========

Make image kind an explicit part of the runtime image-map request.

1. **Extend ``MM_MMAP`` image-run wire format.**

   ``MM_MMAP`` now uses ``regs[6]`` for ``image_id`` and ``regs[7]`` for
   ``image_kind``. The two fields are paired: callers either set both to
   zero for an ordinary mmap, or set both for an image-run mmap. mmsrv
   rejects partially populated image metadata.

   The wire kind values are the existing stage image-kind values:

   - ``STAGE_IMAGE_KIND_TEXT``
   - ``STAGE_IMAGE_KIND_RODATA``
   - ``STAGE_IMAGE_KIND_DATA``
   - ``STAGE_IMAGE_KIND_BSS``

   This deliberately reuses the stage-time vocabulary instead of creating
   a second runtime-only enum.

2. **Have rtld pass the concrete run kind.**

   The runtime loader converts ``ImageRunKind`` into the wire image kind
   and supplies it for both code-MO-backed and anonymous runtime image runs.
   TEXT, RODATA, DATA, and BSS are no longer inferred by mmsrv from the
   final protection alone.

3. **Classify runtime image mappings in mmsrv.**

   mmsrv now derives image-region metadata from the explicit image kind:

   - TEXT maps as ``REGION_IMAGE_TEXT`` with image fork policy.
   - RODATA maps as ``REGION_SHARED_LIB`` with image fork policy.
   - DATA maps as ``REGION_IMAGE_DATA`` with private COW image policy.
   - BSS maps as ``REGION_IMAGE_BSS`` with private image policy.

   Shared code-MO mappings for TEXT and RODATA keep their caller-provided
   file/code-MO backing, because that source path owns an external cap.
   Registry-managed or anonymous image materialization uses
   ``BackingDescriptor::Image`` with the explicit image kind.

4. **Make invalid source/kind combinations impossible.**

   The self-tier mmap path now rejects combinations that do not describe a
   valid image run:

   - image metadata with stack mappings;
   - image metadata with shared anonymous mappings;
   - image metadata with SHM MOs;
   - anonymous TEXT or DATA image runs;
   - private code-MO TEXT or BSS image runs;
   - shared code-MO DATA or BSS image runs.

   Early validation failures after receiving an MO cap delete the receive
   scratch cap before replying, so failed requests do not leave stale caps
   in the scratch slot.

5. **Materialize partial RODATA tail pages in rtld, then restore final
   protection.**

   When a private RODATA run has file bytes shorter than the mapped run,
   rtld maps the private child temporarily writable, zero-fills the tail,
   then calls ``mprotect`` to restore the final read-only protection before
   handing control onward.

   This keeps the mmsrv self-tier path non-blocking and avoids adding a
   state-lock-sensitive data-copy path there. It also matches the standard
   dynamic-loader pattern: loader-owned relocation or tail materialization
   can temporarily write private image pages before applying final program
   protections.

Consequences
============

Positive
--------

- **Runtime and stage-time image metadata now match.** Both paths carry an
  explicit image kind and use it as the authority for image region
  classification.
- **RFC-0010 image reservations now preserve semantics, not only span
  membership.** ``image_id`` validates placement and grouping; ``image_kind``
  selects memory semantics.
- **W^X and maximum-protection policy are less inference-dependent.** mmsrv
  no longer has to decide whether a runtime run is TEXT, RODATA, DATA, or
  BSS from protection bits alone.
- **Fork policy is stable across loader paths.** Runtime DATA and BSS use
  private image semantics; TEXT and RODATA use shared image semantics.
- **Failure cleanup is tighter.** Failed code-MO mmap validations that had
  already received a cap now clear the scratch receive slot before replying.

Negative
--------

- **``MM_MMAP`` has one more image-only register.** Image callers that set
  ``regs[6]`` must now also set ``regs[7]``. Ordinary callers that leave
  zero-initialized request registers unchanged remain ordinary mmap callers.
- **The runtime loader has a temporary writable window for partial RODATA
  private pages.** The window is loader-local and is closed with
  ``mprotect`` before control is handed onward, but it is still an explicit
  part of the design.

Neutral
-------

- Shared TEXT/RODATA runtime mappings may still use a file/code-MO backing
  descriptor rather than ``BackingDescriptor::Image`` when the source path
  retains a caller-provided MO cap. The image kind still governs region type,
  fork policy, and maximum protection.
- ``MM_UNMAP_IMAGE`` remains reservation-id based. It does not need the
  image kind because teardown is grouped by image reservation.
- This ADR records the runtime image-mapping classification decision. It
  does not claim that the whole path-execution surface is complete.

Rejected alternatives
=====================

- **Keep only ``image_id`` and infer image kind from protection flags.**
  Rejected because protection flags are not a stable identity. ``PROT_READ``
  can describe RODATA, ordinary read-only mmap data, or a temporarily
  writable private page after final protection is restored.

- **Treat runtime DSO runs as generic mmap regions.** Rejected because
  RFC-0010 models loaded DSOs as image reservations in the DSO area, not as
  ordinary mmap allocations. Generic mmap semantics lose image teardown,
  region type, maximum-protection, and fork-policy information.

- **Add a separate runtime-only image-map verb.** Rejected because
  ``MM_MMAP`` already maps caller-owned MOs and anonymous runs into the
  caller VSpace. Extending it with paired image metadata is smaller and
  mirrors ``MM_STAGE_IMAGE_REGION`` without introducing another IPC shape.

- **Materialize RODATA tails inside mmsrv.** Rejected for this change
  because mmsrv would need a blocking copy path while carefully preserving
  state-lock and receive-scratch discipline. The loader already owns the
  bytes and can perform temporary private-page writes before restoring final
  protection.

Implementation
==============

- ``lib/trona/protocol/src/mm.rs``

  - added ``MM_MMAP_REQ_REG_IMAGE_KIND`` at ``regs[7]``;
  - documented ``regs[6]`` / ``regs[7]`` as a paired image-run metadata
    field;
  - clarified that stage image kind does not imply one fixed backing
    descriptor across all source paths.

- ``lib/trona/runtime/src/client/mm.rs``

  - ``map_image_run_mo`` now accepts and sends ``image_kind``;
  - ``map_image_run_anon`` now accepts and sends ``image_kind``;
  - both image-run helpers send eight request registers so ``regs[7]`` is
    part of the wire message.

- ``lib/trona/loader/rtld/image_sink.rs``

  - translates ``ImageRunKind`` into the protocol image-kind constants;
  - passes image kind for MO-backed and anonymous image-run mappings;
  - maps partial private RODATA tails temporarily writable, zero-fills them,
    then restores final protection with ``mprotect``.

- ``userland/core/mmsrv/src/mmap.rs``

  - parses and validates paired ``image_id`` / ``image_kind`` metadata;
  - maps image kind to region type and fork policy;
  - publishes image-aware backing metadata where mmsrv owns the image
    materialization;
  - rejects invalid source/kind combinations;
  - deletes received scratch caps on early validation failure.

- ``lib/trona/loader/common/image.rs``

  - documents that RODATA boundary pages may be temporarily writable inside
    the loader, but must be restored to final read-only protection before
    user code runs.

- ``lib/trona/runtime/src/weak.rs``

  - corrected the netsrv comment to describe its actual lazy-only
    resolution contract rather than a non-existent startup cap-table role.

Verification
============

- User-side verification confirmed no additional regressions after this
  patch series.
- This ADR intentionally does not claim that path execution or ``execve`` is
  fully fixed; it records the runtime image-mapping wire and classification
  decision.
- Build, boot, and test commands were not run by the agent in this session,
  per instruction.
