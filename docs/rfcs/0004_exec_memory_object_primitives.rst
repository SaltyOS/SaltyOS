==================================================================
RFC-0004: Kernel Memory-Object Primitives for exec
==================================================================

:Status: Implemented
:Areas: Kernel; Memory; Capability
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Description: Three kernel capabilities that let a process be handed its executable as a MemoryObject and mapped from it: rights-checked MemoryObject mapping (executable / writable gated on the cap's rights), a per-mapping protection ceiling that ``protect`` cannot exceed, and a sub-range copy-on-write clone.

Problem Statement
=================

To map a process's image from a MemoryObject (MO) capability it was handed,
three things the kernel could not express were needed:

- ``VSPACE_MAP_MO`` did not consult the MO capability's rights, so an executable
  or writable mapping could be created from a capability that lacked
  ``EXECUTE`` / ``WRITE``. The loader's W^X and exec-bit guarantees rest on the
  capability, not on the syscall arguments.
- A mapping carried no protection ceiling. A region mapped read-only or R-X could
  be re-elevated by a later ``protect`` (``mprotect``), so a deliberately
  restricted MO capability bought nothing.
- ``MO_CLONE`` was whole-MO 1:1 only — it hard-coded the child's page count to
  the parent's and attached at offset zero. A writable data segment is a
  *sub-range* of the image MO, so a sub-range copy-on-write clone was missing.

A ``Capability`` carries its rights by value, and a typed lookup returns the
whole capability, so a mapping looked up for ``READ`` can still test
``has_right(WRITE / EXECUTE)``.

Summary
=======

- ``VSPACE_MAP_MO`` checks the MO capability's rights: a writable mapping requires
  ``WRITE``, an executable mapping requires ``EXECUTE``; the existing
  writable-and-executable rejection stands.
- ``VmArea`` gains a ``max_prot`` ceiling (carved from existing padding, so the
  struct size is unchanged). ``protect`` pre-scans the covered areas and
  atomically rejects a request whose protection exceeds any area's ``max_prot``,
  rather than silently clamping.
- ``MO_CLONE_RANGE`` clones an arbitrary ``[offset, count)`` sub-range of a parent
  MO as a copy-on-write child.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- An executable or writable MO mapping MUST require the matching cap right; W^X
  in one mapping MUST stay rejected.
- A mapping's protection ceiling MUST be enforced in-kernel, so a direct
  ``CAP_SELF_VSPACE`` invoke cannot raise protection past it.
- ``protect`` rejection MUST be atomic — no partial protection change on reject.
- The sub-range clone MUST leave the whole-MO clone path unchanged.

Design
======

Rights-checked mapping
----------------------

``syscall_vspace_map_mo`` mirrors the existing device-range mapping: it looks up
the MO capability for ``READ`` and requires ``WRITE`` for a writable mapping and
``EXECUTE`` for an executable one. This makes a mapping's maximum protection a
property of the capability it was created from, which the loader relies on to
issue a read-and-execute (never writable) image.

The protection ceiling
----------------------

Each ``VmArea`` records a ``max_prot`` derived at creation from the backing
capability's rights (a frame mapping, which backs page tables and IPC buffers,
defaults to full rights and carries no W^X policy). ``protect`` pre-scans the
``VmArea``\s a request covers and rejects atomically if the requested protection
exceeds any covered ceiling; nothing is changed on reject, matching POSIX
``mprotect`` atomicity. The reject is the kernel backstop — the userland memory
manager mediates ``mprotect`` against its own record, but a direct
``CAP_SELF_VSPACE`` invoke would bypass that, so the kernel enforces the ceiling
itself.

Sub-range copy-on-write clone
-----------------------------

``MO_CLONE_RANGE`` attaches a child to a ``[offset, count)`` window of the parent
under copy-on-write. The whole-MO clone and the sub-range clone share one
implementation parameterized by ``(offset, count)`` rather than two copies of the
delicate bind protocol; the whole-MO path is byte-identical to before. This is
the first runtime use of a non-zero clone offset, so the offset-bearing resolve,
snapshot, and lazy-collapse paths are exercised for the first time.

Implementation
==============

Landed alongside RFC-0002 (the per-COW-tree lock that the clone bind protocol
runs under). The original plan kept the whole-MO and range clone as separate copies;
in implementation the single path was parameterized instead, because duplicating
the bind protocol invited drift. A static review confirmed the whole-MO path is
unchanged and that every parent-indexing site honours the clone offset.

Performance
===========

The mapping and protect paths gain bounded right-bit and ceiling checks. The
sub-range clone adds no per-page cost beyond the existing clone, and the single
parameterized path avoids a second copy of the bind protocol.

Ergonomics
==========

No interface change beyond the new ``MO_CLONE_RANGE`` invocation. Existing
full-rights mappings are unaffected; only under-righted executable / writable
mappings are newly rejected.

Backwards Compatibility
=======================

A new MemoryObject invoke label for the sub-range clone; ``VmArea`` keeps its
size. ``VSPACE_MAP_MO`` newly rejects an executable / writable mapping whose
capability lacks the right — a tightening, transparent to full-rights callers. No
personality-visible change.

Security Considerations
=======================

The rights check and the protection ceiling are the kernel half of W^X: a mapping
cannot become executable or writable beyond the capability it was created from,
and ``protect`` cannot raise it past the ceiling even through a direct vspace
invoke. The sub-range clone preserves copy-on-write isolation for a writable
segment that shares an MO with read-only segments.

Testing
=======

``just warn`` clean on x86_64 and aarch64. The clone offset path is exercised by
a write / read-back / copy-on-write-break test and by a fork over a cloned
sub-range; the ceiling by a ``protect`` that tries to raise a read-only region's
protection and is rejected, including through a direct ``CAP_SELF_VSPACE`` invoke.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Copy the clone path for the range variant** (original plan). Rejected in
  implementation: two copies of the bind protocol drift; the single path is
  parameterized and the whole-MO path stays byte-identical.
- **Silently clamp ``protect`` instead of rejecting.** Rejected: a silent clamp
  desyncs the kernel's protection state from the userland memory manager's
  record.

Prior Art and References
========================

- **seL4 / Genode** — a parent supplies a child's executable as a capability with
  explicit rights; the rights-checked mapping is what that model needs.
- **Zircon (Fuchsia)** — ``zx_vmo_create_child`` clones a sub-range of a VMO under
  copy-on-write; ``MO_CLONE_RANGE`` is the same primitive.
