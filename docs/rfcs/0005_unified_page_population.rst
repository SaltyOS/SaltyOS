======================================================================
RFC-0005: Unified Page Population and Declarative ForkPolicy
======================================================================

:Status: Implemented
:Areas: Kernel; Memory; mmsrv
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Description: Replace the per-path re-derivation of where a MemoryObject page's bytes come from with one classifier and one populate path that every consumer calls, and make fork inheritance a value stored on each region rather than a property guessed from the backing at fork time.

Problem Statement
=================

Every consumer of a MemoryObject (MO) page — the demand-fault handler, ``MO_READ``,
``MO_WRITE``, ``MO_COMMIT``, prefault, and mapping — independently decided where the
page's bytes come from. Two corruptions followed from that divergence:

- ``MO_COMMIT`` zero-filled a page without checking the backing kind. A file MO
  capability is reachable with full rights, so a commit could zero a
  pager-backed (file) page, overwriting its contents.
- A pager failure was flattened to "no page" at the resolve layer and then
  degraded to a zero page, turning an I/O error into silent zero data.

Fork inheritance had the same shape: whether a region was shared, copy-on-write
inherited, or excluded across ``fork`` was re-derived from the backing at fork
time, so a backing kind the derivation did not anticipate fell through to the
wrong arm — which is how a process that exec'd and then forked broke.

Summary
=======

One classifier names a page's effective source, and one populate path acts on it;
fault / read / write / commit / prefault / map all call it instead of re-deriving
the backing. A page's source *class* is fixed by the MO kind — anonymous and
shared-memory pages are zero-sourced, a file-backed page is external — and a
pager failure is a first-class outcome carried across the whole copy-on-write
chain, never a zero page.

Fork inheritance becomes a value, ``ForkPolicy``, stored on each region and set at
construction (with a validation backstop that makes an invalid policy/backing
combination unconstructible). ``fork`` dispatches on the stored policy instead of
guessing. An exec'd image's text and read-only segments carry the share policy —
the fix for exec-then-fork — as do writable shared mappings.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- One place decides a page's effective source; consumers MUST NOT re-derive it.
- The source class MUST follow the MO kind, not a "has a pager?" test, which
  mishandles a detached file-backed page as zero.
- A pager failure MUST be a recoverable outcome, never a silent zero page.
- Per-page population MUST classify and act under one continuous hold; only a
  pager wait may drop the lock and re-classify on resume.
- Fork inheritance MUST be a stored, validated policy, not a fork-time guess.

Design
======

The classifier
--------------

A non-blocking classifier walks the copy-on-write chain and reports a page as
resident, zero-sourced, pager-backed, or failed. The class is the MO kind:
anonymous / shared-memory resolve to zero, file-backed is external, and only
within the external case does the presence of a pager distinguish "fetch from the
pager" from "the pager failed". A failure is folded across the entire chain, so a
detached file-backed page reports failed rather than silently zero.

The populate path
-----------------

A populate primitive classifies, then acts: a zero page is committed in place, a
pager-backed page parks on a pager request. A classified source is valid only
within the hold it was observed in; resident and zero pages are acted on in that
same hold, and only the pager park drops the lock, after which a blocking wrapper
re-classifies. The demand-fault handler collapses its former three branches into
one match on this primitive.

The MO syscalls drive the same path: ``MO_READ`` commits the page on read,
``MO_WRITE`` breaks copy-on-write and populates writable, and ``MO_COMMIT``
operates per page and returns a status rather than zero-filling — dropping
whole-range atomicity for per-page progress, as mainstream kernels do across
pager I/O.

Declarative ForkPolicy
----------------------

Each region stores a ``ForkPolicy`` — share, copy-on-write inherit, or exclude.
A checked constructor and an install-time validation backstop make an invalid
combination unconstructible. ``fork`` is a dispatch on the stored value. The share
arm is general enough to retain a shared MO handle or duplicate a capability from
the live region. Exec text and read-only segments are stored as share (so a fork
after exec keeps sharing their pages), as are writable shared mappings.

Implementation
==============

Landed on top of RFC-0002 (the per-COW-tree lock). The classify-then-act
discipline rides that lock: classification and action share one hold, and only the
pager park drops it. ``MO_COMMIT``'s shift to per-page and status-only converged
over several review passes; the load-bearing corrections were pinning the MO
across the per-page loop and carving fresh storage only for zero-sourced pages.

Performance
===========

The classifier and populate path replace the branch each consumer carried, with
no added per-page cost. ``MO_COMMIT`` trades whole-range atomicity for per-page
progress.

Ergonomics
==========

Consumers call one populate primitive instead of re-implementing backing logic,
and a region's fork behaviour is read from a stored value rather than recomputed.

Backwards Compatibility
=======================

``MO_COMMIT`` returns a status rather than a committed count. ``ForkPolicy`` is an
internal region field. No personality-visible change.

Security Considerations
=======================

The unified source closes the two corruptions: a commit can no longer zero a
file-backed page, and a pager I/O failure surfaces recoverably instead of as
silent zero data. The stored ``ForkPolicy`` removes the silent fall-through that
mis-shared or mis-excluded a backing across ``fork``.

Testing
=======

``just warn`` clean on x86_64 and aarch64; fork / mmap / copy-on-write under
``--smp 2`` is the gate before anything builds on the unified populate and
``ForkPolicy``.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Classify a page by "has a pager?" instead of by MO kind.** Rejected: a
  detached file-backed page would classify as zero and corrupt.
- **Keep ``MO_COMMIT`` whole-range atomic.** Rejected: range atomicity across
  pager I/O has no mainstream precedent and holds the hierarchy lock across I/O;
  per-page progress matches Zircon and Linux.
- **Derive ``ForkPolicy`` at fork time.** Rejected: that is the silent
  fall-through that broke exec-then-fork.

Prior Art and References
========================

- **Zircon (Fuchsia)** — ``zx_vmo_op_range(COMMIT)`` drops the hierarchy lock for
  pager I/O and returns a recoverable error; the per-page, status-returning model
  follows it.
- **Linux** — ``__mm_populate`` drops the mmap lock per chunk, so commit is not
  range-atomic; ``dup_mmap`` inherits per-VMA, mirrored by the stored per-region
  ``ForkPolicy``.
