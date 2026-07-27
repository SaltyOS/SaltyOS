==========================================================
RFC-0006: execve via a Caller-Provided Memory Object
==========================================================

:Status: Implemented
:Areas: Userland; mmsrv; VFS; init
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Description: The process calling ``execve`` resolves the binary path with its own VFS authority; VFS issues it a read-and-execute MemoryObject for the resolved file; the caller hands that capability to ``init``, which maps the image's segments zero-copy from it. ``init`` never becomes a VFS client.

Problem Statement
=================

``init`` (PID 1) loaded a process image itself, resolving the path through a VFS
client. But ``init`` holds only hardware and kernel role capabilities — it has no
VFS authority — so the resolve returned nothing and every ``execve`` failed.

This is structural, not a missing capability. ``init`` is not a VFS client and
cannot resolve a path. Granting ``init`` VFS authority inverts the layering
(``init`` would depend on VFS) and raises an unanswerable question: under whose
working directory and credential is the path resolved? The exec *model* therefore
changes rather than being patched.

Summary
=======

The process calling ``execve`` resolves the binary with its own VFS authority —
its own working directory and credential. VFS applies the exec policy (a regular,
executable file on a mount that permits execution) and issues a *read-and-execute*
(never writable) MemoryObject capability for the resolved file. The caller hands
that capability to ``init``, which maps the image's segments directly from it:
text and read-only segments shared from the MemoryObject's pages, the writable
data segment as a private copy-on-write sub-range, and bss as demand-zero.
``init`` never opens a file and never becomes a VFS client.

This is the model seL4 / Genode (the parent provides the ELF as a capability) and
Fuchsia / Zircon (the caller provides an executable VMO) converge on.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- ``init`` MUST NOT be a VFS client; path resolution happens in the calling
  process under its own authority.
- VFS MUST issue the binary as a read-and-execute capability, never writable,
  after an exec policy check.
- Segment mapping MUST be zero-copy for a page-aligned image: text and read-only
  segments share the file's pages, the data segment is private copy-on-write, bss
  is demand-zero.
- A process that exec'd and then forks MUST keep sharing its read-only segments
  and inherit its data segment copy-on-write.

Design
======

Resolution and issuance
-----------------------

The calling process asks VFS to open the path *for execution*. VFS resolves it
under the caller's working directory and credential, checks that the leaf is a
regular file on a mount that permits execution and that the caller may execute it,
and replies with a read-and-execute MemoryObject capability for the file's
contents. Because the caller — not ``init`` — supplies the authority, there is no
ambiguity about whose namespace the path is resolved in.

Mapping the image
-----------------

The caller forwards the MemoryObject capability to ``init``. ``init`` maps the
image's headers read-only to read the segment table, then maps each segment from
the capability: text and read-only segments shared and demand-paged, so the
file's physical pages are shared across every process running the binary; the
writable data segment as a private copy-on-write sub-range of the same
MemoryObject (RFC-0004's sub-range clone); and the trailing bss demand-zero. A
page-aligned image loads with no copy.

Exec-then-fork
--------------

Because the read-only segments are mapped shared and the data segment is private
copy-on-write, a fork after exec keeps the child sharing text and read-only pages
and inheriting data copy-on-write, carried by the stored fork policy (RFC-0005).

Implementation
==============

In flight. The kernel and mmsrv side — the MemoryObject primitives (RFC-0004),
the unified page population (RFC-0005), and the per-segment mapping of an image
from a provided MemoryObject — are in place, as is the VFS open-for-execution
path. The remaining work is the live wiring in the calling process and ``init``:
switching them from the old open-and-read-bytes path to forwarding and consuming
the MemoryObject. This RFC is ``Draft`` until that wiring lands and the image
boots from the zero-copy path.

Performance
===========

A page-aligned image loads zero-copy: text and read-only segments share physical
pages across processes, data is lazy copy-on-write, bss is demand-zero. A
misaligned segment falls back to a copy; the normal static-PIE target is
page-aligned.

Ergonomics
==========

``execve`` is unchanged to its caller. ``init`` sheds its image-loading byte path
and holds no filesystem authority.

Backwards Compatibility
=======================

A new VFS open-for-execution operation and the addition of the image
MemoryObject to the exec request. ``init`` stops opening the binary. The public
``execve`` semantics are unchanged.

Security Considerations
=======================

The binary is issued read-and-execute and never writable (W^X, enforced by
RFC-0004). The path resolution and the exec policy check run under the calling
process's own VFS authority, not ``init``'s — ``init`` carries no ambient
filesystem authority. A forwarded capability that lacks execute rights fails the
exec gracefully rather than faulting the kernel.

Testing
=======

``just warn`` clean on x86_64 and aarch64. End to end: a binary executes; its
data is writable and private (a global write is copy-on-write into the child); bss
is zero; argv and envp arrive. A fork after exec shares text and read-only and
inherits data copy-on-write. Concurrent exec under ``--smp 2``.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Give ``init`` VFS authority and keep it loading the image.** Rejected: a
  layering inversion that also leaves "whose working directory / credential
  resolves the path?" unanswerable.
- **Copy the image through IPC instead of sharing a MemoryObject.** Rejected:
  loses zero-copy and the cross-process page sharing of text and read-only
  segments.

Prior Art and References
========================

- **seL4 / Genode** — the parent provides a child's executable as a capability;
  the system carries no ambient authority to open it.
- **Fuchsia / Zircon** — the launcher resolves the binary and hands the new
  process an *executable* VMO; the loader maps from that VMO.
