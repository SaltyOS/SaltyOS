================================================================
The SaltyOS-Native Personality and the Object Spine
================================================================

:Status: Draft
:Areas: Personalities; trona runtime; VFS; Authorization
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Depends: substrate_neutralization
:Description: The SaltyOS-native personality — a first-class application
   environment in which programs use SaltyOS's own model directly — and the native
   object model (the "spine") it rests on. The personality is the **interop and
   capability** environment: a CoreFoundation-style object model unifies the
   system's objects so a POSIX ``fd``, a Win32 ``HANDLE``, and a native reference
   are toll-free-bridged views of one object, and on it the personality offers
   capability-native operation (an opt-in Capsicum-style mode), POSIX+Win32 interop
   within a single process, and native control-plane APIs (the
   ``principalid_access_control`` authorization tooling, capability management,
   secure services). The object model, capability-native operation, and the
   control plane are deliverable first; the cross-format engine that completes
   interop is the ``elf_pe_coexistence`` draft, deferred, and the object model is
   designed for it from the start. Depends on the personality-neutral substrate
   (the ``substrate_neutralization`` draft).

Status and Scope
================

Depends on the ``substrate_neutralization`` draft (the neutral substrate, CRT, and
unified C runtime). This RFC defines the native personality and the native object
model it is built on. The personality's scope is the whole interop-and-capability
environment. What lands *first* is the object model, capability-native operation,
and the control plane — they depend on no Win32 content and serve secure services
and control-plane tooling immediately. The cross-format coexistence engine and the
borrowed Win32 content that *complete* interop are the ``elf_pe_coexistence``
draft: a deferred build, **not** a scope reduction. The object model is designed
format-agnostic precisely so that the engine adds the Win32 path without reshaping
it.

Problem Statement
=================

SaltyOS's value is its capability microkernel, but the POSIX personality *hides*
that model: it emulates ambient authority (open-by-path, uid checks) over
capabilities, so no application ever uses SaltyOS as a capability system. And
SaltyOS uniquely implements *both* POSIX and Win32 natively on one capability
kernel — which makes possible a capability no other system has: one process using
both API worlds over shared objects. Two concrete gaps make the personality
necessary now: the system has no environment in which an application targets
SaltyOS's own abstractions, and the ``principalid_access_control`` draft's neutral
``AccessControl`` model — richer than POSIX ``mode`` — needs native tooling the
POSIX ``chmod`` interface cannot express.

The native personality is where these converge: SaltyOS's own model exposed to
applications, capability-native operation, cross-personality interop, and the
native control plane.

Identity
========

The SaltyOS-native personality is the **interop-and-capability environment**, on a
native object model:

- **The native object model (the spine)** — a CoreFoundation analog: one
  per-process object model in which a POSIX ``fd``, a Win32 ``HANDLE``, and a
  native reference are toll-free-bridged views of the same underlying object.
- **POSIX+Win32 interop** — a single process using both API worlds over shared
  objects. SaltyOS's unique value, possible only because it runs both
  personalities natively on one capability kernel; no other system offers it.
- **Capability-native operation** — an opt-in Capsicum-style mode that drops
  ambient authority and runs on held capabilities only.
- **Native control-plane APIs** — direct APIs over SaltyOS's own model: the
  ``principalid_access_control`` draft's authorization tooling (an
  ``AccessControl`` editor the POSIX ``chmod`` surface cannot express), capability
  management, and secure services.

The personality is **public but not recommended**: it is SaltyOS-specific, so
portable software should target POSIX; the native lane is for software that wants
SaltyOS's model — including its interop — directly.

**What lands first** is the object model, capability-native operation, and the
control plane: they have users immediately and need no Win32 content. The
cross-format engine and content that complete interop are the
``elf_pe_coexistence`` draft. This is build sequencing, not a narrower
personality — interop is intrinsic to the identity, and the object model is built
to carry it.

**The bridgeable set.** Toll-free bridging reaches only objects that live in the
spine: the cross-personality object types — files, sockets, and pipes today, and
further types (such as synchronization objects) only as they are implemented
natively in the spine. Win32's Win32-specific object universe — the registry,
process and window-station objects, and the API breadth borrowed from Wine — lives
outside the spine (the ``elf_pe_coexistence`` draft) and is therefore outside the
bridge. Interop is POSIX and Win32 jointly operating on the object types both
worlds share, not POSIX gaining visibility into the whole Win32 object universe.

Design
======

The native object model (the spine)
-----------------------------------

The spine is a per-process layer in the runtime and C library — a table of
**names** and **references to open-instances** — not a kernel change. It unifies
the system's object types: files, sockets, and pipes (held by the VFS), and
shared memory, memory objects, and endpoints (kernel capabilities).

The authoritative open-instance — the one that carries the shared offset — lives
where its backing lives, **not** in the process. For a VFS-backed object the
open-instance is the VFS ``OpenObject`` held **server-side**, and the spine holds
a reference to it; for a kernel-capability-backed object it is the kernel object.
The spine's per-process part is the name table and the references; the
offset-bearing open-instance is never copied into the address space. This is what
keeps ``fork`` correct — ``fork`` duplicates the name table and the references, so
parent and child name the *same* server-side open-instance and share its offset,
as POSIX requires. A client-side offset would instead be duplicated by ``fork``
and the two processes would diverge, a POSIX violation.

Capability semantics do not require a per-object kernel capability: as in Capsicum,
rights enforced at the backing are sufficient, so the spine core adds no kernel
mechanism. A POSIX ``fd``, a Win32 ``HANDLE``, and a native reference are
personality-specific names over this one model, which is what makes interop
possible at all.

Three layers
------------

The model is three layers, matching POSIX's own structure:

- **L1 — name (personality-specific).** A POSIX ``fd`` (dense, the lowest unused
  number, carrying ``close-on-exec``) or a Win32 ``HANDLE`` (opaque, carrying
  ``HANDLE_FLAG_INHERIT``). The fd table and the HANDLE table are **separate
  views** with separate, non-collapsible semantics — ``close-on-exec`` and
  ``HANDLE_FLAG_INHERIT`` are opposite, not the same flag. The dense lowest-unused
  contract lives here; real software depends on it.
- **L2 — open-instance (the bridged unit).** An object reference plus the current
  offset and status flags, held at the backing authority (server-side in the VFS
  for a file). Created per ``open`` / ``CreateFile``; shared by
  ``dup`` / ``DuplicateHandle`` / ``fork``. The VFS ``OpenObject`` already has this
  shape. Because the offset lives here, two names for one open-instance share it
  (``dup``) while two opens of one object get separate offsets — correct for both
  personalities.
- **L3 — object.** The backing capability or server handle, where identity and
  rights live (Capsicum-style).

This split is faithful to POSIX itself, which already separates the per-``fd``
flags (``F_GETFD``) from the per-open-instance flags and offset (``F_GETFL``).

The model is **symmetric**: the native surface MUST NOT mutate an open-instance in
ways the POSIX or Win32 views cannot observe. The native surface is a third name
over the same L2/L3, not a privileged owner — otherwise the native personality
silently becomes the canonical one, which this design rejects.

Capability mode
---------------

Capability mode is opt-in (a ``cap_enter`` equivalent). After entry the process
holds no ambient authority and operates only on the handles and capabilities it
already has; ``openat`` relative to a directory handle replaces open-by-path.

Enforcement is **cross-cutting, not one mechanism**: the kernel enforces rights on
capability-backed objects, and the VFS enforces them on file-backed objects — in
capability mode the VFS MUST refuse an ambient open-by-path. The policy is stated
once and enforced by each authority over its objects.

Capability mode is **per-process** (``cap_enter`` is process-global) while
personality is **per-handle**; the two axes are orthogonal. The VFS drops its
per-client personality stamp (below) but keeps a per-process capability-mode bit,
and refuses an ambient open-by-path while that bit is set.

Per-handle personality
----------------------

The VFS today stamps a single personality per client and rejects mismatched
traffic. The spine moves personality from **per-client to per-handle**: an
open-instance records the personality that opened it, and one process may hold
POSIX-named and (later) Win32-named handles at once. This is the concrete first
change the model forces, and the precondition for the interop the personality
exists to provide.

Process creation
----------------

Process creation is where POSIX ``fork`` and capability purity meet, and both are
specified:

- **POSIX ``fork``** shares the parent's L2 open-instances (shared offsets) and
  duplicates the L1 fd table (same instances, independent fd numbers). ``exec``
  drops the L1 names marked ``close-on-exec``; the rest, and their L2 instances,
  survive.
- **Capability-endowment spawn** (the cap-mode creation primitive) gives the
  child only a named set of handles — no ambient inheritance. This is the
  cap-native counterpart to ``fork`` and the path a capability-mode program uses.

Authorization interplay
-----------------------

A capability-backed handle carries its authority at L3, so holding it *is* the
authorization — a capability-mode access consults no ACL. The
``principalid_access_control`` draft's identity-plus-ACL evaluation governs the
ambient-identity personalities (POSIX uid, Win32 SID) and the broker that mints a
handle for an identity (deciding, once, whether to grant it). The native
control-plane tooling *manages* that identity model; capability-native
applications *use* handles directly. The ACL is thus consumed at the
identity-to-capability boundary, not on every native access.

Backwards Compatibility
=======================

Clean-slate. The per-handle personality replaces the VFS per-client stamp; the
spine is additive in the runtime and C library over the neutral substrate (the
``substrate_neutralization`` draft). No on-disk or syscall-surface migration.

Open Questions
==============

- **The identity-to-capability broker.** The interface that, given a ``Principal``
  (the ``principalid_access_control`` draft), evaluates the ACL and mints a handle
  for a capability-mode program (a powerbox / Capsicum-Casper analog).
- **``O_APPEND`` atomicity.** Append MUST be atomic at the backing operation, not
  read-offset-then-write; the L2 offset is advisory for append.
- **The capability-mode enforcement split.** The exact division of the refusal
  policy between the kernel and the VFS, and how a directory handle scopes
  ``openat``.
- **The remaining L1 contracts.** ``select`` / ``poll`` descriptor-set density,
  ``SCM_RIGHTS`` handle passing, ``/proc/self/fd``, and ``dup2`` to a chosen
  number, each placed at its layer.

Prior Art and References
========================

- **macOS CoreFoundation** — a C-level object model under toll-free-bridged
  Foundation and Carbon: one object, multiple API views. The model for the spine's
  role as the shared object substrate that makes interop possible.
- **Capsicum (FreeBSD)** — rights limited on file descriptors, ``cap_enter`` to
  drop ambient authority, ``openat`` from a directory capability, and Casper for
  delegating the few ambient operations. The model keeps POSIX's layering and adds
  rights; it does not collapse the layers.
- **Fuchsia fdio** — a dense, POSIX-shaped ``fd`` table maintained in a client
  library over zircon handles; the name layer separated from the object handle.
- **CloudABI / WASI** — capability-pure, ambient-authority-free POSIX
  derivatives; they collapse toward ``fd`` ≈ capability and so lose the
  open-instance sharing that software such as a compiler or a process monitor
  relies on — the reason this design keeps the three layers.
- **The ``principalid_access_control`` draft** — the neutral ``AccessControl``
  model the native control-plane tooling manages and the identity-to-capability
  broker consumes.
