============================================================
Personality-Neutral Substrate and C Runtime
============================================================

:Status: Draft
:Areas: trona runtime; basaltc; Personalities; Loader
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Depends: (none)
:Description: Straighten the sagged personality boundary in the userland
   substrate. A genuinely neutral core already exists (``kernite`` plus the
   ``trona_kernel`` / ``trona_server`` / ``trona_runtime`` crates), but POSIX has
   leaked below where it belongs: neutral servers reach for a POSIX thread-local
   accessor, the canonical thread-local block carries POSIX and PE fields
   unconditionally, and the only ELF C runtime forces POSIX initialization on
   every process. This RFC re-establishes the boundary — a neutral CRT, a split
   ``libtrona``, a core-plus-extension thread-local block, and a unified ISO C
   core — so POSIX semantics live only in the POSIX surface and the neutral
   substrate becomes a real, app-facing lane over a C ABI. Landable now; it is the
   foundation the cap-native spine (the ``cap_native_spine`` draft) and the ELF+PE
   engine (the ``elf_pe_coexistence`` draft) build on.

Problem Statement
=================

The kernel and the ``trona_kernel`` / ``trona_server`` / ``trona_runtime`` crates
are personality-blind. Three leaks undermine that:

- **Neutral servers depend on the POSIX personality.** Most core servers and
  drivers link ``trona_posix`` and call ``trona_posix::tls::current_ipc_ctx`` to
  obtain the IPC-buffer pointer, although the neutral
  ``trona_runtime::current_ipc_ctx`` exists. The accessor is trivial, but the
  dependency is not: a neutral server pulls the POSIX personality into its address
  space for nothing.
- **The canonical thread-local block is personality-contaminated.**
  ``trona_kernel``'s ``ThreadLocalBlock`` carries POSIX fields (``errno``,
  cancellation state, the cleanup stack) and the Win32 PE thread-pointer block
  unconditionally, with no ``cfg`` gate. The kernel-ABI layer thereby ships every
  personality's per-thread state.
- **Every ELF process is POSIX.** ``libtrona.so`` bundles ``trona_posix``
  unconditionally; ``libc.so`` is built against ``trona_posix``; and the only ELF
  C runtime (``__libc_start_main``) unconditionally runs POSIX thread-local
  initialization. A process becomes POSIX the moment it enters userland, and there
  is no neutral lane an application can target.

The net effect is that POSIX squats in the substrate's place: the neutral core
exists but is not a usable, app-facing environment, and POSIX is the de-facto
default by leakage rather than by choice.

Requirements
============

- The substrate — kernel ABI, IPC, runtime, server primitives, the ISO C core,
  and the C runtime entry — MUST be personality-neutral.
- POSIX semantics MUST live only in the POSIX surface; no personality field or
  call may sit unconditionally in a neutral type or the neutral CRT.
- POSIX applications MUST be unchanged in source and behavior; the
  neutralization is internal.
- The public application ABI MUST be the C ABI (headers plus shared object). Rust
  crate metadata is an in-tree build convenience, not a distributable ABI.

Design
======

libtrona split
--------------

``libtrona.so`` divides into ``libtrona-core`` (the neutral
``trona_kernel`` / ``trona_server`` / ``trona_runtime`` surface) and a POSIX
surface library. Neutral servers, the loader, and the native lane link only
``libtrona-core``; only POSIX programs pull the POSIX surface.

Neutral CRT
-----------

The runtime / IPC / thread-local-core / slot initialization is extracted from
``__libc_start_main`` into a neutral CRT entry. An ELF process runs the neutral
CRT first; personality initialization layers on top. For a POSIX program,
``__libc_start_main`` is unchanged from the application's view (it still links
basalt ``libc`` and enters at ``_start``) but it now calls the neutral
initialization instead of owning it, then adds the POSIX layer (``errno`` and
cancellation thread-local state, ``stdio``, locale, ``environ``). A native
program runs the neutral CRT and stops there — no POSIX thread-local
initialization.

Thread-local block: core plus extension
----------------------------------------

``ThreadLocalBlock`` in ``trona_kernel`` holds only neutral fields (the IPC
context, the thread-local base, the thread id, the scheduling-context capability,
slot-allocator state). Personality state moves to an extension: the POSIX
extension (``errno``, cancellation, the cleanup stack, libc scratch) and the
Win32 extension (the PE thread-pointer block, PE TLS). The neutral type can no
longer grow a personality field — the contamination is removed by construction,
not by review.

The extension is placed at a **fixed offset adjacent to the core**, not reached
through a runtime pointer, so a hot field like ``errno`` resolves to a
compile-time thread-local offset — the cost model glibc and musl rely on. A
pointer-chased extension would add a dereference to every ``errno`` access; the
fixed-adjacent layout is the load-bearing detail and a measurement target.

basaltc as the unified C runtime
--------------------------------

basaltc becomes one C-runtime project. A single ABI-neutral ISO C core source
(explicit-width types, no ``long`` / ``wchar_t`` assumptions) compiles to the
per-personality C library: the native libc and the POSIX libc (the neutral core
plus the POSIX system-interface surface), both ELF. ``kernel32`` remains the
Win32 *API* shim, separate from the C runtime. The Win32 C runtime (the same core
recompiled to PE) is the ``elf_pe_coexistence`` engine's concern and out of scope
here.

The core's backing — the byte sink behind ``stdio`` and the heap behind
``malloc`` — is a **neutral runtime hook**, not a POSIX call. The POSIX surface
and the native surface each supply an implementation (POSIX over the VFS write
path, native over the runtime/spine write path); the ISO C core never calls a
POSIX ``write`` directly. This backend hook is exactly where the core / POSIX
boundary is drawn, so a native program's ``printf`` reaches a neutral sink and the
native lane is genuinely POSIX-independent.

Neutral servers
---------------

The neutral servers and drivers drop ``trona_posix`` and use
``trona_runtime::current_ipc_ctx``. The exact membership of the neutral set is
confirmed by audit at implementation time, because two read-only passes disagreed
on which servers already use the neutral accessor; the cleanup target is every
server that is not a personality server.

Public ABI
----------

Distributed and self-hosted applications build against installed C headers and
shared objects. Rust ``.rmeta`` cannot be a public ABI — a self-hosted application
does not carry the source tree — so the stable boundary is C, with an optional
source-distributed Rust binding crate over it for Rust applications.

Backwards Compatibility
=======================

Clean-slate; this aligns with the in-flight userland rewrite and needs no
migration. The split and the core-plus-extension thread-local block are additive
structure over an already-neutral kernel boundary. POSIX source and behavior are
unchanged.

Testing
=======

``just warn`` clean on x86_64 and aarch64. A neutral server links only
``libtrona-core`` and contains no ``trona_posix`` symbol. A native (non-POSIX)
program starts through the neutral CRT and runs without POSIX thread-local
initialization. POSIX programs build and behave identically to before.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Leave the neutral core unnamed and internal.** Rejected: it forecloses the
  native lane (the ``cap_native_spine`` draft) and lets POSIX keep squatting in
  the substrate's place.
- **``cfg``-gate the personality fields instead of splitting the type.**
  Rejected for the thread-local block: a core-plus-extension split removes the
  contamination structurally, whereas a ``cfg`` gate leaves the neutral type able
  to regrow personality fields.
- **Unknown:** the precise neutral-server membership, resolved by audit at
  implementation.

Prior Art and References
========================

- **glibc** — the canonical layer is the kernel system-call ABI (a neutral
  substrate, not a personality); ISO C, POSIX, and the GNU extensions are
  surfaces in one C library. The model this RFC restores at the SaltyOS substrate.
- **musl / newlib** — a portable ISO C core over a small, swappable OS backend;
  the structure basaltc adopts for its per-personality libraries.
