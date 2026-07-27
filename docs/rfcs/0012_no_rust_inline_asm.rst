==================================================
RFC-0012: Explicit Assembly Boundary
==================================================

:Status: Implemented
:Areas: kernite; trona; basaltc; userland tests; build/lint
:Authors: Hamin Sung
:Reviewers: GPT 5.5
:Date: 2026-06-30
:Depends: none
:Supersedes: none
:Description: Ban Rust inline assembly in built SaltyOS code and require
  all ISA-specific instructions to live in explicit per-architecture assembly
  translation units.

Problem
=======

Rust inline assembly makes architecture ABI boundaries too easy to get subtly
wrong. A missing clobber, stale register assumption, or architecture-specific
calling convention detail can survive review because the instruction sequence
is embedded in otherwise ordinary Rust control flow.

The aarch64 syscall/capability handoff failure that motivated this RFC was
exactly that class of bug: the failing behavior looked like stale userspace
arguments across an ABI boundary. Even when a local inline-asm fix is possible,
the model remains hard to audit because every call site can express its own
register contract.

Decision
========

Built SaltyOS Rust code must not use:

- ``asm!``
- ``global_asm!``
- ``naked_asm!``
- ``#[unsafe(naked)]``

All instruction sequences must live in explicit assembly files:

- ``kernite/src/arch/<arch>/*.S``
- ``lib/trona/**/arch/<arch>/*.S``
- ``lib/basalt/c/src/arch/<arch>/*.S``
- ``userland/.../src/arch/<arch>/*.S`` for built userland tests or programs
- bootloader assembly under ``boot/**/arch/<arch>/``

Rust may declare narrow ``unsafe extern "C"`` helpers and wrap them in safe or
documented-unsafe APIs. The Rust wrapper owns type-level policy; the ``.S`` file
owns register allocation, trap instructions, privileged instructions, and entry
trampolines.

Layering Rule
=============

Architecture-specific assembly must not live in a common path. If an operation
is conceptually shared, common Rust calls an architecture API; the instruction
body still lives under the owning architecture directory. This includes libc and
runtime code: ``basalt`` follows the musl/glibc-style split where math, memory,
string, trap, and startup stubs are explicit assembly units rather than Rust
inline assembly snippets.

Mechanical Enforcement
======================

``tools/lint/asm_discipline.sh`` enforces two hard checks:

- no Rust inline assembly tokens in built source trees;
- no ``.S`` / ``.asm`` source outside an ``arch/x86_64``, ``arch/aarch64``, or
  bootloader ``arch/x86`` path.

The lint is wired into ``just fmt-check`` and is available directly via
``just lint-asm-discipline``. Archived, non-built ``userland/core/vfs_old*``
trees are excluded until deleted or revived.

Consequences
============

- ABI boundaries are reviewable as ordinary object-file interfaces.
- Clobber sets are expressed by the external function ABI instead of bespoke
  inline constraints.
- Assembly layout now mirrors prior art in libc and kernel codebases: one
  Rust owner has a matching arch-owned assembly implementation where needed.
- Adding a new architecture requires adding explicit ``.S`` implementations
  instead of hiding architecture branches inside common Rust.
