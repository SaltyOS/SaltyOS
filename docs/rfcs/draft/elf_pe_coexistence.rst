============================================================
ELF + PE In-Process Coexistence Engine
============================================================

:Status: Draft (experimental; deferred)
:Areas: Personalities; Loader; Win32; trona runtime
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Depends: substrate_neutralization, cap_native_spine
:Description: The engine that lets ELF (native/POSIX) and PE (Win32) modules
   coexist and call each other inside one address space, so a native process can
   use borrowed Win32 API content (Wine's PE DLL stack) while remaining a
   native/POSIX process. SaltyOS owns the coexistence mechanism — the loader, the
   calling-convention bridge, the cap-handle integration gate, and TLS; Wine
   supplies only the PE Win32 *content* (the breadth SaltyOS will not reimplement:
   ntdll/kernel32/user32, the registry, the low-level Windows ABI). Experimental,
   and deferred behind the substrate-neutralization and cap-native-spine work and
   a validating prototype.

Status and Scope
================

This RFC is **experimental and deferred**. It banks the design and keeps the
cap-native object model format-agnostic; it does not authorize implementation. It
MUST NOT block or distort the two foundational tracks it depends on:

- *substrate neutralization* — neutral CRT, ``libtrona-core``, a unified ISO C
  core, and a de-contaminated thread-local block; and
- *the cap-native spine* — the per-process open-instance object model that POSIX
  ``fd`` and Win32 ``HANDLE`` both name.

Implementation is gated behind those two and behind a prototype that resolves the
open questions below. Interop is intrinsic to the native personality (the ``cap_native_spine`` draft);
this RFC is the
deferred *engine* that completes its cross-format mechanism. What the personality
delivers first — its object model, capability-native operation, and the control
plane — needs none of this engine; the engine and its borrowed Win32 content come
later.

Problem Statement
=================

SaltyOS implements POSIX and Win32 as first-class native personalities on one
capability microkernel. The unique capability that creates is letting a single
process use both API surfaces over shared objects. The full Win32 surface
(registry, the thousands of API functions, the low-level Windows ABI) is
impractical to reimplement, so the Win32 *content* is borrowed from Wine. Wine's
modern form is PE: its DLLs are PE/COFF and call a narrow uniform boundary into a
host "unixlib". To host that content in a SaltyOS-native process, PE (Win32) and
ELF (native/POSIX) modules must coexist and interoperate inside one address
space.

The coexistence *engine* — loader, calling-convention bridge, integration gate,
TLS — is SaltyOS-owned core. Wine is borrowed *content* that runs on the engine.
SaltyOS does not depend on Wine for the coexistence mechanism.

Design
======

Division of labor
-----------------

**Ours (the engine):**

- An **ELF-primary unified loader** (``ldtrona``) with ELF and PE frontends
  sharing one address-space manager and one symbol namespace. The process is a
  native ELF process; PE modules are loaded into it as guests. SaltyOS does not
  borrow Wine's loader or process model (Wine is PE-primary).
- The **calling-convention bridge** (below).
- The **native gate** — an implementation of Wine's unix-call boundary ABI,
  backed by SaltyOS cap-handle operations.
- **TLS** reconciliation across the ELF and PE TLS models.

**Wine (borrowed content, kept as PE, running on the engine):** the PE Win32 DLL
stack (``ntdll``, ``kernel32``, ``user32`` ...), the registry, and the low-level
Windows ABI breadth SaltyOS will not reimplement.

The native gate
---------------

Wine's PE-to-host boundary is a single uniform call (verified against
``include/wine/unixlib.h``)::

    typedef UINT64 unixlib_handle_t;
    NTSTATUS __wine_unix_call( unixlib_handle_t handle, unsigned int code, void *args );

Per-function arguments are marshaled into one ``args`` struct; ``code`` indexes a
dispatch array; ``handle`` identifies the unixlib. SaltyOS implements *this ABI*
as the native gate, but its handlers perform cap-handle operations instead of
host syscalls: a Win32 ``NtCreateFile`` reaches the gate and creates an
open-instance in the cap-native spine, returning a ``HANDLE`` that names it. The
gate is the SaltyOS-owned "unixlib" the borrowed PE stack thunks into.

Calling-convention bridge
-------------------------

Convention translation between SysV (ELF) and Microsoft x64 (PE) is bounded, not
per-function:

- **app to PE Win32** — the Win32 headers annotate functions ``ms_abi``; the
  compiler emits Microsoft-x64 calls directly at those call sites. No loader
  thunk.
- **PE to native** — the single uniform gate above (one Microsoft-x64 to SysV
  thunk; arguments travel in the ``args`` struct).
- **escape hatches** that still need *generated* thunks: PE-to-app callbacks
  (window procedures, ``Enum*`` callbacks, APC/completion routines), function
  pointers obtained via ``GetProcAddress``, COM vtable calls, varargs, and
  by-value aggregate / SSE argument classes. ``ms_abi`` covers annotated
  ``CALLBACK``/``WINAPI`` call sites in compiled C, not arbitrary or unannotated
  pointers; the loader generates convention thunks for the rest.

The accurate claim is therefore "one syscall-style gate **plus** generated
callback/import thunks", not "one thunk".

Spine integration
-----------------

A Win32 ``HANDLE`` (produced by the gate) and a POSIX ``fd`` both name an
open-instance in the per-process cap-native spine. Because the spine sits below
the format boundary, cross-format mixing is by construction: the two are
personality-specific *names* (the L1 layer) over one shared open-instance (L2)
over an object capability or server handle (L3). The spine is format-agnostic, so
this engine adds a PE-side naming path without changing the spine.

TLS
---

Both TLS models live in one process: ``%fs`` for ELF TLS and ``%gs`` for the PE
``TEB`` on x86_64; ``TPIDR_EL0`` for ELF TLS and the reserved ``x18`` for the
``TEB`` on aarch64. Both are anchored in the shared thread-local block.

Process model: the PE island
----------------------------

Verified against Wine's startup path: Wine's ``ntdll`` (the unix side,
``ntdll.so``) bootstraps the process into a "Windows-like environment" —
``server_init_process_done`` registers with the server, ``signal_start_thread``
switches into the PE world, and ``call_init_thunk`` hands control to
``LdrInitializeThunk`` in the PE ``ntdll``. Wine's ``ntdll`` assumes it owns
process initialization: the ``PEB``/``TEB``, the loader lock and ``Ldr`` module
lists, and APC/exception dispatch.

The consequence is that an ELF-primary native process hosts Win32 as a **PE
island**: the native process constructs the environment Wine's ``ntdll`` expects
and hands the Win32 world a region it bootstraps, rather than the two formats
hosting each other symmetrically. The native process stays primary; the PE island
is a bootstrapped Win32 sub-world that reaches the rest of the system through the
native gate.

The wineserver dependency
-------------------------

``wineserver`` is a separate daemon that provides the services the Windows kernel
would, over a custom RPC: the server-side handle table, synchronization objects,
the registry, process/thread objects, and window stations. File I/O can land on
the SaltyOS spine through the gate, but handle, synchronization, registry, and
process/thread semantics are wineserver's. Replacing only the per-process unixlib
is therefore insufficient: hosting real Win32 breadth requires ``wineserver``
(vendored) or a SaltyOS service that provides its semantics. This is the
"low-level breadth SaltyOS will not reimplement" that motivates borrowing Wine,
and it is the largest integration cost.

Open Questions (prototype-resolved, not prose-resolved)
=======================================================

These do not yield to further design discussion; each needs a measurement.

- **PE-island viability.** Can a native-primary process host Wine ``ntdll``'s
  bootstrap without ceding process control — give it a credible
  ``PEB``/``TEB``/loader environment while the native loader stays primary?
  Resolved by a minimal spike (a PE ``ntdll`` brought up inside a native
  process), not by analysis.
- **wineserver integration.** Vendor ``wineserver`` and port its host boundary to
  the cap kernel, or reimplement its services as a SaltyOS server? Which
  subsystems (synchronization, registry, window stations) the target content
  requires, and how coupled they are.
- **Convention-thunk generator scope.** The exact set of callback / function-pointer
  shapes that need generated thunks, and whether a signature-classified generator
  covers them.
- **SEH containment.** Confirm structured-exception handling stays inside the PE
  island (its ``.pdata``/``.xdata``) and never unwinds across the gate, which
  returns ``NTSTATUS``.
- **aarch64 ``x18`` reservation.** Hosting the PE ``TEB`` at ``x18`` requires
  ``x18`` to be reserved process-wide. The AArch64 PCS treats ``x18`` as a
  platform / temporary register, not an always-reserved one, so every piece of
  SaltyOS and native code in the process must be built to reserve it (e.g.
  ``-ffixed-x18``) or ``TEB`` access breaks when other codegen clobbers it.

Backwards Compatibility
=======================

Clean-slate; nothing depends on this yet. The engine is additive over the
cap-native spine. Source-compat (SaltyOS-built PE) is the near/mid target;
running unmodified Windows binaries (binary-compat) is a further, separate effort
deferred to post-Wayland/self-hosting.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Compile Win32 content to ELF instead of hosting PE.** Rejected: it forfeits
  real PE, is not forward-compatible with binary-compat, and diverges from
  modern Wine; it also recreates the "Win32 API as ELF" surface this design
  avoids.
- **Make ELF+PE coexistence a Wine dependency.** Rejected: the coexistence
  mechanism is core and SaltyOS-owned; Wine is borrowed content only.
- **Symmetric peer ELF+PE hosting.** Unsupported by Wine's process model
  (``ntdll`` owns init); the PE-island model is the realistic shape.
- **Unknown:** PE-island viability and wineserver integration cost — both
  prototype-resolved, above.

Prior Art and References
========================

- **Wine PE/unix split** — the uniform ``__wine_unix_call`` boundary, the
  ``ntdll.so`` process bootstrap, and ``wineserver``. SaltyOS studies Wine's
  mechanism as a *reference* and borrows its PE *content*; it does not depend on
  Wine for the coexistence engine. ``include/wine/unixlib.h``,
  ``dlls/ntdll/unix/loader.c``.
- **CloudABI / WASI / Capsicum / Fuchsia** — capability-native, ambient-authority-free
  surfaces; background for the cap-native spine this engine sits on.
