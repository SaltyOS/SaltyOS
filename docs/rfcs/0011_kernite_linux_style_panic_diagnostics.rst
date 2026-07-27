======================================================================
RFC-0011: Kernite Hybrid Panic Diagnostics, Kallsyms, and DWARF Unwind
======================================================================

:Status: Implemented
:Areas: kernite panic path; arch exception handling; printk; spinlock
  diagnostics; stack tracing; build identity; kernel link pipeline; docs
:Authors: Hamin Sung
:Reviewers: GPT 5.5
:Date: 2026-06-29
:Depends: none
:Supersedes: none
:Description: Replace Kernite's minimal panic output with a single structured
  diagnostics path that reports panic ownership, machine-readable BUG/assert
  reasons, architecture trap context, DWARF-backed symbolized tracebacks,
  current-task state, lock diagnostics, scheduler and memory snapshots,
  secondary-CPU panic events, and reproducible build identity. The model is a
  deliberate hybrid: Linux's ``CPU/PID/RIP/Call Trace`` presentation,
  FreeBSD's trapframe-centered fault fields, BSD traceback culture, and
  Windows bugcheck-style reason codes. It does not import Linux process
  semantics or ambient authority.

Problem Statement
=================

Kernite already has a unified panic module, but the panic report is still too
thin for kernel debugging. A panic currently prints the source, reason, CPU,
location, uptime, current task, scheduler snapshot, memory snapshot, and an
``-- arch state --`` section. For ordinary ``panic!`` and assertion failures,
the architecture section can be empty because generic panic entry does not
capture register state. Fatal exception paths can pass an ad hoc architecture
dump closure, but that leaves the ordinary panic path less useful than the
exception path.

The same gap appears in postmortem symbolization and unwinding. The build
produces ``kernite.elf`` with debug information for local debugging, but the
running kernel does not carry a compact kernel-symbol table, data-symbol table,
or unwind metadata. A panic can therefore show raw addresses only where a caller
manually prints them. There is no bounded, in-kernel equivalent of Linux's call
trace lines such as ``symbol+0xoff/0xsize [addr]``, no BSD-style traceback
culture where trap reports naturally lead to a stack walk, and no way to
symbolize lock addresses or global kernel objects through data symbols.

There are also concurrency-specific blind spots:

- The panic owner is selected, but secondary CPU events are not preserved as a
  structured section in the report.
- Panic-time serial output is not fully modeled as owner-only output with
  secondary CPUs recording events and halting.
- Spinlock hard timeouts should join the panic report as lock diagnostics
  instead of emitting a second interleaved full panic.
- Spinlocks do not record enough owner, acquisition, and contender state to
  identify the lock chain that led to the failure.

Finally, panic logs do not identify the exact kernel build in a stable way. A
kernel crash should say which git revision, dirty state, architecture, rustc,
profile, and kernel-affecting configuration produced it, without requiring the
operator to infer that information from the build directory.

Diagnostic Lineage
==================

This RFC intentionally blends several operating-system debugging traditions:

- **Linux:** visible ``CPU``, ``PID``/task identity, ``RIP``/fault PC, and
  ``Call Trace`` sections that are readable from a serial log without an
  external debugger.
- **FreeBSD:** trapframe-centered fault reporting. Exception panics should lead
  with the actual trap frame fields instead of reconstructing a generic panic
  context after the fact.
- **BSD traceback culture:** the stack trace is part of the first panic report,
  not a separate optional debugger command.
- **Windows bugcheck style:** the panic reason is a machine-readable code with
  typed arguments, while still rendering a human-readable explanation.

The "Linux-style" phrase in older notes refers only to source-tree and
diagnostic ergonomics. Kernite remains a capability microkernel.

Goals
=====

- Make one panic owner CPU print the complete report; all other CPUs record a
  secondary event and halt.
- Give ordinary ``panic!`` / ``kassert!`` failures the same architecture
  context quality as fatal exceptions, using generic register snapshots when no
  trap frame exists.
- Make BUG and assertion failures structured, machine-readable reason records,
  not only formatted strings.
- Add in-kernel kallsyms, data symbolization, and DWARF CFI unwinding so panic
  reports include symbolized call traces and symbolized global/data addresses.
- Add build identity to every panic report and to kernel debug dumps.
- Add lock diagnostics that identify held locks, owners, acquisition sites,
  contenders, and wait duration.
- Reuse the same snapshot printer for ``KDEBUG_DUMP_STATE`` without halting.
- Keep the implementation compatible with Kernite's constraints: ``no_std``,
  no heap allocation, bounded buffers, and architecture-specific register
  capture behind narrow arch hooks.

Non-Goals
=========

- This does not import Linux process semantics, Linux locking semantics, or
  Linux's global mutable task model.
- This does not add dynamic allocation to the kernel.
- This does not make recoverable error paths fatal. Conditions that can return a
  kernel error remain ordinary error paths.

Requirements
============

- **R1** Panic reporting MUST have one owner CPU. Only that CPU may print the
  full report after ownership is claimed.
- **R2** A non-owner CPU that panics while another CPU owns panic reporting MUST
  append a bounded secondary event and halt. It MUST NOT print a competing full
  report.
- **R3** A recursive panic on the owner CPU MUST be reported as recursive and
  then halt without attempting to build an unbounded nested report.
- **R4** The panic report MUST include a build identity line:

  ::

      kernel: kernite git=<rev12><-dirty> config=<hash12> arch=<arch> rustc=<rustc> profile=<debug|release>

- **R5** ``config_hash`` MUST be a canonical SHA-256 over kernel-affecting build
  inputs and MUST exclude git revision and dirty state. The full 64-hex digest
  and input summary MUST be visible through ``KDEBUG_DUMP_STATE``.
- **R6** ``kassert!``, ``kassert_eq!``, ``kassert_ne!``, ``kbug!``, and
  ``kbug_on!`` MUST compile in production builds and MUST populate structured
  panic reasons.
- **R7** Runtime kernel control flow MUST NOT depend on ``debug_assert*`` or
  ``cfg(debug_assertions)``. Production invariants use the always-on
  ``kassert*`` / ``kbug*`` family.
- **R8** Generic panic entry MUST capture architecture context. Fatal exception
  entry MUST prefer the trap/exception frame's precise fault context.
- **R9** Call traces MUST use in-kernel DWARF CFI unwinding when unwind metadata
  is available. The frame-pointer walker remains a fallback, not the primary
  target. Both paths MUST be bounded, validate frame state against the current
  kernel stack, detect repeated frames, and stop on invalid alignment or
  out-of-range stack addresses.
- **R10** Kallsyms lookup MUST be allocation-free and based on a sorted,
  read-only table generated at build time. It MUST cover text symbols for code
  addresses and global/static data symbols for diagnostic addresses such as
  locks, queues, kernel objects, and build metadata.
- **R11** Spinlock diagnostics MUST record owner CPU, owner TID, acquired time,
  acquired source location, last contender CPU/TID, and contender wait start.
- **R12** Per-CPU held-lock tracking MUST be bounded. Overflow MUST be counted
  and reported instead of corrupting state.
- **R13** Spinlock hard timeout MUST enter the centralized panic path as a
  structured lock-timeout reason and MUST join the single panic report.
- **R14** ``KDEBUG_DUMP_STATE`` MUST use the same snapshot sections where
  applicable, but it MUST return to the syscall caller instead of halting.
- **R15** Panic reasons MUST have stable bugcheck-like numeric codes and typed
  arguments in addition to their human-readable rendering.
- **R16** The final kernel image MUST preserve compact unwind metadata suitable
  for in-kernel DWARF CFI unwinding. The boot image may strip ordinary debug
  sections only if the compact unwind metadata required by the kernel remains.

Canonical Panic Format
======================

The panic report is intentionally line-oriented so serial logs can be read by
humans, captured by scripts, or compared in runtime tests. The canonical section
order is:

1. header
2. panic owner, current task, uptime, invoke sequence, and kernel identity
3. reason
4. fault context
5. call trace
6. current task
7. lock diagnostics
8. scheduler
9. memory
10. secondary CPUs
11. footer

The header has a stable shape:

::

    ============================================================
    KERNEL PANIC [#N]  SMP
    ============================================================

The top metadata block uses simple keys:

::

    CPU: <cpu>
    PID: <task-trace-id-or-none>
    panic_cpu: <cpu>
    panic_task: <tid-or-none>
    uptime_ns: <ns>
    invoke_seq: <hex>
    kernel: kernite git=<rev12><-dirty> config=<hash12> arch=<arch> rustc=<rustc> profile=<debug|release>

The ``SMP`` marker is present when more than one CPU is online; uniprocessor
builds may print ``UP``. ``PID`` is the current Kernite task trace id until the
kernel grows a separate process identity. The fault context section prints the
architecture's ``RIP``/``PC`` equivalent using the architecture's native name,
and the traceback section is labeled ``Call Trace``.

Bugcheck-Style Reason Model
===========================

Panic reasons become typed records. The printer renders them as a small
indented block while keeping the data available to the panic path before
formatting. Each record has a stable numeric code and up to four typed
arguments, following the Windows bugcheck property that a crash reason can be
matched by tooling without scraping prose:

::

    reason:
      code: 0x00000003
      kind: assertion_failed
      expr: <source expression>
      arg0: <typed value>
      arg1: <typed value>
      message: <optional formatted message>
      location: <file>:<line>:<column>

Required reason kinds:

- ``panic``: ordinary Rust ``panic!`` or ``panic_now`` input.
- ``bug``: unconditional kernel BUG.
- ``bug_on``: conditional kernel BUG.
- ``assertion_failed``: ``kassert!``.
- ``assertion_eq_failed``: ``kassert_eq!`` with left/right debug values when
  printable without allocation.
- ``assertion_ne_failed``: ``kassert_ne!`` with left/right debug values when
  printable without allocation.
- ``fatal_exception``: architecture exception or trap.
- ``spinlock_timeout``: spinlock acquisition exceeded the hard timeout.
- ``kdebug_dump``: non-fatal state dump reason.

Reason codes are part of the diagnostics ABI for logs and tests. Names may be
renamed in source, but code meanings must remain stable once implemented.
Formatted payloads may be bounded and lossy; typed arguments must be preserved
where the reason kind defines them. The implementation MUST not allocate, and
it MUST not evaluate assertion operands more than once.

Panic Record
============

The panic path builds a ``PanicRecord`` on the owner CPU's stack. It contains
only fixed-size or borrowed data:

::

    pub(crate) struct PanicRecord<'a> {
        pub source: PanicSource,
        pub sequence: usize,
        pub panic_cpu: usize,
        pub panic_task: Option<u64>,
        pub uptime_ns: u64,
        pub invoke_seq: u64,
        pub build: &'static BuildInfo,
        pub reason: PanicReason<'a>,
        pub arch: ArchPanicContext,
        pub trace: StackTrace,
        pub task: TaskSnapshot,
        pub locks: LockDiagnostics,
        pub scheduler: SchedulerSnapshot,
        pub memory: MemorySnapshot,
        pub secondary: SecondaryCpuSnapshot,
    }

The exact Rust fields may differ, but ownership must remain the same: capture
state first, then print the captured state. This prevents later diagnostic
steps from observing a different current task, lock stack, or secondary event
cursor from the one that caused the panic.

Build Identity
==============

The build generates a small object file, ``kernite_build_info.o``, and links it
into the kernel. The object places a fixed-layout record in
``.rodata.kernite_build_info`` and exposes linker symbols for the kernel to
read.

Generation is handled by ``tools/kernite-build-info.py``. Inputs:

- ``git_rev``: ``git rev-parse --short=12 HEAD``, or ``unknown`` on failure.
- ``dirty``: true when staged or unstaged diffs exist.
- ``arch``: the Meson architecture option.
- ``rustc_version``: the exact compiler version string used for the kernel.
- ``profile``: ``debug`` or ``release`` as derived from Meson buildtype and
  optimization/debug settings.
- ``config_hash``: SHA-256 over kernel-affecting configuration, excluding git
  revision and dirty state.

The canonical hash input includes:

- ``arch``
- ``rustc_version``
- ``kernel_log_level``
- ``kernel_debug_modules``
- ``debug_serial``
- ``debug_symbols``
- ``max_cpus``
- ``kernel_stack_size``
- hash of the selected kernel target JSON
- hash of the selected linker script
- kernel Rust ``--cfg`` list, sorted into canonical order

The panic line prints the first twelve hex characters of ``config_hash``. The
full 64-hex digest and canonical input summary are printed by
``KDEBUG_DUMP_STATE``.

Kallsyms And Data Symbolization
===============================

The kernel link pipeline gains a preliminary link:

1. Compile Rust and assembly into the normal object set.
2. Link those objects into ``kernite.pre.elf`` without kallsyms.
3. Run ``llvm-nm -n --defined-only --format=posix kernite.pre.elf``.
4. Run ``llvm-readelf -S kernite.pre.elf`` so the generator can classify
   symbols by section.
5. Run ``tools/kernite-kallsyms.py`` to generate an assembly blob containing
   text, rodata, data, and bss symbols.
6. Assemble that blob into ``kallsyms.o``.
7. Link the final ``kernite.elf`` and stripped ``kernite.boot.elf`` with
   ``kallsyms.o`` and ``kernite_build_info.o``.

The kallsyms blob lives in read-only data so it does not perturb ``.text``
layout between the preliminary and final links. The linker scripts add an
explicit ``.kallsyms`` placement inside read-only data:

::

    __kallsyms_start = .;
    KEEP(*(.kallsyms))
    __kallsyms_end = .;

The blob format is architecture-neutral:

::

    magic: u32
    version: u16
    entry_size: u16
    count: u32
    strings_size: u32
    entries[count]: {
        addr: u64,
        name_off: u32,
        size: u32,
        kind: u16,
        flags: u16,
    }
    strings[strings_size]: nul-terminated symbol names

Entries are sorted by address. ``kind`` identifies at least ``text``,
``rodata``, ``data``, ``bss``, ``absolute``, and ``unknown``. ``size`` comes
from ``llvm-nm`` where available and otherwise from the next compatible symbol
in the same section. A zero-size tail symbol is valid but renders as unknown
extent.

The kernel API has separate code and data lookup entry points so callers can
state intent:

::

    pub(crate) fn lookup(addr: usize) -> Option<Symbol>
    pub(crate) fn lookup_code(addr: usize) -> Option<Symbol>
    pub(crate) fn lookup_data(addr: usize) -> Option<Symbol>

Each lookup performs a binary search and renders:

::

    <symbol>+0x<offset>/0x<size> [0x<addr>]

Call traces use ``lookup_code``. Lock diagnostics, current-lock pointers,
global queues, static kernel objects, linker-provided records, and other
diagnostic addresses use ``lookup_data`` or the generic ``lookup`` when the
caller genuinely does not know the address class. This is symbolization, not
heap-object introspection: a dynamically carved kernel object can be named only
through explicit object metadata, while globals and statics are named through
kallsyms.

DWARF CFI Unwind Metadata
=========================

Kernite keeps compact unwind metadata in the booted kernel so the primary
traceback path is DWARF CFI, not a frame-pointer-only best effort. The build
enables unwind-table emission for Rust and C/assembly inputs:

- Rust kernel objects use the equivalent of ``-C force-unwind-tables=yes`` and
  keep frame pointers enabled as a fallback.
- C/assembly inputs that participate in kernel entry/exception/syscall paths
  use CFI annotations or architecture-specific hand-written unwind records.
- Linker scripts stop discarding the unwind section required by the in-kernel
  unwinder. Ordinary debug sections may remain stripped from
  ``kernite.boot.elf``.

The kernel does not use DWARF for exception unwinding or stack cleanup. It uses
the CFI tables only as read-only traceback metadata during panic and debug
dumps.

The representation may either preserve a bounded subset of ``.eh_frame``
directly or generate a compact Kernite unwind table from ``kernite.pre.elf``.
In both cases the in-kernel reader MUST support the CFI operations emitted by
the toolchain for Kernite's Rust and C/assembly objects, and MUST fail closed
to the frame-pointer fallback when it sees unsupported or corrupt metadata.

Architecture Context And Traceback
==================================

Each architecture provides two capture modes:

- generic panic capture: snapshot the current instruction/stack/frame state;
- exception capture: convert the trap frame into the same
  ``ArchPanicContext`` shape while preserving precise fault fields.

x86_64 generic context includes:

- ``rip``
- ``rsp``
- ``rbp``
- ``rflags``
- ``cr2``
- ``cr3``
- interrupt state
- preemption count, if present
- current lock pointer/class, if present

x86_64 exception context includes the trap frame's exact ``rip``, ``rsp``,
``rflags``, vector, and error code, plus ``cr2`` for page faults.

aarch64 generic context includes:

- ``elr``
- ``sp``
- ``x29``
- ``x30``
- ``daif``
- ``esr_el1``
- ``far_el1``
- ``ttbr0_el1``

aarch64 exception context includes the exception frame's precise ``ELR``,
``ESR_EL1``, ``FAR_EL1``, ``SP``, ``X29``, and ``X30``.

``kernel::stacktrace`` owns the architecture-neutral trace container, DWARF CFI
unwinder, fallback frame-pointer walker, and printing. The architecture modules
provide register capture plus the architecture-specific CFI register mapping:

- x86_64 walks the ``RBP`` chain.
- aarch64 walks the ``X29`` frame-pointer chain and records ``LR`` return
  addresses.

The DWARF unwinder is tried first for ordinary Rust/C frames and for assembly
frames that provide valid CFI. The frame-pointer chain is the required fallback
for early boot, hand-written assembly without CFI, unsupported CFI opcodes, and
corrupt unwind records.

Both unwind paths are bounded by a small constant frame count, validate each
computed stack pointer against the active kernel stack bounds, reject invalid
alignment, and stop on repeated or non-monotonic frames. A partial traceback is
better than a risky walk; the printer marks the stop reason explicitly.

Lock Diagnostics
================

``SpinLock`` records enough state to explain owner/contender relationships
without allocating:

- owner CPU
- owner TID
- acquisition timestamp in ns
- acquisition source location
- last contender CPU
- last contender TID
- contender wait-start timestamp in ns

Each CPU also maintains a bounded held-lock stack. Successful acquisition pushes
the lock identity; unlock removes it. The implementation may use a small fixed
array and a per-CPU overflow counter:

::

    lock diagnostics:
      held_locks:
        - addr=0x... class=SpinLock acquired_at=<file>:<line> owner_cpu=<cpu> owner_tid=<tid> held_ns=<ns>
      contenders:
        - lock=0x... cpu=<cpu> tid=<tid> waiting_ns=<ns>
      overflow: <count>

Spinlock hard timeout calls ``panic::spinlock_timeout(...)`` with the lock
metadata and contender metadata. If another CPU already owns the panic report,
the timeout becomes a secondary event and the CPU halts.

Secondary CPU Events
====================

Secondary CPUs write compact events into a bounded ring:

- CPU id
- current TID, if any
- reason kind
- source location, if known
- instruction pointer or exception PC, if known
- timestamp

The owner CPU prints the ring under:

::

    secondary CPUs:
      - cpu=<cpu> tid=<tid-or-none> reason=<kind> ip=0x... uptime_ns=<ns> location=<file>:<line>

If the ring overflows, the owner prints the number of dropped secondary events.
Secondary event recording must be best-effort and must not block on locks that
could be held by the panic owner.

Printk And Serial Ownership
===========================

``kernel::printk`` becomes the only low-level output plane used by panic,
regular kernel logs, and debug dumps. During panic:

- the panic owner may use raw serial output;
- non-owner CPUs suppress normal serial output after observing an active panic;
- panic printing avoids locks that could already be held by the failing CPU;
- framebuffer console output is best-effort and must not delay serial panic
  output.

This preserves the existing ``debug_serial=false`` behavior for ordinary logs:
panic/crash raw output remains available even when debug serial logging is
disabled.

KDEBUG_DUMP_STATE
=================

``KDEBUG_DUMP_STATE`` uses the same snapshot printers as panic for:

- kernel build identity and full config hash summary
- current task
- lock diagnostics
- scheduler
- memory
- call trace when a meaningful current stack can be captured

It does not claim ``PANIC_CPU``, does not halt, and must return to the syscall
caller. If a real panic is active, non-owner dump output is suppressed according
to the panic serial ownership rules.

Source Layout
=============

The implementation should keep panic diagnostics in the kernel infrastructure
plane:

::

    kernite/src/kernel/build_info.rs
    kernite/src/kernel/kallsyms.rs
    kernite/src/kernel/stacktrace.rs
    kernite/src/kernel/unwind.rs
    kernite/src/kernel/panic.rs
    kernite/src/kernel/bug.rs
    kernite/src/kernel/printk.rs

New build tools:

::

    tools/kernite-build-info.py
    tools/kernite-kallsyms.py
    tools/kernite-unwind.py

The linker scripts for both architectures add explicit read-only placements
and start/end symbols for:

- ``.kallsyms``
- ``.kernite_unwind`` or the preserved compact ``.eh_frame`` subset
- ``.rodata.kernite_build_info``

Meson owns the preliminary ELF target, the generated build-info object, the
generated kallsyms object, the generated/preserved unwind metadata, and the
final kernel link inputs for both the debug ELF and stripped boot ELF.

Documentation Updates
=====================

The implementation updates ``docs/spec/kernite.md`` and
``docs/design/kernel.md`` with:

- the hybrid diagnostics lineage: Linux ``CPU/PID/RIP/Call Trace``, FreeBSD
  trapframe fields, BSD traceback expectations, and Windows bugcheck-like
  structured reasons;
- the canonical panic report section order from this RFC;
- ``git_rev``, dirty marker, and ``config_hash`` semantics;
- the rule that runtime kernel invariants use ``kassert*`` / ``kbug*`` rather
  than ``debug_assert*`` or ``cfg(debug_assertions)``;
- the expected behavior of ``KDEBUG_DUMP_STATE`` as a non-fatal snapshot.

Rollout Plan
============

1. Add the build-info generator and ``kernel::build_info`` reader.
2. Add the preliminary link, kallsyms generator, linker-script sections, and
   ``kernel::kallsyms`` lookup for text and data symbols.
3. Add unwind-table preservation/generation and ``kernel::unwind`` DWARF CFI
   traceback support.
4. Add architecture context capture and ``kernel::stacktrace``.
5. Replace formatted-only panic input with ``PanicRecord`` and structured
   reason types.
6. Move BUG/assert macros onto the structured reason path.
7. Add spinlock owner/contender tracking and per-CPU held-lock stacks.
8. Add secondary CPU event recording and owner-only panic printing.
9. Teach ``KDEBUG_DUMP_STATE`` to use the shared snapshot printers.
10. Update design/spec documentation after the behavior lands.

The rollout should remain bisectable, but the externally visible panic format is
accepted only when the full canonical report is present.

Verification
============

Static checks:

::

    rg "debug_assert|debug_assertions|crate::println!|crate::serial_|crate::SerialGuard|crate::BOOT_TIME_NS|crate::rng|crate::bootinfo|crate::acpi" kernite/src
    llvm-nm -n build-x86_64/kernite/kernite.elf
    llvm-readelf -S build-x86_64/kernite/kernite.elf
    llvm-readelf --unwind build-x86_64/kernite/kernite.elf

Build checks:

::

    just fmt-check
    just build
    just arch=aarch64 build

Runtime acceptance criteria:

- a forced ordinary ``panic!`` prints non-empty ``fault context``;
- a forced exception panic uses the trap/exception frame's precise PC/SP and
  error fields;
- the panic reason contains a stable numeric code and typed arguments for
  BUG/assert/lock-timeout paths;
- the panic log contains the ``kernel:`` identity line;
- the panic log contains a DWARF-backed symbolized traceback when unwind
  metadata covers the frames, and explicitly reports frame-pointer fallback
  when it is used;
- lock diagnostics symbolize global/static lock addresses through data
  kallsyms where possible;
- lock timeout panic includes held-lock and contender diagnostics;
- a secondary CPU panic does not interleave a second full report;
- ``KDEBUG_DUMP_STATE`` prints the build identity and shared snapshots, then
  returns to its caller.

Risks And Mitigations
=====================

- **Preliminary/final link drift.** Keeping kallsyms and unwind metadata in
  read-only data and out of text prevents diagnostic tables from changing code
  addresses between links.
- **Bad unwinding during a corrupted stack.** Bounded frame count, stack range
  checks, alignment checks, repeat detection, and unsupported-CFI fallback stop
  the walk early.
- **Panic path lock recursion.** Raw owner-only serial printing and best-effort
  secondary event recording avoid ordinary lock acquisition during panic.
- **Diagnostic state races.** Panic captures a snapshot before printing and
  reports overflow counters where bounded buffers lose data.
- **Config hash instability.** The generator must canonicalize key order,
  normalize paths to content hashes, and exclude git revision/dirty state from
  the hash input.

Review Questions
================

- Is the panic report format stable enough to treat as canonical for tests and
  documentation?
- Which data-symbol classes should be hidden from panic logs, if any, to avoid
  printing misleading or security-sensitive names?
- Is twelve hex characters enough for the short ``config_hash`` in the panic
  line, given that the full hash is available through ``KDEBUG_DUMP_STATE``?
- Should unsupported DWARF CFI opcodes be counted globally so
  ``KDEBUG_DUMP_STATE`` can show unwind coverage gaps?
- Should spinlock acquisition locations be captured by macro call sites only,
  or should ``SpinLock::lock`` also have a fallback caller-address capture?
