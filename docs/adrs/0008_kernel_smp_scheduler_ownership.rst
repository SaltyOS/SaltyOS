=================================================================
ADR-0008: Kernel SMP scheduler ownership and AP bring-up races
=================================================================

:Status: Implemented
:Areas: kernite scheduler; TCB placement; per-CPU pending enqueue;
  deferred scheduler releases; x86_64 AP bring-up; panic/printk diagnostics
:Authors: Hamin Sung
:Reviewers: GPT 5.5
:Date: 2026-06-29
:Supersedes: none
:Depends: ``docs/rfcs/0011_kernite_linux_style_panic_diagnostics.rst``;
  ``docs/design/scheduling.md``; ``kernite/src/sched/scheduler/*``;
  ``kernite/src/sched/thread.rs``; ``kernite/src/arch/x86_64/*``.
:Description: Record the SMP race fixes made while hardening the kernel's
  panic diagnostics and scheduler: APs must not use normal per-CPU services
  before their CPU-local state is installed, scheduler ownership is a
  first-class TCB state that covers running, switch-save, pending, and
  ready-queue dequeue claims, and stack-local scheduler release lists are
  per-CPU so migrating TCBs cannot corrupt each other's release batches.

Context
=======

The Linux-style panic diagnostics work made several previously latent SMP
races visible. The important failures were:

- x86_64 AP startup reached the AP trampoline / SIPI path and then stopped
  making progress before ordinary AP online messages.
- a scheduler panic reported a TCB dequeued on one CPU while still owned by
  another CPU::

      [SCHED] schedule_unlocked: dequeued tcb=... still owned by cpu=0 on cpu=2

- another scheduler panic reported ``DeferredReleaseList`` saturation for a
  single TCB. That showed that different CPUs could stage scheduler reference
  releases for the same migrating TCB into one intrusive list field.
- earlier scheduler and wait-queue corruption was possible because the Fair
  ready tree reused TCB fields that were also used by sleep, futex, and VSpace
  wait queues.

The common bug class was not "one bad lock" but missing ownership states.
Several transitions temporarily made a TCB appear claimable to another CPU
even though a scheduler slot still owned it, or made one intrusive field
serve two independent producers.

Decision
========

Use explicit ownership barriers instead of relying on observers to infer
state from a mix of ``ready_queued``, ``current[]``, pending slots, and
thread state.

1. AP-local services are unavailable until per-CPU state is installed
--------------------------------------------------------------------------------

x86_64 AP bring-up now keeps early boot output on the printk early-serial
path and avoids ordinary lock/per-CPU dependent logging before CPU-local
state exists.

- AP entry installs per-CPU GS before any normal kernel logging path that can
  take locks or query the current CPU.
- ``per_cpu_ready`` checks the actual CPU-local state rather than a global
  readiness hint.
- early AP startup diagnostics use centralized printk early serial helpers
  instead of local ``raw_serial_puts`` loops.
- AP startup waits avoid PIT-dependent delay loops after SIPI delivery; the
  BSP uses a TSC/spin based wait in the AP bring-up window.
- early time reads avoid paths that require a valid ``current_cpu`` before
  the AP has completed CPU-local setup.

This prevents AP bootstrap diagnostics from accidentally depending on the
very per-CPU state they are trying to bring up.

2. ``run_owner_cpu`` is scheduler-slot ownership, not only "currently running"
--------------------------------------------------------------------------------

``Tcb::placement.run_owner_cpu`` now represents the CPU that owns a live
scheduler slot for the TCB. That includes:

- the current thread on a CPU;
- the outgoing thread during the context-switch register-save window;
- a TCB parked in that CPU's deferred pending-enqueue slot;
- a ready-queue dequeue or steal claim before the TCB is published as the
  next current thread.

The ready-queue consumer claims this ownership with an atomic
``try_claim_run_owner_cpu(cpu)`` before unlinking the TCB from the queue. This
closes the old gap:

1. dequeue removed the TCB and set ``ready_queued = false``;
2. ``set_current`` had not yet set ``run_owner_cpu``;
3. a remote wake/enqueue observer could see "not ready, not owned" and create
   a second ready slot for the same TCB.

With the new rule, no observer sees a dequeued TCB as unqueued and unowned.

3. Ready insertion revalidates against every scheduler owner
--------------------------------------------------------------------------------

Ready insertion is only allowed when all of the following are true under the
target CPU's scheduler lock:

- no live ``run_owner_cpu`` exists;
- the TCB is not the atomic ``CURRENT_ON_CPU`` mirror on any online CPU;
- the TCB is not already ``ready_queued``;
- the TCB is not present in any ``pending_enqueue`` slot.

If the recheck fails after a speculative ready-slot reference was taken, the
would-be ready-slot reference is released after the lock drops. The current,
pending, or dequeue-claim owner keeps its own reference.

4. Pending enqueue is the switch-save barrier
--------------------------------------------------------------------------------

Runnable current threads are not inserted directly into a ready queue while
their registers are still live on a CPU. They are first published to that
CPU's ``pending_enqueue`` slot. The slot is flushed only after the low-level
context switch calls ``sched_context_saved(old_tcb)`` and clears the old
TCB's owner.

Pending-slot code must not blindly clear ``run_owner_cpu``. It validates
``live_owner_cpu`` and either waits for the owning CPU to finish its
switch-save window or treats a mismatched owner as scheduler corruption.

5. Dequeue and steal consume stale ready slots without creating a second owner
--------------------------------------------------------------------------------

The dequeue and steal paths now claim before unlinking for deadline, RT FIFO,
and Fair entities. If an entry is still linked in a ready queue but is already
owned by another scheduler slot, the consumer removes only that stale ready
slot and drops its ready-slot reference. It does not clear the live owner.

This is not the primary correctness mechanism. The primary mechanism is the
atomic claim before unlink and insertion revalidation. Stale-slot consumption
is the cleanup path for entries left by earlier races or by a transition that
lost the insertion race.

6. Deferred scheduler releases are per-CPU
--------------------------------------------------------------------------------

``DeferredReleaseList`` is stack-local to the scheduler operation running on
one CPU, but the same TCB can migrate and have releases staged by different
CPUs at the same time. A single ``deferred_release_next`` /
``deferred_release_count`` pair on the TCB made those independent lists share
one intrusive node.

The TCB now carries one deferred-release link/count per CPU, and each
``DeferredReleaseList`` records its owner CPU. Draining a list only touches
that CPU's link/count pair. This prevents two CPUs from corrupting each
other's list topology or artificially saturating one shared release count.

7. Fair ready-tree links are not wait-queue links
--------------------------------------------------------------------------------

The Fair scheduler tree uses dedicated ``fair_left``, ``fair_right``,
``fair_parent``, ``fair_subtree_min``, and ``fair_subtree_stealable`` fields.
It no longer stores tree topology in fields also used by sleep/futex/VSpace
wait queues. Wait-queue detach, timeout, and wake paths can therefore mutate
their own intrusive links without corrupting Fair ready-tree topology.

8. Panic diagnostics are part of the SMP safety net
--------------------------------------------------------------------------------

The scheduler fixes were driven by panic reports that identified the panic
CPU, task, structured reason, arch context, call trace, scheduler snapshot,
and secondary CPU events. Panic printing is owned by one panic CPU and routed
through the centralized printk/panic path so secondary CPUs do not interleave
full reports.

The diagnostics are not the synchronization mechanism, but they are now part
of the kernel's SMP debugging contract: ownership violations must report
enough CPU/TID/PC/context information to distinguish a scheduler invariant
bug from an unrelated object lifetime bug.

Invariants
==========

The resulting scheduler invariants are:

- A live TCB may be in at most one scheduler-owned slot class at a time:
  current/switch-save/dequeue-claim, pending enqueue, ready queue, or a
  non-ready wait/detach structure.
- A ready-queue consumer must claim ``run_owner_cpu`` before it clears
  ``ready_queued``.
- A ready-queue producer must revalidate ``run_owner_cpu``, current mirrors,
  ready membership, and pending membership while holding the target queue
  lock.
- A pending slot is a register-save barrier. It is not equivalent to a ready
  queue entry, and it is not flushed before the owner has cleared the
  switch-save ownership.
- Stack-local deferred-release batches never share one TCB intrusive list
  link across CPUs.
- Intrusive links are owned by one subsystem. Fair ready-tree links are not
  reused by wait queues.
- Early AP code may use early printk serial helpers, but not normal
  per-CPU-dependent logging paths before the AP's CPU-local state is valid.

Consequences
============

Positive
--------

- The ready-queue dequeue window no longer exposes a TCB as both unqueued and
  unowned before it becomes current.
- Remote wake/enqueue paths can refuse to insert a TCB already owned by a
  running, switch-save, pending, or dequeue-claim slot.
- Per-CPU release lists remove the cross-CPU intrusive-list corruption that
  manifested as release-count saturation.
- x86_64 AP startup logging no longer depends on normal per-CPU state before
  that state exists.
- Fair scheduling no longer aliases tree fields with wait-queue fields, which
  removes a class of topology corruption under concurrent wake/detach.
- Future SMP ownership regressions should panic with enough context to show
  which CPU owned the TCB and which CPU attempted to claim or enqueue it.

Negative
--------

- ``run_owner_cpu`` is now a broader scheduler ownership concept. Callers must
  not assume it means "is exactly CURRENT_ON_CPU".
- Dequeue and steal paths are slightly more complex because they must claim,
  unlink, and release stale ready-slot references as one operation.
- The TCB is larger due to per-CPU deferred-release arrays and dedicated Fair
  tree fields. This was accepted to keep ownership explicit and avoid
  field-sharing races.
- Some scheduler corruption cases still intentionally panic. For example, a
  pending slot owned by a different CPU is not silently repaired because that
  violates the pending-slot handoff model.

Rejected alternatives
=====================

- **Only drop owned TCBs at dequeue time.** This is defensive recovery, not
  safe-by-construction. It leaves the unqueued/unowned window open and relies
  on consumers to clean up after a duplicated ready slot appears.
- **Clear ``run_owner_cpu`` in enqueue or pending flush to make insertion
  succeed.** This hides the switch-save owner and can let another CPU run a
  TCB whose registers have not been saved yet.
- **Use one global scheduler lock for all ready queues.** This would close
  many races by serialization, but it discards the per-CPU scheduler design
  and would make timer/IPI scheduling scale poorly.
- **Keep one deferred-release intrusive link per TCB.** A stack-local list on
  CPU N cannot safely share an intrusive node with CPU M. Counting more
  releases in one field does not solve list topology corruption.
- **Reuse wait-queue links for the Fair tree.** It saves object space but
  makes independent subsystems overwrite each other's topology.
- **Keep local AP ``raw_serial_puts`` call sites.** That keeps output working
  in some early cases, but it spreads panic/serial ownership rules across the
  architecture code and makes future SMP print interleaving harder to audit.

Implementation
==============

- ``kernite/src/sched/thread.rs`` documents ``run_owner_cpu`` as scheduler
  slot ownership and adds ``try_claim_run_owner_cpu``.
- ``kernite/src/sched/scheduler/rq.rs`` claims before unlinking ready-queue
  entries in local dequeue and steal paths; insertion revalidates under the
  target CPU lock; stale owned ready entries release only their ready-slot
  reference.
- ``kernite/src/sched/scheduler/slots.rs`` treats ``live_owner_cpu`` as a
  scheduler-slot owner query, not a current-mirror query, and pending enqueue
  processing respects the switch-save owner.
- ``kernite/src/sched/scheduler/support.rs`` and ``thread.rs`` back
  ``DeferredReleaseList`` with per-CPU link/count storage.
- ``kernite/src/sched/scheduler/switch.rs`` keeps
  ``sched_context_saved(old_tcb)`` as the point where switch-save ownership is
  cleared.
- ``kernite/src/arch/x86_64/{ap_boot,apic,cpu}.rs`` and
  ``kernite/src/kernel/printk.rs`` centralize early serial output and avoid
  normal per-CPU dependencies before AP local state is installed.
- ``kernite/src/sched/thread.rs`` and ``kernite/src/sched/scheduler/rq.rs``
  use dedicated Fair ready-tree fields instead of wait-queue fields.

Testing
=======

Verification performed for this ADR's implementation state:

- ``just build`` passed for x86_64.
- ``just arch=aarch64 build`` passed. The existing aarch64 linker warning
  about ``.bss`` alignment remained unchanged.
- ``just fmt-check`` completed with ``cap_discipline: PASS``. Existing
  rustfmt diffs in unrelated files were still reported; the scheduler
  ownership changes were build-checked after formatting the changed line.

QEMU boot verification was intentionally left to the user in this debugging
loop. The expected runtime checks are:

- x86_64 AP startup proceeds past SIPI delivery and AP online messages.
- no panic reports ``schedule_unlocked: dequeued ... still owned``.
- no panic reports deferred release count saturation.
- panic reports, if any remain, include the owner CPU, current task,
  scheduler snapshot, and arch detail needed to classify the next bug.
