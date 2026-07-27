===============================================================
RFC-0007: Priority no-drop interrupt delivery on the EventQueue
===============================================================

:Status: Implemented
:Areas: Kernel; Events; Interrupts
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-24
:Description: Give the ``EventQueue`` a dedicated, priority, no-drop interrupt lane. A bound ``IrqHandler`` is itself the reserved delivery slot: ``signal_fire`` links the handler intrusively onto the queue's interrupt lane instead of pushing an ``EVENT_TYPE_IRQ`` record into the shared FIFO ring, and ``EQ_WAIT`` drains that lane before the ring. Lane membership is a dedicated ``eq_queued`` flag (not ``STATE_SIGNALED``); delivery coalesces while linked and re-arms on dequeue. The change also closes two pre-existing bind/unbind bugs (a cookie-ordering window and an unbind/``signal_fire`` use-after-free) and bumps the ``IrqHandler`` / ``EventQueue`` retype sizes, which are UAPI. No userland record/invoke ABI change.

Problem Statement
=================

In the edge model a hardware interrupt is delivered to userland through an
``EventQueue``. ``IrqHandler::signal_fire`` (``kernite/src/event/irq.rs``) runs
in interrupt context: it asserts ``STATE_SIGNALED`` on the handler, publishes
that state to any registered ``Watch`` (gated on the 0→1 edge), and — on **every**
fire while a ``bound_eq`` is set (by ``IRQ_BIND_EQ``) — builds an ``EventRecord``
with ``kind = EVENT_TYPE_IRQ`` and pushes it through ``EventQueue::enqueue`` into
the queue's single FIFO ring.

That shared ring is the whole delivery surface for every event class — state
fires, timers, pager requests, and interrupts all share one
``[EventRecord; EVENT_QUEUE_CAPACITY]`` ring with a drop-on-full overflow
counter. Routing interrupts through it has two defects:

- **Drop under pressure.** When the ring is full, ``enqueue`` does not store the
  record; it bumps the ``dropped`` counter and emits a single ``OVERFLOW``
  placeholder at the consumer end. An interrupt record is dropped exactly like a
  best-effort state fire. A burst of state events on a server's queue can
  silently swallow an interrupt.
- **Head-of-line blocking.** The ring is strict FIFO. An interrupt record queued
  behind a backlog of IPC ``STATE_READABLE`` records waits for the whole backlog
  to drain before it is dequeued, so interrupt latency is bounded only by the
  server's IPC backlog.

Two further bugs already live on the bind path and are exposed (and fixed) by this
work, because the interrupt lane interacts with both:

- **Bind cookie ordering.** ``syscall_irq_bind_eq`` publishes ``bound_eq`` (a
  ``compare_exchange``) and only **afterward** stores ``bound_cookie``, so a fire
  in that window observes the new queue carrying a stale cookie (e.g. ``0`` left
  by a prior unbind).
- **Unbind / signal_fire use-after-free.** ``signal_fire`` loads ``bound_eq`` and
  dereferences it without taking its own reference, while
  ``syscall_irq_unbind_eq`` swaps ``bound_eq`` to null and releases the bind
  reference. If unbind drops the last reference between ``signal_fire``'s load and
  its dereference, ``signal_fire`` touches a freed queue.

No userland binds an interrupt to a queue today — ``grep -rn IRQ_BIND_EQ
userland/`` returns no callers — so the binding path is exercised for the first
time by the console reactor migration. This RFC fixes the delivery mechanism, and
the two latent bind/unbind bugs, before that first consumer lands.

Summary
=======

Add a dedicated interrupt lane to the ``EventQueue``: an intrusive FIFO of pending
``IrqHandler`` objects (``irq_head`` / ``irq_tail``), drained by ``EQ_WAIT``
**before** the record ring. The ``IrqHandler`` is its own reserved delivery slot —
no per-fire allocation, no ring slot consumed — so an interrupt can never be
dropped for lack of ring space. Lane membership is a dedicated ``eq_queued`` flag
on the handler, set when ``signal_fire`` links it and cleared when ``dequeue``
pops it; a fire while the handler is still linked coalesces, and the handler
re-arms for the next fire on dequeue. ``dequeue`` drains the lane first and
synthesizes the ``EVENT_TYPE_IRQ`` record from the handler's fields.

This is the same shape as Zircon — ``PortDispatcher`` keeps interrupt packets in a
separate list serviced ahead of the regular packet queue, with the packet
embedded in the ``InterruptDispatcher`` (pre-allocated, reused, no-drop). SaltyOS
re-arms on dequeue rather than on ack (it has no mask-until-ack hardware path; see
*Coalescing and re-arming*), which is the correct fit for its model and is leaner
than carrying Zircon's NEEDACK pending flag.

The change is kernel-only at the source level. The userland ``EVENT_TYPE_IRQ``
record shape and the ``IRQ_BIND_EQ`` / ``IRQ_UNBIND_EQ`` invocations are unchanged;
the observable differences are quality of service (interrupts are no longer
dropped or delayed behind the ring) and the ``IrqHandler`` / ``EventQueue`` retype
sizes, which are UAPI constants.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- A bound interrupt MUST NOT be dropped because the ``EventQueue`` record ring is
  full. Delivery is guaranteed by a reserved slot, not by ring capacity.
- Interrupt records MUST be dequeued ahead of regular ring records, so interrupt
  latency is not bounded by a server's IPC backlog.
- The reserved slot MUST live in an already-allocated kernel object and be linked
  intrusively. No heap, no per-fire allocation (every object is retyped from
  untyped, never malloc'd).
- Lane membership MUST be guarded by a dedicated flag, **not** by
  ``STATE_SIGNALED`` — the consumer clears ``STATE_SIGNALED`` independently via
  ``irq_ack``, so it cannot track whether the handler is on the lane. A handler
  MUST be linked at most once (no intrusive-list corruption).
- A fire while the handler is already linked MUST coalesce; a fire after dequeue
  MUST re-arm. No fire that occurs while the handler is unlinked may be lost.
- ``IRQ_UNBIND_EQ`` and ``IrqHandler`` cleanup MUST be serialized against
  ``dispatch_irq`` so they cannot race ``signal_fire``'s load/deref/link, and MUST
  unlink the handler (by pointer) before releasing the bind reference. Neither may
  leave a dangling handler pointer in any queue's lane.
- ``IRQ_BIND_EQ`` MUST be serialized under ``IRQ_LOCK`` and store ``bound_cookie``
  before publishing ``bound_eq``; a bind that finds the handler already bound MUST
  fail without touching ``bound_cookie`` (no overwrite of a live binding's cookie).
- The userland ABI (the ``EVENT_TYPE_IRQ`` record shape and the
  ``IRQ_BIND_EQ`` / ``IRQ_UNBIND_EQ`` invoke labels) MUST be unchanged.

Design
======

The shared-ring delivery today
------------------------------

``EventQueue`` (``kernite/src/event/event_queue.rs``) is a fixed-capacity ring:
``ring: [EventRecord; EVENT_QUEUE_CAPACITY]`` with ``head`` / ``tail`` / ``used``
and a ``dropped`` / ``dropped_pending`` overflow counter. ``enqueue`` pushes at
``tail`` (or rolls into ``dropped`` when full), sets ``STATE_READABLE`` and pops a
waiter **under** the queue lock, then unlocks and runs the ``watcher_list.publish``
and the wake **after** the lock is released. ``dequeue_locked`` pops at ``head``
(or emits one ``OVERFLOW`` record). A separate intrusive FIFO of TCBs blocked in
``EQ_WAIT`` already exists — ``waiter_head`` / ``waiter_tail: *mut Tcb`` — and is
the structural template for the interrupt lane.

``IrqHandler`` already carries ``irq_num`` and ``bound_cookie`` (enough to
reconstruct its record) and a ``next: *mut IrqHandler`` link — but ``next`` is the
*shared-IRQ chain* (multiple handlers on one hardware line) and is unrelated to
queue membership.

The interrupt lane
------------------

Add to ``IrqHandler``::

    pub eq_next: AtomicPtr<IrqHandler>,  // intrusive lane link; null when unlinked
    pub eq_queued: AtomicBool,           // on a queue's lane now; set/cleared under EventQueue.lock

Add to ``EventQueue``::

    pub irq_head: *mut IrqHandler,  // FIFO of pending handlers, drained before `ring`
    pub irq_tail: *mut IrqHandler,

A handler is bound to at most one queue (``bound_eq``) and is on that queue's lane
at most once, guarded by ``eq_queued`` — a single ``eq_next`` link suffices. The
handler *is* the reserved slot: while linked, its pending interrupt occupies no
ring capacity and cannot be dropped. ``eq_queued`` is independent of
``STATE_SIGNALED`` (the watch-facing signal the consumer clears on ack); lane
membership is **never** inferred from ``STATE_SIGNALED``.

The two new fields are atomic (``AtomicPtr`` / ``AtomicBool``), like the
``IrqHandler``'s existing ``bound_eq`` / ``state_flags``. They are written only
under ``EventQueue.lock``, but the handler is concurrently reachable from
interrupt context, so ``signal_fire`` takes ``&self`` and mutates through interior
mutability rather than an exclusive borrow it cannot legitimately hold. For the
same reason ``WatcherList``'s list head is an ``UnsafeCell`` and its ``publish`` /
``insert`` / ``remove`` / ``drain_closed`` take ``&self``, so ``signal_fire`` links
the lane and publishes the watcher edge on a shared reference with no
``&self``-to-``&mut`` cast.

signal_fire: link, do not enqueue
---------------------------------

``signal_fire`` keeps its ``STATE_SIGNALED`` 0→1 gate around the ``Watch``
publication unchanged. Its bound-queue arm changes from "build a record and
``enqueue`` it on every fire" to "link the handler onto the bound queue's lane,
at most once":

- Load ``bound_eq``; if null, done.
- Call ``link_irq(self)`` on the queue. Under ``EventQueue.lock``: if
  ``self.eq_queued`` is already set, return (coalesce — the pending delivery
  stands); otherwise set ``eq_queued``, append ``self`` at ``irq_tail``, set
  ``STATE_READABLE`` (0→1 edge) and pop one waiter. Release the lock, **then**
  publish to the ``watcher_list`` and run the wake (unlock-before-publish, exactly
  as ``enqueue`` does today).

No ring slot is consumed, so the link cannot fail or drop.

dequeue: drain the interrupt lane first
---------------------------------------

``dequeue_locked`` gains a priority check ahead of the ring:

- If ``irq_head != null``: pop the head handler (advance ``irq_head`` along
  ``eq_next``, clear the popped handler's ``eq_next`` and its ``eq_queued``, reset
  ``irq_tail`` when the lane empties), synthesize the ``EventRecord`` from the
  handler's fields, recompute ``STATE_READABLE``, and return it.
- Otherwise: the existing ring / overflow path runs unchanged.

``STATE_READABLE`` is cleared only when the lane is empty **and** the ring is
empty **and** no ``dropped_pending`` placeholder remains; ``wait_block``'s "has a
record" predicate is widened to ``irq_head != null || used != 0 ||
dropped_pending != 0``.

Record synthesis
----------------

The record is synthesized on drain from the handler's fields and is identical to
the one ``signal_fire`` builds today::

    kind=EVENT_TYPE_IRQ, status=EVENT_STATUS_OK, cookie=bound_cookie,
    object_id=irq_num, state_set=STATE_SIGNALED, payload0=irq_num

Synthesizing ``cookie`` at drain time is correct because the cookie is fixed for
the lifetime of a binding: ``IRQ_BIND_EQ`` sets it (now before ``bound_eq`` is
published — see *Binding, teardown, and the unbind race*) and ``IRQ_UNBIND_EQ``
clears it only after unlinking the handler under the queue lock. A re-bind
therefore cannot change the cookie of an already-linked delivery.

Coalescing and re-arming
------------------------

Lane membership is guarded by ``eq_queued``, manipulated only under
``EventQueue.lock`` — never by ``STATE_SIGNALED``. ``signal_fire`` links only when
``eq_queued`` is false. A fire that arrives while the handler is still linked (not
yet dequeued) coalesces: it links nothing, because the already-queued delivery
will drive the consumer to drain the device. ``dequeue`` clears ``eq_queued`` when
it pops the handler, so the **next** fire re-links and delivers again. No fire
that occurs while the handler is unlinked is lost.

This is a deliberate semantic change from the current path, which enqueues one
record per fire (no coalescing) and can drop records when the ring is full. The
lane instead delivers an edge-coalesced "device ready" signal and re-arms on
dequeue; the consumer contract is the standard interrupt-handler contract — drain
the device's hardware FIFO fully on each delivery (the FIFO depth is far below
console's ``drain_input`` buffer, so a coalesced burst is consumed in one drain).
Because no userland binds an interrupt today, no existing consumer's behavior
regresses, and the first consumer (console) is drain-style and correct under
coalescing.

Re-arming is on **dequeue**, not on ``irq_ack``. Zircon re-arms on ack (its
NEEDACK cycle) because its hardware model masks the interrupt until ack; SaltyOS
has no mask-until-ack path — ``signal_ack`` only clears ``STATE_SIGNALED`` and no
common ack path unmasks the line (per-arch unmask routines exist, but nothing
wires them to ack) — a pre-existing gap that affects level-triggered PCI lines and
is out of scope here.
Dequeue-rearm is the correct fit for SaltyOS's model and avoids carrying an unused
NEEDACK pending flag; capturing a fire that arrives during a future
mask-until-ack window can be added later (see *Drawbacks*) without changing the
lane structure.

Binding, teardown, and the unbind race
--------------------------------------

Two pre-existing ordering bugs are fixed here because the lane interacts with both.

**Bind ordering.** ``syscall_irq_bind_eq`` is serialized under ``IRQ_LOCK`` so it
cannot race ``signal_fire`` or a concurrent bind/unbind. Holding ``IRQ_LOCK`` it
checks ``bound_eq``: if the handler is already bound it fails with
``AlreadyExists`` **without touching ``bound_cookie``** — a failed or racing bind
must never overwrite a live binding's cookie. Otherwise it takes the queue
refcount, stores ``bound_cookie``, then publishes ``bound_eq``. Because
``IRQ_LOCK`` excludes ``signal_fire``, no fire can observe the intermediate state,
so a plain store suffices (no ``compare_exchange`` needed) and the published
``bound_eq`` always carries the matching cookie.

**Unbind / signal_fire race.** Because ``signal_fire`` derefs ``bound_eq`` without
its own reference, unbind is serialized against ``dispatch_irq`` via ``IRQ_LOCK``:
``syscall_irq_unbind_eq`` takes ``IRQ_LOCK`` (which ``dispatch_irq`` holds across
the handler chain), then ``EventQueue.lock``, unlinks the handler from the lane if
``eq_queued`` and clears ``eq_queued``, swaps ``bound_eq`` to null, and only
**then** releases the bind reference. Since ``signal_fire`` runs entirely under
``IRQ_LOCK``, it can never be mid-flight when unbind runs, so its load / deref /
link always targets a live, still-bound queue. ``IrqHandler`` cleanup performs the
same ``IRQ_LOCK`` → ``EventQueue.lock`` unlink before the object is torn down, so a
handler is never freed while linked. Lane removal is always **by handler
pointer**, never by cookie.

WATCH_CANCEL and purge_matching
-------------------------------

``EventQueue::purge_matching`` (the ``WATCH_CANCEL`` cookie purge) compacts ring
records by cookie. It MUST NOT scan the interrupt lane by cookie — an interrupt's
cookie is opaque and unrelated to a watch cookie, and removing lane entries by
cookie could cancel an unrelated interrupt. The lane is only ever modified by
pointer (link / dequeue / unbind / cleanup). ``purge_matching`` does share the
``STATE_READABLE`` recompute, so its clear condition must also require
``irq_head == null``.

Lock ordering
-------------

The interrupt lane is manipulated only under ``EventQueue.lock``: ``link_irq``
(from ``signal_fire``), the priority pop (from ``dequeue``), and ``unlink_irq``
(from unbind / cleanup). ``signal_fire`` runs under ``IRQ_LOCK`` and already nests
``EventQueue.lock`` inside it via today's ``enqueue``; unbind and cleanup take
``IRQ_LOCK`` → ``EventQueue.lock`` for the same reason; ``dequeue`` takes
``EventQueue.lock`` alone (it never needs ``IRQ_LOCK``). The order is uniformly
``IRQ_LOCK`` → ``EventQueue.lock``, so no cycle is possible.

The "mark readable + wake one waiter" work is split exactly as ``enqueue`` splits
it today: ``STATE_READABLE`` is set and one waiter is popped **under**
``EventQueue.lock``, but ``watcher_list.publish`` and the wake run **after** the
lock is released. ``link_irq`` factors this tail into a shared helper and
preserves the unlock-before-publish ordering; publishing under the queue lock
could deadlock through a watch fire path (``WatcherList`` itself avoids firing
while holding its own lock for the same reason).

Object size
-----------

``IrqHandler`` grows by one atomic pointer plus an atomic bool (``eq_next`` +
``eq_queued``) and
``EventQueue`` by two pointers (``irq_head`` / ``irq_tail``). The compile-time size
assertions in ``kernite/src/cap/object_size_assert.rs`` and the
``KERNITE_IRQ_HANDLER_BYTES`` / ``KERNITE_EVENT_QUEUE_BYTES`` UAPI constants are
updated to the new actual sizes for **both** ``x86_64`` and ``aarch64`` (the
assertions are evaluated per target, so both must match). Per project policy the
design is written correctly first and the ``*_BYTES`` constants are set to the
resulting size — capacity is not shrunk to hold a stale number.

Implementation
==============

Touched files:

- ``kernite/src/event/irq.rs`` — add ``eq_next`` / ``eq_queued``; rewrite
  ``signal_fire``'s bound-queue arm to call ``link_irq``; unlink in handler
  cleanup under ``IRQ_LOCK`` → ``EventQueue.lock``.
- ``kernite/src/event/event_queue.rs`` — add ``irq_head`` / ``irq_tail``; the
  shared "set readable + wake one waiter" helper; ``link_irq`` / ``unlink_irq``;
  priority drain in ``dequeue_locked``; the widened ``wait_block`` predicate; the
  ``purge_matching`` readable recompute.
- ``kernite/src/syscall/event.rs`` — ``syscall_irq_bind_eq`` serializes under
  ``IRQ_LOCK``, fails closed on already-bound without touching the cookie, else
  stores the cookie then publishes ``bound_eq``; ``syscall_irq_unbind_eq`` takes
  ``IRQ_LOCK`` → ``EventQueue.lock``, unlinks, then releases the bind reference.
- ``kernite/src/cap/object_size_assert.rs`` and the UAPI ``*_BYTES`` constants
  (``kernite/include/uapi/object.h`` exposes them) — new sizes for both
  architectures.

Performance
===========

Link is O(1) (tail append). Priority drain is O(1) (head pop) with one extra
branch on the ``EQ_WAIT`` hot path. Unlink on unbind / cleanup is O(lane length),
and the lane holds at most one entry per bound interrupt. No allocation on any
path.

Backwards Compatibility
=======================

The userland record/invoke ABI is unchanged: the ``EVENT_TYPE_IRQ`` record shape
is identical and ``IRQ_BIND_EQ`` / ``IRQ_UNBIND_EQ`` keep their labels and
arguments. The ``IrqHandler`` / ``EventQueue`` **retype sizes** change, and those
``*_BYTES`` constants are UAPI (exposed via ``kernite/include/uapi/object.h``), so
this is a retype-size UAPI change even though no message wire format moves. No
userland binds an interrupt to a queue today, so no consumer's behavior regresses;
the first consumer (the console reactor) sees correct, no-drop, priority delivery
from the start, and the two pre-existing bind/unbind bugs are closed before it
relies on them.

Security Considerations
=======================

Binding an interrupt to a queue remains capability-mediated: ``IRQ_BIND_EQ``
requires both the ``IrqHandler`` capability and the target ``EventQueue``
capability. The lane is per-queue, so an interrupt bound to one server's queue is
invisible to another's. A flood on a single line coalesces under ``eq_queued`` —
it occupies its one reserved slot and cannot exhaust the queue or starve the ring.
This is stronger than the shared-ring path, where a flood could fill the ring and
drop unrelated state events. The unbind/``signal_fire`` serialization removes a
use-after-free that, while only reachable by the binding owner, was a real memory
-safety hole.

Testing
=======

- ``just warn`` clean (x86_64 and ``just arch=aarch64 warn``); ``just build``.
- ``just run --headless`` boots to ``test_runner`` with no ``KERNEL PANIC`` and no
  size-assertion failure on either architecture.
- The console reactor delivers keyboard / serial input through ``handle_other``.
  Note: kernel lane priority only orders the **next** ``EQ_WAIT`` dequeue; for an
  interrupt to be handled ahead of a service-pipe backlog, the console dispatcher
  must return ``false`` from ``continue_readable_drain`` so the reactor yields to
  ``EQ_WAIT`` after each pipe message rather than draining the pipe to
  ``WOULD_BLOCK``. The priority lane plus that policy together bound interrupt
  latency.
- ``just run --smp 2`` / ``--smp 4``: an interrupt firing concurrently with a
  ring-filling state-event burst is delivered, not dropped; bind immediately
  followed by unbind under concurrent fires does not fault (the ``IRQ_LOCK``
  serialization and cookie ordering).

Documentation
=============

``docs/spec/kernite.md`` (the ``EventQueue`` / IRQ sections) gains a note that
interrupt delivery uses a separate priority lane rather than the record ring, and
that re-arming is on dequeue.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Alternative — keep the shared ring, avoid long drains.** Leave interrupts on
  the FIFO ring and rely on each reactor returning ``false`` from
  ``continue_readable_drain``. Rejected: it does not fix drop-under-pressure at
  all, and it pushes a correctness property onto per-server discipline rather than
  the kernel. This is the "go simple" option and is explicitly declined.
- **Alternative — reserve N ring slots for the IRQ kind.** Partition the ring.
  Rejected: still bounded and droppable past N, and it forces a kind-aware scan on
  dequeue; the intrusive lane is simpler and unbounded-safe.
- **Alternative — a separate EventQueue per interrupt.** Rejected: the reactor
  blocks on a single ``eq_cap``; multiplying queues multiplies wait points and
  defeats the single-``EQ_WAIT`` reactor model.
- **Alternative — re-arm on ack (Zircon NEEDACK).** Rejected for now: SaltyOS has
  no mask-until-ack hardware path, so an ack-rearm cycle with a pending flag would
  be machinery with no backing semantics. Dequeue-rearm is correct for the current
  model. If a future change adds mask-until-ack (closing the level-triggered unmask
  gap), a per-handler pending flag can be added without touching the lane.
- **Unknown / out of scope — the level-triggered unmask gap.** ``dispatch_irq``
  masks level-triggered (PCI) lines but no common ack path unmasks them. This is pre-existing
  and orthogonal to delivery; console's lines are edge-triggered (ISA) and
  unaffected. It is noted, not fixed, here.

Prior Art and References
========================

- Zircon ``zx_interrupt_bind`` / ``zx_port_wait`` / ``zx_interrupt_ack``:
  ``PortDispatcher`` holds interrupt packets in a separate list serviced ahead of
  the regular packet queue; the packet is embedded in the ``InterruptDispatcher``
  (pre-allocated, reused, no-drop) and coalesced via a NEEDACK state that re-arms
  on ack. SaltyOS adopts the separate-priority-lane and reserved-slot ideas but
  re-arms on dequeue rather than ack (no mask-until-ack model). (Mechanics drawn
  from Fuchsia documentation and RFCs.)
- RFC-0002 (``VmHierarchyState``) — establishes the ``EventQueue`` / ``Watch``
  edge-model context this builds on.
- RFC-0003 (per-thread ``MessageWaiter``) — the same pattern of reserving the
  delivery slot in an already-allocated object (there the per-thread waiter, here
  the ``IrqHandler``) so a fast producer can never lose or drop the delivery.
