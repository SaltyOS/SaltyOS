==========================================================
RFC-0003: Per-Thread MessageWaiter for MP_CALL Replies
==========================================================

:Status: Implemented
:Areas: Kernel; IPC
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Description: The MP_CALL reply is delivered out-of-band into a per-thread, Zircon-style ``MessageWaiter`` (txid + ready flag + the reply record + its MOVE-cap carriers), not into the receive ring. The caller registers as a call-waiter at request-enqueue time, atomically under one ``MessagePipeCore.lock``, so a fast reply cannot be lost; the reply arm matches by txid and direct-wakes. The userland ``ipc_call_retry`` retry loop is removed. A reply-in-ring variant was designed and reverted (see Alternatives).

Problem Statement
=================

All SaltyOS IPC is MessagePipe invocation: a single ``Invoke`` syscall, with
``MP_WRITE`` (0x160), ``MP_READ`` (0x161), and ``MP_CALL`` (0x163) dispatched in
``cspace.rs``. ``MP_CALL`` is the synchronous request/reply (the SaltyOS analog
of ``zx_channel_call``), used by every userland RPC.

The reply-wait had two problems:

- A **lost-wakeup race**: a fast server could reply between the caller's request
  enqueue and the caller registering its wait, so the wakeup was missed.
- Userland papered over interrupted calls with an ``ipc_call_retry`` re-send loop
  wrapped around every RPC, duplicating restart logic the kernel should own.

The reply payload itself was an ad-hoc set of per-TCB fields. The clean-slate
restructures the reply path into one named primitive and closes the race at its
source.

Summary
=======

A reply is delivered into a per-thread ``MessageWaiter`` — the kernel analog of
Zircon's ``MessageWaiter`` — embedded in the caller's TCB:
``{ txid, ready, reply: MpRecord, reply_carriers: CarrierSlots }``. A matching
reply-marked ``MP_WRITE`` (the ``try_write_record`` reply arm, matched by txid)
writes the reply *here*, out-of-band, flips ``ready``, and direct-wakes the
caller; the payload lives in this per-TCB slot, **never** in the receive ring.

The lost-wakeup race is closed by **register-at-send**: ``try_call_write_record``
pushes the caller onto ``waiters_call`` and the ring request atomically under one
``MessagePipeCore.lock`` hold, so a reply that arrives immediately still finds a
registered txid waiter to wake. MOVE-cap carriers ride the reply's
``CarrierSlots`` (installed into the caller's CSpace on consume, dropped via the
CDT on timeout / teardown), with the in-transit pin preserved. The userland
``ipc_call_retry`` loop is removed; callers invoke ``mp_call_ctx`` directly and
the kernel reply-wait absorbs interrupt / restart semantics.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- The reply MUST reach exactly its txid call-waiter and direct-wake it.
- The path MUST be lost-wakeup-free: a reply arriving immediately after the
  request MUST still wake the caller.
- MOVE-cap transfer, the in-transit pin, and the ``MP_CALL`` / ``ReplyRecv`` names
  MUST be preserved.
- The reply path MUST NOT make a synchronous RPC's success depend on free
  capacity in the caller's receive ring.

Design
======

The MessageWaiter
-----------------

Each TCB embeds a ``MessageWaiter``
(``kernite/src/ipc/message_pipe.rs``, ``kernite/src/sched/thread.rs``):
``txid`` (the active transaction id while parked in ``MP_CALL``, ``0`` when
idle), ``ready`` (set by the reply arm, polled by the consume path), ``reply``
(the delivered ``MpRecord``), and ``reply_carriers`` (the reply's MOVE-cap
``CarrierSlots``). The reply is delivered here out-of-band; it does not occupy a
receive-ring slot.

Register-at-send closes the race
--------------------------------

The caller registers as a call-waiter at **request enqueue time**, not at
reply-wait time. ``try_call_write_record`` performs ``waiters_call(me).push`` and
the ring request push atomically under one ``MessagePipeCore.lock`` hold, closing
the window in which a fast server reply could arrive between request enqueue and
caller wait registration. ``block_call_with_timeout`` then only transitions the
already-registered waiter to blocked. A reply reaches only a registered txid
waiter, so if a reply was sent the caller is already registered.

Direct wake
-----------

``try_write_record``'s reply arm finds the registered call-waiter by txid through
``waiters_call`` and wakes it directly (``wake_thread``); ``waiters_call`` is kept
solely as that perf wake structure. Because the wake is a direct signal rather
than an observed readiness edge, it is not exposed to the edge-trigger
lost-wakeup trap.

Capabilities and teardown
-------------------------

The reply's MOVE carriers live in ``reply_carriers`` and are installed into the
caller's CSpace when the caller consumes the reply; on timeout or thread teardown
they are dropped through the CDT. The in-transit pin keeps a transferred cap's
object alive across the hand-off.

Retiring ipc_call_retry
-----------------------

With the race closed in the kernel, the userland ``ipc_call_retry`` loop
(``lib/trona`` and every caller across at / file / socket / poll / mm / misc /
pipe / proc / dns / signals / pthread / bulk) is replaced by a direct
``mp_call_ctx`` call; the wrappers now issue one blocking ``MP_CALL``.

Implementation
==============

Landed as part of the in-flight clean-slate. The reply-in-ring variant (below)
was implemented during design exploration and reverted; the per-thread
``MessageWaiter`` is the accepted design. ``register-at-send`` under the core
lock is the load-bearing correctness piece.

Backwards Compatibility
=======================

Kernel-internal IPC plumbing; no syscall-number or invoke-label change.
``MP_WRITE`` / ``MP_READ`` fastpath, MOVE-cap semantics, the in-transit pin, and
the label names are unchanged. The userland ABI change is the removal of
``ipc_call_retry`` in favour of a direct ``mp_call_ctx``.

Security Considerations
=======================

A reply must reach only its txid call-waiter. Because the reply is delivered into
the caller's own per-thread ``MessageWaiter`` (keyed by txid) and never enters a
shared receive ring, an unrelated reader cannot observe or intercept it, and a
MOVE carrier cannot be misdelivered to a different reader.

Testing
=======

Boot + the existing ``test_runner`` (every synchronous RPC — mmap / namesrv /
vfs — receives its reply). Focused ``MP_CALL`` scenarios: a reply that arrives
immediately after the request still wakes the caller (register-at-send);
reply-with-cap MOVE delivery; timeout; thread teardown mid-call; concurrent
callers. ``just warn`` clean on x86_64 and aarch64.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Reply-in-ring (designed, reverted).** An alternative delivered the reply as
  an ordinary record in the caller's receive ring (``MP_FLAG_REPLY`` + txid) with
  its carriers in that slot's ``CarrierSlots``, making ``STATE_READABLE`` the
  single readiness truth and removing the per-TCB slot. It was reverted for two
  reasons: (1) the receive ring is bounded, so in certain situations replies
  competing for ring slots could fill it — a synchronous RPC's success should not
  depend on free ring capacity; and (2) it has no prior art — no production
  channel IPC places replies in the message ring. Zircon keeps the reply in a
  per-thread out-of-band ``MessageWaiter``, which is the design retained here.
  The reply-in-ring variant would also have required new ring mechanics
  (out-of-order slot claim, arbitrary-slot rollback, a plain-``MP_READ``
  reply-skip filter) that the per-thread slot makes unnecessary.
- **Arrival-generation counter for lost-wakeup safety.** Considered for the
  reply-in-ring variant; unnecessary under register-at-send, which makes the path
  lost-wakeup-free directly.

Prior Art and References
========================

- **Zircon (Fuchsia)** — ``zx_channel_call`` parks the caller on a per-thread
  ``MessageWaiter`` and the reply is delivered into that waiter out-of-band, not
  enqueued on the channel's message queue. The per-thread ``MessageWaiter``, its
  name, and the out-of-band delivery are taken from it.
