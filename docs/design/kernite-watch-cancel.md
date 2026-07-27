# kernite Watch cancellation

## Background

Each `Watch` capability binds to a single `EventQueue` and watches
some target object's `state_flags`. When the watched flags transition
into a publisher-supplied mask the kernel enqueues an `EventRecord`
into the bound EQ; userspace drains the EQ via `KERNITE_INV_EQ_WAIT`.

The original `Watch` API has two cap-level operations:

* `KERNITE_INV_WATCH_REGISTER` — bind the cap to an EQ, install
  the cookie, arm the watch.
* `KERNITE_INV_WATCH_DISARM` — clear `armed`, leaving the watch
  on the watcher list and the bound EQ ring possibly still
  carrying records that fired before the disarm took effect.

Disarm is the right primitive when the userspace dispatcher is
about to retire the watch and either drain the EQ wholesale or
rely on cookie-generation validation to filter stale records on
the read side. It is the wrong primitive when the dispatcher
would like the watch's *EQ footprint* to disappear too — for
example when a backend session tears down and the dispatcher does
not want stale-cookie records lingering on the ring while the EQ
is still live for sibling sessions.

## `KERNITE_INV_WATCH_CANCEL`

`KERNITE_INV_WATCH_CANCEL = 0x142` extends the disarm sequence:

1. Set `Watch.armed` to `0` (the disarm semantic).
2. Remove the `Watch` from its `WatcherList` so subsequent
   publishers do not even attempt to enqueue against it.
3. Bump `Watch.cancel_epoch` (atomic, AcqRel) so any in-flight
   `WatcherList::publish` snapshot detects the cancel and skips
   its enqueue.
4. Walk the bound EQ's ring and remove every `EventRecord` whose
   cookie matches the watch's cookie via
   [`EventQueue::purge_matching`].
5. Drop the EQ strong reference held by the watcher (the same
   teardown step `WATCH_DISARM` performs).

The kernel-side guarantees:

* No `EventRecord` for this watch lands on the ring after `CANCEL`
  returns. The race window between `WatcherList::publish`'s batch
  snapshot and the actual enqueue is closed by the `cancel_epoch`
  recheck inside `publish`'s fire path.
* Records dequeued *before* `CANCEL` are not affected. Those are
  already in userspace; cookie generation validation on the read
  side filters them out.

VFS correctness (and any future user of this primitive) does not
depend on the EQ purge: the cookie carries a generation field and
stale records are filtered on read regardless of whether they
managed to reach the ring. The purge is hygiene — it bounds the
ring's footprint during a long session-teardown sweep — and a
parity item with Zircon's `zx_object_wait_async` cancellation
semantics so subsystems ported from / inspired by Fuchsia behave
identically.

## Substrate helper

`lib/trona/substrate/invoke.rs` exposes `watch_cancel(cap)` —
just an `KERNITE_INV_WATCH_CANCEL` invocation against a cap with
`CAP_RIGHTS_WRITE`. The substrate's
[`EqWaitDemuxReactor::cancel_watch`] helper rides this so every
EQ-driven dispatcher gets identical teardown behaviour.

## Required invariant chain

The dispatcher's session teardown must run in this order:

1. Advance the session's `live_gen` counter (so any in-flight
   record dequeued past this point fails the generation check).
2. Issue `WATCH_CANCEL` against the watch capability.
3. Cancel every `PendingOp` enrolled against the now-dead
   session.
4. Release the callback / pager caps held against the backend.

Steps 2 and 3 are independent — the order does not matter for
correctness — but step 1 must precede step 2, and step 4 must
follow step 3 (so a pending op's reply path still sees a live
cap). This is the same ordering vfs's session module runs.
