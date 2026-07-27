# `trona_server` Event Loop

## Background

Every userspace server in SaltyOS that owns more than one MP /
Timer / Watch source uses the same loop shape: drain one
`EventQueue` via `KERNITE_INV_EQ_WAIT`, demultiplex the dequeued
record by cookie, locate the corresponding source MP, drain it
via `MP_READ`, and dispatch the message. The detail that varies
between servers is *what* each cookie maps to — namesrv tracks
publisher REGISTER cookies and timer cookies, mmsrv tracks
per-client request MPs and the pager callback, init tracks
per-process control MPs, vfs tracks frontend / backend / pager /
timer slots — but the loop itself is identical.

`lib/trona/substrate/event_loop.rs` lifts the loop
into a shared abstraction. Each server provides:

* a [`CookieTable<T>`] (a `SegmentedArray<CookieEntry<T>>`) with
  the server's own `T` payload;
* an `EqDispatcher` impl that resolves a cookie to its source MP
  and dispatches the inbound message.

The reactor's `run_iteration` does the rest: `EQ_WAIT`,
generation check, `MP_READ`, `dispatch_state`. Overflow / timer
/ pipe records flow through dedicated trait hooks so the
dispatcher does not have to re-implement the boilerplate.

## Cookie encoding

Cookies pack three fields into a single `u64`:

```
bits 56..64 : kind (u8)            — server-defined source kind
bits 32..56 : slot index (u24)     — index into the cookie table
bits  0..32 : live generation (u32) — increments on slot reuse
```

The `kind` discriminates between a server's own source classes
(e.g. vfs uses `0` for frontend, `1` for backend, `2` for pager,
`3` for timer); the dispatcher routes accordingly. The `live_gen`
field is the truth source for stale-record filtering: when a
slot is reassigned its generation advances, and a leftover
record from the previous occupant fails the validation in
`run_iteration` and is silently dropped.

`encode_cookie` / `decode_cookie` helpers in the same module
keep the bit layout in one place so a future kernel change to
the EventRecord cookie field is a one-line patch.

## `cancel_watch`

When a server retires a cookie slot it calls
`reactor.cancel_watch(kind, slot)`. The helper:

1. Looks up the cookie table entry; bails on miss.
2. Issues `KERNITE_INV_WATCH_CANCEL` against the entry's
   stored `watch_cap` so the kernel ring is purged of any
   pending records the slot had outstanding.
3. Tombstones the entry (`active = false`) and bumps its
   `live_gen` so future arrivals from the cancelled slot fail
   the generation check.

Stable indices: `cancel_watch` never shifts storage, so cookies
that bind to specific table positions (vfs's per-client MP
slot, mmsrv's per-client client_id, namesrv's publisher slot)
keep their identity across cancel cycles. The `CookieTable`'s
underlying `SegmentedArray` enforces the same property at the
container level.

## Servers using the abstraction

* **namesrv** — publisher REGISTER / SUBSCRIBE / parked LOOKUP
  timer.
* **mmsrv** — per-client request MP (kind 0), pager callback
  (kind 1), fault MP fan-in (kind 2 — the dispatcher TCB has
  its own reactor instance).
* **rsrcsrv** — single master MP (kind 0).
* **init** — per-client INIT_CONTROL MP, per-process supervision,
  control timer.
* **vfs** — frontend (kind 0), backend (kind 1), pager (kind 2),
  timer (kind 3).
