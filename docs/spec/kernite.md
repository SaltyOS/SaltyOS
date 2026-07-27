# Kernite Architectural Direction

This document records the intended architectural direction for the `kernite`
microkernel as of `2026-04-30`. It is not a line-by-line description of the
current implementation. It is a target-state specification for the next major
refactor.

The goal is to stabilize the kernel by making subsystem ownership explicit,
reducing cross-layer mutation, and replacing several fragile "open-coded"
protocols with narrower, verifiable interfaces.

---

## 1. Scope

This document covers:

- kernel architectural direction
- subsystem boundaries
- ownership rules between task / scheduler / IPC / MM / event delivery
- object lifetime and destruction model
- code organization direction
- staged migration strategy

This document does not define:

- user-visible syscall ABI changes in detail
- final wire layouts for new pipe, queue, watch, and event-record objects
- bootloader changes
- userspace service policy

Those belong in dedicated ABI or subsystem specifications once the kernel-side
direction is accepted.

---

## 2. Architectural Thesis

The target Kernite architecture is:

- **semantic core:** capability object kernel with explicit authority
- **resource model:** `seL4-inspired` untyped memory, CNodes, and rights
- **IPC/event edge:** pipe, state-flag, watch, and event-queue objects
- **code organization:** `Linux-style tree layout`

This combination is deliberate.

- The kernel's authority model and resource model are already
  capability-centric: `Untyped`, `CNode`, `TCB`, `VSpace`, typed invocation,
  and explicit rights are all closer to seL4 than to Linux or BSD.
- The current instability is not caused by the capability model. It is caused by
  boundary collapse: scheduler, task lifecycle, async wakeup, and object
  destruction currently reach into each other too freely.
- Zircon/Fuchsia provides a useful design reference specifically for
  object-state notification, packetized delivery, and handle-like multiplexing.
  Kernite should adopt those ideas under SaltyOS names without importing
  Zircon's handle-table authority model.
- Linux is useful here as an organization reference, not as a semantic model.
  Its source tree separates concerns more effectively than the current
  file-heavy layout, but Kernite should not adopt Linux's ambient-authority or
  highly mutable task model.
- The old seL4-style synchronous rendezvous endpoint should no longer be the
  primary IPC transport. It remains useful as a migration target and as a
  compatibility object, but new IPC should be expressed through pipe objects,
  object state flags, watches, and event records.

In short:

- **Do not Linux-ify kernel semantics.**
- **Do Linux-ify module layout and responsibility boundaries.**
- **Do preserve seL4-like authority and untyped resource invariants.**
- **Do replace ad-hoc synchronous IPC variants with object-state/event
  primitives.**

---

## 3. Current Structural Problems

The current kernel has several recurring failure modes:

1. **Task state is mutated from too many places.**
   Endpoint IPC, notification delivery, fastpath IPC, suspend/resume, and some
   destroy paths all perform direct state transitions on `TCB` fields.

2. **Scheduler ownership and task lifecycle are entangled.**
   The scheduler currently owns not just runnable placement, but also parts of
   quiesce, wake, deferred destruction coordination, VSpace waiter draining, and
   state publication.

3. **Object destruction is too synchronous.**
   `release_object()` can immediately cascade into deep cleanup, including MM and
   cross-object teardown, from contexts that should only be dropping a reference.

4. **Asynchronous events are represented as side effects on task state.**
   `woken_by_notification`, bound notifications, IRQ wakeups, and synthetic
   notification-frame injection create hidden coupling between event delivery and
   synchronous IPC state.

5. **One file often owns too many layers at once.**
   Representative hotspots:
   - `kernite/src/syscall/mod.rs`
   - `kernite/src/sched/scheduler.rs`
   - `kernite/src/mm/vspace.rs`
   - `kernite/src/ipc/endpoint.rs`

6. **IPC variants encode policy combinations in the kernel ABI.**
   `NBSend`, timed send/receive, `RecvAny`, and `ReplyRecvAny` are examples of
   the wrong pressure: each adds a special syscall shape for one composition of
   readiness, timeout, reply, and multiplexing. The target model should expose
   smaller primitives that compose through watchable object state.

These are not merely style problems. They are the source of correctness
problems: lock inversion, stale ownership, open-coded wake races, quiesce loops,
and MM lifetime bugs.

---

## 4. Target Kernel Model

### 4.1 Core Model

Kernite remains a capability-based microkernel with the following load-bearing
properties:

- all authority remains capability-mediated
- kernel objects continue to be carved from untyped memory
- `TCB`, `CNode`, `VSpace`, `SchedContext`, `MemoryObject`, and `IrqHandler`
  remain explicit kernel objects
- `MessagePipe`, `DataPipe`, and `EventQueue` become first-class IPC/event
  objects
- legacy `Endpoint` and `Notification` objects remain only for migration and
  compatibility
- the default IPC transport is non-blocking, bounded, object-backed message
  delivery with explicit state flags
- kernel-visible synchronous RPC may exist only as a narrow `MessagePipe`
  helper, not as the primary server model
- user address spaces remain explicit `VSpace` objects

### 4.2 New Separation Of Concerns

The refactor introduces three strong planes:

1. **Task plane**
   Owns thread lifecycle, wait reasons, stop/configure rules, reply/call
   context, and legal state transitions.

2. **Scheduling plane**
   Owns runnable placement, CPU selection, preemption, accounting, and class
   policy. It does not own lifecycle semantics.

3. **Event plane**
   Owns object state flags, watches, event records, event queues, and
   asynchronous delivery from pipe, IRQ, timer, fault, and compatibility
   notification-like sources. It posts events; it does not directly perform deep
   task-state surgery.

Additionally:

- **IPC plane** owns pipe object semantics, message transfer, capability
  transfer, and the optional kernel-visible call helper.
- **Object lifetime plane** owns deferred destruction and final cleanup.

---

## 5. Hard Design Rules

The following rules define the intended architecture and should be treated as
spec-level constraints.

### R1. Only the task plane may perform lifecycle transitions.

The task plane is the sole owner of transitions such as:

- `Created -> Configured`
- `Configured -> Runnable`
- `Runnable -> Blocked`
- `Blocked -> Runnable`
- `Runnable/Blocked -> Stopped`
- `Stopped -> Dying`

The scheduler may request a transition, but must not open-code it.

### R2. Structural mutation is allowed only on a stopped task.

Operations such as:

- changing `VSpace`
- changing `CSpace`
- configuring entry point / kernel stack / trampoline stack
- rebinding task-local async resources such as event queues or legacy
  notifications
- changing scheduler class or bound scheduling context

must require the task to be in an explicit non-runnable control state. The
current `Inactive` state is too overloaded; the refactor should split lifecycle
states rather than overloading one enum value.

### R3. The scheduler owns runnability, not object lifetime.

The scheduler may own:

- runnable queues
- per-CPU current ownership
- preemption and class ordering
- CPU-time accounting

The scheduler must not own:

- final object destruction
- VSpace or MM teardown semantics
- direct capability lifetime decisions
- asynchronous event semantics

### R4. IPC readiness and async delivery must be object-state based.

Pipe readiness, IRQ, timer, fault, and notification-compatible events should be
normalized into explicit object state and event-delivery models:

- watchable object publishes state flags
- watch registration binds selected flags to an event queue
- state satisfaction queues an event record
- waiting task observes event records via a defined interface

Long term, async delivery should not depend on kernel-side synthesis of user
stack frames.

### R5. The kernel must expose primitives, not combinatorial IPC variants.

The target syscall surface should avoid policy-specific combinations such as:

- `send_timed`
- `recv_any_timed`
- `reply_recv_any`
- `message_pipe_call_timed`
- `message_pipe_call_any`

Instead, timeout, multiplexing, cancellation, and request policy should compose
from:

- watchable object state
- `EventQueue`
- timer objects
- explicit userland protocol state

Kernel responsibility is correctness of object state, queueing, wakeup, and
lifetime. Userland responsibility is protocol policy.

### R6. Object release must be shallow; destruction must be deferred.

Reference release may:

- decrement a refcount
- enqueue a reaper item

Reference release must not:

- directly recurse into multi-object cleanup trees
- trigger MM teardown inline from arbitrary lock contexts
- depend on the caller already understanding deep subsystem ordering

### R7. Optional queues must be opt-in object cost.

The `NBSend` mistake must not repeat. Large or queue-heavy structures must not
be embedded into every endpoint-like object when only a few users need them.

Kernel memory should be spent where it directly increases expressiveness:

- `MessagePipe` queue capacity is paid only by message-pipe objects
- `DataPipe` shared-ring metadata is paid only by data-pipe objects
- `EventQueue` packet depth is paid only by event-queue objects
- watch registration records are paid only by registered watches

### R8. Legacy compatibility paths must be frozen, not extended.

During migration:

- old code may remain for compatibility
- old code must not become the place where new features land
- new kernel invariants must be enforced in new modules first

The target state is not dual ownership. It is ownership transfer.

---

## 6. Target Subsystem Boundaries

### 6.1 Task Plane

The task plane owns:

- task lifecycle state
- wait reason state
- stop / configure / resume gating
- reply/call context lifetime
- binding of task-local resources
- quiesce protocol

It should expose narrow operations such as:

- `task_stop()`
- `task_configure_space()`
- `task_bind_sched_context()`
- `task_block(reason)`
- `task_make_runnable(cause)`
- `task_begin_destroy()`

### 6.2 Scheduling Plane

The scheduling plane owns:

- run queue representation
- class policy (`deadline`, `rt`, `fair`, `idle`)
- cross-CPU balancing
- preemption tests
- CPU ownership publication
- runtime accounting

It should not manipulate arbitrary `blocked_reason` fields directly. The
scheduler should consume task-plane decisions such as "this task is now
runnable", not decide lifecycle legality on its own.

### 6.3 IPC Plane

The IPC plane owns:

- `MessagePipe` endpoint-pair semantics
- bounded small-message queues
- capability transfer during pipe message delivery
- `DataPipe` setup and endpoint ownership
- optional `message_pipe_call` transaction tracking
- fault IPC delivery

It must not own:

- global async wake reasons
- arbitrary task reconfiguration
- object teardown
- protocol-specific retry, serialization, batching, or cancellation policy

### 6.4 Event Plane

The event plane owns:

- object state flags
- object watches
- event queues
- event records
- IRQ-to-event delivery
- timer-to-event delivery
- notification compatibility shim

The event plane should be the only async wake authority. It may notify the task
plane that an event is pending, but should not itself mutate unrelated IPC
state.

### 6.5 Object Lifetime Plane

The object lifetime plane owns:

- refcount transitions that cross into destruction
- reaper queues
- final cleanup sequencing
- serialization of destroy-time ordering

It must become the single place where "refcount reached zero" turns into "final
cleanup now runs".

---

## 7. Scheduler Direction

The scheduler should be refactored during the same effort rather than left as a
legacy island.

This does **not** mean changing scheduling policy from scratch. The existing
class model is still the right direction:

- deadline class
- RT FIFO class
- fair class
- idle class

What changes is ownership and factoring.

### 7.1 Scheduler Responsibilities To Keep

- maintain runnable sets
- choose next runnable task
- perform preemption decisions
- track per-CPU current task ownership
- perform accounting and balancing

### 7.2 Scheduler Responsibilities To Remove

- deep lifecycle legality checks
- direct destroy-time refcount orchestration
- VSpace teardown semantics
- ad-hoc wake protocols for unrelated subsystems
- task-configuration side effects

### 7.3 Scheduler Refactor Shape

The scheduler should be split into:

- `core`: top-level scheduler object, CPU-local state, entry points
- `rq`: run queue implementation and enqueue/dequeue helpers
- `wake`: runnable publication and cross-CPU wake logic
- `switch`: context-switch publication, current-task transitions
- `balance`: CPU balancing and affinity migration
- `clock`: tick / timebase helpers
- `accounting`: runtime accounting
- `pi`: priority inheritance support
- `class/*`: class-specific queue logic

The scheduler should consume a task abstraction rather than raw task-state
internals whenever practical.

---

## 8. IPC And Event Object Direction

The current endpoint and notification models are too tightly coupled to task
internals and to IPC interruption state.

The target direction is a small set of expressive kernel objects:

- `MessagePipe`: small control messages and capability transfer
- `DataPipe`: mapped shared-memory data path with kernel-owned lifetime and
  readiness
- `EventQueue`: queued event records from watched object state
- object watches: lost-wakeup-free binding from object state flags to
  `EventQueue`

`Endpoint` and `Notification` remain only as legacy compatibility objects. New
servers and drivers should not extend them.

### 8.1 Naming

Kernite intentionally uses SaltyOS names instead of importing Zircon/Fuchsia
names directly:

| Design role | Kernite name |
|-------------|--------------|
| Small message endpoint pair | `MessagePipe` |
| Shared-memory ring/data path | `DataPipe` |
| Packet queue for watched objects | `EventQueue` |
| Object signal word | state flags |
| Async wait registration | object watch |
| Queued packet | `EventRecord` |

This keeps the semantics clear without turning Zircon handle/dispatcher
terminology into the public authority model.

### 8.2 MessagePipe

`MessagePipe` is the default control-plane IPC object. It is a bounded
endpoint-pair object:

```text
message_pipe_create(options) -> left, right
message_pipe_write(end, message, caps)
message_pipe_read(end, out_message, out_caps)
message_pipe_close(end)
```

Properties:

- `write` and `read` are non-blocking by default
- pipe ends are capability objects with explicit rights
- messages carry small register/byte payloads plus optional transferred caps
- large payloads move through `DataPipe` or `MemoryObject`, not inline pipe
  queues
- each end publishes state flags such as `READABLE`, `WRITABLE`, and
  `PEER_CLOSED`
- peer close and object destruction must update state and wake watchers

`MessagePipe` replaces new uses of synchronous `Endpoint` IPC. The legacy
endpoint can remain during migration, but new kernel features should target
pipe semantics.

### 8.3 DataPipe

`DataPipe` is an opt-in data-plane object for bulk transfer. It is a
kernel-owned shared ring whose payload storage is mapped into userspace:

```text
data_pipe_create(size, options) -> producer, consumer
data_pipe_map(end, vaddr, rights)
data_pipe_produce(end, amount)
data_pipe_consume(end, amount)
data_pipe_query(end)
```

Properties:

- the kernel owns lifetime, rights, accounting, mapping, and readiness
- userspace accesses the mapped payload pages directly
- the kernel does not parse service-specific data formats
- producer/consumer rights may be separated
- readable/writable/peer-closed/overrun state is watchable
- hot paths are not forced through copy syscalls

This is the preferred replacement for ad-hoc shared-memory rings plus
notification bits. Console, display, block, network, and filesystem streaming
paths should move toward `DataPipe` when their payload volume justifies it.

### 8.4 EventQueue

`EventQueue` is the kernel object used to multiplex readiness and completion
from many objects:

```text
event_queue_create(depth) -> queue
event_queue_wait(queue) -> EventRecord
event_queue_poll(queue) -> EventRecord
event_queue_cancel(queue, object, key)
```

An `EventRecord` has the following conceptual shape:

```c
struct EventRecord {
    uint64_t key;       /* user-provided opaque value */
    uint32_t type;      /* STATE, IRQ, TIMER, FAULT, USER, ... */
    uint32_t status;    /* OK, CANCELLED, OBJECT_CLOSED, DROPPED, ... */
    uint64_t observed;  /* observed state flags at trigger time */
    uint64_t data0;
    uint64_t data1;
};
```

Properties:

- queue depth is bounded and charged to the `EventQueue` object
- overflow must be observable through status, counters, or a dropped-event
  record
- `event_queue_wait` blocks only on the queue itself; deadlines and timeouts are
  modeled by watching timer objects
- event records are hints with an observed state snapshot, not a replacement for
  re-reading the source object

The exact ABI layout belongs in the syscall/ABI specification. The
architectural requirement is that event delivery is explicit, queued, bounded,
and typed.

### 8.5 Object Watches

An object watch binds selected state flags on one object to an `EventQueue`:

```text
object_watch(object, flags, queue, key, options)
```

Required guarantees:

- if `flags` are already satisfied at registration time, an event record is
  queued
- no state transition can be lost between registration and blocking in
  `event_queue_wait`
- object close, peer close, and destruction wake or cancel all affected watches
- `EventRecord.observed` contains the flags observed at trigger time
- userspace may re-query or read the source object after receiving the event
- watch registrations hold the lifetime references needed to make cancellation
  and destruction race-free
- watches are one-shot by default; persistent watches may be added only if they
  do not obscure backpressure or overflow behavior

This is the replacement for bound notifications, synthetic notification frames,
and endpoint-specific `recv_any` logic.

### 8.6 State Flags

State flags are object-specific but should share a common core:

```text
READABLE
WRITABLE
PEER_CLOSED
CLOSED
ERROR
HANGUP
OVERRUN
SIGNALED
```

Examples:

- `MessagePipe` end: `READABLE`, `WRITABLE`, `PEER_CLOSED`
- `DataPipe` end: `READABLE`, `WRITABLE`, `PEER_CLOSED`, `OVERRUN`
- `Timer`: `SIGNALED`
- `IrqHandler`: `SIGNALED`
- task/process-like objects, if added later: `SIGNALED`, `ERROR`, `CLOSED`

### 8.7 IRQ And Timer Delivery

IRQ and timer delivery should become normal watchable-object delivery:

```text
timer_create()
timer_set(deadline, slack, mode)
object_watch(timer, SIGNALED, queue, key)

irq_handler_get(irq)
object_watch(irq, SIGNALED, queue, key)
irq_ack(irq)
```

The event plane owns the state transition and event-record enqueue. Device
policy and service dispatch stay in userspace.

### 8.8 Compatibility Policy

During the migration, servers that already rely on seL4-style bound
notifications should treat the notification word as a reserved bit namespace.
For example, the VFS owner loop binds a single `pty_ntfn`: PTY readiness owns
the low `1 << pty_id` bits, while backend worker completions own `1 << 63`.
That keeps today's single-bound-notification ABI deterministic without
introducing a second notification object that endpoint receive cannot observe.

When `EventQueue` and object watches land, this namespace should collapse into
event keys: `PTY_READY`, `BACKEND_WORKER_COMPLETE`, timer expiry, IRQ events,
and pipe readability become separate queued records rather than bits
multiplexed through one notification word.

Long term, async events should no longer depend on:

- `woken_by_notification`
- synthetic user stack frame injection
- hidden coupling between `ReplyWait` and notification interruption

Async delivery should instead become an explicit user-visible event-consumption
path.

---

## 9. Reply And Call Direction

The current reply path relies heavily on raw `reply_tcb` ownership, endpoint
rendezvous state, and direct task-field mutation.

The target direction is to make synchronous RPC optional and narrow.

The default server model should be:

```text
object_watch(server_pipe, READABLE, queue, KEY_SERVER)

loop:
  record = event_queue_wait(queue)
  if record.key == KEY_SERVER:
      request = message_pipe_read(server_pipe)
      reply = handle(request)
      message_pipe_write(server_pipe, reply)
```

RPC transaction IDs, serialization, batching, retry, and cancellation policy are
userspace protocol responsibilities.

The retained synchronous RPC shape is a client-side helper only:

```text
message_pipe_call(end, request, out_reply, deadline, options)
```

Constraints:

- `message_pipe_call` writes a `MP_CALL` record and waits on the caller's
  inbound side for a reply record
- reply matching beyond the pipe connection is userspace protocol state
- the server still receives requests via normal pipe readability
- the server replies with normal `message_pipe_write`
- no `message_pipe_reply_recv`, `message_pipe_call_timed`,
  `message_pipe_call_any`, or equivalent combinatorial variants
- `message_pipe_call` takes an explicit `deadline` argument (as Zircon's
  `zx_channel_call`): expiry returns `TIMED_OUT`, peer / server close returns
  `PEER_CLOSED`. The deadline is one argument on the single call primitive — not a
  `message_pipe_call_timed` variant. Timer objects + `EventQueue` compose timeouts
  across *multiple* sources; a single call's own deadline is a direct argument.
  (`message_pipe_call` is slowpath, so its request body travels in the IPC buffer
  like `zx_channel_call`'s args struct; the register-payload fastpath is `MP_WRITE` /
  `MP_READ` only.)

What matters is the invariant:

- reply/call ownership must be explicit
- lifetime must not depend on ad-hoc raw-pointer conventions
- peer close, caller death, server death, cancellation, and object destruction
  must observe one call-state machine
- synchronous call support must not become the primary multiplexing model

---

## 10. Object Lifetime And Reaper Direction

The current refcount model should be refactored into:

1. shallow release
2. deferred reaper enqueue
3. explicit final cleanup execution

This reaper should serialize object finalization for:

- `TCB`
- `VSpace`
- `SchedContext`
- `MemoryObject`
- `MessagePipe`
- `DataPipe`
- `EventQueue`
- watch registration state
- legacy `Notification`
- legacy `Endpoint`

The goal is not a single giant global destroy lock. The goal is a single,
predictable semantic boundary:

`reference release != final cleanup`

This boundary is essential for removing lock-order-dependent destroy bugs.

---

## 11. Code Organization Direction

The source tree should move toward Linux-style organization while preserving the
microkernel semantic model.

Target shape:

```text
kernite/src/
  lib.rs
  kernel/
    mod.rs
    printk.rs
    panic.rs
    bug.rs
    time.rs
    random.rs
  init/
    mod.rs
    main.rs
    bootinfo.rs
    cpio.rs
    elf.rs
  firmware/
    mod.rs
    acpi.rs
  arch/
  task/
    mod.rs
    state.rs
    control.rs
    wait.rs
    stop.rs
    reply.rs
    quiesce.rs
  sched/
    mod.rs
    core.rs
    rq.rs
    wake.rs
    switch.rs
    balance.rs
    clock.rs
    accounting.rs
    pi.rs
    class/
      deadline.rs
      rt.rs
      fair.rs
      idle.rs
  ipc/
    mod.rs
    message_pipe.rs
    data_pipe.rs
    transfer.rs
    fault.rs
    legacy_endpoint.rs
    legacy_notification.rs
  event/
    mod.rs
    event_queue.rs
    record.rs
    state.rs
    watch.rs
    fault.rs
    source.rs
    irq.rs
    timer.rs
    notification_compat.rs
  object/
    mod.rs
    lifetime.rs
    reaper.rs
  cap/
  mm/
  syscall/
    mod.rs
    dispatch.rs
    tcb.rs
    ipc.rs
    event.rs
    mm.rs
    cap.rs
```

Important note:

- this is a code organization target
- it does **not** imply Linux process model semantics
- capability, untyped memory, and microkernel object semantics remain intact
- `lib.rs` is only the crate root; kernel infrastructure belongs under
  `kernel/`, boot/init code under `init/`, and firmware discovery under
  `firmware/`
- fatal diagnostics are centralized in `kernel/panic.rs`: Rust panics,
  assembly `kernel_panic`, x86 fatal exceptions, aarch64 EL1 exceptions,
  aarch64 SError, always-on BUG/assert paths, and spinlock hard timeouts all
  use the same hybrid report
- production kernel invariants use `kernel/bug.rs` (`kassert!`, `kassert_eq!`,
  `kassert_ne!`, `kbug!`, `kbug_on!`) rather than Rust debug-only assertions

### 11.1 Kernel Failure Diagnostics

Kernite's panic diagnostics are a hybrid style: Linux contributes the
`CPU`/`PID`/instruction-pointer/`Call Trace` shape, FreeBSD contributes
trapframe-centered register fields, BSD contributes the expectation that every
fatal path has a traceback, and Windows bugchecks contribute a stable
machine-readable reason code plus arguments.

The canonical report order is:

```text
header
panic_cpu, panic_task, uptime_ns, invoke_seq, source, kernel identity
reason
fault context
Call Trace
current task
lock diagnostics
scheduler
memory
secondary CPUs
arch detail
footer
```

The `kernel:` identity line has this form:

```text
kernel: kernite git=<rev12><-dirty> config=<hash12> arch=<arch> rustc=<rustc> profile=<debug|release>
```

`git` is `unknown` when the build cannot read the repository. The `-dirty`
suffix records staged or unstaged changes at build time. `config` is a
canonical SHA-256 over kernel-affecting inputs excluding the git revision and
dirty bit; its short form is printed in the panic header and its full form plus
summary is printed by `KDEBUG_DUMP_STATE`.

`kallsyms` is linked into `.rodata` from a preliminary kernel ELF and covers
defined text and data symbols. Call traces and diagnostic object addresses use
this table for bounded in-kernel symbolization. Stack unwinding first attempts
bounded DWARF CFI from preserved `.eh_frame`, then falls back to validated
frame-pointer chains; invalid stack bounds, repeated frames, and maximum frame
count stop the walk.

Only the panic owner CPU prints the full report. Secondary CPUs append bounded
events containing CPU, task, reason code, instruction pointer, uptime, and
location, then halt. Serial output from non-owner CPUs is suppressed after a
panic owner is established.

`debug_assert*` and `cfg(debug_assertions)` must not guard production runtime
kernel invariant checks. Fatal invariants use the always-compiled `kassert*` and
`kbug*` macros so structured reasons remain available in release kernels.

---

## 12. Migration Strategy

This refactor should be staged, but the target state must be defined up front.

### Phase 1. Establish The New Planes

- introduce `task`, `sched`, `event`, and `object` modules directly under
  `kernite/src/`
- move interfaces first, not implementation detail
- freeze new feature development in legacy hot files

### Phase 2. Build The Reaper

- convert `release_object()` into shallow release + deferred reaper path
- move final cleanup behind the reaper boundary
- make destroy ordering explicit

### Phase 3. Move Task Lifecycle Out Of Syscall/Scheduler

- centralize task stop/configure/resume/suspend legality
- remove open-coded lifecycle transitions from syscall handlers and fastpaths
- make structural task mutation require stopped-task state

### Phase 4. Refactor Scheduler Around Runnable Ownership

- split queue logic from lifecycle logic
- move class-specific policy into dedicated files
- make scheduler consume task-plane operations instead of mutating state ad hoc

### Phase 5. Introduce EventQueue And Object Watches

- implement object state flags
- implement `EventQueue` and `EventRecord`
- implement object watches with lost-wakeup-free registration
- route IRQ and timer through watchable object state
- rebuild notification as compatibility on top of event records

### Phase 6. Introduce MessagePipe And DataPipe

- implement `MessagePipe` as the default small-message IPC transport
- implement capability transfer through `MessagePipe`
- implement `DataPipe` for opt-in shared-ring data paths
- migrate new servers away from `Endpoint` and bound notifications

### Phase 7. Rebuild Call/Async Interaction

- replace raw reply ownership conventions with explicit call-state objects
- decide whether `message_pipe_call` remains as the narrow sync RPC helper
- remove legacy async interruption glue from direct task fields
- keep server multiplexing on `EventQueue`, not reply-receive variants

### Phase 8. Retire Legacy Paths

- freeze old notification and direct wake side channels
- delete compatibility layers only after userland migration is complete

---

## 13. Non-Goals

This refactor does **not** aim to:

- turn Kernite into Linux
- replace capabilities with handle tables
- replace `CNode` / `Untyped` / `VSpace` with Zircon VMAR/process semantics
- redesign all scheduling policy from scratch
- parse arbitrary service protocols in the kernel
- force bulk payloads through kernel copy queues
- add a new syscall for every combination of timeout, multiplexing, reply, and
  cancellation
- make every endpoint-like object pay the memory cost of optional queues
- move large kernel services into userspace again; that is already the model

---

## 14. Acceptance Criteria

The direction described here should be considered implemented only when all of
the following are true:

1. task lifecycle has one owning subsystem
2. scheduler no longer directly owns object destruction semantics
3. new IPC is represented by `MessagePipe`, `DataPipe`, `EventQueue`, and
   object watches rather than synchronous endpoint variants
4. deep cleanup never runs inline from generic refcount release
5. structural task mutation is rejected unless the task is in an explicit
   stopped/configurable state
6. object watches are lost-wakeup-free across registration, close, and destroy
7. a single blocking primitive's timeout is an explicit `deadline` argument
   (`message_pipe_call` and `event_queue_wait`, as in Zircon `zx_channel_call` /
   `zx_port_wait`); multiplexing and multi-source / periodic timeout compose through
   timer objects + `EventQueue` — without dedicated per-combination IPC syscall variants
8. legacy compatibility paths are wrappers around new ownership boundaries, not
   alternate ownership paths

---

## 15. Current Decision

The current architectural decision is:

- **yes** to a major Kernite refactor
- **yes** to refactoring the scheduler as part of the same effort
- **yes** to Linux-style directory organization
- **yes** to preserving seL4-like untyped memory, CNodes, and explicit
  capability rights
- **yes** to replacing the primary IPC/event edge with `MessagePipe`,
  `DataPipe`, `EventQueue`, state flags, and object watches
- **yes** to treating `message_pipe_call` as an optional narrow sync RPC helper,
  not the default server model
- **no** to importing Linux process/task semantics
- **no** to turning Zircon/Fuchsia handle/dispatcher semantics into the kernel's
  primary authority model
- **no** to extending legacy `Endpoint` / `Notification` as the place where new
  IPC features land

This document should be updated as subsystem-specific specifications land.
