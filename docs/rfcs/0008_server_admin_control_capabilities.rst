========================================================================
RFC-0008: Per-client control capabilities for server admin authority
========================================================================

:Status: Implemented
:Areas: mmsrv; VFS; init supervisor; Authorization; Capabilities; Fork/Exec
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-24
:Description: Replace the ambient shared-admin-badge-plus-trusted-integer model on the ``mmsrv`` and VFS admin surfaces with per-client **control capabilities**. Each server mints a per-client control cap at registration (badge = ``TAG | ROOT | generation | slot``) and returns it to ``init``; invoking that cap both authorizes the verb (control caps are minted only to ``init``) and identifies the exact client (badge stamped on invoke), so no caller-supplied integer ``client_id`` and no shared admin badge survive. A per-server ROOT control cap (``init``-only) authorizes registration. Two-operand verbs (mmsrv ``FORK_VSPACE`` / ``STAGE_IMAGE_REGION``, VFS clone) pin both operands by control-cap identity via a two-step transactional invoke. The same change makes fork FD-clone and exec ``FD_CLOEXEC`` sweep ``init``-driven admin verbs and removes the client-facing lifecycle labels (``VFS_CLONE_FDS``, ``VFS_CLIENT_EXEC``) that an unprivileged client could previously invoke against another process.

Problem Statement
=================

Two trusted servers, ``mmsrv`` (memory manager) and VFS, expose an *admin
surface*: operations only the supervisor ``init`` is meant to drive. Today both
authorize that surface with a single **shared ambient badge** plus a
**caller-supplied integer identity**, and a verified fork-authorization audit
showed this is both a live security hole and a correctness gap.

mmsrv admin surface
-------------------

``mmsrv``'s eight admin labels — ``REGISTER_CLIENT`` (0x400),
``DEREGISTER_CLIENT`` (0x401), ``FORK_VSPACE`` (0x402),
``REGISTER_FAULT_PIPE`` (0x403), ``STAGE_IMAGE_REGION`` (0x404),
``BEGIN`` / ``COMMIT`` / ``ABORT_EXEC_REPLACE`` (0x405/6/7) — are gated by
``require_admin`` (``userland/core/mmsrv/src/dispatch.rs``), which checks
``badge == INIT_PRIV_BADGE_FROM_MMSRV`` (one shared constant). Each handler then
**trusts** the caller-supplied ``client_id`` integers in ``regs[]`` and resolves
them by ``find_by_client_id``. Authority is therefore *ambient*: one token
authorizes every verb on every client, and the operand identity is a forgeable
integer. ``handle_fork_vspace`` performs **no parent-child validation** — an
``init`` bug (or a future second holder of the admin badge) that passes swapped
or wrong ``client_id``\ s would clone an arbitrary process's address space into
another. This is the audit's Finding 3.

VFS admin and client surfaces
-----------------------------

VFS splits worse. Its *fork FD-clone* lives on the **general POSIX client
endpoint**: ``VFS_CLONE_FDS`` (0x5C0) routes through
``userland/core/vfs/src/personality/posix/dispatch.rs`` gated only by a
personality check, and ``handle_clone_fds`` trusts the parent/child identifiers
in ``regs[0]/regs[1]`` with **no caller check at all**. Any POSIX client can
clone an arbitrary parent client's FD table — with its credentials, cwd, and
mount namespace — into a child client it names (audit Finding 1, Critical).

Meanwhile the live ``init`` fork path never drives FD-clone: the archived
``procmgr`` used to, but it is unbuilt, so **POSIX fork FD inheritance is
currently broken** — a forked child receives an empty FD table (audit Finding 2,
High). The same shape repeats for exec: ``VFS_CLIENT_EXEC`` (0x5D3) sits on the
client endpoint and is **undriven** by the live exec path, so ``FD_CLOEXEC``
descriptors leak across ``execve`` (found during design review; in scope by
decision). VFS's one existing admin verb, ``VFS_DEREGISTER_CLIENT``, runs over a
shared admin badge ``INIT_PRIV_BADGE_FROM_VFS`` — the same ambient pattern
``mmsrv`` uses.

The common root cause
---------------------

Both servers conflate *authority* (who may drive a privileged transition) with a
single shared token, and derive *identity* (which client) from an untrusted
integer; and the privileged lifecycle transitions that should be ``init``-only
and ``init``-driven (fork FD-clone, exec sweep) are partly exposed to clients and
partly not wired at all. Fixing the symptoms piecemeal would leave the ambient
authority and the forgeable identity in place.

Summary
=======

Replace the shared-badge-plus-integer model on **both** admin surfaces with
**per-client control capabilities** (the "pure-A" model):

- At registration a server **mints a per-client control capability** — a badged,
  non-``GRANT`` ``READ``|``WRITE`` capability to the server's existing master
  endpoint, ``badge = TAG | ROOT | generation | slot`` — and returns it to
  ``init`` via cap transfer. ``init`` stores one control cap per process.
- **Invoking a control cap is both the authorization and the identity.** The
  kernel stamps the badge onto the delivered record only on invoke; the server
  decodes ``slot`` + ``generation`` to find the exact client. Control caps are
  minted *only* to ``init``, so possession-and-invocation proves ``init``. No
  caller-supplied ``client_id`` and no shared admin badge remain for per-client
  verbs.
- A single per-server **ROOT control cap** (held only by ``init``) authorizes
  ``REGISTER_CLIENT`` — the one verb that has no per-client cap yet because the
  client does not exist.
- **Two-operand verbs** (mmsrv ``FORK_VSPACE`` parent+child and
  ``STAGE_IMAGE_REGION`` dst+src; VFS clone parent+child) pin *both* operands by
  control-cap identity with a **two-step transactional invoke**, because the
  kernel surfaces a badge only on invoke (a transferred cap's badge is not
  readable).
- The same change makes **fork FD-clone** and **exec ``FD_CLOEXEC`` sweep**
  ``init``-driven admin verbs and **removes the client-facing lifecycle labels**
  (``VFS_CLONE_FDS``, ``VFS_CLIENT_EXEC``).

This is the Zircon-handle shape (a handle authorizes per-object operations),
chosen over an address-space-identity resolver (see *Drawbacks, Alternatives*)
because SaltyOS supports POSIX-like ``fork`` and the roadmap
(``cap_native_spine`` native personality and a Linux-compatible POSIX personality
with ``vfork`` / ``CLONE_VM``) makes *distinct client identities sharing one
address space* plausible; per-client control caps stay 1:1 in that world and
provide defense-in-depth once control caps are held by more than one privileged
manager.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- No admin verb may be authorized by an ambient shared token or by a
  caller-supplied integer identity. Authority **and** target identity MUST come
  from an unforgeable per-client control capability (badge stamped on invoke).
- Admin verbs MUST be ``init``-only **by construction** — a server mints control
  caps only into ``init``'s reply, so no other client can ever hold one.
- ``REGISTER_CLIENT`` MUST be authorized by a per-server ROOT control cap held
  only by ``init``; no other verb may be authorized by the ROOT cap.
- Control caps MUST be minted as non-``GRANT`` ``READ``|``WRITE`` capabilities:
  the reply-bearing verbs (register, fork-clone, exec-sweep) are driven with
  ``MP_CALL``, which the kernel gates on ``READ``|``WRITE``; the non-reply
  deregister uses fire-and-forget ``MP_WRITE`` (``WRITE`` alone).
- Two-operand verbs MUST pin **both** operands by control-cap identity. Neither
  operand may be a trusted integer or an unauthenticated transferred cap. The
  two-step ``pending`` state MUST be self-healing against an orphaned step 1.
- Control caps MUST be ABA-safe: a cap for a client whose slot was recycled MUST
  fail closed. This uses a **dedicated** per-slot ``generation`` bumped on every
  teardown (the explicit-deregister path), not the arena's slot epoch.
- Fork FD-clone MUST be synchronous and MUST **fail the fork** on error: it runs
  *before* the fork commits, and a failed fork after the clone MUST drop the
  cloned ``OpenObject`` references via rollback. The exec ``FD_CLOEXEC`` sweep is
  the mirror image: it MUST run **after** the exec point of no return
  (``mm_commit_exec_replace``) and be best-effort — a successful exec cannot be
  un-committed, so the sweep's failure MUST NOT fail the already-committed exec
  (matching POSIX, where CLOEXEC close is a consequence of a successful exec).
- ``init``'s ``client_id`` allocator MUST NOT hand out a ``client_id`` that
  collides with a live (or pre-created-for-fork) client, so VFS bind-adoption by
  ``client_id`` is unambiguous.
- The client-facing fork/exec lifecycle labels (``VFS_CLONE_FDS``,
  ``VFS_CLIENT_EXEC``) MUST be removed from the client dispatch and their public
  constants and POSIX alias deleted; only ``init`` may drive fork FD-clone and
  exec sweep.
- The shared admin badges ``INIT_PRIV_BADGE_FROM_MMSRV`` and
  ``INIT_PRIV_BADGE_FROM_VFS`` MUST be removed.
- No regression to boot or to client registration of any server.

Design
======

Control-cap badge codec
-----------------------

A control cap is a **badged, non-``GRANT`` ``READ``|``WRITE`` capability to the
server's existing master endpoint** — no new kernel object per client, so the
server's reactor topology (one master receive, one watch, one dispatcher entry)
is unchanged. ``READ``|``WRITE`` (not write-only) is required because the
reply-bearing admin verbs are driven with ``MP_CALL``, which the kernel gates on
``READ``|``WRITE``; the non-reply deregister uses fire-and-forget ``MP_WRITE``.
Authority and identity ride entirely on the badge::

    bits [63:60] = 0xC          control-cap tag (disjoint from the legacy 0xF
                                privileged-class badges and the 0x0 self-tier)
    bit  [59]    = ROOT         1 = the register-only root cap; 0 = per-client
    bits [58:16] = generation   per-slot reuse counter (43 bits)
    bits [15: 0] = slot         client arena slot index (up to 65536 clients)

``decode(badge) -> (slot, generation)`` and ``is_root(badge)`` are pure bit ops.
The ROOT cap is ``TAG | ROOT`` with ``slot``/``generation`` zero. The slot field
is 16 bits (far above either server's client cap) and the rest of the word is
generation, so reuse-to-collision is unreachable in practice (see *Generation*).
Badges are unforgeable: the kernel stamps the invoked cap's badge onto the
delivered record (fastpath, ``MP_WRITE``, and ``MP_CALL`` all stamp it), and
there is no primitive to mint or alter a badge from userland without the server's
master-endpoint mint authority.

Generation and ABA safety
-------------------------

Each server's client table gains a **dedicated** per-slot ``generation`` —
distinct from the arena's slot epoch (the VFS arena bumps its epoch only on its
sweep, not on every ``release``, so it is not a reliable per-vacate counter). The
``generation`` is bumped inside the single teardown function each server runs for
both explicit deregister and fork rollback (VFS ``remove_client``; the mmsrv
vacate path). VFS in particular has **no reliable ``PEER_CLOSED`` death signal**
(it retains its own request-MP send side), so ``init`` drives an explicit
``DEREGISTER_CLIENT`` on exit — the generation bump must live on that path, not a
peer-closed path.

The badge captures the generation at mint time; ``resolve_control`` rejects a
presented badge whose generation does not match the slot's current value, so a
control cap for a dead-and-recycled client fails closed (``INSUFFICIENT_RIGHTS``
/ ``NOT_FOUND``). The 43-bit generation makes wrap-to-collision unreachable in
practice (~8.8e12 reuses of one slot). This mirrors the existing ``Watch``
``live_gen`` discipline.

Mint at registration
--------------------

On ``REGISTER_CLIENT`` (authorized by the ROOT cap), after the client slot is
installed, the server mints a control cap from a retained capability to its own
master endpoint with ``badge = encode(slot, generation)`` and returns it in the
reply's transferred-cap slot. This is the established mint-via-temp pattern:
borrow a transient slot, ``cnode_mint`` a badged copy into it, place it in the
reply caps, let the reply move it into ``init``'s receive window, and adopt it as
an ``OwnedCap`` (namesrv's ``lookup_resolve`` ``BADGE_AS_CALLER`` path and
``init``'s ``mint_from_raw_send`` are the precedents).

The retained mint source MUST carry ``GRANT`` (``cnode_mint`` requires ``GRANT``
on the source). VFS already retains a master-endpoint capability
(``ROLE_SERVICE_CLIENT_EP``). **mmsrv does not** — boot moves only the receive
side into mmsrv and reclaims the send side — so mmsrv gains a **new retained,
``GRANT``-bearing master-endpoint send role** that ``init`` delivers at boot
instead of reclaiming. Mint strips ``GRANT`` from the copy, so the per-client
control cap is a leaf token (non-``GRANT`` ``READ``|``WRITE``) that cannot itself
re-mint — the correct property.

Resolver replaces the badge check
---------------------------------

``require_admin`` is replaced by two predicates:

- ``require_root(badge)`` — ``is_root(badge)`` else delete any received caps and
  reply ``INSUFFICIENT_RIGHTS``. Used only by ``REGISTER_CLIENT``.
- ``resolve_control(badge) -> Option<slot>`` — validate the tag, that ``slot`` is
  active, and that ``generation`` matches; return the arena ``slot``. On any
  mismatch, delete received caps and reply ``INSUFFICIENT_RIGHTS`` / ``NOT_FOUND``.

``resolve_control`` *is* both the authorization and the target identification:
there is no ``client_id`` argument to trust. The returned ``slot`` is already the
key into the existing per-client tables (client record, region/VM state, pending
exec), so no new indirection is introduced — the linear ``find_by_client_id``
scans disappear from the admin path entirely.

Two-step transactional invoke for two-operand verbs
---------------------------------------------------

A verb with two client operands (fork: parent + child; mmsrv stage: dst + src)
cannot carry the second operand as a transferred control cap, because the kernel
surfaces a badge **only on invoke** — a cap sitting in the receive window has no
readable badge or identity. The second operand is therefore established by a
prior invoke:

1. ``init`` invokes the **secondary** operand's control cap with a
   ``*_SET_PARTNER`` label and a monotonic ``nonce``. The server validates the
   secondary by ``resolve_control`` and records ``pending{secondary_slot,
   secondary_generation, nonce}``. (``init`` is the single lifecycle driver, so
   the ``nonce`` binds step 1 to step 2; it is not an anti-forgery token —
   forgery is already impossible because only ``init`` holds control caps.)
2. ``init`` invokes the **primary** operand's control cap with the operate label,
   the same ``nonce``, and the op arguments. The server resolves the primary by
   ``resolve_control``, looks up and **consumes** the matching ``pending``
   (re-checking the secondary's generation), runs the op against the two resolved
   slots, and clears ``pending`` on success **and on every error path**.

Consume-once is the replay guard; the generation re-check is the ABA guard. The
operand *role* is encoded structurally — the secondary is the one invoked with
``*_SET_PARTNER``, the primary the one invoked with the operate label — and
``init`` uses typed wrappers so the roles cannot be transposed.

The ``pending`` record is a **single slot**, which suffices because ``init`` is
the sole, serial lifecycle driver (at most one fork/stage in flight). It is
**self-healing** against an orphaned step 1 (a step 2 that never arrives — IPC
error or abort between the calls): ``*_SET_PARTNER`` **overwrites** any existing
``pending`` (a fresh transaction supersedes a stale one), a secondary's
``DEREGISTER`` **clears** any ``pending`` naming it, and the operate step
**consumes** it. No timeout is required.

Application to mmsrv
--------------------

Full surface 0x400–0x407. The resolved ``slot`` replaces every trusted
``client_id``:

- ``REGISTER_CLIENT`` (0x400) — ROOT cap; allocates the slot, then mints and
  returns the per-client control cap.
- ``DEREGISTER_CLIENT`` (0x401) — client control cap; bumps the slot generation.
- ``FORK_VSPACE`` (0x402) — two-step: child ``SET_PARTNER``, then parent operate;
  both client slots come from the two invoked caps.
- ``REGISTER_FAULT_PIPE`` (0x403) — client control cap.
- ``STAGE_IMAGE_REGION`` (0x404) — two-step: source ``SET_PARTNER``, then
  destination operate; both client slots from the two invoked caps.
- ``BEGIN_EXEC_REPLACE`` (0x405) — client control cap; returns ``txn_id``.
- ``COMMIT_EXEC_REPLACE`` (0x406) — client control cap plus ``txn_id``.
- ``ABORT_EXEC_REPLACE`` (0x407) — client control cap plus ``txn_id``.

The ``STAGE_IMAGE_REGION`` ``EXEC_MO_SRC`` sub-path has no source *client* (the
source is the held exec ``MemoryObject`` captured at ``BEGIN_EXEC_REPLACE``), so
it takes only the destination control cap and no ``SET_PARTNER`` step.
``txn_id`` remains a per-client selector resolved *after* the client is
authorized by its control cap; it cannot name another client's transaction, so
trusting it is sound. ``MM_BIND_CLIENT_SELF`` (0x408) is the client's own bind
and is unchanged.

Application to VFS
------------------

VFS clients are badge-keyed and bind lazily, so pure-A adds an ``init``-driven
registration that mints the control cap, while lazy bind still establishes the
per-client request-MessagePipe:

- ``VFS_ADMIN_REGISTER_CLIENT`` (new) — ROOT cap. Creates a ``ClientState``
  keyed by ``client_id`` with the badge **unset** and not yet in the badge map,
  mints the per-client control cap, returns it to ``init``.
- ``VFS_ADMIN_CLONE_FDS`` (new) — two-step (child ``SET_PARTNER``, parent
  operate). Clones the parent client's FD table into the child's pre-created
  entry: aliased ``OpenObject`` handles with a refcount bump, plus the
  ``FD_CLOEXEC`` slot flags and the credential / cwd / mount-namespace snapshot.
- ``VFS_ADMIN_EXEC_SWEEP`` (new) — client control cap. Drops the invoking
  client's ``FD_CLOEXEC`` descriptors (releasing their ``OpenObject`` refs). It
  is driven **after** ``mm_commit_exec_replace`` (the exec point of no return)
  and before the post-exec TCB resumes, and is **best-effort**: it only frees
  state (cannot fail under normal conditions) and its failure does not fail the
  already-committed exec.
- ``VFS_DEREGISTER_CLIENT`` (existing) — now authorized by the client control
  cap via fire-and-forget ``MP_WRITE`` (it must stay non-blocking to avoid the
  documented exit-path deadlock); ``remove_client`` releases the FD table and
  per-client resources and bumps the generation.
- **Removed from the client endpoint:** ``VFS_CLONE_FDS`` (0x5C0) and
  ``VFS_CLIENT_EXEC`` (0x5D3). They had no live functional caller (the only
  driver was archived ``procmgr``).

**Bind adoption.** Because the child VFS client is pre-created by
``init`` during fork (to receive its control cap and its cloned FDs) but the
child only learns its real badge when it later self-binds,
``handle_bind_client_self`` is extended: derive ``client_id`` from the presenting
badge, first look up an existing **unbound** entry for that ``client_id`` and, if
found, *adopt* it — set ``client_badge``, insert ``badge_map[badge] -> handle``,
and allocate the request-MP — so the pre-created entry (already carrying the
cloned FD table) and the child's self-bind converge on one slot. With no
pre-created entry it falls back to the existing first-bind path. The identity is
the ``client_id`` (the badge low bits ``init`` controls): ``init`` stamps the
child's namesrv badge low 32 bits with the ``client_id``, namesrv mints the VFS
cap with the caller's low 32 bits, and VFS derives ``client_id`` from those same
bits — so the pre-created entry and the self-bind agree by construction, provided
``init``'s ``client_id`` allocator never collides with a live client.

What is removed
---------------

``INIT_PRIV_BADGE_FROM_MMSRV`` and ``INIT_PRIV_BADGE_FROM_VFS`` are deleted. The
client-facing ``VFS_CLONE_FDS`` / ``VFS_CLIENT_EXEC`` labels are removed from the
POSIX client dispatch **and** their public constants
(``lib/trona/protocol/src/vfs/public.rs``) and the POSIX alias
(``lib/trona/protocol/src/posix.rs``) are deleted; only the unbuilt archived
trees (``procmgr``, ``vfs_old*``) still name them and are excluded from the
removal-verification grep. The trusted ``client_id`` arguments are removed from
every admin verb's wire format.

Implementation
==============

mmsrv (workstream B):

- ``userland/core/mmsrv/src/labels.rs`` — control-cap badge constants;
  ``LABEL_FORK_SET_PARTNER``, ``LABEL_STAGE_SET_SOURCE``.
- ``userland/core/mmsrv/src/client.rs`` — a dedicated per-slot ``generation``
  with bump-on-vacate; the badge codec helpers.
- ``userland/core/mmsrv/src/dispatch.rs`` — ``require_root`` / ``resolve_control``
  replacing ``require_admin``; the eight handlers take their slot from the
  resolved badge; the two-step protocol for ``FORK_VSPACE`` and
  ``STAGE_IMAGE_REGION``; mint-and-return in ``handle_register_client``.
- mmsrv boot / main loop — a **new retained ``GRANT``-bearing master-endpoint
  send role** (``init`` delivers it at boot instead of reclaiming) so mmsrv can
  mint control caps.
- ``init``: ``supervisor/state.rs`` (ROOT control cap replaces the shared
  ``mmsrv_client_mp``), ``supervisor/proc_table.rs``
  (``ProcessRecord.mmsrv_control_cap``, dropped on exit), ``supervisor/mm_ipc.rs``
  (invoke the per-client control cap; register via ROOT and capture the returned
  cap; typed ``SET_PARTNER`` wrappers for fork/stage), ``supervisor/boot_core.rs``
  (mint + hold the ROOT cap; deliver the new master-send role to mmsrv instead of
  reclaiming it), and the fork call site in ``supervisor/lifecycle/phase.rs`` (the
  two-step invoke).

VFS (workstream C):

- ``lib/trona/protocol/src/vfs/public.rs`` — add ``VFS_ADMIN_REGISTER_CLIENT``,
  ``VFS_ADMIN_CLONE_FDS``, ``VFS_ADMIN_EXEC_SWEEP``,
  ``VFS_ADMIN_CLONE_SET_PARTNER``; delete client-range ``VFS_CLONE_FDS`` and
  ``VFS_CLIENT_EXEC`` (constants too) and ``INIT_PRIV_BADGE_FROM_VFS``;
  ``lib/trona/protocol/src/posix.rs`` — delete the POSIX alias.
- ``userland/core/vfs/src/personality/posix/dispatch.rs`` — remove the
  ``VFS_CLONE_FDS`` / ``VFS_CLIENT_EXEC`` client arms.
- ``userland/core/vfs/src/ipc/dispatch.rs`` — the master-record admin path uses
  ``resolve_control`` instead of ``INIT_PRIV_BADGE_FROM_VFS``; synchronous admin
  handlers for register (mint + return), clone (two-step), exec-sweep, and the
  fire-and-forget deregister; bind adoption in ``handle_bind_client_self``.
- ``userland/core/vfs/src/owner/clients.rs`` — dedicated generation + badge
  codec; mint on ``init``-driven register; the generation bump in
  ``remove_client``; the bind-adoption lookup.
- ``userland/core/vfs/src/personality/posix/fork_clone.rs`` — **fix the OOM
  truncation** (``clone_fd_table`` must propagate a snapshot-push failure as
  ``Err(NoMem)`` rather than silently dropping fds); rework ``handle_clone_fds``
  into the admin clone handler keyed by the resolved slots; add the exec
  ``FD_CLOEXEC`` sweep handler.
- ``init``: ``supervisor/state.rs`` / ``proc_table.rs`` (VFS ROOT cap;
  ``ProcessRecord.vfs_control_cap``), ``supervisor/lifecycle/phase.rs`` (register
  child VFS client and drive the two-step clone before the child TCB resumes —
  **fail the fork on clone error**), ``supervisor/lifecycle/exec.rs`` (drive the
  exec sweep **after** ``mm_commit_exec_replace`` and before
  ``configure_and_start_tcb``, best-effort), ``supervisor/lifecycle.rs``
  (``rollback_unpublished_process`` adds a VFS deregister so a failed fork drops
  the cloned refs), ``supervisor/lifecycle/exit.rs`` (deregister via the control
  cap, fire-and-forget).
- ``init``'s ``client_id`` allocator (``supervisor/state.rs``
  ``alloc_client_id``) — skip ``client_id``\ s that collide with a live or
  pre-created client.

F5 (workstream D): remove the ``LABEL_FORK_RESULT`` handler arm in
``userland/core/init/src/supervisor/dispatch.rs`` and the
``LABEL_FORK_RESULT`` / ``INIT_FORK_RESULT`` (0x108) constant in
``userland/core/init/src/wire.rs`` and ``lib/trona/protocol/src/posix.rs`` (no
live sender or consumer; 0x108 is retired, not reused).

Per-server pure-A is structurally identical; the badge codec, ``resolve_control``,
and the two-step helper are factored to avoid divergence.

Performance
===========

``resolve_control`` is O(1) badge decode plus an active/generation check on the
arena slot — strictly cheaper than the ``find_by_client_id`` linear scan it
replaces. Mint at register is one extra ``cnode_mint`` per client (once per
process lifetime). The two-step protocol adds one round-trip to ``FORK_VSPACE``
and ``VFS_ADMIN_CLONE_FDS`` (once per ``fork``, not a hot path) and to genuine
cross-client ``STAGE_IMAGE_REGION`` (rare — exec/load staging is ``EXEC_MO_SRC``
or single-client and takes no partner step). No allocation on any admin path
beyond the transient mint slot.

Backwards Compatibility
=======================

This is an **admin-wire ABI change**, intentionally. The admin verbs drop their
trusted ``client_id`` arguments and gain control-cap authorization; the shared
admin badges are deleted; ``VFS_CLONE_FDS`` / ``VFS_CLIENT_EXEC`` (labels,
constants, and the POSIX alias) are removed. Every admin caller is ``init``
(in-tree), and the removed client labels had no live functional caller, so there
is no out-of-tree-binary compatibility surface to preserve. ``MM_BIND_CLIENT_SELF``
and ``VFS_BIND_CLIENT_SELF`` (the clients' own binds) are unchanged except for
VFS bind's adoption of a pre-created entry. The ``INIT_FORK_RESULT`` (0x108)
label is retired.

Security Considerations
=======================

**The fork mis-targeting gap is closed.** After this change neither ``mmsrv``
``FORK_VSPACE`` nor VFS clone has a ``client_id`` argument. The parent identity is
the badge of the control cap ``init`` invoked for the operate step; the child
identity is the badge of the control cap ``init`` invoked for ``SET_PARTNER``.
For ``init`` to fork P into C it must possess and invoke P's and C's control
caps — caps it holds only for processes it created. A swapped or wrong integer is
no longer expressible, and a control cap for a recycled slot fails the generation
check.

**Admin is ``init``-only by construction.** A server mints control caps only into
the reply to a ROOT-authorized ``REGISTER_CLIENT`` — i.e. only to ``init``. A
non-``init`` process never holds a control cap and so cannot invoke any
per-client admin verb; it cannot reach the surface at all. This is a smaller
trusted surface than a "supervisor gate" that must be correctly enforced on every
verb, and it removes the prior hole where a client could invoke ``VFS_CLONE_FDS``
against another process.

**Residual trust.** ``init`` holds every control cap and remains trusted to pair
the correct two caps for a legitimate fork; this is inherent to ``init`` being the
process supervisor and is identical under any model. The ROOT cap is a single
``init``-only token, but it authorizes *only* ``REGISTER_CLIENT`` — it cannot
fork, stage, or exec-replace — so it is not ambient authority over the surface.
The 43-bit generation (a dedicated counter bumped on every deregister/teardown,
not the arena's slot epoch) makes reuse-to-collision unreachable in practice.

**Exec sweep transactionality.** The exec ``FD_CLOEXEC`` sweep is deliberately
post-commit and best-effort (see *Requirements*): closing CLOEXEC fds is a
consequence of a *successful* exec, so it must run after ``mm_commit_exec_replace``
(it cannot be allowed to fail an exec that has already committed) and must not run
before commit (a later exec failure must not close fds in the surviving old
image). Fork FD-clone is the opposite — pre-commit and must fail the fork on
error — because a fork has not committed when the clone runs.

**Why pure-A over the alternatives** (see *Drawbacks* for detail): an
address-space-identity resolver (read the presented VSpace cap's kernel
``trace_id``) was considered. It is simpler today but (a) keeps a shared
supervisor token as the *authority* — it upgrades identity only — and (b)
``trace_id`` names an *address space*, not a client, so it becomes ambiguous the
moment two client identities share one address space (Linux ``vfork`` /
``CLONE_VM``, plausible under the POSIX/Linux personality). Per-client control
caps stay 1:1 in that world and give defense-in-depth once control caps are held
by more than one privileged manager (the ``cap_native_spine`` native personality
future). Because SaltyOS supports POSIX-like ``fork``, pure-A is the durable
choice.

**Out of scope — VFS credential authority.** VFS still derives several decisions
from root/default credentials rather than ``init``-stamped process credentials.
That is a separate authorization concern tracked by
``docs/rfcs/draft/principalid_access_control.rst`` and is not addressed here;
this RFC governs *who may drive admin verbs*, not *what credentials a client
acts under*.

Testing
=======

- ``just warn`` clean (x86_64 and ``just arch=aarch64 warn``); then ``just
  build``.
- ``just run`` boots to ``test_runner`` with no ``KERNEL PANIC`` and no ``init``
  abort. A clean boot exercises register / fork / exec / deregister over control
  caps for both servers end-to-end, so boot success is the primary proof the
  control-cap plumbing works. ``just run --smp 2`` must not deadlock.
- The ``test_runner`` ``fork`` module confirms a child inherits parent fds (open
  in parent, ``fork``, child reads/writes the inherited fd); ``pipe`` /
  ``signal`` / ``terminal`` depend on fork and must stay green.
- An ``FD_CLOEXEC`` fd opened before ``execve`` is gone in the exec'd image; a
  non-CLOEXEC fd survives.
- ``rg`` (excluding the unbuilt archived ``procmgr`` / ``vfs_old*`` trees)
  confirms ``VFS_CLONE_FDS`` / ``VFS_CLIENT_EXEC`` and their constants / alias are
  gone, and ``INIT_PRIV_BADGE_FROM_MMSRV`` / ``INIT_PRIV_BADGE_FROM_VFS`` no
  longer appear.

Documentation
=============

``docs/design/mmsrv.md`` and ``docs/spec/mmsrv.md`` gain the control-cap
authorization model and the per-verb list. The VFS design / spec documents gain
the admin-channel control-cap model, the new admin verbs, the removal of the
client-facing ``VFS_CLONE_FDS`` / ``VFS_CLIENT_EXEC``, and the bind-adoption rule.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Alternative — VSpace-cap ``trace_id`` resolver ("Model B").** Authorize a verb
  by a retained supervisor token and resolve the target by reading the presented
  VSpace cap's immutable kernel ``trace_id`` (``vspace_get_trace_id``). Rejected
  as the base model: it upgrades *identity* but leaves *authority* as a shared
  ambient supervisor token (it does not deliver "capability authority for the
  admin surface"), and ``trace_id`` identifies an address space, not a client, so
  it is ambiguous under shared address spaces (``vfork`` / ``CLONE_VM``). It is
  also weaker once control of admin verbs is delegated to per-personality
  managers, because VSpace caps are far more widely held than control caps.
- **Alternative — "refined-A" (control cap for the primary, ``trace_id`` for the
  secondary operand).** Removes the two-step round-trip for two-operand verbs and
  is security-equivalent to pure-A *under the current invariants*. Rejected for
  the same forward-looking reasons: the secondary's identity degrades to address
  -space identity (shared-VSpace ambiguity) and, once control caps are held by
  multiple managers, a two-operand attack needs only one leaked control cap plus
  any VSpace cap rather than two control caps. Pure-A keeps both operands 1:1 and
  preserves defense-in-depth. The two-step cost it avoids is small (concentrated
  on infrequent ``fork`` and rare cross-client stage).
- **Drawback — control-cap bookkeeping.** ``init`` holds one extra cap per process
  (the control cap, alongside the VSpace cap it already holds), the client table
  grows a ``generation`` field, and the server must retain a ``GRANT``-bearing
  master-endpoint cap to mint (a new role for mmsrv). These are the price of
  removing ambient authority; each is small and well-precedented.
- **Drawback — the two-step protocol.** Two-operand verbs carry a small stateful
  ``pending`` record (one entry, overwrite-on-SET_PARTNER, consume-once,
  generation-checked, cleared on error and on the secondary's deregister). The
  race surface is tiny (``init`` is the single, serial lifecycle driver and each
  server is a single reactor); it is the cost of pinning both operands by
  capability rather than by address-space identity.
- **Unknown / future — extending the model.** Any other server that today uses a
  shared supervisor badge can adopt the same control-cap model; this RFC
  establishes the pattern but converts only ``mmsrv`` and VFS.

Prior Art and References
========================

- **seL4** — there is no ``fork``; authority *is* holding the object capability.
  The pure-A control cap is one indirection from this: ``init`` holds a control
  cap whose badge names the client whose VSpace the server holds.
- **Zircon** — every per-object operation requires presenting a *handle* to that
  object; the kernel resolves handle to object and checks rights. The per-client
  control cap is the direct analogue: invoking it resolves badge to client and the
  possession is the authorization. Zircon also avoids cross-process address-space
  sharing and uses handles, the same lineage this RFC follows.
- ``cap_native_spine`` (draft) — the SaltyOS-native personality and object spine;
  the multi-privileged-manager future that motivates per-client (not ambient)
  admin authority.
- ``principalid_access_control`` (draft) — the neutral credential / AccessControl
  model; owns the VFS credential authority left out of scope here.
- RFC-0006 (``execve_caller_memory_object``) — the exec memory-object protocol
  this builds on for the exec ``FD_CLOEXEC`` sweep verb.
