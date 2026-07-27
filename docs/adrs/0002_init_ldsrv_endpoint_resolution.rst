===================================================================
ADR-0002: Init owns ldsrv endpoint via namesrv, bypassing cap-table
===================================================================

:Status: Implemented
:Areas: libtrona runtime client surface (``client::ldsrv``,
  ``client::lazy_resolve``); init supervisor (``state.rs``,
  ``loader/code_mo.rs``)
:Authors: Hamin Sung
:Reviewers: MiniMax M3
:Date: 2026-06-28
:Supersedes: none
:Depends: ``docs/rfcs/0009_capability_bounded_wx.rst`` (the code-loading
  authority / ldsrv), ``kernite/include/uapi/startup.h``
  (``SALTYOS_CAP_ROLE_LDSRV_CLIENT``, ``SALTYOS_CAP_ROLE_NAMESRV_CLIENT``),
  ``lib/trona/runtime/src/spawn/cap_table.rs`` (``install_well_known_caps``),
  ``kernite/src/init.rs`` (``setup_init_cspace``,
  ``compose_init_startup_stack``).
:Description: PID 1 must not rely on the runtime weak-symbol lazy-resolve path
  for the ldsrv endpoint. Namesrv and ldsrv do not exist at init's startup, so
  ``ROLE_NAMESRV_CLIENT`` and ``ROLE_LDSRV_CLIENT`` cannot be installed into
  init's startup cap-table by the kernel; init owns ``ldsrv_client_ep``
  directly in ``SupervisorState``, looked up lazily on first post-handoff
  library resolution via ``NAMESRV_LOOKUP("ldsrv")`` against
  ``state.caps.namesrv_client_mp``. ``client::ldsrv::resolve_library`` is
  split into a thin lazy-resolve wrapper + a public ``resolve_library_at``
  IPC body that init (and any other supervisor-grade caller that already
  holds the EP) can drive directly.

Context
=======

RFC-0009 makes ``ldsrv`` the steady-state code-loading authority and the
sole ``EXECUTE``-conferring principal after the Stage-1 handoff. PID 1
spawns ``ldsrv`` and resolves program libraries through it via
``get_code_mo(CodeSource::Library { name, .. })``
(``userland/core/init/src/supervisor/loader/code_mo.rs:73``), which calls
``trona_runtime::client::ldsrv::resolve_library(name)``.

For every normal process this works because:

- the spawner installs ``ROLE_LDSRV_CLIENT`` into the child's startup
  cap-table (``lib/trona/runtime/src/spawn/cap_table.rs:446`` →
  ``system_role_target`` arm at line 446);
- ``install_well_known_caps`` (``cap_table.rs:346``) writes the slot
  number into ``__trona_cap_ldsrv_ep``;
- ``client::caps::ldsrv_ep()`` (``caps.rs:54``) reads the weak symbol;
  if zero, the lazy-resolve helper
  (``client/lazy_resolve.rs::resolve_simple``) issues
  ``NAMESRV_LOOKUP("ldsrv")`` against ``__trona_cap_namesrv_ep``, also
  populated via the same cap-table path.

PID 1 is the supervisor. The kernel populates its cap-table in
``kernite/src/init.rs::compose_init_startup_stack`` (``init.rs:500-533``),
which only installs roles the corresponding service for exists *at* init's
startup — ``ROLE_KERNEL_RNG``, ``ROLE_CLOCK``, ``ROLE_SYSTEM_CONTROL``,
``ROLE_SYSTEM_INFO``, ``ROLE_KERNEL_DEBUG``, ``ROLE_INITRD_UNTYPED``,
``ROLE_FB_UNTYPED``, ``ROLE_PCI_IOPORT``, ``ROLE_COM1_IOPORT``,
``ROLE_COM1_IRQ``, ``ROLE_KBD_IOPORT``/``_IRQ`` (x86_64), and
``ROLE_DEVICE_CONTROL``. The kernel-side ``setup_init_cspace``
(``init.rs:638-900``) installs the runtime object caps, and likewise
deliberately omits service EPs for namesrv / ldsrv / vfs / rsrcsrv /
mmsrv / console / log / netsrv / win32srv — none of those services exist
at init's startup. ``ROLE_NAMESRV_CLIENT`` and ``ROLE_LDSRV_CLIENT`` are
therefore *never* installed for init, and both weak symbols stay
permanently zero.

Init's own spawn of namesrv works (init holds the freshly-rettyped master
MP send under ``state.caps.namesrv_client_mp``,
``userland/core/init/src/supervisor/state.rs:84``, and uses it directly),
so the bootstrap reachability of namesrv is unaffected. The break is at
the *post-handoff library resolution* step: ``client::caps::ldsrv_ep()``
is invoked from a context where ``__trona_cap_namesrv_ep`` is 0, the
lazy-resolve path returns ``None`` before issuing any IPC, and
``resolve_library`` returns ``KERNITE_ERR_NOT_FOUND`` from the client
side. ldsrv's reactor, the adopt set, and the cache are all healthy —
no request ever reaches them.

Symptom (logged on the failing boot)
------------------------------------

::

    [INIT] spawning logsrv
    [MMSRV] client registered id=0x7 pid=6 ...
    [LDSRV-CLIENT] resolve_library name=ldtrona-elf.so ep=0x0
    [INIT] spawn logsrv failed phase=stage err=0x6

The diagnostic line is the tell: ``ep=0x0`` is the *client-side* cap, read
from ``__trona_cap_ldsrv_ep`` before any IPC is staged. ldsrv's own
``[LDSRV] adopt name=`` / ``[LDSRV] resolve_library req`` log lines never
appear because nothing reaches the server. The adopted set is complete
(25 objects, 5 libs); the kernel's adopt-phase IPC works fine.

Decision
========

Two coupled changes plus a small cleanup:

1. **``client::ldsrv::resolve_library`` split into a thin wrapper and
   a public ``resolve_library_at`` IPC body**
   (``lib/trona/runtime/src/client/ldsrv.rs:151``). The lazy-resolve
   wrapper ``resolve_library(soname)`` keeps its existing observable
   behaviour for every non-init process: read ``ldsrv_ep()`` (which
   triggers ``NAMESRV_LOOKUP`` lazy resolve on first call), then call
   ``resolve_library_at(ep, soname)``. ``resolve_library_at(ldsrv_ep,
   soname)`` carries the previously-inlined IPC body — message
   construction, send-cap staging, ``call_resolve`` plumbing, and the
   ``TRONA_OK`` / reply-label error mapping — and accepts the endpoint
   address as a parameter. No wire-format change. No behaviour change
   for processes whose cap-table path works.

2. **Init owns ``ldsrv_client_ep`` directly in ``SupervisorState``**
   (``userland/core/init/src/supervisor/state.rs:91-99``, field added
   next to ``namesrv_master_mp_send_raw``; zeroed at
   ``state.rs:211``). The post-handoff library branch in
   ``code_mo.rs:77-93`` swaps its ``client::ldsrv::resolve_library``
   call for ``init_ldsrv_client_ep(state)?`` followed by
   ``resolve_library_at(cached, name)``. ``init_ldsrv_client_ep``
   (``code_mo.rs:108-163``) is a one-shot lazy cache:

   - hit: return the slot address of the cached cap;
   - miss: issue ``NAMESRV_LOOKUP("ldsrv")`` against
     ``state.caps.namesrv_client_mp`` (init's authoritative namesrv EP,
     not the weak symbol), receive the per-caller ldsrv client-EP cap
     into a fresh slot, store it as ``state.caps.ldsrv_client_ep``, and
     return its slot address. The receive slot is armed via
     ``ipc_ext::set_receive_slot_ctx`` to ``(SELF_CSPACE, dest, 0)``
     and the cap is admitted through ``OwnedSlot::assume_filled`` —
     exactly the same shape as ``client/lazy_resolve.rs::resolve_simple``
     for non-init callers, but driven from init's authoritative
     ``state.caps`` rather than from a weak symbol.

   The NAMESRV_LOOKUP wire layout is packed by a small private helper
   ``pack_name_lookup`` (``code_mo.rs:169-184``) — byte length at
   ``regs[0]``, name bytes 8-per-word starting at ``regs[1]`` — which
   matches ``userland/core/namesrv/src/wire.rs::NAMESRV_LOOKUP` and
   the existing ``lazy_resolve::pack_name_into_msg``.

3. **Cleanup: delete the dead ``LAZY_RESOLVE_ROLES`` constant**
   (``lib/trona/runtime/src/client/lazy_resolve.rs:42-48`` before). The
   constant was unreferenced — the actual fork-after-re-resolution
   reaper is ``reset_lazy_caps_for_fork`` (``lazy_resolve.rs:240``),
   which independently zeroes every lazy-resolved weak symbol,
   including ``__trona_cap_ldsrv_ep`` (line 245). The constant
   duplicated a subset of that list and risked misleading future
   maintainers into thinking ``ROLE_LDSRV_CLIENT`` was *not* lazy —
   the *behavior* was correct (it is lazy, and reset on fork), only
   the documentation was wrong.

Consequences
============

Positive
--------

- **Init's post-handoff library resolution works.** Spawned services
  whose PT_INTERP is ``/lib/ldtrona-elf.so`` (i.e. every dynamically
  linked service) reach the ``CodeSource::Library`` arm, hit
  ``init_ldsrv_client_ep`` on first call, cache the ldsrv client EP,
  and resolve every adopted library through ``resolve_library_at``.
  No weak-symbol path is consulted.
- **General-process API is unchanged.** ``resolve_library(soname)``
  keeps the lazy-resolve contract for every non-init process; no
  caller needs to know about ``resolve_library_at`` unless it already
  holds the EP (which, today, only init does).
- **Wire format and IPC body are factored, not duplicated.** Init
  imports ``resolve_library_at`` from the libtrona client surface and
  reuses its ``call_resolve`` plumbing; no parallel IPC packet
  builder in init. A protocol change in the resolve message layout
  touches exactly one place.
- **Architectural clarity.** PID 1 is the supervisor; the ADR
  documents the rule explicitly — *supervisor-grade callers that
  already hold the EP drive ``resolve_library_at`` directly; cap-table
  consumers keep using ``resolve_library``*. Future supervisor-grade
  callers (e.g. a hypothetical exec-from-init path that needed to
  pre-stage libraries before passing control to a child) follow the
  same pattern.

Negative
--------

- **One new private helper in init.** ``init_ldsrv_client_ep`` plus its
  ``pack_name_lookup`` companion are init-only; both are short, but
  they are a small surface. The alternative (a public
  ``client::namesrv::lookup`` for supervisor use) would have been
  heavier and would have leaked the lazy-cache pattern into libtrona.
- **The cap-table path remains structurally dead for init.** This is
  intentional: PID 1 cannot receive ``ROLE_LDSRV_CLIENT`` from a
  cap-table that namesrv/ldsrv must pre-populate. The dead path is a
  documented invariant, not a latent bug.

Neutral
-------

- **LAZY_RESOLVE_ROLES deletion is mechanical.** No runtime behaviour
  change; the existing ``reset_lazy_caps_for_fork`` already does the
  work.
- **Per-process resolver duplication.** Init's ``pack_name_lookup``
  is local. The same layout is also implemented in
  ``lazy_resolve::pack_name_into_msg``; this is not worth factoring
  further because the two callers differ in their receive-slot
  lifetime handling and the duplication is twelve lines.

Rejected alternatives
=====================

- **Populate ``__trona_cap_namesrv_ep`` directly from init's runtime
  code by writing the slot of ``state.caps.namesrv_client_mp`` into
  the weak symbol after the spawn of namesrv.** Functionally works:
  ``caps::namesrv_ep()`` returns the slot, lazy resolve of ldsrv then
  succeeds. Rejected because it conflates two roles of the weak
  symbols — they are contractually populated from the cap-table at
  startup, not from process code at runtime — and because every other
  lazy-resolved cap that init might need in the future (vfs, console,
  …) would have to repeat the same bypass. Init is a supervisor; the
  supervisor owns its state explicitly.

- **Have the kernel pre-install a *placeholder* ``ROLE_NAMESRV_CLIENT``
  entry pointing at init's own namesrv client MP.** Functionally
  works, but the kernel does not know init's slot layout (init retype's
  its namesrv master MP itself, post-boot, in
  ``compose_init_startup_stack``'s caller). Requires moving the namesrv
  master MP retype into the kernel's ``setup_init_cspace``, which is a
  much larger architectural change with no payoff.

- **Refactor ldsrv to have a per-process *init* cap-table and install
  the ``ROLE_LDSRV_CLIENT`` entry there in addition to the normal
  spawn-time cap-table.** Massive blast radius for a problem that
  has a clean local solution.

- **Block init from issuing post-handoff ``CodeSource::Library`` and
  fall back to ``resolve_main`` for libraries too.** Conflates the two
  seams: ``resolve_main`` confers EXECUTE on a *caller-supplied*
  backing, while ``resolve_library`` resolves a soname against ldsrv's
  content-addressed cache. Forcing all library resolution through
  ``resolve_main`` discards the cache and the dedup behaviour
  (``CodeObject::Identity::of_bytes`` matches adopted MOs) and
  duplicates the wire-format path. Rejected as a regression in
  functionality.

Implementation
==============

- ``lib/trona/runtime/src/client/ldsrv.rs``

  - split ``resolve_library`` into ``resolve_library`` (thin
    ``ldsrv_ep()`` → ``resolve_library_at`` wrapper, line 175) +
    ``resolve_library_at(ldsrv_ep, soname)`` (IPC body, line 151);
  - removed the three diagnostic ``crate::uinfo!`` lines added during
    the boot investigation.

- ``lib/trona/runtime/src/client/lazy_resolve.rs``

  - deleted the dead ``LAZY_RESOLVE_ROLES`` constant (was at lines
    42-48) and the now-unused
    ``use crate::spawn::role_consts::{ROLE_CONSOLE_CLIENT, ...}``
    import that fed it.

- ``userland/core/init/src/supervisor/state.rs``

  - added ``pub ldsrv_client_ep: Option<OwnedCap>`` field to
    ``StartupCaps`` (line 91-99), documenting the supervisor
    exception inline;
  - zeroed in ``StartupCaps::zeroed`` (line 211).

- ``userland/core/init/src/supervisor/loader/code_mo.rs``

  - rewrote the ``CodeSource::Library`` arm to call
    ``init_ldsrv_client_ep(state)?`` + ``resolve_library_at(ep, name)``
    (lines 77-93), with a comment that explains the architectural
    rule;
  - added private ``init_ldsrv_client_ep`` helper (lines 108-163) and
    ``pack_name_lookup`` (lines 169-184);
  - removed the pre-handoff ``Library`` path comment that referenced
    the lazy resolver; the post-handoff comment now references
    ``resolve_library_at`` instead.

Verification
============

- ``just build``: clean rebuild with the new
  ``resolve_library_at`` public surface.
- ``just fmt-check``: rustfmt clean; the libtrona runtime and the init
  supervisor both pass their per-crate lint and layering checks.
- ``just run --headless --smp 2``: full boot now reaches all services —
  ``[INIT] spawn logsrv`` succeeds (was returning ``err=0x6``),
  logsrv registers with mmsrv, and the dispatch graph continues past
  the previously-fatal point. ``[LDSRV-CLIENT]`` diagnostic lines
  (added and then removed during investigation) are gone; the
  per-process serial output matches the pre-bug baseline plus the
  post-ADR-0001 code path.
- Cross-arch smoke: same fix is arch-agnostic (no kernel or arch
  code touched); aarch64 UEFI boot was not re-run for this ADR but
  the change set is purely userland + libtrona.
