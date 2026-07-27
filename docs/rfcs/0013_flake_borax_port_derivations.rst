============================================================================================
RFC-0013: The flake Build System, borax Configuration, and Pure-Functional .port Derivations
============================================================================================

:Status: Accepted
:Areas: build system; configuration; ports; image assembly; toolchain;
  self-hosting
:Authors: Hamin Sung
:Reviewers: GLM 5.2, GPT 5.5
:Date: 2026-06-30
:Depends: none
:Supersedes: the meson + ninja + just build orchestration (does not supersede
  ninja itself, which is retained)
:Description: Replace meson and just with a self-built build system.
  ``flake`` (Rust, evolving from ``tools/port``) is a Nix-style pure-functional
  build engine: it models every artifact as a content-addressed derivation,
  builds in sandboxes, keeps a persistent content-addressed store with signed
  binary substitution, and projects selected closures onto an FHS rootfs at
  image time. ``borax`` (Rust) is a configuration system of Linux-Kconfig
  *class* (full ``select`` / ``depends`` / ``choice`` / ``menu`` capability)
  in a custom TOML format, with deliberate, documented deviations from Linux
  Kconfig semantics. ``.port`` recipe files become pure-functional
  derivations; the ``.port`` extension is retained. ninja is retained as the
  fine-grained compile DAG executor. The Python image and format tools
  (mkcpio/mkimage/mksaltyfs/mkrootfs/mksysroot) are absorbed into ``flake`` as
  compiled Rust, removing Python from the OS image/build path.

Summary
=======

The build is meson + ninja, wrapped by just. meson earns almost none of its
keep: 100% of targets are ``custom_target`` (zero native ``executable()`` /
``shared_library()`` rules anywhere), so meson is used purely as a ninja
generator and option store. just then re-implements meson's job in a large
share of its recipes (target filtering via ``meson introspect | python3``,
hand-written ``toolchain.ini``, multi-arch ``bootstrap`` orchestration,
hard-coded ``build-x86_64`` paths). Configuration is coarse (a handful of
options, mostly ``build_*`` booleans) with zero feature gating, and meson's
option model cannot express Kconfig-style ``select`` / ``depends``. Finally,
the OS image/build path depends on a Python runtime (``mkcpio.py``,
``mkimage.py``, ``mksaltyfs.py``, ``mkrootfs``, ``mksysroot``) — a liability no
serious OS build system carries.

This RFC replaces that stack with three owned components plus a retained
executor:

- **borax** — a configuration system of Linux-Kconfig *class* (full
  ``select`` / ``depends`` / ``choice`` / ``menu`` capability), custom TOML,
  new name.
- **flake** — the build system: a Nix-style pure-functional derivation engine
  (Rust, grown from ``tools/port``) that absorbs the Python tools and owns
  image assembly.
- **.port** — pure-functional derivation recipes (extension retained).
- **ninja** — retained as the fine-grained compile DAG executor.

Problem Statement
=================

1. **meson provides no value but full cost.** Every target is a
   ``custom_target``; sysroot assembly is even done out-of-band by a Python
   ``mksysroot``.
2. **The just/meson layering is structurally broken.** No contract between
   just and meson; a large share of just recipes do work that conceptually
   belongs to the build system.
3. **Configuration cannot express features.** A few coarse options; all
   userland ``subdir()`` calls are unconditional; the program list is
   hard-coded. meson options cannot model ``select`` / ``depends`` / ``choice``.
4. **The image/build path depends on a Python runtime.** Five Python tools sit
   on it. No comparable OS requires an interpreter as a build-system runtime;
   the two that do (Gentoo Portage = Python, Guix = Guile) are criticized for
   exactly that.
5. **Self-hosting is impeded.** Bootstrapping SaltyOS on SaltyOS currently
   drags meson (Python) and the Python image tools onto the target.

Goals
=====

- Own the build description, configuration, and orchestration as compiled Rust.
- A configuration system with full Linux-Kconfig-class semantics (``select``,
  ``depends``, ``choice``, ``menu``) in a custom TOML format.
- A Nix-style pure-functional build model: every artifact is a derivation with
  a cryptographic content-addressed identity, built in a sandbox, living in a
  persistent content-addressed store with signed binary substitution.
- Runtime compatibility preserved: the runtime rootfs remains FHS (POSIX/Win32
  subsystems and basaltc/trona assume it), produced by projecting selected
  store closures onto an FHS layout, carrying over the existing overlay
  provenance / pkg-config rewrite / dev-file filter / ``__base__`` / perms /
  symlink / ``/etc`` machinery.
- Remove Python from the **OS image/build** path; the Python port remains an
  end-user program only.
- Retain ninja's proven incremental execution for the fine-grained compile DAG.
- Reduce, not eliminate, the toolchain-runtime weight on the path to
  self-hosting.

Non-Goals
=========

- A pure-store runtime (NixOS-style). The runtime stays FHS-projected; going
  pure-store would require rewriting path assumptions across the whole OS and
  is out of scope (see Alternatives).
- Byte-compatibility with Linux ``.config`` or the Nix CLI / ``.nix`` language.
- Replacing upstream build systems. Building bash still runs bash's configure;
  purity is about *our* build system's runtime and recipe model, not about
  avoiding ``configure`` / ``make`` / ``cmake``.
- Bootstrapping the **compilers** without Python. Building rustc itself still
  drives ``x.py`` via ``python3`` (``tools/toolchain/build.sh``) until upstream
  rustc drops that; this RFC's "no Python" claim is scoped to the OS
  image/build path, not the toolchain bootstrap.

Scope note — "self-hosting" and "upstream compilers"
====================================================

Two claims that are easy to overstate, stated precisely here:

- **Self-hosting** in this RFC means "rebuild SaltyOS from source on SaltyOS
  using already-built compilers." It does **not** mean "bootstrap the
  compilers on SaltyOS," which still needs Python (``x.py``) for rustc.
- **Compilers** means the **patched SaltyOS toolchain** — rustc/clang that
  know the ``x86_64-unknown-saltyos`` / ``aarch64-unknown-saltyos`` targets
  (``meson.build`` target check). Stock upstream compilers are **not**
  sufficient; upstreaming target support is out of scope.

Prior Art
=========

The decisive axis across source-based package/build systems is **recipe =
script vs recipe = data**, and **what runtime must exist on the build host**.

- **Nix** (``.nix``): recipes are pure functions (data); outputs are
  content-addressed in ``/nix/store/<hash>-name``; builds are sandboxed;
  substitution (binary cache) is first-class. The extreme of "minimize script
  dependence." flake adopts this model.
- **Arch (PKGBUILD/makepkg)**, **Gentoo (ebuild/Portage)**, **FreeBSD ports
  (Makefile + bsd.port.mk)**: recipes are bash/make scripts that run on the
  host as build logic, not as a target runtime dependency. Gentoo's signature
  is global ``USE`` flags; FreeBSD's is per-package options. SaltyOS's current
  ``.port`` is closest to this family (declarative INI with imperative
  ``[prepare]`` / ``[stage]`` shards).
- **GN + ninja** (Fuchsia, Chromium): a compiled generator emits
  ``build.ninja``; ninja executes. flake retains this shape for the compile DAG.
- **kbuild / kconfig** (Linux): a C kconfig + make; the kernel has
  historically *reduced* build dependencies (removed perl). borax is the
  kconfig analogue.

The two systems that depend on an interpreter (Portage = Python, Guix =
Guile) are the criticized outliers. flake does not follow them for the OS
image/build path.

Design Overview
===============

::

    borax  ──config──►  flake  ──derivation graph + ninja emit──►  ninja
                          │                                            │
                          │  content-addressed store (crypto hash)     │  fine-grained
                          │  sandboxed builds (full dimension set)     │  compile DAG
                          │  signed binary substitution                │
                          ▼
                       .port  (pure-functional recipes; extension retained)

- **borax** resolves a config graph (option definitions + a user override)
  into typed values and emits ``config.rs`` / ``config.h`` / cfg-flags / a
  feature manifest.
- **flake** reads ``.port`` derivation recipes + borax config + build specs,
  builds the derivation DAG, realizes each derivation in a sandbox (a
  derivation's builder may emit and run a ``build.ninja`` for fine-grained
  compile work), stores outputs in a content-addressed store, and projects
  selected closures onto an FHS rootfs for the disk image.
- **ninja** is the executor for fine-grained compilation within (or alongside)
  derivations.

borax — Configuration System
============================

A configuration system of **Linux-Kconfig *class*** (full ``select`` /
``depends`` / ``choice`` / ``menu`` capability) in a custom TOML format, with
**deliberate, documented deviations** from Linux Kconfig semantics. It is not
a reimplementation of Linux Kconfig.

Option-graph (developer-authored, one file per subsystem)
---------------------------------------------------------

.. code-block:: toml

    [option.NET]
    type       = "bool"
    default    = true
    select     = ["NETDRV"]        # force-on
    depends_on = "BUILD_USERLAND"  # gate visibility / set-ability
    help       = "Enable the networking stack"

    [choice.console_backend]
    title   = "Console backend"
    default = "CONSOLE_FB"         # exactly one member on
      [choice.console_backend.option.CONSOLE_SERIAL]
      [choice.console_backend.option.CONSOLE_FB]

    [option.MAX_CPUS]
    type = "int"; default = 16; min = 1; max = 256

``type`` ∈ {bool, string, int, choice-member}. ``tristate`` is accepted but
resolves to bool (SaltyOS has no module state today). ``default`` may be a
guard expression ``"X if COND else Y"``.

Semantic contract (the deviations are deliberate)
-------------------------------------------------

borax is fully specified, not loosely "Kconfig-like":

- **Expression grammar** for ``depends_on`` / guards: option-name atoms, the
  operators ``&& || !``, and ``=`` / ``!=`` / ``>=`` / ``<`` comparisons (the
  same version-comparison rules the port tool already implements).
- **Default precedence:** explicit user override > ``default`` (with guard) >
  "off" for hidden options. Defaults evaluate *after* visibility resolves.
- **Visibility:** an option whose ``depends_on`` is false is hidden and fixed
  to its off value; the user cannot set it (an override on a hidden option is
  a hard error).
- **Reverse dependencies (``select``):** evaluated to a fixpoint after user
  overrides. ``select`` forces a target on. **Deviation:** if a select target
  is hidden (its ``depends_on`` unsatisfied) or a select would force two
  members of an active ``choice`` on, borax emits a **hard error** naming the
  offending select chain — not Linux Kconfig's silent warning. SaltyOS is
  small enough to fail loud.
- **Select cycles:** detected and rejected as a hard error.
- **Choice rules:** exactly one member on; if a user overrides the default
  member off without selecting another, the choice default is restored with a
  warning.
- **Generated-output stability:** ``config.rs`` / ``config.h`` / cfg-flags /
  feature-manifest are deterministic given the same resolved config (sorted
  output, no timestamps), so they are themselves content-addressable inputs
  to derivations.
- **Diagnostics:** every hard error names the option(s), the file, and the
  rule violated. ``borax validate`` is a CI gate; ``borax migrate-options``
  reads ``meson.options`` to seed the starter graph (1:1 cross-check).

flake — Build System
====================

A Nix-style pure-functional derivation engine in Rust, grown from
``tools/port`` (reusing its ``parser.rs`` / ``config.rs`` / ``deps.rs`` /
``version.rs`` cores in-crate; the current ``stamps.rs`` ``DefaultHasher``
machinery is **not** inherited — see Hash model).

Derivation model
----------------

Every artifact — ``kernite.elf``, each userland ELF, each port, each image — is
a **derivation**: a pure function of declared inputs (sources, dependency
outputs, config, builder-tool identity) producing one store output. Realizing
a derivation runs its builder in a sandbox with only declared inputs visible.

Derivation hash model (design decision, load-bearing)
-----------------------------------------------------

Store path identity, cache lookup, output references, rebuild invalidation,
and substitution safety all derive from this — so it is a decision, not a
deferred detail:

- The store path is a **cryptographic hash** (SHA-256) of the derivation's
  fully-resolved input set (source hashes + dep output hashes + config hash +
  builder-tool identity + declared env + arch). The current port
  ``DefaultHasher`` phase stamps (``tools/port/stamps.rs``) are explicitly
  **not** the basis — they hash only partial phase inputs and are not
  cryptographic.
- **Base choice: input-addressed** (the classic Nix model). The store path is
  determined before building; references between derivations are stable.
- **Remaining sub-decision (named, bounded):** whether to additionally support
  **floating content-addressed** outputs (hash-of-output) for trustworthy
  cross-machine sharing and deduplication. This is deferred to the Phase-4
  store design because it interacts with self-referential outputs (binaries
  embedding their own store path); the default remains input-addressed until
  then.

Purity contract (declared inputs or denied)
-------------------------------------------

A derivation is pure only if *everything* that affects its output is a
declared input or explicitly denied. The current ports are **not** pure today
(they call ambient ``sh -c`` / ``curl`` / ``tar`` / ``patch`` / ``autoreconf``
/ ``make`` / ``cmake`` / ``cargo update``), so flake must declare or deny:

- **Builder tools** (clang/make/cmake/nasm/bindgen/cargo/autotools) as
  identity-hashed inputs (the patched toolchain's own derivation hash).
- **Environment** (env vars, ``PATH``, ``HOME``, locale) — declared or reset to
  a known minimum.
- **Clock** — fixed (``SOURCE_DATE_EPOCH``); **randomness** — seeded or denied.
- **Network** — denied after the fixed-output fetch step.
- **Filesystem** — sandbox VFS seeing only declared input store paths + a
  private temp/output dir; no host ``/usr``.
- **IPC / process spawn** — restricted to declared builder invocations.

A derivation that reaches an undeclared input fails the build (sandbox
violation), not silently succeeds.

Store
-----

Persistent, content-addressed (``.salty-store/<hash>-<name>/``), surviving
across builds. Multiple versions coexist. A derivation whose inputs are
unchanged is reused, not rebuilt. GC policy (store bounding, LRU/refcount) is
an open detail; the model is GC-able from day one.

Binary substitution (binary cache) — a threat-model concern, not just ops
------------------------------------------------------------------------

Outputs are fetchable by hash from a signed binary cache (substituter); CI
publishes, local builds substitute-then-build. For an OS build this is a
trust surface, so the design specifies:

- **Signatures:** store outputs are signed; clients verify against a trusted
  key set before substitution.
- **Hash coverage:** the substituted hash must cover the *full* input set
  (sources + deps + config + patched-toolchain identity + arch), so a
  substitution is only accepted when the requester's resolved derivation is
  bit-identical to the cached one.
- **Metadata:** the cache records toolchain identity, borax config identity,
  and arch alongside each output, and the client rejects mismatches.
- **Rejection rules:** unsigned, wrong-key, or hash-mismatch outputs are
  refused and the derivation is built locally. (Hosting location — CI artifact
  store vs dedicated cache — remains an ops decision.)

Image assembly (Python tools absorbed)
--------------------------------------

The Python format/image writers become compiled Rust modules of flake:

- **mkcpio → flake cpio**, **mkimage → flake image** (MBR/GPT/ESP/FAT32),
  **mksaltyfs → flake saltyfs** (shares the SaltyFS format with the ``saltyfs``
  server — core OS infra, not a script), **mkrootfs → flake rootfs** (closure →
  FHS projection), **mksysroot → flake sysroot** (base-lib collection).

Each is parity-checkable on **normalized structure**, not raw bytes — see
Determinism.

Determinism (parity prerequisite)
---------------------------------

Current outputs are non-deterministic and must be fixed before byte-parity is
meaningful: ``mksaltyfs.py`` embeds the current time and random UUIDs;
``mkimage.py`` uses random GPT/partition UUIDs. flake's rewrites pin these
(``SOURCE_DATE_EPOCH`` for timestamps, a derivation-derived seed for UUIDs, or
content-derived UUIDs). Until both Python and Rust paths are deterministic,
parity compares **normalized structures** (parsed layouts with volatile fields
zeroed), not raw ``sha256sum``. Making the Python path deterministic first is
a prerequisite for the Phase-4 parity gate.

Bootstrapping
-------------

- **During migration:** meson builds ``flake`` exactly as it builds ``port``
  today (single-file crate: ``rustc --edition=2024 -o flake main.rs`` +
  ``depend_files`` of sibling modules — the ``tools/port/meson.build`` pattern).
- **After meson retirement:** ``flake`` self-bootstraps via a checked-in frozen
  ``tools/flake/bootstrap.ninja`` (~15 lines). ``ninja -f bootstrap.ninja``
  builds ``flake``; that ``flake`` then realizes the whole tree (including
  itself, as a derivation in its own graph). A CI step (``flake gen
  --selfcheck``) regenerates the frozen ninja and ``git diff --exit-code``
  catches drift. No checked-in binary blob, no Cargo.

.port — Pure-Functional Derivations
===================================

The ``.port`` extension is retained; the content becomes a pure-functional
derivation recipe — **data**, not a script: declared inputs (source URL +
**mandatory** fixed-output hash, dependency outputs, build type, configure
flags, install manifest), a chosen builder strategy, and outputs.

- **Fixed-output source hashes are mandatory.** The current ``sha256 = SKIP``
  escape hatch (e.g. ``ports/bash/bash.port``) is rejected: a
  binary-substitutable derivation cannot have an unverified source. Ports
  lacking a hash must add one (or become a fixed-output derivation with a
  declared builder-hash).
- **Declarative ``[install]`` manifest** (``usr/bin/bash = { from = …, mode =
  … }``) replaces the imperative ``[stage]`` shell. Built-in builder
  strategies (autotools/cmake/meson/make/cargo make-install) cover the common
  case with **zero custom script**.
- **Shell snippets survive only as a sandboxed exception** where an upstream
  genuinely requires an imperative step. Such snippets are themselves hashed
  inputs to the derivation (so changing a snippet changes the output identity)
  and run under the full purity contract above; they are auditable and few.

Two-Layer Execution (ninja + derivation engine)
===============================================

- **Coarse layer:** the derivation graph (one derivation per final artifact),
  scheduled by flake's engine; sandboxed; stored; cacheable.
- **Fine layer:** within a derivation's builder, the compile DAG runs via
  ninja. **Granularity caveat:** Rust compiles one crate per ``rustc``
  invocation (no module-level object DAG ninja owns), so Rust dev increment is
  *crate-granular*, not ``.o``-granular; C/asm objects are finer-grained.

ninja is retained because reimplementing correct incremental rebuilds is the
classic build-system tar pit. A derivation's builder may emit a
``build.ninja`` and run it inside its sandbox.

Dev mode (open design point)
----------------------------

Pure derivation realization is too coarse for fast edit-rebuild loops
(editing one ``.rs`` should not re-realize the whole kernite derivation
through the store). flake provides a **dev mode**: the compile DAG runs via
ninja directly against the source tree (no store round-trip), giving
crate-level (Rust) / object-level (C/asm) incrementality. Release/CI mode goes
through derivations + store for purity and cache. The exact dev/release split
(reproducibility guarantees in dev mode, how dev artifacts relate to store
identity) is a Phase-2/3 design point.

Build Sandboxing (full dimension set)
=====================================

Nix purity requires the build to see only declared inputs. A restricted VSpace
is one piece; the full set flake must control:

- **Process spawning** (only declared builder invocations), **VFS namespace**
  (only declared input store paths + private temp/output), **clock**
  (``SOURCE_DATE_EPOCH``), **randomness** (seeded/denied), **network** (denied
  after fetch), **IPC** (denied), **host-tool execution policy**.

- **On SaltyOS:** the kernel capability model is the natural sandbox primitive
  (a build process gets a cap-restricted VSpace + a VFS namespace built from
  declared store paths). Relevant to RFC-0009 (capability-bounded W^X).
- **On Linux dev hosts:** namespace/``chroot`` sandboxing.
- **On macOS dev hosts:** a restricted VSpace is not available; flake falls
  back to a **declared-inputs auditing mode** (it *checks* that the build did
  not touch undeclared inputs after the fact, rather than preventing it). This
  is labeled an **auditing fallback, not a sandbox**, matching Nix's macOS
  limitation; CI runs on a true sandbox (Linux/SaltyOS).

FHS Projection (Runtime Rootfs)
===============================

The runtime rootfs stays FHS. flake's rootfs step resolves the runtime closure
of each selected package (transitive store paths) and projects it onto an FHS
layout, **carrying over the entire existing rootfs/sysroot machinery** so
behavior is preserved:

- overlay **provenance** (per-owner file tracking) and **conflict detection**
  (two packages claiming one FHS path = hard error);
- the **``__base__``** provenance from ``mksysroot`` (stub archives, base
  libs) so package projections cannot collide with base entries;
- **pkg-config ``prefix=`` rewrite** on projected ``.pc`` files;
- the **dev-file filter** (``usr/include/**``, ``*.a``, ``pkgconfig/**`` …)
  applied to the runtime projection;
- **permissions, symlinks, empty FHS dirs** (``/dev``, ``/proc``, ``/tmp``,
  …), and ``/etc`` templates from ``images/``.

The result is a conventional FHS ``rootfs.img`` / ``disk_image.img``,
structurally comparable to today's output. Purity lives at **build** time;
compatibility lives at **runtime**.

Self-Hosting Implications
=========================

After this RFC, **rebuilding** SaltyOS on SaltyOS needs ``flake`` (Rust), ninja
(C++), and the **patched** SaltyOS toolchain (rustc/clang with the
``*-unknown-saltyos`` targets). **No Python in the OS image/build path.** The
Python port is an end-user program, not a build dependency. Bootstrapping the
*compilers* still needs Python (``x.py``) and remains a separate concern.

Rollout / Migration
===================

1. **borax, standalone, consumed by meson now.** Emit config.rs/config.h/
   cfg-flags/feature-manifest; meson consumes them. Parity: ``just build``
   output and target list unchanged.
2. **flake derivation engine + store, proven on one artifact** (e.g. the uapi
   bindgen derivation). Parity: ``sha256sum`` of ``uapi.rs`` and the recompiled
   ``.rmeta`` byte-identical to meson's (this artifact is already
   deterministic).
3. **Migrate subsystems** (uapi → boot → kernite → lib → userland) as
   derivations, each parity-gated.
4. **Absorb Python tools into flake (Rust); make both paths deterministic;
   port recipes → pure-functional ``.port``; image assembly + FHS projection +
   signed substitution in flake.** Parity: normalized-structure comparison of
   ``disk_image.img`` / rootfs / SaltyFS image; QEMU boot-log comparison.
5. **Retire meson + just**; activate flake self-bootstrap; update
   ``CLAUDE.md`` / ``docs/BUILDING.md`` / ``docs/TOOLCHAIN.md`` /
   ``docs/design/ports.md``.

Parity methodology (``tools/parity-check.sh``): for already-deterministic
artifacts, ``sha256sum``; for currently-non-deterministic images (until
determinism lands), normalized-structure comparison; plus ``ninja -t
commands`` diffs where ninja is involved, between the meson reference and
flake.

Alternatives Considered
=======================

- **Keep meson + just, clean up the layering, add a config layer.** Rejected:
  the fundamental mismatch (100% custom targets; meson options cannot express
  feature config) stays.
- **Full from-scratch build engine including ninja.** Rejected: reimplementing
  correct incremental rebuilds is the classic tar pit.
- **Lighter config model (no select/depends/choice).** Rejected by the user:
  full Linux-Kconfig-class capability is required.
- **Keep Python image tools as scripts flake invokes.** Rejected: contradicts
  the minimize-script-dependence goal and self-hosting.
- **Pure-store runtime (NixOS-style).** Rejected: would require rewriting path
  assumptions across the OS; FHS projection is far cheaper.
- **Adopt real Nix / Guix directly.** Rejected: drags their runtimes and
  CLI/language; SaltyOS owns a smaller, Rust, capability-native engine.

Risks and Open Questions
========================

- **Floating content-addressed outputs** (the named sub-decision under Hash
  model) interacts with self-referential binaries; deferred to Phase-4 store
  design.
- **Dev-mode vs release-mode split** (reproducibility guarantees, dev/store
  identity relationship) is a Phase-2/3 design point.
- **macOS sandboxing** is an auditing fallback only; true sandboxing is on
  Linux/SaltyOS (and CI).
- **Store GC policy** (bounding, refcount/LRU) is unspecified.
- **Floating/CA maturity** in the wider Nix ecosystem is still settling;
  flake defaults to input-addressed until CA is justified.
- **Rust rewrite size** for ``mksaltyfs`` / ``mkimage`` (~1K LOC each) is the
  largest single parity risk, mitigated by normalized-structure checks and by
  sharing the SaltyFS format with the ``saltyfs`` server.

Drawbacks
=========

- Large implementation surface (derivation engine, store, substitution,
  sandboxing, Rust rewrites, determinism fixes). Phased, parity-gated rollout
  bounds the risk.
- A new build system the wider world does not know. Mitigated by retaining
  ninja and by clear docs.
- Dev/release mode split adds a mode that pure-ninja projects do not have.
- macOS dev hosts get only an auditing fallback, not a true sandbox.

Cross-References
================

- ``docs/design/ports.md`` — current ``.port`` model this RFC supersedes.
- ``meson.build`` / ``meson.options`` / ``justfile`` — the stack being retired.
- ``tools/port/`` — flake's nucleus (reused cores: parser/config/deps/version;
  ``stamps.rs`` ``DefaultHasher`` is *not* inherited).
- ``tools/mkcpio.py`` / ``mkimage.py`` / ``mksaltyfs.py`` / ``mkrootfs`` /
  ``mksysroot`` — Python tools absorbed into flake.
- ``tools/toolchain/build.sh`` — the ``x.py``/Python toolchain bootstrap that
  scopes the "no Python" claim.
- RFC-0009 — capability-bounded W^X; relevant to the build sandbox model.
