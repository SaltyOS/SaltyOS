# Ports Build System

SaltyOS cross-compiles unmodified third-party C/C++/Rust software with a BSD-ports-style declarative model. This document describes the `.port` file format, the build pipeline, and how port artifacts feed both the build-time sysroot and the runtime rootfs.

## Design goals

1. **Each port installs into its own FHS-shaped stage tree** (`stage-<arch>/usr/...`), produced by the upstream `make install DESTDIR=…` flow whenever possible. Stage layout is the single source of truth for both downstream ports and the runtime rootfs.
2. **Ports never reach into a peer port's work directory.** The build-time sysroot is the *only* surface other ports consume. Peer-work-dir `-I`/`-L` hacks are forbidden.
3. **Dependencies are version-constrained.** `[depends] build = ncurses >= 6.5` is the norm; the port tool refuses to build if the installed version of a dep does not satisfy the constraint.
4. **pkg-config is the canonical dep-query mechanism.** Each upstream's own `.pc` files land in the sysroot; downstream configure scripts pick them up without hand-maintained `FOO_CFLAGS` / `FOO_LIBS` in `[env]`.
5. **One stage tree feeds both build and runtime.** The same `stage-<arch>/` that overlays into the sysroot at build time also overlays into the rootfs at image-assembly time, minus a fixed dev-file filter.
6. **Conflicts and drift are hard errors.** File-level ownership is tracked per port; two ports writing the same path is a fatal overlay error. Version-mismatched deps fail fast before any compilation starts.

## Pipeline overview

```
.port
  │
  ▼
fetch → checksum → extract → patch → config-cache → prepare → configure → build → stage → overlay → package
                                                                           │         │         │
                                                                           │         │         └─ build-<arch>/ports/<name>.manifest (packing list)
                                                                           │         └─ build-<arch>/sysroot/ (overlay + provenance)
                                                                           └─ ports/<name>/stage-<arch>/ (FHS tree)
```

New phases compared to the legacy tool:

| Phase | Replaces / augments |
|-------|---------------------|
| `stage` | Replaces the old flat `[install]` copy. Runs `make install DESTDIR=…` (or scripted equivalent) to materialize a full FHS-shaped `stage-<arch>/`. |
| `overlay` | New. Copies `stage-<arch>/` into `build-<arch>/sysroot/`, records file provenance, and enforces conflict detection. |
| `package` | Now derives the manifest from the stage tree (every file under `stage-<arch>/`), not from a hand-written `[install]` section. |

`fetch`, `extract`, `patch`, `prepare`, `configure`, `build` keep their current semantics.

## `.port` file spec

### `[port]`

Unchanged.

```ini
[port]
name = ncurses
version = 6.5
description = Wide-char terminal UI library
homepage = https://invisible-island.net/ncurses/
license = MIT
```

### `[source]`

Unchanged.

### `[build]`

```ini
[build]
type = autotools        # autotools | cmake | meson | make | custom | targets | cargo
configure =
    --enable-widec
    --disable-shared
```

The `type` governs both the configure/build and the `stage` phase default (see below).

### `[depends]` — versioned

```ini
[depends]
build   = ncurses >= 6.5, zlib >= 1.3
runtime = ncurses >= 6.5, zlib >= 1.3
```

Each entry is comma-separated. Each token is `name [op version [, op version…]]`:

| Operator | Meaning |
|----------|---------|
| `=`, `==` | exact |
| `!=` | not equal |
| `>=`, `>` | lower bound |
| `<=`, `<` | upper bound |

Multiple constraints on one dep AND together with `&&` (semantically), written space-separated after the name:

```
openssl >= 3.4 < 4
perl   >= 5.40
ncurses = 6.5
```

Omitting the operator means "any version" (back-compat for early development). The port tool warns on unconstrained deps but does not fail.

**Version comparison.** Versions are split on `.` and `-`; each component compared numerically if all-digits, lexically otherwise. Pre-release tails (`-rc1`, `-beta`) sort below the bare release (`1.0 > 1.0-rc1`). Only one pre-release convention is supported (numeric-or-string component tail) — ports with exotic schemes (e.g. `2025-01-31`) are treated as string tuples.

**Resolution.** The port tool reads each dep's `.port` file to learn its declared `version`, compares against the constraint, and aborts before `configure` if unsatisfied. `build` deps also drive sysroot overlay ordering: a port's `overlay` stamp must be current before its dependents' `configure` runs.

### `[env]`

Same shape as before, but the following patterns are **prohibited** after the migration:

- `${PORTDIR}/../<other>/${ARCH_WORK}/…` (peer-work-dir reference)
- `${PORTDIR}/../<other>/${ARCH_STAGE}/…` (peer-stage reference)
- `EXTRA_CFLAGS` / `EXTRA_LDFLAGS` adding `-I`/`-L` that point at peer ports

The port tool rejects `.port` files containing any of these patterns with a clear error message. Downstream ports use pkg-config and the automatically-overlaid sysroot instead.

`EXTRA_CFLAGS` / `EXTRA_LDFLAGS` remain valid for upstream-quirks like `-D_GNU_SOURCE` or `-Wno-error=foo`; the restriction is only on cross-port references.

### `[stage]` — new section

Declares how the stage phase materializes `stage-<arch>/`. The default depends on `[build] type`:

| Build type | Default `stage` behavior |
|------------|--------------------------|
| `autotools` | `make install DESTDIR=<stage> prefix=/usr` |
| `make` | `make install DESTDIR=<stage> PREFIX=/usr` (upstream must honor PREFIX) |
| `cmake` | `DESTDIR=<stage> cmake --install _build --prefix /usr` |
| `meson` | `DESTDIR=<stage> meson install -C _build` |
| `custom`, `targets`, `cargo` | No default. Port *must* declare `[stage]`. |

A port can override the default entirely:

```ini
[stage]
mode     = script
commands =
    install -D -m 0755 _build/ninja ${STAGE}/usr/bin/ninja
```

Keys:

| Key | Meaning |
|-----|---------|
| `mode` | `make-install` (default where available) \| `script` \| `none` |
| `commands` | Shell script run in `${SRCDIR}` with stage env vars set (`STAGE`, `SYSROOT`, usual cross-env). Required when `mode = script`. |
| `extra` | Shell script run *after* `make-install` to patch up missed files (optional). Same env as `commands`. |

Within `commands` / `extra`, `${STAGE}` expands to the absolute path of `stage-<arch>/`. All files written must land under `${STAGE}` — the overlay phase asserts no file outside the stage tree was produced.

### `[stage.exclude]` — optional

Paths (glob-style, stage-relative) to delete from the stage tree before overlay. Used for upstreams that install files we don't want (test binaries, locale catalogs, etc.):

```ini
[stage.exclude]
usr/share/man/
usr/share/info/
usr/lib/*.la
```

Wildcards: `*` matches within a single path component; `**` matches any number of components; trailing `/` implies "the directory and everything under it".

### `[install]` — removed

Legacy `[install] bin/bash = bash` is rejected by the parser. Every port moves to `[stage]` (either `make-install` or a short `script`). The migration rewrites all 17 existing ports in one pass.

### `[prepare]`, `[autoconf_cache]`, `[options]`, `[targets]`, `[targets.cflags]`, `[libs]`

Unchanged in shape and semantics. `[options] autoreconf = true` still triggers `autoreconf -fi`.

### Template variables

Existing `${WORKDIR}`, `${SRCDIR}`, `${PORTDIR}`, `${BUILDDIR}`, `${ARCH}`, `${ARCH_WORK}`, `${ARCH_STAGE}`, `${SYSROOT}`, `${REPOROOT}` remain. `${ARCH_STAGE}` now points at the canonical FHS stage dir (`ports/<name>/stage-<arch>/`); older ports that treated it as an opaque output dir need no changes because the name is the same, only the tree layout changes.

New variable:

| Variable | Value |
|----------|-------|
| `${STAGE}` | Absolute path of `ports/<port>/stage-<arch>/` for the current port (used in `[stage]` scripts) |
| `${PKG_CONFIG_SYSROOT_DIR}` | Alias for `${SYSROOT}` — passed through to pkg-config |

## Port tool phases

### Stamp map

| Phase | Stamp inputs (hashed) |
|-------|-----------------------|
| `fetch` | `[source].url`, distfile presence |
| `extract` | distfile checksum, `[source].subdir` |
| `patch` | `patches/*.patch` contents + filenames |
| `config-cache` | (always run — fast) |
| `prepare` | `[prepare]` script text + resolved var map |
| `configure` | `[build].type`, `[build].configure`, `[env]`, cross-env fingerprint |
| `build` | (always run — src-changes hard to track) |
| `stage` | stage-mode + `[stage]` scripts + `[stage.exclude]` globs + build-output fingerprint |
| `overlay` | stage-tree manifest hash + dep `overlay` stamps |
| `package` | manifest hash |

Phases are stamp-tracked incrementally; `just port foo` only re-runs the phases whose inputs changed. The `overlay` phase is special: it also un-overlays any file previously owned by this port that is no longer present in the new stage tree.

### Build-type-specific stage hooks

**autotools.** `make install DESTDIR=${STAGE} prefix=/usr install` is the default; the port tool sets `DESTDIR` and `prefix` as make variables, so even packages that bake `prefix` into configure honor it. Packages that split install into multiple targets (e.g., `install-headers`, `install-data`) declare `[stage] extra` to run them.

**cmake.** `DESTDIR=${STAGE} cmake --install _build --prefix /usr` is the default. Ports configured with a non-`/usr` `CMAKE_INSTALL_PREFIX` must fix the configure args; we don't patch around it.

**meson.** `DESTDIR=${STAGE} meson install -C _build --no-rebuild` is the default.

**make.** `make install DESTDIR=${STAGE} PREFIX=/usr` default; upstreams that honor neither `DESTDIR` nor `PREFIX` (rare but exists — bzip2, zlib old-style Makefiles) must declare `[stage] mode = script`.

**custom.** No default. `[stage] mode = script commands = …` is required. Examples: openssl (`make install_sw DESTDIR=${STAGE}`), perl (`make install DESTDIR=${STAGE} INSTALLFLAGS=…`).

**targets.** No default. `[stage] mode = script` puts individual `_build/<name>` binaries into `${STAGE}/usr/bin/<name>`. Port authors write a straightforward loop.

**cargo.** Default is `cargo install --path . --root ${STAGE}/usr --no-track`. Ports with multi-binary workspaces declare `[stage] mode = script` and copy from `target/<triple>/release/` explicitly.

### Post-stage strip

After the `[stage]` script / `make install DESTDIR=` finishes, and after `[stage.exclude]` deletions, the port tool runs a **strip pass** over the stage tree:

1. Walk `stage-<arch>/` recursively.
2. For each regular file, read the first 4 bytes. If they are `0x7F E L F`, run `llvm-strip --strip-unneeded <file>` (cross-aware via the target arch; strip is idempotent).
3. Non-ELF files, symlinks, and already-stripped binaries are skipped (llvm-strip is a no-op on the latter).

Rationale: `make install DESTDIR=` targets usually do **not** strip (unlike Debian's dh_strip, which runs a separate step). Without this pass the rootfs grows significantly — a stripped libssl.a is roughly 40% the size of its unstripped form. Strip runs in the stage phase (not overlay) so sysroot and rootfs both consume stripped artifacts.

A port can opt out per-file via `[stage.nostrip]` (one glob per line) when something (e.g. a static analysis report) needs the debug symbols kept. Default is "strip everything".

### Overlay phase semantics

For a given port `P` with stage tree `ports/P/stage-<arch>/`:

The overlay runs in **two strict passes**. Pass 1 is read-only and may abort without touching the sysroot; pass 2 does all mutations and only runs if pass 1 succeeded.

**Pass 1 — validation (read-only):**

1. **Load previous provenance.** Read `build-<arch>/sysroot/.port-provenance/P.files` (SHA-256 + path per line, stage-relative). If absent, treat as empty.
2. **Load previous metadata.** Read `build-<arch>/sysroot/.port-provenance/P.meta` for name/version/stamp-hash of the last overlay.
3. **Enumerate new stage files.** Walk `ports/P/stage-<arch>/` producing a list of (relpath, sha256, mode).
4. **Conflict scan.** For every new stage file, check every *other* port's provenance file under `.port-provenance/` (and the `__base__` provenance from `mksysroot`). If any other owner claims the same relpath → abort: `ports/P: file usr/bin/foo also owned by <other>`. Sysroot untouched.
5. **Stage-boundary check.** Verify the recorded stage file list contains no absolute paths or `..` components, and that every entry lives under `stage-<arch>/` (the stage phase should have enforced this, but the overlay double-checks before commit).

**Pass 2 — apply (only after pass 1 clean):**

6. **Remove stale files.** For each path in the old provenance that is not in the new stage list, unlink it from the sysroot. Empty parent dirs cleaned up bottom-up (but never `usr/`, `usr/lib/`, `usr/include/`, `usr/bin/` or other FHS roots).
7. **Copy into sysroot.** Hard-link if source and sysroot share a filesystem (cheap for rebuilds), else regular copy. Preserve mode and mtime. Target files are written via a sibling temp-name + rename-into-place so a partially-completed overlay never leaves torn writes.
8. **Rewrite `.pc` prefix.** Any `.pc` file copied into `usr/lib/pkgconfig/` has its `prefix=` line rewritten to `prefix=/usr` (relative — `PKG_CONFIG_SYSROOT_DIR` then resolves it). Done in-place on the sysroot copy, not the stage tree.
9. **Write new provenance.** `P.files` = new stage file list with hashes; `P.meta` = `{name, version, stamp_hash, overlaid_at}`.

If the process crashes or is killed between passes, the previous provenance is still authoritative; a subsequent overlay run re-does pass 1 and either succeeds cleanly or aborts identically.

### Build-time sysroot layout (after migration)

```
build-<arch>/sysroot/
├── usr/
│   ├── include/
│   │   ├── <basaltc headers>          # from mksysroot (base)
│   │   ├── c++/v1/…                    # from mksysroot (base)
│   │   ├── curses.h                    # from ncurses port overlay
│   │   ├── ncurses.h                   # symlink, from ncurses port
│   │   ├── ncursesw/curses.h           # from ncurses port
│   │   ├── openssl/*.h                 # from openssl port
│   │   └── …
│   ├── lib/
│   │   ├── libc.so, libtrona.so, …     # from mksysroot (base)
│   │   ├── libm.a, libpthread.a, …     # stub archives from mksysroot
│   │   ├── libncursesw.a               # from ncurses port
│   │   ├── libssl.a                    # from openssl port
│   │   └── pkgconfig/
│   │       ├── ncursesw.pc
│   │       ├── libssl.pc
│   │       └── …
│   └── share/
│       └── terminfo/…                  # from ncurses port
├── lib/
│   ├── ldtrona-elf.so                     # from mksysroot (base)
│   └── ldtrona-pe.so
└── .port-provenance/
    ├── ncurses.files
    ├── ncurses.meta
    ├── openssl.files
    └── …
```

Base entries (libc, libtrona, crt_start, linker scripts, stub archives) are written by `mksysroot` and attributed to a sentinel owner `__base__` so port overlays can't collide with them.

### Cross-env changes

`tools/port/config.rs` extends the cross-env with:

- `PKG_CONFIG_PATH = ${SYSROOT}/usr/lib/pkgconfig:${SYSROOT}/usr/share/pkgconfig`
- `PKG_CONFIG_SYSROOT_DIR = ${SYSROOT}`
- `PKG_CONFIG_LIBDIR = ${SYSROOT}/usr/lib/pkgconfig:${SYSROOT}/usr/share/pkgconfig` (suppresses host pkg-config paths in cross builds — standard cross-pkg-config practice)

**`CFLAGS` / `LDFLAGS` are NOT extended with explicit `-I${SYSROOT}/usr/include` / `-L${SYSROOT}/usr/lib`.** Clang with `--sysroot=<sysroot>` already searches `<sysroot>/usr/include` for headers and `<sysroot>/usr/lib` for libraries — adding them again as explicit `-I`/`-L` only creates two problems:

1. **Header shadowing order.** basaltc's headers (installed by `mksysroot` into `<sysroot>/usr/include`) and port-overlaid headers (ncurses, openssl, …) both live in the same include root. The sysroot search order is well-defined (per-arch system include dir first, then `<sysroot>/usr/include`); an extra `-I<sysroot>/usr/include` prepended to CFLAGS upends that order and can cause a port header to shadow a basaltc one.
2. **Duplicate include paths.** Autoconf probes that `#include <foo.h>` don't care if the path appears once or twice; but probes that hand-parse compiler diagnostics (rare but exists — some configure scripts scan stderr) get confused by duplicate search-path listings.

The port tool relies on `--sysroot=` to deliver headers/libs, and on pkg-config (with `PKG_CONFIG_SYSROOT_DIR`) for anything more specific. If a future port breaks because autoconf's probes can't find a header reachable only via the sysroot, the fix is to investigate that probe, not to bolt on `-I<sysroot>/usr/include` globally.

## Rootfs assembly

`images/rootfs.packages` stays — one port name per line. `tools/mkrootfs` replaces its per-port mapping logic with:

1. For each port `P` in `rootfs.packages`, locate `ports/P/stage-<arch>/`. If absent, fail.
2. Walk the stage tree. For each file, test against the **dev-file filter**:

| Glob | Reason |
|------|--------|
| `usr/include/**` | headers |
| `usr/lib/**/*.a` | static archives |
| `usr/lib/**/*.la` | libtool leftovers |
| `usr/lib/pkgconfig/**` | pkg-config metadata |
| `usr/lib/cmake/**` | CMake package configs |
| `usr/share/aclocal/**` | autoconf macros |
| `usr/share/pkgconfig/**` | arch-independent pkg-config |
| `usr/share/man/**` | man pages |
| `usr/share/info/**` | info pages |
| `usr/share/doc/**` | docs |
| `usr/share/gtk-doc/**` | api docs |
| `usr/share/locale/**` | locale catalogs |

Matched files are excluded from the rootfs.

3. Ports that need to *include* normally-filtered files (e.g. `perl` genuinely needs `usr/lib/perl5` and ncurses needs `usr/share/terminfo`) are unaffected because the filter only lists dev-side paths. `usr/share/terminfo` is not in the filter.
4. Surviving files are added to the saltyfs image via `mksaltyfs.py --add-file-from`, preserving mode and relative path.
5. FHS empty dirs (`/dev`, `/proc`, `/tmp`, `/sys`, `/pipe`, `/initramfs`, `/root`, `/var`, `/var/log`, `/var/run`, `/var/tmp`) are added unconditionally, matching current behavior.
6. Optional permission-override file (`images/rootfs.permissions`) continues to work as today.

The legacy manifest-based flow (`images/*.manifest` files with `dst=src` entries) remains available for bespoke content (configuration files, `/etc/*`, initrd-only tools); it coexists with port-stage overlay. `@include` still resolves; `rootfs.packages` conceptually appends port stages *after* manifest entries, and a port-stage path colliding with a manifest path is a fatal error (same overlay logic as sysroot).

## Meson integration

`ports/meson.build` changes in two places:

1. **Stamp dependencies.** Each `port_<name>` `custom_target` adds to `depends`:
   - `port_<dep>` for every dep in the port's `[depends] build =` (transitive — let meson close it)
   - Plus a synthetic `sysroot_port_overlay_<dep>` output — produced by the dep's overlay phase — so the dep's overlay stamp must be current before this port's configure runs.

2. **No output-filename parsing.** The `custom_target` output list becomes `['<name>.manifest']` only; individual file names are no longer extracted from `[install]`. mkcpio/mkrootfs read the stage tree directly when they need file-level info.

## Migration plan (one-pass)

The switch-over is indivisible: mixing the old `[install]` path and the new stage-overlay path in the same sysroot produces conflicts. A single PR does all of the following:

### Tool changes (`tools/port/`)

- `parser.rs`: accept `[stage]`, `[stage.exclude]`, reject `[install]` (clear migration error with the `.port` file path), parse `[depends]` version specs into a new `DepSpec { name, constraints: Vec<Constraint> }` structure.
- `parser.rs` (lint): reject `[env]` values containing `${PORTDIR}/../` — emit the offending line and the `.port` file path.
- `build.rs`: drop the current `do_stage` (install-map copy), add `do_stage` (DESTDIR/script), add `do_overlay` (sysroot copy + provenance), rewrite `do_package` to enumerate the stage tree for manifest generation.
- `config.rs`: add pkg-config env vars to cross-env; add `-I${SYSROOT}/usr/include`, `-L${SYSROOT}/usr/lib` to CFLAGS/LDFLAGS.
- `vars.rs`: add `${STAGE}` and `${PKG_CONFIG_SYSROOT_DIR}`.
- `main.rs`: new phases `stage`, `overlay` in the default build order; `--phase` dispatch understands them.
- new `version.rs`: version parsing + comparison.
- new `overlay.rs`: provenance tracking, conflict detection, un-overlay.
- `stamps.rs`: stamps for the new phases.

### `ports/*.port` rewrites

Every port file is rewritten. Common edits:

- Remove `[install]` section entirely.
- Add `[stage]` section — `mode = make-install` is the common case; `mode = script` for custom/cargo/targets types.
- Remove peer-port `-I`/`-L` from `[env]` (curl, freebsd-utils, python, htop, nano, sudo-rs).
- Add version constraints to `[depends] build =` (all 8 ports with deps).
- Any port whose upstream install target misses files or installs unwanted files declares `[stage] extra` or `[stage.exclude]`.

Per-port notes:

| Port | Migration action |
|------|------------------|
| bash | `[stage] mode = make-install`; no dep changes |
| bzip2 | `[stage] mode = script` (bzip2 Makefile needs `PREFIX=` and manual copy) |
| curl | remove peer `-I`/`-L` from `[env]`; `[depends] build = openssl >= 3.4, zlib >= 1.3`; `[stage] mode = make-install` |
| freebsd-utils | `[stage] mode = script` (targets-type, no upstream install) — **largest migration item**: ~55 install entries covering 25 binaries, libpam.so + 13 pam_*.so modules, libutil.so, PAM config trees under `etc/pam.d/`, and directory copies from `files/openpam/`. Script is non-trivial; budget implementation time accordingly. Remove peer `-L` from `[env]`; `[depends] build = zlib >= 1.3, bzip2 >= 1.0.8, xz >= 5.6, zstd >= 1.5, openssl >= 3.4, ncurses >= 6.5` |
| htop | `[stage] mode = make-install`; remove `NCURSESW_CFLAGS/LIBS` / peer `-I`/`-L` from `[env]`; `[depends] build = ncurses >= 6.5` |
| make | `[stage] mode = make-install` |
| nano | remove peer `-I`/`-L`; `[stage] mode = make-install`; `[depends] build = ncurses >= 6.5` |
| nasm | `[stage] mode = make-install` |
| ncurses | `[stage] mode = make-install` — delivers pkg-config files, `ncurses.h`/`ncursesw/*` headers, terminfo DB |
| ninja | `[stage] mode = script` (cmake install works but we want just the binary for now — or `mode = make-install` if small) |
| openssl | `[stage] mode = script`, `commands = make install_sw DESTDIR=${STAGE}`; `[depends] build = perl >= 5.40` |
| perl | `[stage] mode = script` (custom Configure-driven install) |
| python | `[stage] mode = make-install`; remove peer `-I`/`-L`; `[depends] build = openssl >= 3.4, zlib >= 1.3, bzip2 >= 1.0.8, xz >= 5.6, zstd >= 1.5, ncurses >= 6.5` |
| sudo-rs | `[stage] mode = script`; remove peer `LIBRARY_PATH` from `[env]`; `[depends] build = openssl >= 3.4, freebsd-utils >= 14.2`, `[depends] runtime = freebsd-utils >= 14.2` |
| wget | `[stage] mode = make-install`; `[depends] build = openssl >= 3.4, zlib >= 1.3` |
| xz | `[stage] mode = make-install` |
| zlib | `[stage] mode = make-install` (cmake install handles it) |
| zstd | `[stage] mode = make-install` |

### Meson / tooling

- `ports/meson.build`: wire overlay-stamp deps; stop parsing `[install]` output filenames.
- `tools/mkrootfs`: add port-stage overlay logic + dev-file filter.
- `tools/mksysroot`: mark base files with `__base__` provenance so port overlays can detect collisions against base.
- `images/rootfs.packages`: unchanged (same port list); `images/rootfs-base.manifest` unchanged.

### Docs & tests

- This file (`docs/design/ports.md`) — rewritten in the same PR.
- `justfile` help strings updated where they reference old stage semantics.
- Smoke test: after migration, `just arch=aarch64 port htop` must succeed on a machine whose ncurses `stage-aarch64/` was wiped (no stale symlinks); the same for `just port htop` on x86_64.

## Failure modes and invariants

- **Dep version unsatisfied.** `configure` phase refuses to start. Error format: `ports/htop: dep 'ncurses' version 6.4 does not satisfy constraint '>= 6.5'`.
- **Stage tree leaks outside `${STAGE}`.** `stage` phase fails with the offending path. Scripts must respect the DESTDIR boundary.
- **Overlay collision.** Overlay phase aborts naming both owners and the colliding path. Sysroot unmodified.
- **Stale peer-dir reference.** Parser rejects `[env]` lines matching `${PORTDIR}/../` — rewrite required.
- **Missing `[stage]` on custom/targets/cargo.** Parse-time error: `ports/<name>: build type 'custom' requires [stage] section`.
- **Ghost files on rebuild.** Overlay phase un-overlays files the previous stage owned but the new one does not — no accumulating cruft in the sysroot.
- **Rootfs collision between port stage and bespoke manifest.** `mkrootfs` fails with the colliding path and both sources.

## Future extensions (not in this PR)

- Binary `.pkg` artifacts (`stage-<arch>` tarballed + checksum + meta), so `just port X` can produce a reusable bundle.
- Per-package split (runtime vs -dev vs -doc) using the same dev-file filter logic the rootfs already applies.
- Runtime dep verification against the rootfs manifest during `mkrootfs`.

## Cross-references

- [POSIX Compatibility](posix.md)
- [basaltc Design](basaltc.md)
- [trona Design](trona.md)
- [FreeBSD Ports Collection](https://docs.freebsd.org/en/books/porters-handbook/)
