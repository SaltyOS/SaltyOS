# Ports Build System

This document describes SaltyOS's ports system for cross-compiling third-party C software.

## Overview

The ports system enables building unmodified portable C software (GNU, FreeBSD, etc.) to run on SaltyOS. It follows a BSD ports-style declarative model where each port is described by a `.port` file that specifies how to fetch, patch, configure, build, and install the software.

Key components:

| Component | Location | Purpose |
|-----------|----------|---------|
| `.port` files | `ports/<name>/<name>.port` | Declarative port definitions |
| `portbuild` | `tools/portbuild/` | Host-side build tool (Rust) |
| `besaltc` | `lib/besaltc/` | C standard library (`libc.so`) |
| Meson integration | `ports/meson.build` | Auto-discovery and build orchestration |

## Architecture

### Runtime Stack

```
+-----------------------------------------------+
|        Applications (bash, ls, cat...)         |
+-----------------------------------------------+
|  crt_start.o  |  libc.so (besaltc)             |
|   [_start]    |  [stdio, malloc, string, ...]  |
+-----------------------------------------------+
|           libbesalt.so (Rust)                    |
|  [syscall wrappers, POSIX layer, IPC helpers]  |
+-----------------------------------------------+
|           SaltyOS Microkernel                  |
+-----------------------------------------------+
```

A C program links against:
- `crt_start.o` — assembly entry point (`_start` -> `__libc_start_main`)
- `libc.so` — C standard library (Rust + C implementation)
- `libbesalt.so` — system library with syscall wrappers
- `core.o` + `compiler_builtins.o` — Rust runtime support

### Build-Time Flow

```
.port file
    |
    v
portbuild (host tool)
    |
    +-- fetch -> checksum -> extract -> patch
    |
    +-- config-cache -> prepare -> configure -> build
    |
    v
  stage (strip + copy)
    |
    v
  .manifest file
    |
    v
mkcpio.py --manifest
    |
    v
initrd.cpio (packed into disk image)
```

## Port File Format

Ports are defined by INI-style `.port` files. Each section configures a different aspect of the build.

### `[port]` — Metadata

```ini
[port]
name = bash
version = 5.2.32
description = GNU Bourne Again Shell
homepage = https://www.gnu.org/software/bash/
license = GPL-3.0
```

| Key | Required | Description |
|-----|----------|-------------|
| `name` | Yes | Port name (used for directory and manifest naming) |
| `version` | Yes | Version string |
| `description` | No | Human-readable description |
| `homepage` | No | Project URL |
| `license` | No | SPDX license identifier |

### `[source]` — Download

```ini
[source]
url = https://ftp.gnu.org/gnu/bash/bash-${version}.tar.gz
subdir = bash-${version}
sha256 = SKIP
```

| Key | Description |
|-----|-------------|
| `url` | Download URL (supports `${version}` substitution) |
| `subdir` | Expected directory name inside the tarball |
| `sha256` | SHA-256 checksum, or `SKIP` to disable verification during development |

### `[build]` — Build Configuration

```ini
[build]
type = autotools
configure =
    -C
    --enable-minimal-config
    --without-bash-malloc
```

| Key | Description |
|-----|-------------|
| `type` | Build system: `autotools`, `cmake`, `meson`, `make`, `custom`, or `targets` |
| `configure` | Configure arguments (multi-line, one per indented line) |

**Build types:**

| Type | Configure | Build |
|------|-----------|-------|
| `autotools` | `./configure --host=x86_64-unknown-none --prefix=/usr [args]` | `make -j$NPROC` |
| `cmake` | `cmake [args] ..` in `_build/` | `cmake --build _build -j $NPROC` |
| `meson` | `meson setup _build` | `meson compile -C _build` |
| `make` | (none) | `make -j$NPROC` |
| `custom` | (none) | `make -j$NPROC` |
| `targets` | (none) | Direct `clang` invocation per target |

### `[env]` — Environment Overrides

```ini
[env]
CFLAGS_FOR_BUILD = -std=gnu89
EXTRA_CFLAGS = -std=gnu89
```

Variables set here override or extend the cross-compilation environment. The `EXTRA_CFLAGS`, `EXTRA_LDFLAGS`, and `EXTRA_LIBS` keys are special: they **append** to the computed base flags instead of replacing them.

### `[autoconf_cache]` — Cross-Compile Cache

```ini
[autoconf_cache]
ac_cv_func_mmap_fixed_mapped = yes
bash_cv_job_control_missing = missing
bash_cv_getenv_redef = yes
```

Pre-populates autotools `config.cache` to prevent configure from running target binaries during cross-compilation. Each key-value pair becomes a cache variable.

### `[targets]` — Direct Compilation (for `type = targets`)

```ini
[targets]
echo     = bin/echo/echo.c
cat      = bin/cat/cat.c :: -DBOOTSTRAP_CAT
ls       = bin/ls/ls.c bin/ls/cmp.c bin/ls/print.c bin/ls/util.c :: -Ibin/ls
```

Each line defines a compilation target:
```
name = source1.c source2.c [:: -Dflag -Ipath]
```

Sources are space-separated. Per-target extra flags follow `::`. Each target compiles to a single binary via:
```
clang $CFLAGS $TARGETS_CFLAGS $EXTRA_FLAGS $LDFLAGS -o $OUT $SOURCES $LIBS
```

### `[targets.cflags]` — Shared Target Flags

```ini
[targets.cflags]
-I${SRCDIR} -I${SRCDIR}/include -I${SRCDIR}/lib/libc/include
-I${SRCDIR}/sys -I${SRCDIR}/sys/amd64/include
-include sys/cdefs.h
```

CFLAGS applied to all `[targets]` entries. Supports multi-line (continuation lines are joined with spaces).

### `[prepare]` — Pre-Configure Script

```ini
[prepare]
sed -i 's/^LIBS_FOR_BUILD = .*/LIBS_FOR_BUILD =/' ${SRCDIR}/support/Makefile.in
ln -sfn amd64/include ${SRCDIR}/sys/machine
```

Shell commands executed in the source directory before configure. Runs with the cross-compilation environment. Supports variable substitution.

### `[install]` — Output Mapping

```ini
[install]
bash.elf = bash
bin/echo = echo
usr/bin/head = head
```

Maps initrd paths (left) to build artifacts (right). The left side determines the filename in the initrd (flattened: `bin/echo` becomes `echo.elf`). The right side is the artifact name within the build tree.

### Template Variables

Available in `[source].url`, `[source].subdir`, `[prepare]`, `[targets.cflags]`, and `[build].configure`:

| Variable | Value |
|----------|-------|
| `${name}` | Port name from `[port]` |
| `${version}` | Port version from `[port]` |
| `${WORKDIR}` | `<port-dir>/work/` |
| `${SRCDIR}` | Resolved source directory inside work/ |
| `${SOURCE_SUBDIR}` | Subdirectory name within work/ |
| `${PORTDIR}` | Port directory (e.g., `ports/bash/`) |
| `${BUILDDIR}` | Meson build root |
| `${SALTY_HOST}` | Target triple (`x86_64-unknown-none`) |
| `${SALTY_INC}` | Path to `lib/besaltc/include/` |
| `${NPROC}` | Number of parallel jobs |

## portbuild Tool

`portbuild` is a Rust host tool (`tools/portbuild/`) that executes the port build pipeline.

### Usage

```
portbuild <command> <port-dir> [options]

Commands:
  build   Full build (all phases)
  fetch   Download source only
  clean   Remove work/ and stage/
  info    Show parsed port config

Options:
  -o, --output <dir>     Output directory (default: build/ports/)
  -b, --build-dir <dir>  Meson build root (default: build/)
  -j, --jobs <n>         Parallel jobs (default: nproc)
  -v, --verbose          Show subprocess output
  --skip-fetch           Skip download phase
  --phase <name>         Run single phase
```

### Build Phases

The `build` command runs 9 phases in order:

| # | Phase | Description | Cached? |
|---|-------|-------------|---------|
| 1 | **fetch** | Download source tarball to `ports/distfiles/` | Yes |
| 2 | **checksum** | Verify SHA-256 (or skip if `SKIP`) | No |
| 3 | **extract** | Extract tarball into `<port-dir>/work/` | Yes |
| 4 | **patch** | Apply `patches/*.patch` files (sorted, `-p1`) | Yes |
| 5 | **config-cache** | Generate `config.cache` from `[autoconf_cache]` | No |
| 6 | **prepare** | Run `[prepare]` shell script | Yes |
| 7 | **configure** | Run configure (autotools/cmake/meson) | Yes |
| 8 | **build** | Compile (`make` or direct targets) | No |
| 9 | **stage** | Strip binaries, copy to output, write manifest | No |

Cached phases use stamp files with input hashing. If a cached phase's inputs haven't changed, it's skipped. Phases marked "No" always run (either fast or hard to track source changes).

### Cross-Compilation Environment

portbuild automatically configures the cross-compilation environment:

| Variable | Value |
|----------|-------|
| `CC` | `clang` |
| `CFLAGS` | `-ffreestanding -nostdlib -nostdinc -fno-stack-protector -mno-red-zone -fPIC -isystem <besaltc-include> -isystem <clang-resource-dir>/include --target=x86_64-unknown-none` |
| `LDFLAGS` | `-nostdlib -nostartfiles -fuse-ld=lld --target=x86_64-unknown-none -L<besaltc> -L<libbesalt> -L<rust> -Wl,--dynamic-linker,/lib/ld-besalt.so` |
| `LIBS` | `<besaltc>/crt_start.o -lc -lbesalt <rust>/core.o <rust>/compiler_builtins.o` |
| `AR` | `llvm-ar` |
| `RANLIB` | `llvm-ranlib` |
| `STRIP` | `llvm-strip` |
| `CC_FOR_BUILD` | `cc` (native compiler for host-side build tools) |

Library and include paths are derived automatically from the Meson build root.

### Directory Layout

```
ports/
├── meson.build          # Auto-discovery + Meson targets
├── .gitignore           # Excludes work/, stage/, distfiles/
├── distfiles/           # Shared source tarball cache
├── bash/
│   ├── bash.port        # Port definition
│   ├── patches/         # Patches (applied sorted, -p1)
│   ├── work/            # Extracted sources (gitignored)
│   └── stage/           # Staged binaries (gitignored)
└── freebsd-utils/
    ├── freebsd-utils.port
    ├── patches/
    │   ├── 01-uname-use-posix.patch
    │   ├── 02-env-remove-login-cap.patch
    │   ├── 03-remove-tls-rune.patch
    │   └── 04-remove-acl-mac.patch
    ├── work/
    └── stage/
```

## C Standard Library (besaltc)

Ports link against `libc.so`, SaltyOS's C standard library implemented primarily in Rust with some C/ASM components.

### Architecture

```
lib/besaltc/
├── src/
│   ├── lib.rs           # Crate root
│   ├── crt.rs           # __libc_start_main (runtime init)
│   ├── stdio.rs         # printf, fopen, fread, FILE streams
│   ├── malloc.rs        # malloc/free/realloc (first-fit free-list)
│   ├── string.rs        # strlen, strcmp, memcpy, strlcpy, ...
│   ├── unistd.rs        # open, close, read, write, fork, exec, ...
│   ├── process.rs       # fork, execve, execvp, wait
│   ├── stdlib_impl.rs   # strtol, qsort, bsearch, rand
│   ├── math_impl.rs     # fabs, copysign (x87 FPU inline asm)
│   ├── err_impl.rs      # err(3), warn(3) BSD error reporting
│   └── compat/freebsd/  # FreeBSD-specific stubs (capsicum, rune, bsd_io, ...)
├── crt_start.S          # _start entry point (calls __libc_start_main)
├── setjmp.S             # setjmp/longjmp
├── fts.c                # BSD file tree stream
├── getopt.c             # POSIX getopt + GNU getopt_long
├── libutil_compat.c     # expand_number, humanize_number, fgetln
├── md5.c                # RFC 1321 MD5
├── cap_fileargs.c       # Capsicum fileargs wrapper
├── xo_stub.c            # libxo text-mode stubs
├── include/             # 72 POSIX/BSD headers
├── besaltc.ld            # Shared library linker script
└── meson.build          # Build configuration
```

**Build output:**
- `libc.so` — shared library (all Rust + C objects linked together)
- `crt_start.o` — separate object, linked per-program (not in `libc.so` to avoid unresolved `main`)

### Runtime Initialization

`crt_start.S` calls `__libc_start_main(main, rsp)` which:

1. Parses the initial stack: `argc`, `argv[]`, `envp[]`, `auxv[]`
2. Initializes IPC buffer (fixed at `0x200000`)
3. Reads SaltyOS-specific auxv entries (untyped cap, vspace cap, scratch address, slot allocator)
4. Initializes heap (1MB after scratch area via `sbrk`)
5. Calls `main(argc, argv, envp)`
6. Calls `exit()` with the return value

### Headers

72 headers in `lib/besaltc/include/` provide the C API surface:

- **Standard C**: `stdio.h`, `stdlib.h`, `string.h`, `ctype.h`, `math.h`, `time.h`, `signal.h`, `setjmp.h`, `stddef.h`, `stdint.h`, `stdarg.h`, `stdbool.h`, `errno.h`, `assert.h`, `limits.h`, `inttypes.h`, `locale.h`
- **POSIX**: `unistd.h`, `fcntl.h`, `dirent.h`, `sys/types.h`, `sys/stat.h`, `sys/mman.h`, `sys/socket.h`, `sys/un.h`, `sys/time.h`, `sys/wait.h`, `sys/select.h`, `sys/uio.h`, `sys/resource.h`, `poll.h`, `termios.h`, `sched.h`, `pwd.h`, `grp.h`, `glob.h`, `fnmatch.h`, `regex.h`
- **BSD**: `err.h`, `fts.h`, `getopt.h`, `libutil.h`, `paths.h`, `sysexits.h`, `sys/cdefs.h`, `sys/param.h`, `md5.h`, `libxo/xo.h`, `sys/capsicum.h`

## Meson Integration

`ports/meson.build` provides automatic port discovery and build orchestration.

### How It Works

1. **Discovery**: Scans `ports/` for directories containing `<name>/<name>.port`
2. **Parsing**: Reads the `[install]` section to determine output filenames
3. **Target creation**: Creates a Meson `custom_target` per port:
   ```
   custom_target('port_bash',
     output: ['bash.elf'],
     depends: [portbuild, libbesalt_so, libc_so, crt_start_obj],
     command: [portbuild, 'build', <port-dir>, '-o', '@OUTDIR@', '-b', <build-root>],
   )
   ```
4. **Manifest**: Each port generates a `.manifest` file listing its outputs
5. **Initrd packing**: `mkcpio.py --manifest build/ports/bash.manifest` includes port binaries in the initrd

Ports are built as part of `just build` when `build_userland=true`.

## How to Add a New Port

### 1. Create the Port Directory

```bash
mkdir -p ports/myport/patches
```

### 2. Write the `.port` File

Create `ports/myport/myport.port`:

```ini
[port]
name = myport
version = 1.0
description = My ported program
license = MIT

[source]
url = https://example.com/myport-${version}.tar.gz
subdir = myport-${version}
sha256 = SKIP

[build]
type = autotools
configure =
    --disable-shared
    --enable-static

[install]
myport.elf = myport
```

### 3. Add Patches (if needed)

Place patch files in `ports/myport/patches/`. They are applied in sorted order with `patch -p1`:

```
patches/
├── 01-fix-headers.patch
├── 02-remove-unsupported.patch
```

### 4. Add a Prepare Script (if needed)

For source modifications that don't warrant a patch file:

```ini
[prepare]
sed -i 's/HAVE_FEATURE/0/' ${SRCDIR}/config.h.in
ln -sfn compat ${SRCDIR}/sys/machine
```

### 5. Build and Test

```bash
just distclean && just setup && just build
just run
```

### Tips

- Use `portbuild info ports/myport` to verify the parsed configuration
- Use `portbuild build ports/myport -v` for verbose build output
- Use `--phase configure` to run a single phase for debugging
- Set `sha256 = SKIP` during development, add the real checksum before committing
- For programs that run host tools during build (e.g., code generators), ensure `CC_FOR_BUILD` and `CFLAGS_FOR_BUILD` are set correctly in `[env]`
- For large source trees where only a few files are needed, use `type = targets` instead of a full build system

## Current Ports

| Port | Version | Build Type | Programs | Description |
|------|---------|------------|----------|-------------|
| bash | 5.2.32 | autotools | `bash` | GNU Bourne Again Shell (minimal config: no readline, history, job control) |
| freebsd-utils | 14.2 | targets | 22 utilities | FreeBSD userland utilities |

### freebsd-utils Programs

| Category | Programs |
|----------|----------|
| `bin/` | echo, cat, ls, cp, mv, rm, mkdir, rmdir, ln, chmod, test, sleep, pwd |
| `usr/bin/` | head, tail, wc, sort, uniq, basename, dirname, env, tee, id, uname, true, false |

## References

- [FreeBSD Ports Collection](https://docs.freebsd.org/en/books/porters-handbook/)
- [POSIX Compatibility](posix.md) — besaltc POSIX API coverage
