# saltyc -- C Standard Library

This document describes the design and implementation of saltyc, SaltyOS's C standard library.

## Overview

saltyc is a C standard library (`libc.so`) implemented primarily in Rust, providing a POSIX.1-2008 subset plus BSD extensions sufficient to run ported FreeBSD userland utilities (ls, cat, etc.). It is not a standalone library -- all system operations are delegated to libsalty, which communicates with kernel services via IPC. This layered design means saltyc never issues syscalls directly; it translates C calling conventions into libsalty's Rust API.

The library targets a single platform (SaltyOS on x86_64) and a single execution model (single-threaded processes). This deliberate narrowing eliminates the complexity of thread-safety, TLS, and multi-architecture support that dominates traditional C library implementations.

## Design Goals

**Port-compatible.** The primary goal is to compile unmodified FreeBSD utility source code. Function signatures, errno values, header layouts, and struct definitions match what ported C code expects. Where FreeBSD's libc exposes internal symbols (e.g., `__stdoutp`, `___runetype`, `__swbuf`), saltyc provides them.

**Minimal footprint.** The library uses static allocation wherever possible -- fixed-size pools for FILE streams (16), DIR handles (16), environment variables (128), and atexit handlers (32). The only dynamic allocation is through the malloc subsystem, which itself uses a simple sbrk-backed free list.

**Rust safety at the boundary.** Although the exported C ABI functions are inherently unsafe (raw pointers, no lifetime tracking), the internal implementations use Rust's type system where practical. Each `unsafe` block is scoped tightly around the actual pointer dereference or FFI call.

**Single-user simplicity.** SaltyOS has one user (root, uid=0). The password database, group database, and UID/GID accessors return hardcoded values. Permission checks always succeed. This eliminates the complexity of NSS, PAM, and shadow password files.

## Architecture

### Runtime Stack

```
+------------------------------------------------+
|         C program (main, compiled by clang)     |
+------------------------------------------------+
|  crt_start.o  |       libc.so (saltyc)          |
|   [_start]    |  [stdio, malloc, string, ...]   |
+------------------------------------------------+
|            libsalty.so (Rust)                    |
|  [syscall wrappers, POSIX layer, IPC helpers]   |
+------------------------------------------------+
|           SaltyOS kernel (Rust)                  |
|  [IPC endpoints, capability invocations]         |
+------------------------------------------------+
```

The startup sequence:

1. The dynamic linker (`rtld`) loads `libc.so` and `libsalty.so`, then calls `_start` in `crt_start.o`
2. `_start` (assembly) passes `main` and the stack pointer to `__libc_start_main`
3. `__libc_start_main` (Rust) parses argc/argv/envp/auxv, initializes IPC context, memory manager, locale tables, and program name
4. `main()` is called
5. On return, `exit()` runs atexit handlers, flushes stdio, and calls `_exit()`

### Module Table

| Module | Source | Purpose | Backend |
|--------|--------|---------|---------|
| `crt.rs` | Rust | CRT startup, atexit, exit | libsalty IPC + posix_mm init |
| `stdio.rs` | Rust | Buffered I/O (FILE), printf/scanf | libsalty posix_read/write |
| `malloc.rs` | Rust | malloc/free/realloc/calloc | libsalty posix_sbrk |
| `string.rs` | Rust | strlen, strcmp, strcpy, strlcpy, strerror | Pure Rust |
| `mem.rs` | Rust | memcpy, memset, memmove, memcmp | Pure Rust (compiler intrinsics) |
| `ctype.rs` | Rust | isalpha, isdigit, toupper, etc. | Pure Rust (lookup table) |
| `unistd.rs` | Rust | open, close, read, write, stat, mmap, *at() | libsalty posix_* |
| `process.rs` | Rust | fork, exec*, waitpid, kill, getpid, uid/gid | libsalty posix_* |
| `signal_impl.rs` | Rust | signal, sigaction, sigprocmask, sigset ops | libsalty notifications |
| `dirent_impl.rs` | Rust | opendir, readdir, closedir | libsalty posix_opendir/readdir |
| `env.rs` | Rust | getenv, setenv, unsetenv, environ | Static array (128 entries) |
| `errno.rs` | Rust | errno global, __errno_location | Static `ERRNO` variable |
| `time_impl.rs` | Rust | time, gmtime, strftime, clock_gettime | libsalty posix_clock_gettime |
| `stdlib_impl.rs` | Rust | atoi, strtol, strtod, qsort, bsearch, rand | Pure Rust |
| `locale.rs` | Rust | setlocale (C-only), localeconv, gettext | Pure Rust (hardcoded C locale) |
| `wchar.rs` | Rust | Wide char/multibyte stubs (MB_CUR_MAX=1) | Pure Rust (ASCII pass-through) |
| `regex.rs` | Rust | POSIX BRE/ERE regex (backtracking NFA) | Pure Rust |
| `sysinfo.rs` | Rust | uname, sysconf, getrlimit, gethostname | Pure Rust (hardcoded values) |
| `pwd_impl.rs` | Rust | getpwnam, getpwuid, getgrnam, getgrgid | Pure Rust (root-only) |
| `glob_impl.rs` | Rust | glob() pathname pattern matching | libsalty posix_opendir |
| `select_impl.rs` | Rust | select/pselect wrappers | libsalty posix_select |
| `math_impl.rs` | Rust | Basic math functions (fabs, sqrt, pow, etc.) | Pure Rust (soft-float) |
| `misc_impl.rs` | Rust | getprogname, dirname, basename, getentropy | Mixed |
| `err_impl.rs` | Rust | BSD err/warn/errx/warnx | stdio + errno |
| `termios.rs` | Rust | Terminal I/O stubs | Returns defaults |
| `termcap.rs` | Rust | termcap/terminfo stubs | Returns defaults |
| `ioctl.rs` | Rust | ioctl stubs | libsalty posix_ioctl |
| `jobctl.rs` | Rust | Job control stubs (setpgid, tcgetpgrp) | Hardcoded returns |
| `compat/` | Rust | FreeBSD compatibility layer | See below |
| `crt_start.S` | ASM | `_start` entry point | Calls `__libc_start_main` |
| `setjmp.S` | ASM | setjmp/longjmp/sigsetjmp/siglongjmp | Register save/restore |
| `fts.c` | C | BSD file tree stream (fts_open, etc.) | opendir/stat |
| `getopt.c` | C | POSIX getopt + GNU getopt_long | Pure C |
| `libutil_compat.c` | C | expand_number, fgetln | stdio + malloc |
| `md5.c` | C | RFC 1321 MD5 hash | Pure C |
| `cap_fileargs.c` | C | Capsicum fileargs wrapper (stub) | No-op |
| `xo_stub.c` | C | libxo text-mode stub | fprintf |

## Key Design Decisions

### Why Rust for a C Library

Writing a C standard library in Rust is unusual but practical here:

1. **Shared toolchain.** SaltyOS already uses Rust everywhere (kernel, libsalty, userland). Adding a C-only library would require maintaining separate build infrastructure.
2. **Backend reuse.** Most saltyc functions are thin wrappers around libsalty's Rust API. Writing them in Rust means direct function calls instead of FFI thunks.
3. **Controlled unsafety.** Each `unsafe` block is narrow and documented. The Rust compiler catches logic errors in the safe portions (off-by-one, type mismatches) that would silently compile in C.
4. **No performance penalty.** The exported functions use `extern "C"` ABI. From the caller's perspective, they are indistinguishable from C implementations.

The tradeoff is reliance on nightly Rust features (`c_variadic` for printf/scanf families, `linkage` for weak symbols).

### Static Allocation Strategy

All pools use fixed-size arrays in static memory:

| Resource | Pool Size | Location |
|----------|-----------|----------|
| FILE streams | 16 (3 reserved for std*) | `stdio.rs: OPEN_FILES` |
| DIR handles | 16 | `dirent_impl.rs: DIR_POOL` |
| Environment vars | 128 | `env.rs: ENV_PTRS` |
| atexit handlers | 32 | `crt.rs: ATEXIT_FUNCS` |

This eliminates any dependency on malloc during early startup and prevents allocation failures in resource management code. The limits are sufficient for ported utilities -- FreeBSD's ls, cat, and similar tools rarely open more than a handful of files simultaneously.

### errno Implementation

errno is a single `static mut ERRNO: i32`. The `__errno_location()` function returns its address, matching the Linux ABI that C headers expand `errno` to `(*__errno_location())`. This works because SaltyOS processes are single-threaded. A multi-threaded implementation would require thread-local storage (TLS), which the platform does not yet support.

errno values use Linux numbering (ENOENT=2, EINVAL=22, etc.) rather than FreeBSD numbering. This is intentional -- the header files that ported programs include define these constants, so the numeric values are consistent within a given compilation.

### Buffered I/O (stdio)

Each FILE contains a 1024-byte internal buffer and supports three modes:

| Mode | Constant | Default For | Behavior |
|------|----------|-------------|----------|
| Full | `_IOFBF` | Regular files | Flush when buffer fills |
| Line | `_IOLBF` | stdout | Flush on newline or buffer full |
| Unbuffered | `_IONBF` | stderr | Write every byte immediately |

The printf engine (`format_impl`) handles the full format specifier set: `%d`, `%i`, `%u`, `%x`/`%X`, `%o`, `%s`, `%c`, `%p`, `%f`, `%e`/`%E`, `%g`/`%G`, `%n`, `%%`, plus width, precision, and flag modifiers. It formats into a 4096-byte stack buffer, then writes the result to the stream.

The scanf engine (`sscanf_impl`) supports `%d`, `%i`, `%u`, `%x`, `%o`, `%s`, `%c`, `%[...]` scansets, `%n`, with width limits and suppression (`*`).

FreeBSD compatibility aliases (`__stdoutp`, `__stdinp`, `__stderrp`, `__isthreaded`) are exported so that FreeBSD's stdio.h macros resolve correctly.

### malloc Implementation

A first-fit free-list allocator backed by `sbrk()` (via libsalty's `posix_sbrk`). Every allocation has a 16-byte `BlockHeader` placed immediately before the returned pointer:

```
[BlockHeader (16 bytes)] [user data (aligned to 16)]
     size | next             ^ returned pointer
```

- **Alignment:** All allocations are 16-byte aligned.
- **Splitting:** Blocks are split when the remainder exceeds 32 bytes (HEADER_SIZE + ALIGN).
- **Coalescing:** The free list is sorted by address. On `free()`, adjacent blocks (both before and after) are merged when contiguous.
- **No thread-safety:** Single `static mut FREE_LIST` with no locking.

The allocator is deliberately simple. Performance-critical paths in SaltyOS use `posix_mmap()` (delegated to mmsrv via IPC) rather than malloc.

### CRT Initialization

The CRT startup parses the SaltyOS auxiliary vector (`auxv`) to discover per-process resources:

| Tag | Constant | Purpose |
|-----|----------|---------|
| `0x1000` | `AT_SALTY_UNTYPED` | Untyped memory cap (rtld bootstrap only; general frame alloc via mmsrv) |
| `0x1001` | `AT_SALTY_VSPACE` | VSpace capability slot |
| `0x1002` | `AT_SALTY_SCRATCH` | Scratch virtual address region |
| `0x1005` | `AT_SALTY_FRAME_SLOT` | Frame slot for page mapping |
| `0x1007` | `AT_SALTY_SLOT_BASE` | Slot allocator pool base |
| `0x1008` | `AT_SALTY_SLOT_COUNT` | Slot allocator pool size |
| `0x1009` | `AT_SALTY_EXPAND_EP` | Endpoint for requesting more slots |

The RTLD may have already consumed some slots while loading shared libraries, so its exported `__salty_slot_base` / `__salty_slot_count` take precedence over raw auxv values when non-zero.

After slot allocation setup, the heap region is placed 1 MB after the scratch area, and the mmap region starts 16 MB after the heap base.

## SaltyOS Auxv Entries

| Tag | Name | Type | Description |
|-----|------|------|-------------|
| `0x0000` | `AT_NULL` | - | End of auxv |
| `0x1000` | `AT_SALTY_UNTYPED` | slot | Untyped memory cap (rtld bootstrap only; general frame allocation via mmsrv) |
| `0x1001` | `AT_SALTY_VSPACE` | slot | VSpace cap for mapping frames |
| `0x1002` | `AT_SALTY_SCRATCH` | vaddr | Scratch region base address |
| `0x1005` | `AT_SALTY_FRAME_SLOT` | slot | CSpace slot for temporary frames |
| `0x1007` | `AT_SALTY_SLOT_BASE` | slot | First available cap slot |
| `0x1008` | `AT_SALTY_SLOT_COUNT` | count | Number of available cap slots |
| `0x1009` | `AT_SALTY_EXPAND_EP` | slot | Endpoint to request more slots from procmgr |

## FreeBSD Compatibility Layer

### Three-Tier Strategy

The `compat/freebsd/` module implements FreeBSD-specific interfaces using a three-tier approach:

**Real implementations** -- functions with meaningful behavior:

| Module | Functions | Description |
|--------|-----------|-------------|
| `rune.rs` | `___runetype`, `___toupper`, `___tolower` | ASCII rune table for FreeBSD ctype.h inline expansions |
| `bsd_flags.rs` | `strmode`, `setmode`, `getmode` | mode_t to ls-style string conversion |
| `bsd_sort.rs` | `mergesort`, `heapsort`, `strverscmp`, `strtonum` | Sorting algorithms and version comparison |
| `bsd_io.rs` | `__swbuf`, `__srget` | FreeBSD putc()/getc() macro internals |
| `bsd_misc.rs` | `getbsize`, `eaccess`, `vfork`, `__assert` | Miscellaneous FreeBSD functions |

**Stub implementations** -- functions that return safe defaults:

| Function | Behavior | Rationale |
|----------|----------|-----------|
| `capsicum.rs`: `__cap_rights_is_set` | Always returns true | Capsicum not enforced; SaltyOS uses kernel capabilities |
| `capsicum.rs`: `__cap_rights_set` | No-op, returns input | Same as above |
| `bsd_misc.rs`: `pledge`, `unveil` | Return 0 (success) | OpenBSD security model; not applicable |
| `bsd_misc.rs`: `getlogin` | Returns "root" | Single-user system |
| `bsd_misc.rs`: `getosreldate` | Returns `1402000` | FreeBSD 14.2 release date |

**ENOSYS implementations** -- functions that cannot be meaningfully stubbed:

| Function | Module | Why ENOSYS |
|----------|--------|------------|
| `kqueue`, `kevent` | `bsd_misc.rs` | BSD event notification requires kernel support |
| `chflags`, `lchflags`, `fchflags` | `bsd_flags.rs` | BSD file flags not in SaltyOS VFS |
| `statfs`, `fstatfs` | `bsd_misc.rs` | Filesystem statistics not tracked |
| `statvfs`, `fstatvfs` | `statvfs.rs` | Same as above |
| `mknod` | `bsd_misc.rs` | Device special files not supported |

### C Components

Some FreeBSD compatibility code is written in C rather than Rust because the original source is reused directly or the code uses C-specific patterns:

| File | Purpose | Origin |
|------|---------|--------|
| `fts.c` | File tree stream (`fts_open`, `fts_read`, etc.) | Adapted from FreeBSD |
| `getopt.c` | POSIX getopt + GNU getopt_long/getopt_long_only | Standard implementation |
| `libutil_compat.c` | `expand_number`, `fgetln` | FreeBSD libutil |
| `md5.c` | RFC 1321 MD5 hash (used by FreeBSD md5(1)) | Standard implementation |
| `cap_fileargs.c` | Capsicum fileargs wrapper (fileargs_init, etc.) | Minimal stub |
| `xo_stub.c` | libxo text-mode output (xo_emit -> fprintf) | Minimal stub |

### Headers

saltyc provides 70+ headers in `lib/saltyc/include/` organized to match standard POSIX/BSD layout:

- Standard C: `stdio.h`, `stdlib.h`, `string.h`, `ctype.h`, `errno.h`, `math.h`, `stdint.h`, `stddef.h`, `stdarg.h`, `stdbool.h`, `limits.h`, `assert.h`, `setjmp.h`, `inttypes.h`, `time.h`, `locale.h`, `wchar.h`, `wctype.h`, `signal.h`, `fcntl.h`
- POSIX: `unistd.h`, `dirent.h`, `pwd.h`, `grp.h`, `poll.h`, `regex.h`, `fnmatch.h`, `glob.h`, `getopt.h`, `termios.h`, `sched.h`, `libgen.h`, `utime.h`
- sys/: `sys/types.h`, `sys/stat.h`, `sys/wait.h`, `sys/mman.h`, `sys/select.h`, `sys/socket.h`, `sys/un.h`, `sys/time.h`, `sys/times.h`, `sys/ioctl.h`, `sys/utsname.h`, `sys/resource.h`, `sys/uio.h`, `sys/file.h`, `sys/param.h`, `sys/cdefs.h`, `sys/statvfs.h`, `sys/mount.h`, `sys/sysctl.h`, `sys/capsicum.h`, `sys/acl.h`, `sys/mac.h`
- FreeBSD-specific: `err.h`, `fts.h`, `paths.h`, `sysexits.h`, `libutil.h`, `login_cap.h`, `osreldate.h`, `mntent.h`, `termcap.h`, `md5.h`, `capsicum_helpers.h`, `libcasper.h`, `casper/cap_net.h`, `casper/cap_fileargs.h`, `libxo/xo.h`

## Limitations

**Single-threaded only.** All global state (`errno`, `STRTOK_SAVE`, `FREE_LIST`, `OPEN_FILES`, etc.) uses `static mut` without synchronization. Adding pthreads would require replacing these with TLS or mutex-protected storage.

**C locale only.** `setlocale()` always returns "C". All character classification is ASCII. Wide character functions treat `wchar_t` as a simple 32-bit value with `MB_CUR_MAX = 1`. No multibyte encoding support.

**UTC only.** `localtime()` is an alias for `gmtime()`. No timezone database, no DST support, no `TZ` environment variable parsing. `strftime %Z` always produces "UTC".

**No CSPRNG.** `getentropy()` uses a xorshift64 PRNG seeded from the monotonic clock and PID. It is suitable for hash table seeding but not for cryptographic keys or nonces.

**No dlopen.** The dynamic linker loads shared libraries at process startup only. Runtime dynamic loading (`dlopen`, `dlsym`, `dlclose`) is not supported.

**No symlinks.** `lstat()` is identical to `stat()`. `readlink()`, `symlink()`, `readlinkat()`, `symlinkat()` return `ENOSYS`. The VFS does not implement symbolic links.

**No hard links or device nodes.** `link()`, `linkat()`, `mknod()`, `mknodat()` return `ENOSYS`.

**No file locking.** `flock()` returns `ENOSYS`. POSIX advisory locks (`fcntl F_SETLK`) are not implemented.

**No popen/system.** Shell execution (`popen`, `system`) returns `ENOSYS`/-1. There is no shell binary on the system yet.

**Regex limitations.** The regex engine is a backtracking NFA, not a compiled DFA. It handles basic and extended regular expressions but may exhibit exponential behavior on pathological patterns.

## Build Pipeline

saltyc is built through four parallel compilation steps, then linked into a single shared object:

```
Step 1: Rust sources
  src/lib.rs ─── rustc ───> saltyc.o + saltyc.rmeta
                 --extern salty=libsalty.rmeta
                 --crate-type=lib

Step 2: Assembly sources
  crt_start.S ── clang -c ──> crt_start.o    (NOT linked into libc.so)
  setjmp.S   ── clang -c ──> setjmp.o

Step 3: C sources
  fts.c            ── clang -c ──> fts.o
  getopt.c         ── clang -c ──> getopt.o
  libutil_compat.c ── clang -c ──> libutil_compat.o
  md5.c            ── clang -c ──> md5.o
  cap_fileargs.c   ── clang -c ──> cap_fileargs.o
  xo_stub.c        ── clang -c ──> xo_stub.o

Step 4: Link
  saltyc.o + setjmp.o + fts.o + getopt.o + libutil_compat.o
  + md5.o + cap_fileargs.o + xo_stub.o + core.o
  + compiler_builtins.o
  ───> libc.so  (-shared, -T saltyc.ld, -soname libc.so)
```

`crt_start.o` is intentionally excluded from `libc.so` because it contains an unresolved reference to `main()`. Instead, it is linked directly into each C program's executable, providing the `_start` entry point.

C sources are compiled with `-ffreestanding -nostdlib -nostdinc -isystem lib/saltyc/include/` to use saltyc's own headers rather than the host system's.

## Cross-References

- **[ports.md](ports.md)** -- How saltyc enables cross-compilation of third-party C software
- **[posix.md](posix.md)** -- POSIX compatibility layer in libsalty that saltyc delegates to
- **[saltyc-api.md](../spec/saltyc-api.md)** -- Complete API reference with function signatures
