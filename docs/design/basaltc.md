# basaltc -- C Standard Library

This document describes the design and implementation of basaltc, SaltyOS's C standard library.

## Overview

basaltc is a C standard library (`libc.so`) implemented primarily in Rust, providing a POSIX.1-2008 subset plus BSD extensions sufficient to run ported FreeBSD userland utilities (ls, cat, etc.). It is not a standalone library -- all system operations are delegated to trona, which communicates with kernel services via IPC. This layered design means basaltc never issues syscalls directly; it translates C calling conventions into trona's Rust API.

The library targets SaltyOS on x86_64 and aarch64. Multi-threading is supported via POSIX pthreads (mutexes, condition variables, barriers, semaphores, TLS). This dual-arch, multi-threaded design provides the foundation for a fully self-hosting OS.

## Design Goals

**Port-compatible.** The primary goal is to compile unmodified FreeBSD utility source code. Function signatures, errno values, header layouts, and struct definitions match what ported C code expects. Where FreeBSD's libc exposes internal symbols (e.g., `__stdoutp`, `___runetype`, `__swbuf`), basaltc provides them.

**Minimal footprint.** The library uses static allocation wherever possible -- fixed-size pools for FILE streams (16), DIR handles (16), environment variables (128), and atexit handlers (32). The only dynamic allocation is through the malloc subsystem, which itself uses a simple sbrk-backed free list.

**Rust safety at the boundary.** Although the exported C ABI functions are inherently unsafe (raw pointers, no lifetime tracking), the internal implementations use Rust's type system where practical. Each `unsafe` block is scoped tightly around the actual pointer dereference or FFI call.

**Single-user simplicity.** SaltyOS has one user (root, uid=0). The password database, group database, and UID/GID accessors return hardcoded values. Permission checks always succeed. This eliminates the complexity of NSS, PAM, and shadow password files.

## Architecture

### Runtime Stack

```
+------------------------------------------------+
|         C program (main, compiled by clang)     |
+------------------------------------------------+
|  crt_start.o  |       libc.so (basaltc)          |
|   [_start]    |  [stdio, malloc, string, ...]   |
+------------------------------------------------+
|            libtrona.so (Rust)                    |
|  [syscall wrappers, POSIX layer, IPC helpers]   |
+------------------------------------------------+
|           SaltyOS kernel (Rust)                  |
|  [IPC endpoints, capability invocations]         |
+------------------------------------------------+
```

The startup sequence:

1. The dynamic linker (`rtld`) loads `libc.so` and `libtrona.so`, then calls `_start` in `crt_start.o`
2. `_start` (assembly) passes `main` and the stack pointer to `__libc_start_main`
3. `__libc_start_main` (Rust) parses argc/argv/envp/auxv, initializes IPC context, memory manager, locale tables, and program name
4. `main()` is called
5. On return, `exit()` runs atexit handlers, flushes stdio, and calls `_exit()`

### Module Table

| Module | Source | Purpose | Backend |
|--------|--------|---------|---------|
| `crt.rs` | Rust | CRT startup, atexit, exit | trona IPC + posix_mm init |
| `stdio.rs` | Rust | Buffered I/O (FILE), printf/scanf | trona posix_read/write |
| `malloc.rs` | Rust | malloc/free/realloc/calloc | trona posix_sbrk |
| `string.rs` | Rust | strlen, strcmp, strcpy, strlcpy, strerror | Pure Rust |
| `mem.rs` | Rust | memcpy, memset, memmove, memcmp | Pure Rust (compiler intrinsics) |
| `ctype.rs` | Rust | isalpha, isdigit, toupper, etc. | Pure Rust (lookup table) |
| `unistd.rs` | Rust | open, close, read, write, stat, mmap, *at() | trona posix_* |
| `process.rs` | Rust | fork, exec*, waitpid, kill, getpid, uid/gid | trona posix_* |
| `signal.rs` | Rust | signal, sigaction, sigprocmask, sigset ops | trona notifications |
| `dirent.rs` | Rust | opendir, readdir, closedir, scandir, alphasort | trona posix_opendir/readdir |
| `env.rs` | Rust | getenv, setenv, unsetenv, environ | Static array (128 entries) |
| `errno.rs` | Rust | errno global, __errno_location | Static `ERRNO` variable |
| `time.rs` | Rust | time, gmtime, localtime, mktime, strftime, tzset | trona posix_clock_gettime |
| `stdlib.rs` | Rust | atoi, strtol, strtod, qsort, bsearch, rand | Pure Rust |
| `locale.rs` | Rust | setlocale (C-only), localeconv, gettext, nl_langinfo | Pure Rust (hardcoded C locale) |
| `wchar.rs` | Rust | Wide char/multibyte (UTF-8, MB_CUR_MAX=4) | Pure Rust (full UTF-8 codec) |
| `regex.rs` | Rust | POSIX BRE/ERE regex (backtracking NFA) | Pure Rust |
| `sysinfo.rs` | Rust | uname, sysconf, getrlimit, gethostname | Pure Rust (hardcoded values) |
| `pwd.rs` | Rust | getpwnam, getpwuid, getgrnam, user_from_uid | Pure Rust (root-only) |
| `glob.rs` | Rust | glob() pathname pattern matching | trona posix_opendir |
| `select.rs` | Rust | select/pselect wrappers | trona posix_select |
| `math.rs` | Rust | Math functions (fabs, sqrt, pow, sin, etc.) | Pure Rust + x87/NEON |
| `misc.rs` | Rust | dirname, basename, utime, syslog stubs | Mixed |
| `pthread.rs` | Rust | pthreads, mutexes, condvars, semaphores, TLS | trona::sync / trona::tls |
| `search.rs` | Rust | tsearch, tfind, tdelete, twalk | Pure Rust |
| `dlfcn.rs` | Rust | dlopen/dlsym/dlclose/dladdr/dl_iterate_phdr/dlfunc/dlerror C ABI shims | Dispatches into rtld via `RtldDlfcnV1` (see `docs/spec/rtld-loader.md` § 11) |
| `socket.rs` | Rust | Socket API (socket, bind, connect, etc.) | trona posix_socket |
| `inet.rs` | Rust | inet_aton, htonl, getservbyname, etc. | Pure Rust |
| `netif.rs` | Rust | if_nametoindex, if_indextoname | Pure Rust |
| `getrandom.rs` | Rust | getrandom, getentropy | trona::syscall (`KernelRng`) |
| `getopt.rs` | Rust | POSIX getopt + GNU getopt_long/getopt_long_only | Pure Rust |
| `fts.rs` | Rust | BSD file tree stream (fts_open, fts_read, etc.) | opendir/stat |
| `iconv.rs` | Rust | Character encoding conversion (8 encodings) | Pure Rust |
| `termios.rs` | Rust | Terminal I/O stubs | Returns defaults |
| `termcap.rs` | Rust | termcap/terminfo stubs | Returns defaults |
| `ioctl.rs` | Rust | ioctl stubs | trona posix_ioctl |
| `jobctl.rs` | Rust | Job control stubs (setpgid, tcgetpgrp) | Hardcoded returns |
| `stack_protector.rs` | Rust | Stack smashing detection (`__stack_chk_fail`) | Pure Rust |
| `compat/` | Rust | FreeBSD compatibility layer | See below |
| `arch/x86_64/` | ASM + Rust | x86_64: crt_start.S, setjmp.S, math_x87.rs, math_sse2.rs, mem_sse2.rs, string_sse2.rs | Register save/restore, x87 FPU, SSE2 intrinsics |
| `arch/aarch64/` | ASM + Rust | aarch64: crt_start.S, setjmp.S, mod.rs | Register save/restore, scalar FP instructions (fsqrt, frintp), no NEON optimization yet |

## Key Design Decisions

### Why Rust for a C Library

Writing a C standard library in Rust is unusual but practical here:

1. **Shared toolchain.** SaltyOS already uses Rust everywhere (kernel, trona, userland). Adding a C-only library would require maintaining separate build infrastructure.
2. **Backend reuse.** Most basaltc functions are thin wrappers around trona's Rust API. Writing them in Rust means direct function calls instead of FFI thunks.
3. **Controlled unsafety.** Each `unsafe` block is narrow and documented. The Rust compiler catches logic errors in the safe portions (off-by-one, type mismatches) that would silently compile in C.
4. **No performance penalty.** The exported functions use `extern "C"` ABI. From the caller's perspective, they are indistinguishable from C implementations.

The tradeoff is reliance on nightly Rust features (`c_variadic` for printf/scanf families, `linkage` for weak symbols).

### Static Allocation Strategy

All pools use fixed-size arrays in static memory:

| Resource | Pool Size | Location |
|----------|-----------|----------|
| FILE streams | 16 (3 reserved for std*) | `stdio.rs: OPEN_FILES` |
| DIR handles | 16 | `dirent.rs: DIR_POOL` |
| Environment vars | 128 | `env.rs: ENV_PTRS` |
| atexit handlers | 32 | `crt.rs: ATEXIT_FUNCS` |

This eliminates any dependency on malloc during early startup and prevents allocation failures in resource management code. The limits are sufficient for ported utilities -- FreeBSD's ls, cat, and similar tools rarely open more than a handful of files simultaneously.

### errno Implementation

errno is a single `static mut ERRNO: i32` protected by a spinlock. The `__errno_location()` function returns its address, matching the Linux ABI that C headers expand `errno` to `(*__errno_location())`.

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

A first-fit free-list allocator backed by `sbrk()` (via trona's `posix_sbrk`). Every allocation has a 16-byte `BlockHeader` placed immediately before the returned pointer:

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

The CRT startup parses the standard ELF auxiliary vector plus one
SaltyOS-private pointer, `AT_SALTYOS_STARTUP`, to discover per-process
resources. The referenced `SaltyOSStartupLayoutV1` carries bootstrap-only
addresses and pointers such as the IPC buffer, dynamic-loader window,
CSpace layout pointer, and embedded capability-table pointer.

The RTLD may consume slots while loading shared libraries, so it publishes
the post-startup cursor in `TronaRuntimeV1.next_free_slot` while leaving
`SaltyOSStartupLayoutV1` bootstrap-only. The shared `SaltyOSCspaceLayoutV1`
still describes the slot ranges available to the process.

After slot allocation setup, the heap region is placed relative to the
planned process layout rather than a legacy scratch auxv tag.

## SaltyOS Auxv Entries

| Tag | Name | Type | Description |
|-----|------|------|-------------|
| `0x0000` | `AT_NULL` | - | End of auxv |
| `0x0003` | `AT_PHDR` | vaddr | Main executable program-header table |
| `0x0007` | `AT_BASE` | vaddr | Runtime linker base address |
| `0x2005` | `AT_SALTYOS_STARTUP` | ptr | Pointer to validated `SaltyOSStartupLayoutV1` |

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

### Compat Rust Modules

FreeBSD compatibility code that was previously in C has been converted to Rust:

| Module | Purpose |
|--------|---------|
| `compat/freebsd/cap_fileargs.rs` | Capsicum fileargs wrapper (open/fopen/lstat delegation) |
| `compat/freebsd/xo.rs` | libxo text-mode stub (xo_emit → vfprintf) |
| `compat/freebsd/md5.rs` | RFC 1321 MD5 hash (used by sort -R) |
| `compat/freebsd/libutil.rs` | expand_number, humanize_number, fgetln |

### Headers

basaltc provides 105 headers in `lib/basalt/c/include/` organized to match standard POSIX/BSD layout:

- Standard C: `stdio.h`, `stdlib.h`, `string.h`, `ctype.h`, `errno.h`, `math.h`, `stdint.h`, `stddef.h`, `stdarg.h`, `stdbool.h`, `limits.h`, `assert.h`, `setjmp.h`, `inttypes.h`, `time.h`, `locale.h`, `wchar.h`, `wctype.h`, `signal.h`, `fcntl.h`
- POSIX: `unistd.h`, `dirent.h`, `pwd.h`, `grp.h`, `poll.h`, `regex.h`, `fnmatch.h`, `glob.h`, `getopt.h`, `termios.h`, `sched.h`, `libgen.h`, `utime.h`
- sys/: `sys/types.h`, `sys/stat.h`, `sys/wait.h`, `sys/mman.h`, `sys/select.h`, `sys/socket.h`, `sys/un.h`, `sys/time.h`, `sys/times.h`, `sys/ioctl.h`, `sys/utsname.h`, `sys/resource.h`, `sys/uio.h`, `sys/file.h`, `sys/param.h`, `sys/cdefs.h`, `sys/statvfs.h`, `sys/mount.h`, `sys/sysctl.h`, `sys/capsicum.h`, `sys/acl.h`, `sys/mac.h`
- FreeBSD-specific: `err.h`, `fts.h`, `paths.h`, `sysexits.h`, `libutil.h`, `login_cap.h`, `osreldate.h`, `mntent.h`, `termcap.h`, `md5.h`, `capsicum_helpers.h`, `libcasper.h`, `casper/cap_net.h`, `casper/cap_fileargs.h`, `libxo/xo.h`

## Limitations

**C locale only.** `setlocale()` always returns "C". All character classification is ASCII. Wide character and multibyte functions support full UTF-8 (MB_CUR_MAX=4), but locale switching is not implemented.

**No timezone database.** Timezone support is via the POSIX `TZ` environment variable only (e.g., `TZ=EST5EDT,M3.2.0,M11.1.0`). There is no `/usr/share/zoneinfo` or binary TZ file support. `tzset()` parses POSIX TZ strings with full DST transition rule support (Mm.w.d format). Without `TZ`, the default is UTC.

**Runtime dlfcn lives in the rtld.** libc's `dlfcn.rs` is a thin C ABI shim; the runtime dynamic linker (`ldtrona-elf.so`) owns `dlopen` / `dlsym` / `dlclose` / `dladdr` / `dl_iterate_phdr` and the dynamic TLS DTV. RTLD_NEXT, RTLD_DEFAULT, RTLD_GLOBAL, RTLD_LOCAL, RTLD_NOLOAD, and RTLD_NODELETE are implemented. See `docs/spec/rtld-loader.md` § 11 for the full ABI.

**No device nodes.** `mknod()`, `mknodat()` return `ENOSYS`.

**No file locking.** `flock()` returns `ENOSYS`. POSIX advisory locks (`fcntl F_SETLK`) are not implemented.

**iconv encoding subset.** iconv supports 8 encodings (UTF-8, ASCII, ISO-8859-1, ISO-8859-15, UTF-16LE/BE, UTF-32LE/BE). CJK encodings (Shift-JIS, EUC-JP, GB2312, etc.) are not implemented.

**Regex limitations.** The regex engine is a backtracking NFA, not a compiled DFA. It handles basic and extended regular expressions but may exhibit exponential behavior on pathological patterns.

## Build Pipeline

basaltc is built in three steps, then linked into a single shared object. Most libc policy remains in Rust, while all ISA instructions live in explicit per-architecture `.S` files under `src/arch/<arch>/`:

```
Step 1: Rust sources
  src/lib.rs ─── rustc ───> basaltc.o + basaltc.rmeta
                 --extern trona=trona.rmeta
                 --crate-name=basaltc

Step 2: Assembly sources
  crt_start.S ── clang -c ──> crt_start.o    (NOT linked into libc.so)
  setjmp.S   ── clang -c ──> setjmp.o
  math*.S    ── clang -c ──> basaltc_math*.o
  mem*.S     ── clang -c ──> basaltc_mem*.o
  string*.S  ── clang -c ──> basaltc_string*.o
  misc.S     ── clang -c ──> basaltc_misc.o

Step 3: Link
  basaltc.o + setjmp.o + arch asm objects + core.o + compiler_builtins.o
  ───> libc.so  (-shared, -T arch/<ARCH>/basaltc.ld, -soname libc.so)
```

`crt_start.o` is intentionally excluded from `libc.so` because it contains an unresolved reference to `main()`. Instead, it is linked directly into each C program's executable, providing the `_start` entry point.

A separate freestanding `string.c` provides basic string/memory functions for the statically-linked `init` binary, which cannot use `libc.so`.

## Cross-References

- **[ports.md](ports.md)** -- How basaltc enables cross-compilation of third-party C software (16 ports)
- **[posix.md](posix.md)** -- POSIX compatibility layer in trona that basaltc delegates to
- **[trona.md](trona.md)** -- System library (5-crate architecture) that basaltc depends on
- **[basaltc-api.md](../spec/basaltc-api.md)** -- Complete API reference with function signatures
