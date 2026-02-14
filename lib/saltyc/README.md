# saltyc

saltyc is the SaltyOS C standard library, shipped as `libc.so`. It provides POSIX-compatible C functions (stdio, stdlib, string, unistd, etc.) implemented in Rust, plus assembly stubs (setjmp/longjmp, CRT startup) and C source files (fts, getopt, md5) ported from FreeBSD. saltyc depends on libsalty for all system operations -- it translates C API calls into libsalty function calls, which in turn make IPC requests to kernel services.

## Directory Structure

```
lib/saltyc/
|-- meson.build              Build rules (rustc, clang, lld)
|-- saltyc.ld                Linker script for libc.so
|-- crt_start.S              C runtime entry point (_start -> __libc_start_main)
|-- setjmp.S                 setjmp/longjmp assembly (callee-saved register save/restore)
|-- fts.c                    BSD file tree stream (FTS) — ported from FreeBSD
|-- getopt.c                 POSIX getopt + GNU getopt_long — ported from FreeBSD
|-- libutil_compat.c         BSD utility functions (expand_number, fgetln)
|-- md5.c                    RFC 1321 MD5 implementation
|-- cap_fileargs.c           Capsicum fileargs wrapper (compatibility stub)
|-- xo_stub.c               libxo text-mode stub (xo_emit -> printf)
|-- src/
|   |-- lib.rs               Crate root (29 modules)
|   |-- crt.rs               C runtime: __libc_start_main, auxv parsing, atexit, exit
|   |-- stdio.rs             FILE-based I/O: fopen, fprintf, fread, fwrite, printf, snprintf
|   |-- string.rs            String functions: strlen, strcpy, strcmp, memcpy, strstr, strtok
|   |-- mem.rs               Memory functions: memset, memcmp, memmove, bzero
|   |-- malloc.rs            Heap allocator: malloc, calloc, realloc, free (sbrk-based)
|   |-- unistd.rs            POSIX unistd: read, write, close, fork, execve, getpid, pipe, chdir
|   |-- process.rs           Process control: waitpid, kill, system, popen/pclose
|   |-- stdlib_impl.rs       stdlib: atoi, strtol, strtoul, qsort, bsearch, mkstemp, realpath
|   |-- signal_impl.rs       Signal functions: signal, sigaction, sigprocmask, raise
|   |-- env.rs               Environment: getenv, setenv, unsetenv, environ
|   |-- errno.rs             Thread-local errno via __errno_location
|   |-- ctype.rs             Character classification: isalpha, isdigit, toupper, tolower
|   |-- dirent_impl.rs       Directory functions: opendir, readdir, closedir
|   |-- time_impl.rs         Time functions: time, gmtime, localtime, strftime, mktime
|   |-- math_impl.rs         Math functions: floor, ceil, sqrt, pow, fabs, log, sin, cos
|   |-- regex.rs             POSIX regex: regcomp, regexec, regfree, regerror
|   |-- wchar.rs             Wide character stubs: wcwidth, wcslen, mbrtowc, mbtowc
|   |-- glob_impl.rs         POSIX glob/globfree pattern matching
|   |-- select_impl.rs       select() wrapper (converts to poll)
|   |-- termios.rs           Terminal I/O: tcgetattr, tcsetattr, cfgetospeed
|   |-- termcap.rs           termcap/terminfo: tgetent, tgetstr, tgetnum, tputs, tgoto
|   |-- ioctl.rs             ioctl wrapper
|   |-- jobctl.rs            Job control: tcgetpgrp, tcsetpgrp
|   |-- locale.rs            Locale stubs: setlocale, localeconv, nl_langinfo
|   |-- pwd_impl.rs          Password database: getpwnam, getpwuid, getlogin
|   |-- sysinfo.rs           System info: uname, sysconf, getpagesize
|   |-- err_impl.rs          BSD error functions: err, errx, warn, warnx
|   |-- misc_impl.rs         Miscellaneous: getprogname, setprogname, mergesort, heapsort
|   |-- compat/              FreeBSD compatibility layer
|   |   |-- mod.rs            Module root
|   |   |-- freebsd/
|   |       |-- mod.rs        FreeBSD submodule root
|   |       |-- rune.rs       _RuneLocale / ctype integration
|   |       |-- capsicum.rs   Capsicum cap_rights stubs
|   |       |-- bsd_io.rs     BSD I/O helpers (fgetln shim)
|   |       |-- bsd_flags.rs  fflagstostr / strtofflags
|   |       |-- bsd_misc.rs   arc4random, getbsize, humanize_number, login_cap stubs
|   |       |-- bsd_sort.rs   mergesort, heapsort implementations
|   |       |-- mntent.rs     getmntent stub
|   |       |-- statvfs.rs    statvfs stub
|-- include/                 C headers (72 files)
    |-- assert.h, ctype.h, dirent.h, errno.h, fcntl.h, ...
    |-- stdio.h, stdlib.h, string.h, strings.h, unistd.h, ...
    |-- signal.h, setjmp.h, termios.h, regex.h, glob.h, ...
    |-- math.h, limits.h, locale.h, time.h, pwd.h, grp.h, ...
    |-- poll.h, getopt.h, fnmatch.h, fts.h, err.h, ...
    |-- md5.h, libutil.h, libcasper.h, login_cap.h, ...
    |-- sys/
    |   |-- types.h, stat.h, wait.h, mman.h, ioctl.h, ...
    |   |-- socket.h, un.h, select.h, time.h, utsname.h, ...
    |   |-- param.h, cdefs.h, uio.h, file.h, resource.h, ...
    |-- casper/
    |   |-- cap_fileargs.h, cap_net.h
    |-- libxo/
        |-- xo.h
```

## Build Pipeline

saltyc is built via Meson with four compilation steps, then linked into `libc.so`:

```
Step 1: rustc
  src/lib.rs  -->  saltyc.o + saltyc.rmeta
  Depends on: libsalty.rmeta (--extern salty=libsalty.rmeta)
  Flags: --edition=2024 --target=x86_64-unknown-none
         -C panic=abort -C opt-level=2
         -C code-model=small -C relocation-model=pic

Step 2: clang (assembly)
  crt_start.S  -->  crt_start.o   (NOT linked into libc.so)
  setjmp.S     -->  setjmp.o

Step 3: clang (C sources)
  fts.c             -->  fts.o
  getopt.c          -->  getopt.o
  libutil_compat.c  -->  libutil_compat.o
  md5.c             -->  md5.o
  cap_fileargs.c    -->  cap_fileargs.o
  xo_stub.c         -->  xo_stub.o
  Flags: -ffreestanding -nostdlib -nostdinc -fPIC
         -isystem include/

Step 4: lld (via clang -fuse-ld=lld)
  saltyc.o + setjmp.o + fts.o + getopt.o + libutil_compat.o
  + md5.o + cap_fileargs.o + xo_stub.o + core.o + compiler_builtins.o
    --> libc.so
  Linked with: -shared -nostdlib -nostartfiles
               -Wl,-soname,libc.so
               -T saltyc.ld
```

**Note:** `crt_start.o` is deliberately excluded from `libc.so`. It contains `_start` which calls `main()`, so it must be linked directly into each C program binary to avoid an unresolved `main` symbol in the shared library.

## How to Add a New Function

1. **Implement** the function in the appropriate `src/*.rs` module (or create a new module and add `pub mod` to `src/lib.rs`). Use `#[unsafe(no_mangle)] pub extern "C" fn` with the standard C name.

2. **Declare** the function in the corresponding `include/*.h` header file so C programs can find it.

3. **Delegate** to libsalty if the function requires a system operation. For example, a new file operation would call `salty::posix::posix_*()` internally.

4. **Rebuild**: run `just distclean && just setup && just build` if you added a new source file or module (Meson auto-discovers `.rs` files only during `meson setup`).

## Related Documentation

- [Ports build system](../../docs/design/ports.md) -- how FreeBSD utilities are cross-compiled against saltyc
- [POSIX compatibility](../../docs/design/posix.md) -- which POSIX interfaces are implemented and how
- [libsalty README](../libsalty/README.md) -- the system library that saltyc delegates to
