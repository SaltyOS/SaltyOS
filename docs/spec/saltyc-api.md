# besaltc API Reference

SaltyOS C Standard Library — POSIX and BSD-compatible C functions implemented in
Rust. All functions use C ABI (`extern "C"`) and are linked into executables via
`libbesalt.so`.

**Status key:** **F** = full implementation, **P** = partial (reduced functionality),
**S** = stub (returns ENOSYS/-1/no-op).

**Source:** `lib/besalt/c/src/`

---

## Table of Contents

- [stdio.h](#stdioh)
- [stdlib.h](#stdlibh)
- [string.h](#stringh)
- [ctype.h](#ctypeh)
- [errno.h](#errnoh)
- [unistd.h](#unistdh)
- [fcntl.h](#fcntlh)
- [sys/stat.h](#sysstat-h)
- [sys/mman.h](#sysmmanh)
- [sys/socket.h](#syssocketh)
- [sys/select.h](#sysselecth)
- [poll.h](#pollh)
- [sys/wait.h](#syswaith)
- [signal.h](#signalh)
- [time.h / sys/time.h](#timeh--systimeh)
- [math.h](#mathh)
- [dirent.h](#direnth)
- [termios.h](#termiosh)
- [termcap.h](#termcaph)
- [regex.h](#regexh)
- [glob.h / fnmatch.h](#globh--fnmatchh)
- [pwd.h](#pwdh)
- [grp.h](#grph)
- [locale.h](#localeh)
- [wchar.h / wctype.h](#wcharh--wctypeh)
- [err.h](#errh)
- [sysexits.h](#sysexitsh)
- [sys/utsname.h](#sysutsnameh)
- [sys/resource.h](#sysresourceh)
- [sys/ioctl.h](#sysioctlh)
- [getopt (unistd.h)](#getopt-unistdh)
- [setjmp.h](#setjmph)
- [environ / env](#environ--env)
- [fts.h](#ftsh)
- [mntent.h](#mntenth)
- [sys/statvfs.h](#sysstatvfsh)
- [sys/capsicum.h (FreeBSD)](#syscapsicumh-freebsd)
- [FreeBSD Compat — Sorting](#freebsd-compat--sorting)
- [FreeBSD Compat — File Flags](#freebsd-compat--file-flags)
- [FreeBSD Compat — Rune / Locale Internals](#freebsd-compat--rune--locale-internals)
- [FreeBSD Compat — Miscellaneous](#freebsd-compat--miscellaneous)
- [Miscellaneous POSIX](#miscellaneous-posix)
- [CRT / Process Startup](#crt--process-startup)
- [Design Notes](#design-notes)

---

## stdio.h

Source: `stdio.rs`

Max 16 simultaneously open `FILE` streams. Each has a 1024-byte internal buffer.
Three predefined streams: `stdin` (fd 0), `stdout` (fd 1, line-buffered),
`stderr` (fd 2, unbuffered). FreeBSD aliases `__stdinp`, `__stdoutp`,
`__stderrp`, and `__isthreaded` (always 0) are exported.

| Function | St | Notes |
|---|---|---|
| `fopen` | F | Modes: r, w, a, r+, w+, a+ |
| `fdopen` | F | Wraps existing fd in FILE |
| `fclose` | F | Flushes, releases from static pool |
| `freopen` | F | Closes old stream, opens new on same FILE slot |
| `fflush` | F | NULL flushes all open streams |
| `fgetc` | F | Refills buffer on empty |
| `getchar` | F | `fgetc(stdin)` |
| `getc` | F | Same as `fgetc` |
| `ungetc` | F | Single-byte pushback |
| `fputc` | F | Flushes on newline (line-buffered) or full buffer |
| `putchar` | F | `fputc(c, stdout)` |
| `putc` | F | Same as `fputc` |
| `fputs` | F | Does not append newline |
| `puts` | F | Appends newline, writes to stdout |
| `fgets` | F | Reads up to n-1 chars or newline |
| `fread` | F | Binary read, returns items read |
| `fwrite` | F | Binary write, returns items written |
| `fseek` | F | SEEK_SET/SEEK_CUR/SEEK_END via VFS lseek |
| `ftell` | F | Returns current position |
| `rewind` | F | `fseek(f, 0, SEEK_SET)` + clear error |
| `fileno` | F | Returns underlying fd |
| `ferror` | F | Returns error flag |
| `feof` | F | Returns EOF flag |
| `clearerr` | F | Clears both error and EOF flags |
| `setvbuf` | F | _IOFBF, _IOLBF, _IONBF |
| `setbuf` | F | Wrapper around `setvbuf` |
| `setlinebuf` | F | Sets stream to line-buffered |
| `printf` | F | Full format engine (see below) |
| `fprintf` | F | To arbitrary stream |
| `vprintf` | F | va_list variant |
| `vfprintf` | F | va_list variant |
| `sprintf` | F | To buffer (no overflow check) |
| `snprintf` | F | To buffer with size limit |
| `vsprintf` | F | va_list variant |
| `vsnprintf` | F | va_list variant; core engine for all printf |
| `dprintf` | F | To file descriptor |
| `asprintf` | F | malloc-allocated result |
| `vasprintf` | F | va_list variant |
| `sscanf` | F | Full scanset support ([...]) |
| `vsscanf` | F | Core engine; supports %d/%i/%u/%x/%o/%s/%c/%n/%[...] |
| `perror` | F | Prints to stderr with strerror |
| `remove` | F | Delegates to VFS unlink |
| `rename` | F | Delegates to VFS rename |
| `open_memstream` | P | Returns a FILE backed by malloc buffer; fclose writes NUL |
| `tmpfile` | F | Creates /tmp/tmpXXXXXX and unlinks immediately |
| `mkstemp` | F | Template-based temp file creation |
| `getdelim` | F | Read until delimiter, malloc-grows buffer |
| `getline` | F | `getdelim` with '\n' delimiter |
| `fseeko` | F | Alias for `fseek` (off_t is i64) |
| `ftello` | F | Alias for `ftell` |

**printf format specifiers:** `%d`, `%i`, `%u`, `%x`/`%X`, `%o`, `%s`, `%c`,
`%p`, `%f`, `%e`/`%E`, `%g`/`%G`, `%n`, `%ld`/`%li`/`%lu`/`%lx`/`%lo`,
`%lld`/`%lli`/`%llu`/`%llx`/`%llo`, `%zd`/`%zu`/`%zx`, `%jd`/`%ju`.
Flags: `-`, `+`, ` `, `0`, `#`. Width and precision supported (including `*`).

---

## stdlib.h

Source: `stdlib_impl.rs`, `malloc.rs`, `process.rs`

### Memory Allocation (malloc.rs)

sbrk-based first-fit allocator with 16-byte aligned blocks. Coalesces adjacent
free blocks on `free()`. No thread safety.

| Function | St | Notes |
|---|---|---|
| `malloc` | F | 16-byte aligned; sbrk backend |
| `free` | F | Bidirectional coalescing |
| `realloc` | F | malloc + copy + free |
| `calloc` | F | malloc + zero-fill |
| `posix_memalign` | F | Aligned allocation (power-of-2 alignment) |
| `strdup` | F | malloc + strcpy |
| `strndup` | F | malloc + bounded copy |

### Conversions and Utilities (stdlib_impl.rs)

| Function | St | Notes |
|---|---|---|
| `atoi` | F | Delegates to `strtol` |
| `atol` | F | Delegates to `strtol` |
| `atoll` | F | Delegates to `strtoll` |
| `strtol` | F | Base 0/2-36, overflow to LONG_MIN/MAX + ERANGE |
| `strtoll` | F | 64-bit variant |
| `strtoul` | F | Unsigned variant |
| `strtoull` | F | Unsigned 64-bit variant |
| `strtoimax` | F | Alias for `strtoll` |
| `strtoumax` | F | Alias for `strtoull` |
| `strtod` | F | Integer + fractional + exponent parsing |
| `strtof` | F | Truncates `strtod` result |
| `strtold` | F | Alias for `strtod` (no true long double) |
| `qsort` | F | Insertion sort with stack/heap swap buffer |
| `bsearch` | F | Standard binary search |
| `abs` | F | |
| `labs` | F | |
| `llabs` | F | |
| `div` | F | |
| `ldiv` | F | |
| `lldiv` | F | |
| `srand` | F | Seeds LCG PRNG |
| `srandom` | F | Alias for `srand` |
| `rand` | F | LCG: `seed * 6364136223846793005 + 1` |
| `random` | F | Alias for `rand` |
| `rand_r` | F | Reentrant LCG |
| `system` | S | Returns -1 (no shell) |
| `realpath` | P | Copies path without resolution (no symlinks/`.`/`..` processing) |
| `mktemp` | P | Simple counter-based template fill |
| `mkdtemp` | S | Returns NULL / ENOSYS |

### Process Control (process.rs, crt.rs)

| Function | St | Notes |
|---|---|---|
| `exit` | F | Calls atexit handlers, then `_exit` |
| `_exit` | F | Immediate process termination via `posix_exit` |
| `_Exit` | F | Alias for `_exit` |
| `atexit` | F | Max 32 handlers (static array) |
| `abort` | F | Sends SIGABRT to self, then `_exit(134)` |

---

## string.h

Source: `string.rs`, `mem.rs`

### NUL-terminated String Operations (string.rs)

| Function | St | Notes |
|---|---|---|
| `strlen` | F | |
| `strnlen` | F | |
| `strcpy` | F | |
| `strncpy` | F | NUL-pads to n |
| `stpcpy` | F | Returns pointer to terminating NUL |
| `stpncpy` | F | |
| `strcmp` | F | |
| `strncmp` | F | |
| `strcasecmp` | F | ASCII case-folding only |
| `strncasecmp` | F | ASCII case-folding only |
| `strchr` | F | |
| `strrchr` | F | |
| `strchrnul` | F | Returns pointer to NUL if not found |
| `strcat` | F | |
| `strncat` | F | |
| `strstr` | F | |
| `strcasestr` | F | Case-insensitive substring search |
| `strpbrk` | F | |
| `strspn` | F | |
| `strcspn` | F | |
| `strtok` | F | Uses static state (not reentrant) |
| `strtok_r` | F | Reentrant variant |
| `strcoll` | F | Same as `strcmp` (C locale) |
| `strxfrm` | F | Copies string (C locale — no transformation) |
| `strerror` | F | 13-entry table covering common errno values |
| `strerror_r` | F | Reentrant variant |
| `strsignal` | F | 23-entry table (signals 1-22) |
| `strlcpy` | F | BSD: always NUL-terminates, returns src length |
| `strlcat` | F | BSD: always NUL-terminates, returns combined length |

### Memory Operations (mem.rs)

Compiler intrinsics — byte-level implementations.

| Function | St | Notes |
|---|---|---|
| `memcpy` | F | |
| `memset` | F | |
| `memmove` | F | Handles overlapping regions |
| `memcmp` | F | |
| `mempcpy` | F | Returns pointer past copied region |
| `memchr` | F | |
| `memrchr` | F | Reverse search |
| `bzero` | F | Delegates to `memset` |
| `bcopy` | F | Delegates to `memmove` (note: args are (src, dst)) |
| `explicit_bzero` | F | Volatile byte-by-byte writes (not optimized away) |

---

## ctype.h

Source: `ctype.rs`

ASCII-only (128-entry lookup table with bitmask flags). Characters >= 128 are
classified as 0 (no flags set). All functions take `int` and return `int`.

| Function | St | Notes |
|---|---|---|
| `isalpha` | F | A-Z, a-z |
| `isdigit` | F | 0-9 |
| `isalnum` | F | Alpha or digit |
| `isspace` | F | Space, tab, newline, CR, FF, VT |
| `isupper` | F | A-Z |
| `islower` | F | a-z |
| `isprint` | F | 0x20-0x7E |
| `iscntrl` | F | 0x00-0x1F, 0x7F |
| `ispunct` | F | Printable non-alnum non-space |
| `isxdigit` | F | 0-9, A-F, a-f |
| `isgraph` | F | Printable non-space |
| `isascii` | F | 0x00-0x7F |
| `isblank` | F | Space, tab |
| `toupper` | F | ASCII only |
| `tolower` | F | ASCII only |
| `toascii` | F | Masks to 7 bits |

---

## errno.h

Source: `errno.rs`

Single global `static mut ERRNO` — not thread-safe (single-threaded assumption).
Uses Linux errno numbering.

| Function | St | Notes |
|---|---|---|
| `__errno_location` | F | Returns `&mut ERRNO` |

Defined constants (50+): `EPERM`(1), `ENOENT`(2), `ESRCH`(3), `EINTR`(4),
`EIO`(5), `ENXIO`(6), `E2BIG`(7), `ENOEXEC`(8), `EBADF`(9), `ECHILD`(10),
`EAGAIN`(11), `ENOMEM`(12), `EACCES`(13), `EFAULT`(14), `EBUSY`(16),
`EEXIST`(17), `EXDEV`(18), `ENODEV`(19), `ENOTDIR`(20), `EISDIR`(21),
`EINVAL`(22), `ENFILE`(23), `EMFILE`(24), `ENOTTY`(25), `EFBIG`(27),
`ENOSPC`(28), `ESPIPE`(29), `EROFS`(30), `EPIPE`(32), `EDOM`(33),
`ERANGE`(34), `EDEADLK`(35), `ENAMETOOLONG`(36), `ENOLCK`(37),
`ENOSYS`(38), `ENOTEMPTY`(39), `ELOOP`(40), `EWOULDBLOCK`(11),
`ENOTSOCK`(88), `EAFNOSUPPORT`(97), `EADDRINUSE`(98),
`EADDRNOTAVAIL`(99), `ENETUNREACH`(101), `ECONNABORTED`(103),
`ECONNRESET`(104), `ENOBUFS`(105), `EISCONN`(106), `ENOTCONN`(107),
`ETIMEDOUT`(110), `ECONNREFUSED`(111), `EALREADY`(114),
`EINPROGRESS`(115), `EOVERFLOW`(75), `EILSEQ`(84), `EOPNOTSUPP`(95),
`EPROTONOSUPPORT`(93).

---

## unistd.h

Source: `unistd.rs`

All file operations delegate to `libbesalt` POSIX wrappers which communicate
with the VFS server via IPC.

### File I/O

| Function | St | Notes |
|---|---|---|
| `open` | F | Flags: O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL, O_DIRECTORY, O_NONBLOCK, O_CLOEXEC |
| `creat` | F | `open(path, O_WRONLY\|O_CREAT\|O_TRUNC, mode)` |
| `close` | F | |
| `read` | F | |
| `write` | F | |
| `lseek` | F | SEEK_SET, SEEK_CUR, SEEK_END |
| `dup` | F | |
| `dup2` | F | |
| `dup3` | F | Supports O_CLOEXEC flag |
| `pipe` | F | Creates connected fd pair via VFS |
| `pipe2` | F | With O_CLOEXEC/O_NONBLOCK flags |
| `fcntl` | P | F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD; other cmds return 0 |
| `isatty` | F | Checks via VFS ioctl |
| `writev` | F | Scatter-gather write |
| `readv` | F | Scatter-gather read |
| `ftruncate` | F | Via VFS |
| `truncate` | S | Returns ENOSYS |
| `flock` | S | Returns 0 (no-op) |

### Directory Operations

| Function | St | Notes |
|---|---|---|
| `chdir` | F | Via VFS |
| `fchdir` | S | Returns ENOSYS |
| `getcwd` | F | Via VFS |
| `access` | F | Via VFS; checks F_OK/R_OK/W_OK/X_OK |
| `unlink` | F | Via VFS |
| `rmdir` | F | Via VFS |
| `mkdir` | F | Via VFS |
| `link` | S | Returns ENOSYS (no hard links) |
| `symlink` | S | Returns ENOSYS (no symlinks) |
| `readlink` | S | Returns ENOSYS |
| `mkfifo` | F | Creates named pipe via VFS |

### Stat Family

| Function | St | Notes |
|---|---|---|
| `stat` | F | Returns `struct stat` with st_mode, st_size, st_nlink, st_ino, st_dev, st_uid, st_gid, times |
| `lstat` | F | Same as `stat` (no symlinks) |
| `fstat` | F | By file descriptor |

`struct stat` includes FreeBSD-compatible fields: `st_flags` (u32),
`st_gen` (u32), `st_birthtim` (timespec).

### *at Family

| Function | St | Notes |
|---|---|---|
| `openat` | F | AT_FDCWD supported; absolute paths ignore dirfd |
| `fstatat` | F | AT_SYMLINK_NOFOLLOW accepted but ignored |
| `unlinkat` | F | AT_REMOVEDIR flag supported |
| `renameat` | F | |
| `mkdirat` | F | |
| `mknodat` | S | Returns ENOSYS |
| `faccessat` | F | |
| `fchmodat` | F | |
| `fchownat` | F | No-op (single user) |
| `linkat` | S | Returns ENOSYS |
| `symlinkat` | S | Returns ENOSYS |
| `readlinkat` | S | Returns ENOSYS |
| `utimensat` | F | Via VFS; UTIME_NOW supported |
| `futimens` | F | Via VFS |

### File Mode / Ownership

| Function | St | Notes |
|---|---|---|
| `umask` | F | Local static variable; default 0o022 |
| `chmod` | F | Via VFS |
| `fchmod` | F | Via VFS |
| `chown` | F | No-op, returns 0 (single user) |
| `fchown` | F | No-op, returns 0 |
| `lchown` | F | No-op, returns 0 |

### TTY

| Function | St | Notes |
|---|---|---|
| `ttyname` | F | Returns "/dev/console" for fds 0-2, NULL otherwise |
| `ttyname_r` | F | Reentrant variant |

### Sleep

| Function | St | Notes |
|---|---|---|
| `sleep` | F | Via `nanosleep` |
| `usleep` | F | Via `nanosleep` |
| `nanosleep` | F | Via kernel `NanoSleep` syscall |
| `alarm` | S | Returns 0 (no-op) |
| `pause` | S | Returns -1 / EINTR |

### Path/System Configuration

| Function | St | Notes |
|---|---|---|
| `pathconf` | F | _PC_NAME_MAX=255, _PC_PATH_MAX=4096, _PC_PIPE_BUF=4096, _PC_LINK_MAX=1 |
| `fpathconf` | F | Same as `pathconf` |
| `confstr` | F | _CS_PATH="/bin:/usr/bin" |

---

## fcntl.h

Source: `unistd.rs` (combined with unistd)

Open flags defined: `O_RDONLY`(0), `O_WRONLY`(1), `O_RDWR`(2), `O_CREAT`(0x40),
`O_EXCL`(0x80), `O_TRUNC`(0x200), `O_APPEND`(0x400), `O_NONBLOCK`(0x800),
`O_DIRECTORY`(0x10000), `O_CLOEXEC`(0x80000).

`AT_FDCWD`(-100), `AT_SYMLINK_NOFOLLOW`(0x100), `AT_REMOVEDIR`(0x200).

See [unistd.h](#unistdh) for `open`, `fcntl`, and `*at` functions.

---

## sys/stat.h

Source: `unistd.rs`

See [unistd.h — Stat Family](#stat-family) and [unistd.h — *at Family](#at-family).

Mode constants: `S_IFMT`(0o170000), `S_IFSOCK`(0o140000), `S_IFLNK`(0o120000),
`S_IFREG`(0o100000), `S_IFBLK`(0o060000), `S_IFDIR`(0o040000),
`S_IFCHR`(0o020000), `S_IFIFO`(0o010000), `S_ISUID`(0o4000),
`S_ISGID`(0o2000), `S_ISVTX`(0o1000).

Macros exported as functions: `S_ISREG`, `S_ISDIR`, `S_ISCHR`, `S_ISBLK`,
`S_ISFIFO`, `S_ISLNK`, `S_ISSOCK`.

---

## sys/mman.h

Source: `unistd.rs`

| Function | St | Notes |
|---|---|---|
| `mmap` | F | MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE; pages allocated via libbesalt posix_mmap |
| `munmap` | F | Via libbesalt posix_munmap |

Constants: `PROT_READ`(1), `PROT_WRITE`(2), `PROT_EXEC`(4), `PROT_NONE`(0),
`MAP_SHARED`(1), `MAP_PRIVATE`(2), `MAP_ANONYMOUS`(0x20), `MAP_FIXED`(0x10),
`MAP_FAILED`(-1 as pointer).

`shm_open`/`shm_unlink` are in `libbesalt` (not besaltc).

---

## sys/socket.h

Socket operations are in `libbesalt` (`posix.rs`) rather than besaltc. The besaltc
layer provides type definitions and constants used by ported programs.

Constants: `AF_UNIX`(1), `AF_LOCAL`(1), `SOCK_STREAM`(1), `SOCK_DGRAM`(2),
`SOCK_SEQPACKET`(5), `SOL_SOCKET`(1), `SO_REUSEADDR`(2), `SO_KEEPALIVE`(9),
`SO_RCVBUF`(8), `SO_SNDBUF`(7), `SCM_RIGHTS`(1), `MSG_DONTWAIT`(0x40).

Socket functions (`socket`, `bind`, `listen`, `accept`, `connect`, `send`,
`recv`, `sendmsg`, `recvmsg`, `sendto`, `recvfrom`, `getsockopt`, `setsockopt`,
`shutdown`, `socketpair`, `getpeername`, `getsockname`) are available through
`libbesalt::posix`.

---

## sys/select.h

Source: `select_impl.rs`

| Function | St | Notes |
|---|---|---|
| `select` | F | Converts fd_sets to PollFd array (max 128), calls posix_poll; timeout in struct timeval |
| `__fd_set` | F | FD_SET helper |
| `__fd_clr` | F | FD_CLR helper |
| `__fd_isset` | F | FD_ISSET helper |
| `__fd_zero` | F | FD_ZERO helper |

`FdSet` is a 1024-bit bitmap (128 bytes, matching `FD_SETSIZE`=1024).

---

## poll.h

`poll` is available through `libbesalt::posix::posix_poll`. The besaltc layer
provides the `select` wrapper (see above) which delegates to poll internally.

Constants: `POLLIN`(1), `POLLOUT`(4), `POLLERR`(8), `POLLHUP`(16),
`POLLNVAL`(32).

---

## sys/wait.h

Source: `process.rs`

| Function | St | Notes |
|---|---|---|
| `waitpid` | F | Via procmgr IPC; supports WNOHANG |
| `wait` | F | `waitpid(-1, status, 0)` |
| `wait3` | F | `waitpid(-1, status, options)` — rusage ignored |
| `wait4` | F | `waitpid(pid, status, options)` — rusage ignored |

Status macros (exported as functions): `WIFEXITED`, `WEXITSTATUS`,
`WIFSIGNALED`, `WTERMSIG`, `WIFSTOPPED`, `WSTOPSIG`.

Encoding: bits 7:0 = signal (0 if exited normally), bits 15:8 = exit code.

---

## signal.h

Source: `signal_impl.rs`

Notification-based signal delivery. 32 signals maximum. Signal handlers are
stored in shared `libbesalt` globals and dispatched from a notification-polling
trampoline.

| Function | St | Notes |
|---|---|---|
| `signal` | F | Installs handler via `sigaction`; returns previous handler |
| `sigaction` | F | Stores sa_handler/sa_mask/sa_flags; SA_SIGINFO not supported |
| `sigprocmask` | F | SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK; modifies libbesalt's mask |
| `sigsuspend` | S | Returns -1 / EINTR |
| `sigpending` | S | Returns 0 (empty set) |
| `sigemptyset` | F | |
| `sigfillset` | F | |
| `sigaddset` | F | |
| `sigdelset` | F | |
| `sigismember` | F | |
| `siginterrupt` | S | Returns 0 (no-op) |
| `kill` | F | Via procmgr IPC |
| `killpg` | F | `kill(-pgrp, sig)` |
| `raise` | F | `kill(getpid(), sig)` |

Defined signals: `SIGHUP`(1), `SIGINT`(2), `SIGQUIT`(3), `SIGILL`(4),
`SIGABRT`(6), `SIGFPE`(8), `SIGKILL`(9), `SIGSEGV`(11), `SIGPIPE`(13),
`SIGALRM`(14), `SIGTERM`(15), `SIGUSR1`(10), `SIGUSR2`(12), `SIGCHLD`(17),
`SIGCONT`(18), `SIGSTOP`(19), `SIGTSTP`(20), `SIGTTIN`(21), `SIGTTOU`(22),
`SIGWINCH`(28), `SIGINFO`(29), `SIGSYS`(31).

---

## time.h / sys/time.h

Source: `time_impl.rs`

UTC only — no timezone or DST support. `localtime` and `gmtime` return
identical results. The kernel's monotonic clock starts at zero on boot (not
wall-clock time).

| Function | St | Notes |
|---|---|---|
| `time` | F | Seconds since boot (not epoch) |
| `gettimeofday` | F | Fills struct timeval; tz ignored |
| `clock_gettime` | F | CLOCK_REALTIME, CLOCK_MONOTONIC (same source) |
| `clock` | F | Returns (tv_sec * 1000000 + tv_nsec / 1000) as clock_t |
| `times` | F | Fills struct tms with current time in all fields |
| `difftime` | F | `time1 - time0` as double |
| `gmtime_r` | F | Breaks seconds into year/month/day/etc. Handles leap years. |
| `gmtime` | F | Static-buffer variant |
| `localtime_r` | F | Same as `gmtime_r` (UTC only) |
| `localtime` | F | Same as `gmtime` (UTC only) |
| `mktime` | F | Converts struct tm to time_t; normalizes fields |
| `asctime_r` | F | "Day Mon DD HH:MM:SS YYYY\n" format |
| `asctime` | F | Static-buffer variant |
| `ctime_r` | F | `asctime_r(localtime_r(...))` |
| `ctime` | F | Static-buffer variant |
| `strftime` | F | See supported specifiers below |
| `setitimer` | S | Returns 0 (no-op) |
| `getitimer` | S | Zeroes result, returns 0 |

**strftime specifiers:** `%Y`, `%m`, `%d`, `%e`, `%H`, `%I`, `%M`, `%S`, `%p`,
`%a`, `%A`, `%b`/`%h`, `%B`, `%c`, `%x`, `%X`, `%y`, `%j`, `%w`, `%u`, `%Z`
(always "UTC"), `%R`, `%T`, `%n`, `%t`, `%%`. English day/month names only.

---

## math.h

Source: `math_impl.rs`

All math functions use x87 FPU inline assembly. Both `double` and `float`
variants provided where applicable. No SSE/AVX (target is
`x86_64-unknown-none`).

### Classification

| Function | St | Notes |
|---|---|---|
| `__fpclassify` | F | FP_NAN, FP_INFINITE, FP_ZERO, FP_SUBNORMAL, FP_NORMAL |
| `__fpclassifyf` | F | float variant |
| `__isnan` | F | |
| `__isnanf` | F | |
| `__isinf` | F | |
| `__isinff` | F | |
| `__finite` | F | |
| `__finitef` | F | |
| `__signbit` | F | |
| `__signbitf` | F | |

### Basic Operations

| Function | St | Notes |
|---|---|---|
| `fabs` / `fabsf` | F | Bit manipulation |
| `copysign` / `copysignf` | F | Bit manipulation |
| `fmod` / `fmodf` | F | x87 `fprem` |
| `remainder` / `remainderf` | F | x87 `fprem1` (IEEE) |
| `fma` / `fmaf` | F | `a * b + c` (no true FMA instruction) |
| `fmin` / `fminf` | F | NaN-aware |
| `fmax` / `fmaxf` | F | NaN-aware |
| `fdim` / `fdimf` | F | `max(x - y, 0)` |
| `nan` / `nanf` | F | Returns quiet NaN |

### Rounding

| Function | St | Notes |
|---|---|---|
| `floor` / `floorf` | F | x87 with rounding control |
| `ceil` / `ceilf` | F | x87 with rounding control |
| `trunc` / `truncf` | F | x87 with rounding control |
| `round` / `roundf` | F | Round half away from zero |
| `rint` / `rintf` | F | x87 `frndint` |
| `nearbyint` | F | Alias for `rint` |
| `lrint` | F | `rint` cast to long |
| `lround` | F | `round` cast to long |
| `llrint` | F | `rint` cast to long long |
| `llround` | F | `round` cast to long long |

### Powers and Roots

| Function | St | Notes |
|---|---|---|
| `sqrt` / `sqrtf` | F | x87 `fsqrt` |
| `cbrt` / `cbrtf` | F | `|x|^(1/3)` via x87, preserves sign |
| `pow` / `powf` | F | x87 `fyl2x` + `f2xm1` |
| `hypot` / `hypotf` | F | `sqrt(x*x + y*y)` |

### Exponential and Logarithmic

| Function | St | Notes |
|---|---|---|
| `exp` / `expf` | F | x87 `fyl2x` + `f2xm1` |
| `exp2` / `exp2f` | F | x87 `f2xm1` |
| `expm1` / `expm1f` | F | `exp(x) - 1` |
| `log` / `logf` | F | x87 `fyl2x` with ln(2) |
| `log2` / `log2f` | F | x87 `fyl2x` |
| `log10` / `log10f` | F | x87 `fyl2x` with log10(2) |
| `log1p` / `log1pf` | F | x87 `fyl2xp1` |
| `logb` | F | Extracts unbiased exponent |
| `ilogb` | F | Integer exponent |
| `frexp` | F | Splits into mantissa + exponent |
| `ldexp` / `ldexpf` | F | x87 `fscale` |
| `scalbn` / `scalbnf` | F | x87 `fscale` |
| `scalbln` / `scalblnf` | F | x87 `fscale` |
| `modf` | F | Splits into integer + fraction |

### Trigonometric

| Function | St | Notes |
|---|---|---|
| `sin` / `sinf` | F | x87 `fsin` |
| `cos` / `cosf` | F | x87 `fcos` |
| `tan` / `tanf` | F | x87 `fptan` |
| `asin` / `asinf` | F | x87 `fpatan` based |
| `acos` / `acosf` | F | x87 `fpatan` based |
| `atan` / `atanf` | F | x87 `fpatan` |
| `atan2` / `atan2f` | F | x87 `fpatan` |

### Hyperbolic

| Function | St | Notes |
|---|---|---|
| `sinh` | F | `(exp(x) - exp(-x)) / 2` |
| `cosh` | F | `(exp(x) + exp(-x)) / 2` |
| `tanh` | F | `sinh(x) / cosh(x)` |

### Special Functions

| Function | St | Notes |
|---|---|---|
| `erf` | F | Horner polynomial approximation (7 terms) |
| `erfc` | F | `1 - erf(x)` |
| `lgamma` | F | Stirling approximation for x >= 7, recurrence for smaller x |
| `tgamma` | F | `exp(lgamma(x))` with sign correction |

---

## dirent.h

Source: `dirent_impl.rs`

Static pool of 16 `DIR` entries. Each wraps a POSIX file descriptor obtained
from `opendir` via VFS.

| Function | St | Notes |
|---|---|---|
| `opendir` | F | Opens directory via VFS, allocates DIR from pool |
| `readdir` | F | Returns `struct dirent` with d_name[256], d_type, d_ino, d_reclen |
| `closedir` | F | Closes fd, releases DIR to pool |
| `dirfd` | F | Returns underlying fd |
| `rewinddir` | S | No-op |

`DT_UNKNOWN`(0), `DT_REG`(8), `DT_DIR`(4), `DT_LNK`(10).

---

## termios.h

Source: `termios.rs`

Terminal attributes are routed through VFS to the console server via IPC. Falls
back to local static defaults if the IPC call fails.

| Function | St | Notes |
|---|---|---|
| `tcgetattr` | F | Via VFS -> console IPC; falls back to hardcoded defaults |
| `tcsetattr` | F | Via VFS -> console IPC; also updates local cache |
| `cfgetospeed` | F | |
| `cfgetispeed` | F | |
| `cfsetospeed` | F | |
| `cfsetispeed` | F | |
| `cfmakeraw` | F | Clears ICRNL, IXON, OPOST, ECHO, ICANON, ISIG, IEXTEN; sets CS8 |
| `tcdrain` | S | Returns 0 (no-op) |
| `tcflush` | S | Returns 0 (no-op) |
| `tcsendbreak` | S | Returns 0 (no-op) |
| `tcflow` | S | Returns 0 (no-op) |

Full flag constants defined: `ICRNL`, `IXON`, `OPOST`, `ONLCR`, `CS8`,
`CREAD`, `CLOCAL`, `ISIG`, `ICANON`, `ECHO`, `ECHOE`, `ECHOK`, `ECHONL`,
`NOFLSH`, `TOSTOP`, `IEXTEN`, `ECHOCTL`, `ECHOKE`, etc.

Control character indices: `VINTR`(0)=^C, `VQUIT`(1)=^\, `VERASE`(2)=DEL,
`VKILL`(3)=^U, `VEOF`(4)=^D, `VMIN`(6)=1, `VSTART`(8)=^Q, `VSTOP`(9)=^S,
`VSUSP`(10)=^Z.

Baud rates use actual values: `B9600`(9600), `B19200`, `B38400`, `B57600`,
`B115200`.

---

## termcap.h

Source: `termcap.rs`

Minimal termcap providing ANSI escape sequences. Sufficient for programs that
probe terminal capabilities and fall back to dumb-terminal mode.

| Function | St | Notes |
|---|---|---|
| `tgetent` | F | Always returns 1 (success) |
| `tgetnum` | F | co=80, li=24; -1 for others |
| `tgetflag` | F | Always returns 0 (false) |
| `tgetstr` | F | Returns ANSI escapes for: up, do, le, nd, cl, ce, cm, cr, nl, bl, pc |
| `tputs` | F | Outputs string via putc callback |
| `tgoto` | F | Formats ESC[row;colH into static buffer |

---

## regex.h

Source: `regex.rs`

Backtracking NFA regex matcher supporting both Basic Regular Expressions (BRE)
and Extended Regular Expressions (ERE). Maximum pattern length 256 bytes,
maximum 9 capture groups.

| Function | St | Notes |
|---|---|---|
| `regcomp` | F | REG_EXTENDED, REG_ICASE, REG_NEWLINE, REG_NOSUB |
| `regexec` | F | Backtracking NFA; supports `.`, `^`, `$`, `[...]`, `*`, `+`, `?`, `\|`, groups |
| `regfree` | F | Frees compiled pattern |
| `regerror` | F | Maps REG_NOMATCH, REG_BADRPT, REG_EBRACE, etc. to strings |

Supported syntax: character classes (`[...]`, `[^...]`), anchors (`^`, `$`),
quantifiers (`*`, `+`, `?`), alternation (`|` in ERE, `\|` in BRE),
grouping (`()` in ERE, `\(\)` in BRE), case-insensitive matching.

---

## glob.h / fnmatch.h

Source: `glob_impl.rs`

| Function | St | Notes |
|---|---|---|
| `fnmatch` | F | `*`, `?`, `[...]` patterns; FNM_PATHNAME, FNM_PERIOD, FNM_NOESCAPE, FNM_CASEFOLD |
| `glob` | F | Directory scanning with fnmatch; GLOB_ERR, GLOB_MARK, GLOB_NOSORT, GLOB_NOCHECK, GLOB_APPEND |
| `globfree` | F | Frees glob result array |

`GLOB_NOMATCH`(3) returned when no matches and GLOB_NOCHECK not set.

---

## pwd.h

Source: `pwd_impl.rs`

Single hardcoded user entry: `root` (uid=0, gid=0, home=/root, shell=/bin/sh).
No `/etc/passwd` file is read.

| Function | St | Notes |
|---|---|---|
| `getpwnam` | F | Returns root entry for "root", NULL otherwise |
| `getpwuid` | F | Returns root entry for uid 0, NULL otherwise |
| `getpwent` | F | Returns root on first call, NULL on subsequent |
| `setpwent` | F | Resets iteration |
| `endpwent` | F | Resets iteration |
| `getpwnam_r` | P | Reentrant; copies into caller buffer |
| `getpwuid_r` | P | Reentrant; copies into caller buffer |

`struct passwd` fields: `pw_name`, `pw_passwd` ("*"), `pw_uid`, `pw_gid`,
`pw_gecos` ("root"), `pw_dir` ("/root"), `pw_shell` ("/bin/sh"), `pw_class`
(""), `pw_change` (0), `pw_expire` (0), `pw_fields` (0).

---

## grp.h

Source: `pwd_impl.rs`

Single hardcoded group entry: `wheel` (gid=0, members=["root"]).

| Function | St | Notes |
|---|---|---|
| `getgrnam` | F | Returns wheel entry for "wheel" or "root", NULL otherwise |
| `getgrgid` | F | Returns wheel entry for gid 0, NULL otherwise |
| `getgrent` | F | Returns wheel on first call, NULL on subsequent |
| `setgrent` | F | Resets iteration |
| `endgrent` | F | Resets iteration |

`struct group` fields: `gr_name`, `gr_passwd` ("*"), `gr_gid`, `gr_mem`
(pointer to ["root", NULL]).

---

## locale.h

Source: `locale.rs`

C locale only. No locale data loading or internationalization.

| Function | St | Notes |
|---|---|---|
| `setlocale` | F | Always returns "C" regardless of arguments |
| `localeconv` | F | Returns POSIX default lconv (decimal_point=".", thousands_sep="") |
| `textdomain` | F | Returns domain name (no-op) |
| `bindtextdomain` | F | Returns dirname (no-op) |
| `gettext` | F | Returns input string unchanged |
| `dgettext` | F | Returns input string unchanged |
| `dcgettext` | F | Returns input string unchanged |
| `ngettext` | F | Returns singular or plural form based on n |
| `dngettext` | F | Returns singular or plural form based on n |

---

## wchar.h / wctype.h

Source: `wchar.rs`

ASCII-only wide character support. `wchar_t` is `i32`. MB_CUR_MAX is 1
(single-byte locale). All multibyte functions treat bytes as 1:1 with wchar_t
values.

| Function | St | Notes |
|---|---|---|
| `mbrtowc` | F | Single-byte: byte = wchar |
| `wcrtomb` | F | Single-byte: wchar = byte |
| `mblen` | F | Always 1 (or 0 for NUL) |
| `mbtowc` | F | Single-byte conversion |
| `wctomb` | F | Single-byte conversion |
| `btowc` | F | EOF -> WEOF, else identity |
| `wctob` | F | WEOF -> EOF, else identity |
| `wcwidth` | F | Returns 1 for printable, 0 for NUL, -1 for control |
| `wcslen` | F | |
| `wcscmp` | F | |
| `wcsncmp` | F | |
| `wcscpy` | F | |
| `wcsncpy` | F | |
| `wcschr` | F | |
| `wcsrchr` | F | |
| `wcscat` | F | |
| `wcsncat` | F | |
| `wmemcpy` | F | |
| `wmemset` | F | |
| `mbsinit` | F | Always returns 1 (no shift states) |
| `mbsrtowcs` | F | Byte-by-byte conversion |
| `wcsrtombs` | F | Byte-by-byte conversion |
| `mbstowcs` | F | Byte-by-byte conversion |
| `mbrlen` | F | Delegates to `mbrtowc` |
| `wcscoll` | F | Same as `wcscmp` (C locale) |
| `wcsstr` | F | Wide substring search |
| `wcstod` | F | Converts wide string to double via narrow conversion |
| `wcstoull` | F | Converts wide string to unsigned long long via narrow conversion |
| `wcsdup` | F | malloc + wcscpy |
| `nl_langinfo` | F | Returns "UTF-8" for CODESET, "C"/"POSIX" for others |
| `__ctype_get_mb_cur_max` | F | Returns 1 |
| `fwprintf` | S | Returns 0 (no-op) |

---

## err.h

Source: `err_impl.rs`

BSD err(3) family. All functions write to stderr via `vsnprintf` + `write`.

| Function | St | Notes |
|---|---|---|
| `warn` | F | "progname: message: strerror\n" |
| `warnx` | F | "progname: message\n" (no errno) |
| `warnc` | F | "progname: message: strerror(code)\n" |
| `vwarn` | F | va_list variant |
| `vwarnx` | F | va_list variant |
| `vwarnc` | F | va_list variant |
| `err` | F | `warn` + `exit(eval)` |
| `errx` | F | `warnx` + `exit(eval)` |
| `errc` | F | `warnc` + `exit(eval)` |
| `verr` | F | va_list variant |
| `verrx` | F | va_list variant |

---

## sysexits.h

Standard exit codes are defined as constants in headers. No functions.

---

## sys/utsname.h

Source: `sysinfo.rs`

| Function | St | Notes |
|---|---|---|
| `uname` | F | sysname="SaltyOS", nodename="salty", release="0.1.0", version="0.1.0", machine="x86_64" |
| `__xuname` | F | FreeBSD alias; delegates to `uname` |
| `gethostname` | F | Returns "salty" |

---

## sys/resource.h

Source: `sysinfo.rs`

| Function | St | Notes |
|---|---|---|
| `getrlimit` | F | Returns soft=hard=infinity for all resources |
| `setrlimit` | F | No-op, returns 0 |
| `getrusage` | F | Zeroes all fields, returns 0 |
| `getdtablesize` | F | Returns 256 |

---

## sys/ioctl.h

Source: `ioctl.rs`

| Function | St | Notes |
|---|---|---|
| `ioctl` | P | TIOCGWINSZ returns 80x24; FIONREAD delegates to VFS; others delegate to posix_ioctl |

`TIOCGWINSZ`(0x5413), `TIOCSWINSZ`(0x5414), `FIONREAD`(0x541B),
`TIOCGETA`(0x5401), `TIOCSETA`(0x5402), `TIOCGETD`(0x5424),
`TIOCSETD`(0x5423).

---

## getopt (unistd.h)

Source: `stdlib_impl.rs`

| Function | St | Notes |
|---|---|---|
| `getopt` | F | Standard POSIX option parsing with optind, optarg, opterr, optopt globals |
| `getopt_long` | F | GNU-style long options with `struct option` |
| `getopt_long_only` | F | Long options with single-dash prefix |

Globals: `optind` (starts at 1), `optarg`, `opterr` (1 = print errors),
`optopt`, `optreset` (BSD reset flag).

---

## setjmp.h

Source: `stdlib_impl.rs`

| Function | St | Notes |
|---|---|---|
| `setjmp` | F | Saves rbx, rbp, r12-r15, rsp, return address into jmp_buf |
| `_setjmp` | F | Alias for `setjmp` (no signal mask save) |
| `longjmp` | F | Restores registers and jumps; val=0 becomes 1 |
| `_longjmp` | F | Alias for `longjmp` |
| `sigsetjmp` | F | Alias for `setjmp` (signal mask not saved) |
| `siglongjmp` | F | Alias for `longjmp` |

`jmp_buf` is 8 x `u64` = 64 bytes.

---

## environ / env

Source: `env.rs`

Static array of max 128 environment variable pointers. Variables are stored as
`KEY=VALUE` NUL-terminated strings.

| Function | St | Notes |
|---|---|---|
| `getenv` | F | Linear search through environ array |
| `setenv` | F | Allocates "KEY=VALUE" string via malloc |
| `unsetenv` | F | Removes and shifts array |
| `putenv` | F | Stores pointer directly (does not copy) |
| `clearenv` | F | Sets environ[0] = NULL |

Global: `environ` — pointer to NULL-terminated array of `char *`.

---

## fts.h

Not implemented. FreeBSD utilities that use `fts_open`/`fts_read`/`fts_close`
will need alternatives (e.g., recursive `opendir`/`readdir`).

---

## mntent.h

Source: `compat/freebsd/mntent.rs`

Empty mount table stubs for programs that enumerate mounted filesystems.

| Function | St | Notes |
|---|---|---|
| `setmntent` | S | Returns non-null sentinel |
| `getmntent` | S | Always returns NULL (empty mount table) |
| `endmntent` | S | Returns 1 (success) |
| `hasmntopt` | S | Always returns NULL |

---

## sys/statvfs.h

Source: `compat/freebsd/statvfs.rs`

| Function | St | Notes |
|---|---|---|
| `statvfs` | S | Returns -1 / ENOSYS |
| `fstatvfs` | S | Returns -1 / ENOSYS |

---

## sys/capsicum.h (FreeBSD)

Source: `compat/freebsd/capsicum.rs`

No-op stubs. SaltyOS uses kernel capabilities (seL4-style), not Capsicum.

| Function | St | Notes |
|---|---|---|
| `__cap_rights_init` | S | Returns rights pointer unchanged |
| `__cap_rights_is_set` | S | Always returns true (1) |
| `__cap_rights_set` | S | No-op, returns rights pointer |

---

## FreeBSD Compat — Sorting

Source: `compat/freebsd/bsd_sort.rs`

| Function | St | Notes |
|---|---|---|
| `mergesort` | F | Stable sort; allocates temp buffer via malloc |
| `heapsort` | F | In-place unstable sort |
| `strverscmp` | F | Version-aware string comparison (numeric segments compared as numbers) |
| `strtonum` | F | BSD string-to-number with range checking and error string |
| `vcmp` | F | Alias for `strverscmp` |

---

## FreeBSD Compat — File Flags

Source: `compat/freebsd/bsd_flags.rs`

| Function | St | Notes |
|---|---|---|
| `chflags` | S | Returns -1 / ENOSYS |
| `lchflags` | S | Returns -1 / ENOSYS |
| `fchflags` | S | Returns -1 / ENOSYS |
| `undelete` | S | Returns -1 / ENOSYS |
| `fflagstostr` | S | Always returns empty string |
| `strmode` | F | Converts mode_t to ls-style "drwxrwxrwx " string (12 chars) |
| `setmode` | P | Parses octal numeric modes only; symbolic modes not supported |
| `getmode` | F | Returns mode stored by `setmode` |

---

## FreeBSD Compat — Rune / Locale Internals

Source: `compat/freebsd/rune.rs`

FreeBSD's inline ctype macros expand to these functions. Provides an ASCII rune
table for character classification using FreeBSD's _RuneLocale structure.

| Function | St | Notes |
|---|---|---|
| `___runetype` | F | Returns FreeBSD rune type bits for ASCII chars 0-255 |
| `___toupper` | F | ASCII toupper |
| `___tolower` | F | ASCII tolower |

Globals: `_CurrentRuneLocale` (pointer to ASCII rune table, initialized at CRT
startup), `__mb_sb_limit` (128), `___mb_cur_max` (1).

---

## FreeBSD Compat — Miscellaneous

Source: `compat/freebsd/bsd_misc.rs`, `compat/freebsd/bsd_io.rs`

### bsd_misc.rs

| Function | St | Notes |
|---|---|---|
| `getosreldate` | F | Returns 1402000 (FreeBSD 14.2) |
| `getloginclass` | S | Returns -1 / ENOSYS |
| `getlogin` | F | Returns "root" |
| `getgrouplist` | F | Returns single primary group |
| `pledge` | F | No-op, returns 0 (OpenBSD compat) |
| `unveil` | F | No-op, returns 0 (OpenBSD compat) |
| `lchmod` | S | Returns -1 / ENOSYS |
| `mknod` | S | Returns -1 / ENOSYS |
| `__assert` | F | FreeBSD assert() handler; calls `abort()` |
| `getbsize` | F | Returns "512" / 512-byte blocks |
| `lpathconf` | F | Delegates to `pathconf` |
| `eaccess` | F | Alias for `access` (single-user, no effective/real distinction) |
| `fseeko` | F | Alias for `fseek` |
| `ftello` | F | Alias for `ftell` |
| `vfork` | F | Alias for `fork` (no MMU optimization) |
| `kqueue` | S | Returns -1 / ENOSYS |
| `kevent` | S | Returns -1 / ENOSYS |
| `fstatfs` | S | Returns -1 / ENOSYS |
| `statfs` | S | Returns -1 / ENOSYS |

### bsd_io.rs

| Function | St | Notes |
|---|---|---|
| `__swbuf` | F | FreeBSD putc() buffer-full handler; delegates to `fputc` |
| `__srget` | F | FreeBSD getc() buffer-empty handler; delegates to `fgetc` |

---

## Miscellaneous POSIX

Source: `misc_impl.rs`

| Function | St | Notes |
|---|---|---|
| `getprogname` | F | Returns basename set by `setprogname` |
| `setprogname` | F | Stores basename portion (after last '/') |
| `dirname` | F | POSIX path decomposition into static buffer |
| `basename` | F | POSIX path decomposition; modifies input |
| `sched_yield` | F | Maps to SYS_YIELD syscall |
| `getpagesize` | F | Always returns 4096 |
| `fsync` | F | No-op, returns 0 (ramfs) |
| `fdatasync` | F | No-op, returns 0 (ramfs) |
| `utime` | F | Delegates to utimensat via VFS |
| `utimes` | F | Delegates to utimensat via VFS (converts usec to nsec) |
| `user_from_uid` | F | Looks up username via getpwuid; falls back to decimal string |
| `group_from_gid` | F | Looks up group name via getgrgid; falls back to decimal string |
| `getentropy` | P | xorshift64 PRNG seeded from clock+PID+counter; **NOT cryptographically secure** |
| `copy_file_range` | S | Returns -1 / ENOSYS |
| `sem_init` | S | Returns -1 / ENOSYS |
| `sem_wait` | S | Returns -1 / ENOSYS |
| `sem_post` | S | Returns -1 / ENOSYS |
| `popen` | S | Returns NULL / ENOSYS |
| `pclose` | S | Returns -1 / ENOSYS |

---

## sysconf / System Info

Source: `sysinfo.rs`

| Function | St | Notes |
|---|---|---|
| `sysconf` | F | See values below |

`sysconf` values: `_SC_CLK_TCK`=100, `_SC_OPEN_MAX`=256,
`_SC_PAGESIZE`/`_SC_PAGE_SIZE`=4096, `_SC_NPROCESSORS_CONF`=1,
`_SC_NPROCESSORS_ONLN`=1, `_SC_PHYS_PAGES`=32768, `_SC_CHILD_MAX`=64,
`_SC_HOST_NAME_MAX`=64, `_SC_LOGIN_NAME_MAX`=32, `_SC_GETPW_R_SIZE_MAX`=1024,
`_SC_GETGR_R_SIZE_MAX`=1024. Unknown names return -1.

---

## Job Control

Source: `jobctl.rs`

All job control functions operate on local static state. No kernel process group
support.

| Function | St | Notes |
|---|---|---|
| `setpgid` | P | Stores pgid in local static (pid must be 0 or getpid()) |
| `getpgid` | P | Returns local static pgid |
| `getpgrp` | P | Returns local static pgid |
| `setpgrp` | P | `setpgid(0, 0)` |
| `setsid` | P | Sets pgid and sid to getpid() |
| `getsid` | P | Returns local static sid |
| `tcgetpgrp` | P | Returns local static foreground pgid |
| `tcsetpgrp` | P | Stores foreground pgid locally |

---

## CRT / Process Startup

Source: `crt.rs`

| Function | St | Notes |
|---|---|---|
| `__libc_start_main` | F | CRT entry point; parses auxv for AT_BESALT_* tags, initializes IPC context and memory manager, calls main |

Custom auxiliary vector tags (set by init/rtld):
- `AT_BESALT_IPC_BUFFER` (0x1000) — IPC buffer address
- `AT_BESALT_VFS_EP` (0x1001) — VFS endpoint cap slot
- `AT_BESALT_PROCMGR_EP` (0x1002) — Process manager endpoint cap slot
- `AT_BESALT_CONSOLE_EP` (0x1003) — Console endpoint cap slot
- `AT_BESALT_CSPACE` (0x1004) — CSpace root cap slot
- `AT_BESALT_SIGNAL_NTF` (0x1005) — Signal notification cap slot
- `AT_BESALT_MM_UNTYPED` (0x1006) — Memory manager untyped cap
- `AT_BESALT_MM_VSPACE` (0x1007) — Memory manager vspace cap
- `AT_BESALT_MM_NEXT_FREE` (0x1008) — First free CNode slot
- `AT_BESALT_MM_CNODE_BITS` (0x1009) — CNode size in bits

---

## Design Notes

### General Constraints

- **Single-threaded**: All `static mut` globals are unsynchronized. Thread
  safety is not provided.
- **No heap fragmentation mitigation**: The first-fit allocator does not
  compact. Long-running programs with varied allocation patterns may fragment.
- **ASCII only**: All string functions, ctype, locale, and wide character
  support assume ASCII / C locale. No UTF-8 or multibyte encoding.
- **UTC only**: No timezone database. `localtime` = `gmtime`. The system
  clock starts at zero on boot.
- **Single user**: uid=0 (root), gid=0 (wheel). All credential functions
  return these values.
- **ramfs**: `fsync`/`fdatasync` are no-ops. All data is in memory.
- **No true long double**: `strtold` delegates to `strtod`; `long double` =
  `double`.
- **No SSE/AVX**: Math uses x87 FPU only (kernel target disables SSE).

### Missing Functionality

Functions not yet implemented that may be needed by additional ported programs:

- `fts_open` / `fts_read` / `fts_close` / `fts_children` (file tree walk)
- `nftw` / `ftw` (POSIX file tree walk)
- Thread support (`pthread_*`)
- `dlopen` / `dlsym` / `dlclose` (dynamic loading)
- `iconv` (character encoding conversion)
- Full symbolic mode parsing in `setmode`
- `kqueue`/`kevent` (BSD event notification)
- Cryptographically secure `getentropy` (needs kernel entropy source)
- Real timezone/DST support
