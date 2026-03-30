# POSIX Compatibility Layer

This document describes SaltyOS's approach to POSIX compatibility.

## Philosophy

SaltyOS follows the **microkernel POSIX model** pioneered by Minix3 and QNX:

- The kernel provides only primitives: IPC, scheduling, memory management, capabilities
- POSIX semantics are implemented entirely in **userspace servers**
- **trona** (Rust) provides POSIX wrappers that translate calls to IPC messages
- **basaltc** (C) provides a standard C library on top of trona

```
+-----------------------------------------------+
|              Applications                      |
+-----------------------------------------------+
|    basaltc (C stdlib)  |  trona (Rust)       |
|      [POSIX calls -> IPC + capabilities]       |
+-----------------------------------------------+
|  VFS  |  ProcMgr  |  Console  |  Drivers      |
+-----------------------------------------------+
|            SaltyOS Microkernel                 |
|  [Endpoints, Notifications, CNodes, VSpace]   |
+-----------------------------------------------+
```

### Why This Approach?

| Benefit | Description |
|---------|-------------|
| **Security** | POSIX servers run unprivileged; bugs don't compromise kernel |
| **Flexibility** | Can replace/update POSIX layer without kernel changes |
| **Capability integration** | POSIX operations naturally map to capability checks |
| **Minimal TCB** | Kernel remains small and auditable |

## Architecture

### Libraries: trona + basaltc

SaltyOS uses a two-layer userspace library stack:

- **trona** (`lib/trona/substrate/`, Rust): System library providing raw syscall wrappers, IPC helpers, capability invocations, and POSIX compatibility functions (`posix.rs`, `posix_mm.rs`, `signals.rs`). Compiled as `libtrona.so` (shared) and linked statically into `init`.
- **basaltc** (`lib/basaltc/`, C): Standard C library built on top of trona, providing stdio, stdlib, string, malloc, unistd, signal, termios, dirent, regex, and more.

**How POSIX calls work**:
```rust
// trona posix.rs — open() sends IPC to VFS server
pub extern "C" fn open(path: *const u8, flags: i32, mode: u32) -> i32 {
    // Build IPC message with VFS_OPEN label
    // trona_call(vfs_ep, &msg) → VFS server handles it
}
```

### Server Responsibilities

| Server | POSIX Functions |
|--------|-----------------|
| **VFS** | open, read, write, close, stat, lseek, dup/dup3, pipe/pipe2, mkfifo, socket (AF_UNIX), poll, epoll, shm_open/shm_unlink, ftruncate |
| **ProcMgr** | fork, exec, exit, wait, getpid, kill, signal delivery, process groups |
| **Console** | Serial I/O, line discipline (ICANON/ECHO/ISIG), tcgetattr/tcsetattr, signal generation (Ctrl-C/Ctrl-\/Ctrl-Z) |
| **trona** | mmap (anonymous), munmap, mprotect, brk/sbrk, sigaction, sigprocmask, select |

### IPC Flow Example

```
Application                  trona                    VFS Server
    |                           |                            |
    | open("/etc/hosts", O_RDONLY)                           |
    |-------------------------->|                            |
    |                           | sys_call(vfs_endpoint,     |
    |                           |   VFS_OPEN, path, flags)   |
    |                           |--------------------------->|
    |                           |                            | validate path
    |                           |                            | check capabilities
    |                           |                            | create file handle
    |                           |<---------------------------|
    |                           | return file descriptor     |
    |<--------------------------|                            |
    | fd = 3                    |                            |
```

## Supported Interfaces

### File I/O, Process, and Memory

**File I/O**:
| Function | Status | Notes |
|----------|--------|-------|
| `open` | Implemented | VFS server + posix.h |
| `close` | Implemented | VFS server + posix.h |
| `read` | Implemented | VFS server + posix.h |
| `write` | Implemented | VFS server + posix.h |
| `lseek` | Implemented | VFS server + posix.h |
| `stat`, `fstat`, `lstat` | Implemented | VFS server + posix.h |
| `access` | Implemented | VFS server + posix.h |
| `unlink`, `rename` | Implemented | VFS server + posix.h |
| `mkdir`, `rmdir` | Implemented | VFS server + posix.h |
| `opendir`, `readdir`, `closedir` | Implemented | VFS server + posix.h |

**Process**:
| Function | Status | Notes |
|----------|--------|-------|
| `exit`, `_exit` | Implemented | procmgr + posix.h |
| `getpid`, `getppid` | Implemented | procmgr + posix.h |
| `fork` | Implemented | procmgr + posix.h + fork.S |
| `exec*` family | Implemented | procmgr + posix.h |
| `wait`, `waitpid` | Implemented | procmgr + posix.h (WNOHANG, pid=-1) |

**Memory**:
| Function | Status | Notes |
|----------|--------|-------|
| `mmap` (anonymous) | Implemented | posix_mm.h |
| `munmap` | Implemented | posix_mm.h |
| `mprotect` | Implemented | posix_mm.h |
| `brk`, `sbrk` | Implemented | posix_mm.h |

### Sockets, Event Multiplexing, and Shared Memory

**Unix Domain Sockets**:
| Function | Status | Notes |
|----------|--------|-------|
| `socket(AF_UNIX, ...)` | Implemented | VFS server + trona posix.rs |
| `bind`, `listen`, `accept` | Implemented | VFS server + trona posix.rs |
| `connect` | Implemented | VFS server + trona posix.rs |
| `sendmsg`, `recvmsg` | Implemented | With fd passing support |
| `socketpair` | Implemented | VFS server + trona posix.rs |
| `shutdown` | Implemented | SHUT_RD/SHUT_WR/SHUT_RDWR |
| `SCM_RIGHTS` | Implemented | fd passing via sendmsg/recvmsg |

**Event Multiplexing**:
| Function | Status | Notes |
|----------|--------|-------|
| `poll` | Implemented | VFS server + trona posix.rs |
| `select` | Implemented | Wrapper around poll in trona |
| `epoll_create1`, `epoll_ctl`, `epoll_wait` | Implemented | VFS server + trona posix.rs |

**POSIX Shared Memory**:
| Function | Status | Notes |
|----------|--------|-------|
| `shm_open` | Implemented | VFS server + trona posix.rs |
| `shm_unlink` | Implemented | VFS server + trona posix.rs |
| `mmap` (shared) | Implemented | MAP_SHARED flag support |
| `ftruncate` | Implemented | VFS server + trona posix.rs |

**Signals**:
| Function | Status | Notes |
|----------|--------|-------|
| `kill` | Implemented | Via ProcMgr IPC, pid==0 kills process group |
| `signal` | Implemented | Notification-based delivery |
| `sigaction` | Implemented | sa_mask, SA_RESETHAND, pending re-raise |
| `sigprocmask` | Implemented | Syncs with trona globals |

### Pipes, FIFOs, and File Descriptors

| Function | Status | Notes |
|----------|--------|-------|
| `pipe`, `pipe2` | Implemented | O_NONBLOCK, O_CLOEXEC flags |
| `mkfifo` | Implemented | FIFO inode type with pipe-backed semantics |
| `dup`, `dup2`, `dup3` | Implemented | O_CLOEXEC support, EINVAL validation |

### Terminal

| Function | Status | Notes |
|----------|--------|-------|
| `isatty` | Implemented | VFS server |
| `tcgetattr`, `tcsetattr` | Implemented | Forwarded to console server |
| Line discipline | Implemented | ICANON, ECHO/ECHOE/ECHOK/ECHOCTL, ISIG |
| Signal generation | Implemented | Ctrl-C→SIGINT, Ctrl-\→SIGQUIT, Ctrl-Z→SIGTSTP |

### Time

| Function | Status | Notes |
|----------|--------|-------|
| `clock_gettime` | Implemented | Kernel syscall #12, CLOCK_MONOTONIC/CLOCK_REALTIME |
| `nanosleep` | Implemented | Kernel syscall #13, sleep queue based |

### Networking (TCP/IP)

| Function | Status | Notes |
|----------|--------|-------|
| `socket(AF_INET, ...)` | Future | Via NetStack server |
| `getaddrinfo` | Future | |

## Intentionally Unsupported

### System V IPC

**Functions**: `shmget`, `shmat`, `shmdt`, `semget`, `semop`, `msgget`, `msgsnd`, `msgrcv`

**Status**: Not planned

**Rationale**:
- Legacy interface from 1983
- Modern applications use POSIX shm (`shm_open`) or `memfd_create`
- Modern X11 (since 2013) uses fd-based MIT-SHM, not System V
- Wayland never used System V IPC

**Alternative**: Use POSIX shared memory (`shm_open`/`mmap`) or SaltyOS frame capabilities directly.

### setuid/setgid

**Functions**: `setuid`, `setgid`, `seteuid`, `setegid`, `setreuid`, `setregid`

**Status**: Not planned

**Rationale**:
- Fundamentally incompatible with capability-based security
- Creates ambient authority (UID 0 = access everything)
- Security risk: setuid binaries are common attack vectors

**Alternative**: Capability delegation. Instead of:
```bash
# Traditional Unix: setuid binary
-rwsr-xr-x root /usr/bin/ping
```

SaltyOS uses:
```
ProcMgr grants NET_RAW capability to /usr/bin/ping at exec time
```

**GUI Impact**: None. Modern graphics stacks don't require setuid:
- Rootless Xorg (since 2014) uses logind for device access
- Wayland compositors receive DRM/input capabilities directly

### Traditional Signal Semantics

**Limitation**: SA_RESTART and alternate signal stacks (`sigaltstack`) are not yet supported.

**Status**: Largely implemented

**What we provide**:
- Notification-based async signal delivery
- `sigaction` with `sa_mask` and `SA_RESETHAND`
- `sigprocmask` for blocking/unblocking signals
- Pending signal re-raising after handler execution
- `kill` with pid==0 for process group delivery
- Terminal-generated signals: SIGINT (Ctrl-C), SIGQUIT (Ctrl-\), SIGTSTP (Ctrl-Z)

**Not yet implemented**:
- `SA_RESTART` (auto-restart interrupted syscalls)
- `sigaltstack` (alternate signal stacks)
- Real-time signals (SIGRTMIN-SIGRTMAX)

## POSIX to SaltyOS Mapping

### File Descriptors = Capabilities

In SaltyOS, a file descriptor is internally a capability slot index:

```
POSIX fd 3  -->  CNode slot 3  -->  Capability to VFS file handle
```

Operations:
| POSIX | SaltyOS |
|-------|---------|
| `open()` returns fd | VFS returns capability, stored in CNode |
| `read(fd, ...)` | Invoke capability with READ operation |
| `dup(fd)` | Copy capability to new CNode slot |
| `close(fd)` | Delete capability from CNode |
| `fork()` fd inheritance | Copy capabilities to child's CNode |

### Unix Sockets = Endpoints

| POSIX | SaltyOS |
|-------|---------|
| `socket(AF_UNIX, SOCK_STREAM)` | Create Endpoint |
| `bind("/path")` | Register with nameserver |
| `connect("/path")` | Lookup endpoint, connect |
| `sendmsg` with `SCM_RIGHTS` | Transfer capability via IPC |

### Signals = Notifications

| POSIX | SaltyOS |
|-------|---------|
| `kill(pid, SIGTERM)` | Signal notification to target process |
| `signal(SIGCHLD, handler)` | Bind notification, poll in event loop |
| `sigwait()` | Wait on notification |

### Shared Memory

| POSIX | SaltyOS |
|-------|---------|
| `shm_open("/name")` | Create named shared memory object |
| `mmap(fd, ...)` | Map Frame capability into VSpace |
| Send fd via socket | Transfer Frame capability via IPC |

## GUI Stack Support

### Wayland Compatibility

Wayland requires:

| Requirement | SaltyOS Support |
|-------------|-----------------|
| Unix domain sockets | Via endpoint emulation |
| `SCM_RIGHTS` fd passing | Capability transfer |
| `shm_open`/`mmap` | POSIX shm support |
| `poll`/`epoll` | Multi-wait on endpoints |
| DRM/KMS access | DRM capability to compositor |

**Implementation strategy**:
1. Wayland compositor runs as privileged server with DRM capability
2. Clients connect via Unix socket emulation
3. Buffer sharing via Frame capability transfer
4. Input events via Input server notifications

### X11 Compatibility

For X11 support, recommended approach:

1. **XWayland**: Run X11 on top of Wayland compatibility layer
2. Native X11 server is possible but lower priority

Modern X11 (Xorg 1.15+) no longer requires:
- System V shared memory (uses fd-based MIT-SHM)
- setuid root (rootless mode via logind equivalent)

## Implementation Roadmap

```
Phase 1: Core POSIX                              [DONE]
├── trona (Rust) + basaltc (C stdlib)
├── VFS server (file I/O, ramfs, devfs)
├── ProcMgr (fork, exec, wait, kill)
└── Signal delivery (notification-based)

Phase 2: GUI-Ready                                [DONE]
├── Unix domain sockets (AF_UNIX)
├── SCM_RIGHTS (fd passing via capability transfer)
├── POSIX shared memory (shm_open, shm_unlink)
├── poll/select/epoll
├── Pipes, FIFOs, dup/dup3
└── Terminal line discipline

Phase 3: Extended Compatibility                   [IN PROGRESS]
├── SA_RESTART, sigaltstack                       [Planned]
├── TCP/IP networking                             [Planned]
└── Broader application testing                   [Ongoing]

Phase 4: Optimization                            [Planned]
├── Zero-copy I/O paths
├── Async I/O (io_uring style)
└── Performance tuning
```

## References

- [POSIX.1-2017 Specification](https://pubs.opengroup.org/onlinepubs/9699919799/)
- [Wayland Protocol](https://wayland.freedesktop.org/docs/html/)
- [QNX Resource Managers](https://www.qnx.com/developers/docs/)
- [Minix3 Design](https://wiki.minix3.org/)
