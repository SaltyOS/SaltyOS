# POSIX Compatibility Layer

This document describes SaltyOS's approach to POSIX compatibility.

## Philosophy

SaltyOS follows the **microkernel POSIX model** pioneered by Minix3 and QNX:

- The kernel provides only primitives: IPC, scheduling, memory management, capabilities
- POSIX semantics are implemented entirely in **userspace servers**
- A modified **libc** translates POSIX calls to IPC messages

```
+-----------------------------------------------+
|              Applications                      |
+-----------------------------------------------+
|           Modified musl libc                   |
|      [POSIX calls -> IPC + capabilities]       |
+-----------------------------------------------+
|  VFS  |  ProcMgr  |  NetStack  |  Drivers     |
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

### libc: Modified musl

SaltyOS uses a modified [musl libc](https://musl.libc.org/) for POSIX compatibility:

- **MIT license**: Permissive, suitable for OS inclusion
- **Small codebase**: ~100K lines (vs glibc's 1.5M)
- **Static linking friendly**: Important for early userspace
- **Clean syscall layer**: Easy to replace with IPC calls

**Modification approach**:
```c
// Standard musl (Linux)
long open(const char *path, int flags, mode_t mode) {
    return syscall(SYS_open, path, flags, mode);
}

// SaltyOS musl
long open(const char *path, int flags, mode_t mode) {
    return vfs_ipc_open(path, flags, mode);  // IPC to VFS server
}
```

### Server Responsibilities

| Server | POSIX Functions |
|--------|-----------------|
| **VFS** | open, read, write, close, stat, lseek, mmap (file-backed), dup, pipe |
| **ProcMgr** | fork, exec, exit, wait, getpid, kill, signal handling |
| **NetStack** | socket, bind, connect, listen, accept, send, recv |
| **MemMgr** | mmap (anonymous), munmap, mprotect, shm_open |

### IPC Flow Example

```
Application                    libc                      VFS Server
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

### Phase 1: Core (Minimal Viable)

Essential for basic program execution.

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

### Phase 2: GUI-Ready

Required for running graphical applications (Wayland, X11 via XWayland).

**Unix Domain Sockets**:
| Function | Status | Notes |
|----------|--------|-------|
| `socket(AF_UNIX, ...)` | Implemented | VFS server + libsalty posix.rs |
| `bind`, `listen`, `accept` | Implemented | VFS server + libsalty posix.rs |
| `connect` | Implemented | VFS server + libsalty posix.rs |
| `sendmsg`, `recvmsg` | Implemented | With fd passing support |
| `socketpair` | Implemented | VFS server + libsalty posix.rs |
| `shutdown` | Implemented | SHUT_RD/SHUT_WR/SHUT_RDWR |
| `SCM_RIGHTS` | Implemented | fd passing via sendmsg/recvmsg |

**Event Multiplexing**:
| Function | Status | Notes |
|----------|--------|-------|
| `poll` | Implemented | VFS server + libsalty posix.rs |
| `select` | Implemented | Wrapper around poll in libsalty |
| `epoll_*` | Partial | Constants defined, epoll_create via /dev/epoll |

**POSIX Shared Memory**:
| Function | Status | Notes |
|----------|--------|-------|
| `shm_open` | Implemented | VFS server + libsalty posix.rs |
| `shm_unlink` | Implemented | VFS server + libsalty posix.rs |
| `mmap` (shared) | Implemented | MAP_SHARED flag support |
| `ftruncate` | Implemented | VFS server + libsalty posix.rs |

**Signals** (limited):
| Function | Status | Notes |
|----------|--------|-------|
| `kill` | Implemented | Via ProcMgr IPC |
| `signal` | Implemented | Notification-based delivery |
| `sigaction` | Planned | Full POSIX sigaction struct |
| `sigprocmask` | Planned | |

### Phase 3: Extended

For broader application compatibility.

**Pipes and FIFOs**:
| Function | Status | Notes |
|----------|--------|-------|
| `pipe`, `pipe2` | Planned | |
| `mkfifo` | Planned | |
| `dup`, `dup2`, `dup3` | Planned | |

**Terminal**:
| Function | Status | Notes |
|----------|--------|-------|
| `isatty` | Planned | |
| `tcgetattr`, `tcsetattr` | Planned | |
| `ioctl` (tty) | Planned | |

**Time**:
| Function | Status | Notes |
|----------|--------|-------|
| `gettimeofday` | Planned | |
| `clock_gettime` | Planned | |
| `nanosleep` | Planned | |

**Networking** (TCP/IP):
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

**Limitation**: Full POSIX signal semantics (async delivery, signal stacks, SA_RESTART) are complex.

**Status**: Simplified implementation

**Rationale**:
- Async signal delivery is difficult to implement safely
- Many modern programs use `signalfd` or event loops instead
- Capability-based notification is more natural for SaltyOS

**What we provide**:
- Synchronous signal checking (via ProcMgr queries)
- `signalfd`-style notification integration
- Basic `SIGTERM`, `SIGCHLD`, `SIGPIPE` handling

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
Phase 1: Core POSIX
├── Modified musl libc
├── VFS server (file I/O)
├── ProcMgr (fork, exec, wait)
└── Basic signal delivery

Phase 2: GUI-Ready                     ✓ DONE
├── Unix domain socket emulation        ✓
├── SCM_RIGHTS (capability transfer)    ✓
├── POSIX shared memory                 ✓
├── poll/select                         ✓
├── epoll (partial)
└── Wayland compositor support

Phase 3: Extended Compatibility
├── Full signal semantics
├── Terminal handling
├── TCP/IP networking
└── Broader application testing

Phase 4: Optimization
├── Zero-copy I/O paths
├── Async I/O (io_uring style)
└── Performance tuning
```

## References

- [POSIX.1-2017 Specification](https://pubs.opengroup.org/onlinepubs/9699919799/)
- [musl libc](https://musl.libc.org/)
- [Wayland Protocol](https://wayland.freedesktop.org/docs/html/)
- [QNX Resource Managers](https://www.qnx.com/developers/docs/)
- [Minix3 Design](https://wiki.minix3.org/)
