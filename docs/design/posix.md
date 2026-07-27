# POSIX Compatibility Layer

This document describes SaltyOS's approach to POSIX compatibility.

## Philosophy

SaltyOS follows the **microkernel POSIX model** pioneered by Minix3 and QNX:

- The kernel provides only primitives: IPC, scheduling, memory management, capabilities
- POSIX semantics are implemented entirely in **userspace servers**
- **trona** (Rust) provides POSIX wrappers that translate calls to IPC messages
- **basaltc** (C) provides a standard C library on top of trona

```
+----------------------------------------------------------+
|                     Applications                          |
+----------------------------------------------------------+
|    basaltc (C stdlib)     |  trona (Rust)                |
|         [POSIX calls -> IPC + capabilities]               |
+----------------------------------------------------------+
|  VFS  |  init (supervisor)  |  Console  |  netsrv  |  Drivers  |
+----------------------------------------------------------+
|                 SaltyOS Microkernel                       |
|  [MessagePipe, DataPipe, EventQueue, Watch, CNode, VSpace, MO] |
+----------------------------------------------------------+
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

- **trona** (`lib/trona/`, Rust): System library with 6 crates -- kernel (ABI layer, bindgen consts from `kernite/include/uapi/*.h`), protocol (IPC labels/types), server (server helpers, cap table), runtime (slot allocator, cap ownership), posix (file, socket, poll, mm, signals, pthread, dns), and loader (ELF/PE dynamic linkers). Compiled as `libtrona.so` (shared) and linked statically into `init`.
- **basaltc** (`lib/basalt/c/`, C): Standard C library (40 Rust modules) built on top of trona, providing stdio, stdlib, string, malloc, unistd, signal, termios, dirent, regex, socket, inet, pthread, iconv, and more.

**How POSIX calls work**:
```rust
// trona posix.rs — open() sends IPC to VFS server
pub extern "C" fn open(path: *const u8, flags: i32, mode: u32) -> i32 {
    // Build IPC message with VFS_POSIX_OPEN label
    // trona_call(vfs_ep, &msg) → VFS server handles it
}
```

### Server Responsibilities

| Server | POSIX Functions |
|--------|-----------------|
| **VFS** (`core/vfs/`) | open, read, write, close, stat, lseek, dup/dup3, pipe/pipe2, mkfifo, socket (AF_UNIX), poll, epoll, shm_open/shm_unlink, ftruncate, AF_INET socket proxy (forwarded to netsrv) |
| **init** (`core/init/`) | fork, exec, exit, wait, getpid, kill, signal delivery, process groups, personality state (POSIX/Win32) |
| **Console** (`servers/console/`) | Serial I/O, line discipline (ICANON/ECHO/ISIG), tcgetattr/tcsetattr, signal generation (Ctrl-C/Ctrl-\/Ctrl-Z) |
| **posix_ttysrv** (`servers/posix/posix_ttysrv/`) | TTY daemon with SHM ring buffer for terminal I/O |
| **posix_getty** (`servers/posix/posix_getty/`) | Getty (login prompt) |
| **netsrv** (`servers/netsrv/`) | TCP/UDP/ICMP stack, ARP, DHCP client, DNS forwarding, AF_INET socket implementation |
| **dnssrv** (`servers/dnssrv/`) | Caching DNS resolver, getaddrinfo backend |
| **mmsrv** (`core/mmsrv/`) | mmap (anonymous + file-backed), munmap, mprotect, brk/sbrk, demand paging, shared memory frames |
| **trona** (library) | sigaction, sigprocmask, select (wrapper around poll), pthread |

### IPC Flow Example

```
Application                  trona                    VFS Server
    |                           |                            |
    | open("/etc/hosts", O_RDONLY)                           |
    |-------------------------->|                            |
    |                           | sys_call(vfs_endpoint,     |
    |                           |   VFS_POSIX_OPEN, path, flags)   |
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
| `exit`, `_exit` | Implemented | init + posix.h |
| `getpid`, `getppid` | Implemented | init + posix.h |
| `fork` | Implemented | init + posix.h + fork.S |
| `exec*` family | Implemented | init + posix.h |
| `wait`, `waitpid` | Implemented | init + posix.h (WNOHANG, pid=-1) |

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
| `kill` | Implemented | Via init IPC, pid==0 kills process group |
| `signal` | Implemented | MessagePipe-based delivery |
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

**Terminal servers:** Console (`servers/console/`) provides raw serial I/O with line discipline. posix_ttysrv (`servers/posix/posix_ttysrv/`) provides the TTY daemon using SHM ring buffers for terminal I/O. posix_getty (`servers/posix/posix_getty/`) provides the login prompt (getty).

### Time

| Function | Status | Notes |
|----------|--------|-------|
| `clock_gettime` | Implemented | Kernel syscall #12, CLOCK_MONOTONIC/CLOCK_REALTIME |
| `nanosleep` | Implemented | Kernel syscall #13, sleep queue based |

### Networking (TCP/IP)

| Function | Status | Notes |
|----------|--------|-------|
| `socket(AF_INET, SOCK_STREAM)` | Implemented | VFS → netsrv (TCP) |
| `socket(AF_INET, SOCK_DGRAM)` | Implemented | VFS → netsrv (UDP) |
| `connect` | Implemented | VFS → netsrv (blocking, async completion via shared backend callback EP) |
| `bind` | Implemented | VFS → netsrv |
| `listen` | Implemented | VFS → netsrv |
| `accept` | Implemented | VFS → netsrv (blocking, NET_ACCEPT_WAIT) |
| `send`, `recv` | Implemented | VFS → netsrv (MSG_PEEK supported, NET_RECV_WAIT/NET_SEND_WAIT for blocking) |
| `sendto`, `recvfrom` | Implemented | VFS → netsrv (UDP datagrams) |
| `shutdown` | Implemented | VFS → netsrv |
| `getsockname`, `getpeername` | Implemented | VFS → netsrv |
| `setsockopt`, `getsockopt` | Implemented | VFS → netsrv |
| `getaddrinfo` | Implemented | trona posix dns.rs → dnssrv (caching resolver) |
| `poll` on AF_INET sockets | Implemented | VFS → netsrv (NET_POLL_STATUS) |

**Network architecture:**

```
Application
    ↓ socket(AF_INET, ...)
trona posix
    ↓ IPC (VFS_POSIX_SOCKET, VFS_READ, VFS_WRITE, ...)
VFS (core/vfs/src/posix/inet.rs)
    ↓ IPC forwarding (NET_SOCKET, NET_CONNECT, NET_SEND, ...)
netsrv (servers/netsrv/)
    ├── TCP (net/proto/tcp.rs, net/socket/tcp.rs)
    ├── UDP (net/proto/udp.rs, net/socket/udp.rs)
    ├── ARP (net/proto/arp.rs)
    ├── ICMP (net/proto/icmp.rs)
    ├── DHCP (net/dhcp.rs)
    └── DNS forwarding (net/dns.rs)
    ↓ virtio-net
netdrv (drivers/netdrv/ — virtio-net driver)
```

**NET_* IPC labels** (0xA0-0xBA, 27 labels): `NET_SOCKET`, `NET_CONNECT`, `NET_SEND`, `NET_RECV`, `NET_CLOSE`, `NET_BIND`, `NET_LISTEN`, `NET_ACCEPT`, `NET_SENDTO`, `NET_RECVFROM`, `NET_SHUTDOWN`, `NET_GETSOCKNAME`, `NET_GETPEERNAME`, `NET_SETSOCKOPT`, `NET_GETSOCKOPT`, `NET_POLL_STATUS`, `NET_REGISTER_VFS`, `NET_COMPLETE`, `NET_DNS_RESOLVE`, `NET_DNS_RESOLVE_PTR`, `NET_GET_CONFIG`, `NET_GET_ARP_ENTRY`, `NET_RECV_WAIT`, `NET_ACCEPT_WAIT`, `NET_RECVFROM_WAIT`, `NET_SEND_WAIT`, `NET_SENDTO_WAIT`.

**Blocking operation model:** VFS acts as a proxy between userland and netsrv. Non-blocking operations (socket, bind, listen, getsockname, close) are forwarded synchronously. Blocking operations (connect, recv, accept) save the client's reply cap and return asynchronously via netsrv's badged message on the shared VFS backend callback endpoint when the operation completes.

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
init grants NET_RAW capability to /usr/bin/ping at exec time
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

### Unix Sockets

| POSIX | SaltyOS |
|-------|---------|
| `socket(AF_UNIX, SOCK_STREAM)` | VFS-managed socket object (MessagePipe-backed) |
| `bind("/path")` | Register with VFS / nameserver |
| `connect("/path")` | Look up the socket, connect via VFS |
| `sendmsg` with `SCM_RIGHTS` | Transfer capability via MessagePipe cap-transfer |

### Signals

| POSIX | SaltyOS |
|-------|---------|
| `kill(pid, SIGTERM)` | Deliver via MessagePipe to the target (through init) |
| `signal(SIGCHLD, handler)` | Register a handler; the trampoline consumes the signal pipe via its EventQueue |
| `sigwait()` | `EQ_WAIT` on the signal EventQueue |

### Shared Memory

| POSIX | SaltyOS |
|-------|---------|
| `shm_open("/name")` | Create named shared memory object |
| `mmap(fd, ...)` | Map SHM backing via mmsrv shared/private mmap path |
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
├── init (fork, exec, wait, kill)
└── Signal delivery (MessagePipe-based)

Phase 2: GUI-Ready                                [DONE]
├── Unix domain sockets (AF_UNIX)
├── SCM_RIGHTS (fd passing via capability transfer)
├── POSIX shared memory (shm_open, shm_unlink)
├── poll/select/epoll
├── Pipes, FIFOs, dup/dup3
└── Terminal line discipline

Phase 3: Networking + Threading                   [DONE]
├── TCP/IP stack (netsrv: TCP, UDP, ARP, ICMP)
├── DHCP client (netsrv built-in)
├── DNS resolver (dnssrv — caching)
├── AF_INET sockets (stream + datagram)
├── virtio-net driver (netdrv)
├── POSIX threads (pthread_create, join, mutexes, condvars, barriers, semaphores, TLS)
└── getaddrinfo / DNS resolution

Phase 4: Extended Compatibility                   [IN PROGRESS]
├── SA_RESTART, sigaltstack                       [Planned]
├── Real-time signals (SIGRTMIN-SIGRTMAX)         [Planned]
└── Broader application testing                   [Ongoing]

Phase 5: Optimization                            [Planned]
├── Zero-copy I/O paths
├── Async I/O (io_uring style)
└── Performance tuning
```

## References

- [POSIX.1-2017 Specification](https://pubs.opengroup.org/onlinepubs/9699919799/)
- [Wayland Protocol](https://wayland.freedesktop.org/docs/html/)
- [QNX Resource Managers](https://www.qnx.com/developers/docs/)
- [Minix3 Design](https://wiki.minix3.org/)
