//! SaltyOS system constants
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Userland source of truth for syscall numbers, capability invoke labels,
//! error codes, well-known cap slots, VSpace flags, object types, POSIX
//! protocol labels, ELF constants, and address layout.
//!
//! **These values must be kept in sync with the kernel.** The kernel defines
//! its own copies in `kernel/src/syscall/mod.rs` and `kernel/src/cap/`.
//! Any mismatch will cause silent protocol errors.

/// System call numbers. Each corresponds to a variant of the kernel's
/// `Syscall` enum in `kernel/src/syscall/mod.rs`.
pub const SYS_SEND: u64 = 0;
pub const SYS_RECV: u64 = 1;
pub const SYS_CALL: u64 = 2;
pub const SYS_REPLY_RECV: u64 = 3;
pub const SYS_NBSEND: u64 = 4;
pub const SYS_SIGNAL: u64 = 5;
pub const SYS_WAIT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_YIELD: u64 = 8;
pub const SYS_INVOKE: u64 = 9;
pub const SYS_DEBUG_PUTCHAR: u64 = 10;
pub const SYS_DEBUG_DUMP_STATE: u64 = 11;
pub const SYS_CLOCK_GETTIME: u64 = 12;
pub const SYS_NANOSLEEP: u64 = 13;
pub const SYS_DEBUG_PUTSTR: u64 = 14;
pub const SYS_DEBUG_PUTBUF: u64 = 15;
pub const SYS_DEBUG_CONSOLE_CONTROL: u64 = 16;

/// Clock IDs for `SYS_CLOCK_GETTIME`.
pub const CLOCK_MONOTONIC: i32 = 0;
pub const CLOCK_REALTIME: i32 = 1;

/// CNode invoke labels (0x10-0x18): copy, mint, move, mutate, delete, revoke, save_caller, set_guard, get_info.
pub const CNODE_COPY: u64 = 0x10;
pub const CNODE_MINT: u64 = 0x11;
pub const CNODE_MOVE: u64 = 0x12;
pub const CNODE_MUTATE: u64 = 0x13;
pub const CNODE_DELETE: u64 = 0x14;
pub const CNODE_REVOKE: u64 = 0x15;
pub const CNODE_SAVE_CALLER: u64 = 0x16;
pub const CNODE_SET_GUARD: u64 = 0x17;
pub const CNODE_GET_INFO: u64 = 0x18;

/// Untyped invoke label (0x20): retype raw memory into typed kernel objects.
pub const UNTYPED_RETYPE: u64 = 0x20;

/// SchedContext invoke labels (0x30-0x31): configure budget/period, bind to TCB.
pub const SC_CONFIGURE: u64 = 0x30;
pub const SC_BIND: u64 = 0x31;

/// TCB invoke labels (0x40-0x4B): configure, resume, suspend, set_space, write_registers, etc.
pub const TCB_CONFIGURE: u64 = 0x40;
pub const TCB_RESUME: u64 = 0x41;
pub const TCB_SUSPEND: u64 = 0x42;
pub const TCB_SET_SPACE: u64 = 0x43;
pub const TCB_WRITE_REGISTERS: u64 = 0x46;
pub const TCB_SET_IPC_BUFFER: u64 = 0x48;
pub const TCB_BIND_NOTIFICATION: u64 = 0x49;
pub const TCB_SET_FAULT_HANDLER: u64 = 0x4B;

/// VSpace invoke labels (0x50-0x57): map, unmap, map_pt, walk, copy_page, map_device, clone_cow, map_device_range.
pub const VSPACE_MAP: u64 = 0x50;
pub const VSPACE_UNMAP: u64 = 0x51;
pub const VSPACE_MAP_PT: u64 = 0x52;
pub const VSPACE_WALK: u64 = 0x53;
pub const VSPACE_COPY_PAGE: u64 = 0x54;
pub const VSPACE_MAP_DEVICE: u64 = 0x55;
pub const VSPACE_CLONE_COW_PAGE: u64 = 0x56;
pub const VSPACE_MAP_DEVICE_RANGE: u64 = 0x57;

/// IRQ handler invoke labels (0x61-0x62): acknowledge IRQ, set notification cap.
pub const IRQ_HANDLER_ACK: u64 = 0x61;
pub const IRQ_HANDLER_SET_NOTIFICATION: u64 = 0x62;

/// I/O port invoke labels (0x70-0x73): 8-bit and 16-bit port read/write.
pub const IOPORT_IN8: u64 = 0x70;
pub const IOPORT_OUT8: u64 = 0x71;
pub const IOPORT_IN16: u64 = 0x72;
pub const IOPORT_OUT16: u64 = 0x73;

/// Console server IPC labels: read/write serial data, terminal attributes.
pub const CONSOLE_WRITE: u64 = 1;
pub const CONSOLE_READ: u64 = 2;
pub const CONSOLE_TCGETATTR: u64 = 3;
pub const CONSOLE_TCSETATTR: u64 = 4;

/// Display server IPC labels: framebuffer info, present, fill, text, terminal writes.
pub const DISPLAY_GET_INFO: u64 = 1;
pub const DISPLAY_PRESENT: u64 = 2;
pub const DISPLAY_FILL_RECT: u64 = 6;
pub const DISPLAY_WRITE_TEXT: u64 = 7;
pub const DISPLAY_TERMINAL_WRITE: u64 = 8;

/// Well-known capability slots. Set by the kernel for init, inherited by
/// child processes. Slots 0-15 are reserved; 16+ are untyped memory.
pub const CAP_SELF_TCB: u64 = 0;
pub const CAP_SELF_VSPACE: u64 = 1;
pub const CAP_SELF_CSPACE: u64 = 2;
pub const CAP_PROCMGR_EP: u64 = 3;
pub const CAP_VFS_EP: u64 = 4;
pub const CAP_NAMESERV_EP: u64 = 5;
pub const CAP_SIGNAL_NTFN: u64 = 6;
pub const CAP_UNTYPED: u64 = 7;
pub const CAP_COM1_IOPORT: u64 = 8;
pub const CAP_EXPAND_EP: u64 = 9;
pub const CAP_COM1_IRQ: u64 = 9;
pub const CAP_COM1_NTFN: u64 = 10;
pub const CAP_CONSOLE_EP: u64 = 11;
pub const CAP_INITRD_UNTYPED: u64 = 12;
pub const CAP_FB_UNTYPED: u64 = 13;
pub const CAP_READINESS_NTFN: u64 = 14;
pub const CAP_DISPLAY_EP: u64 = 15;
pub const CAP_UNTYPED_START: u64 = 16;

/// Fixed virtual addresses for well-known memory regions.
pub const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
pub const SCRATCH_VADDR: u64 = 0x0000_0000_0200_0000;
pub const BOOTINFO_VADDR: u64 = 0x0000_0000_00C0_0000;
pub const BOOTINFO_MAGIC: u64 = 0x534C5459_424F4F54; // "SLTYBOOT"

/// Capability rights bitmask (all rights granted).
pub const CAP_RIGHTS_ALL: u64 = 0xFFFF_FFFF;

/// Error codes returned in `SaltyResult.error`. Must match kernel `SyscallError` variants.
pub const SALTY_OK: u64 = 0;
pub const SALTY_INVALID_CAPABILITY: u64 = 1;
pub const SALTY_INVALID_OPERATION: u64 = 2;
pub const SALTY_INSUFFICIENT_RIGHTS: u64 = 3;
pub const SALTY_INVALID_ARGUMENT: u64 = 4;
pub const SALTY_OUT_OF_MEMORY: u64 = 5;
pub const SALTY_NOT_FOUND: u64 = 6;
pub const SALTY_BUSY: u64 = 7;
pub const SALTY_ALREADY_EXISTS: u64 = 8;
pub const SALTY_WOULD_BLOCK: u64 = 9;
pub const SALTY_PENDING: u64 = 0x80;

/// VSpace page mapping flags (passed to `vspace_map`).
pub const VSPACE_FLAG_WRITABLE: u64 = 1 << 0;
pub const VSPACE_FLAG_USER: u64 = 1 << 1;
pub const VSPACE_FLAG_EXECUTABLE: u64 = 1 << 2;
pub const VSPACE_FLAG_CACHE_DISABLE: u64 = 1 << 3;
pub const VSPACE_FLAG_WRITE_THROUGH: u64 = 1 << 4;
pub const VSPACE_FLAG_COW: u64 = 1 << 5;

/// Kernel object types for `UNTYPED_RETYPE`. Must match `kernel/src/cap/untyped.rs`.
pub const OBJ_UNTYPED: u64 = 1;
pub const OBJ_ENDPOINT: u64 = 2;
pub const OBJ_NOTIFICATION: u64 = 3;
pub const OBJ_TCB: u64 = 4;
pub const OBJ_CNODE: u64 = 5;
pub const OBJ_VSPACE: u64 = 6;
pub const OBJ_FRAME: u64 = 7;
pub const OBJ_IRQ_HANDLER: u64 = 8;
pub const OBJ_IO_PORT: u64 = 9;
pub const OBJ_SCHED_CONTEXT: u64 = 10;

/// POSIX VFS IPC protocol labels. Each label identifies a file operation
/// dispatched to the VFS server via `Call(CAP_VFS_EP, ...)`.
pub const POSIX_VFS_OPEN: u64 = 1;
pub const POSIX_VFS_READ: u64 = 2;
pub const POSIX_VFS_WRITE: u64 = 3;
pub const POSIX_VFS_CLOSE: u64 = 4;
pub const POSIX_VFS_STAT: u64 = 5;
pub const POSIX_VFS_LSEEK: u64 = 6;
pub const POSIX_VFS_FSTAT: u64 = 7;
pub const POSIX_VFS_ACCESS: u64 = 8;
pub const POSIX_VFS_UNLINK: u64 = 9;
pub const POSIX_VFS_RENAME: u64 = 10;
pub const POSIX_VFS_MKDIR: u64 = 11;
pub const POSIX_VFS_RMDIR: u64 = 12;
pub const POSIX_VFS_OPENDIR: u64 = 13;
pub const POSIX_VFS_READDIR: u64 = 14;
pub const POSIX_VFS_LSTAT: u64 = 15;
pub const POSIX_VFS_POLL: u64 = 16;
pub const POSIX_VFS_SHM_OPEN: u64 = 17;
pub const POSIX_VFS_SHM_UNLINK: u64 = 18;
pub const POSIX_VFS_FTRUNCATE: u64 = 19;
pub const POSIX_VFS_SOCKET: u64 = 20;
pub const POSIX_VFS_BIND: u64 = 21;
pub const POSIX_VFS_LISTEN: u64 = 22;
pub const POSIX_VFS_ACCEPT: u64 = 23;
pub const POSIX_VFS_CONNECT: u64 = 24;
pub const POSIX_VFS_SENDMSG: u64 = 25;
pub const POSIX_VFS_RECVMSG: u64 = 26;
pub const POSIX_VFS_SOCKPAIR: u64 = 27;
pub const POSIX_VFS_SHUTDOWN: u64 = 28;
pub const POSIX_VFS_PIPE: u64 = 29;
pub const POSIX_VFS_DUP: u64 = 30;
pub const POSIX_VFS_DUP2: u64 = 31;
pub const POSIX_VFS_CLONE_FDS: u64 = 32;
pub const POSIX_VFS_IOCTL: u64 = 33;
pub const POSIX_VFS_ISATTY: u64 = 34;
pub const POSIX_VFS_FCNTL: u64 = 35;
pub const POSIX_VFS_CHDIR: u64 = 36;
pub const POSIX_VFS_GETCWD: u64 = 37;
pub const POSIX_VFS_TCGETATTR: u64 = 38;
pub const POSIX_VFS_TCSETATTR: u64 = 39;
pub const POSIX_VFS_EPOLL_CREATE: u64 = 40;
pub const POSIX_VFS_EPOLL_CTL: u64 = 41;
pub const POSIX_VFS_EPOLL_WAIT: u64 = 42;
pub const POSIX_VFS_DUP3: u64 = 43;
pub const POSIX_VFS_MKFIFO: u64 = 44;
pub const POSIX_VFS_MMAP: u64 = 45;
pub const POSIX_VFS_MUNMAP: u64 = 46;
pub const POSIX_VFS_OPENAT: u64 = 47;
pub const POSIX_VFS_FSTATAT: u64 = 48;
pub const POSIX_VFS_UNLINKAT: u64 = 49;
pub const POSIX_VFS_RENAMEAT: u64 = 50;
pub const POSIX_VFS_MKDIRAT: u64 = 51;
pub const POSIX_VFS_FACCESSAT: u64 = 52;
pub const POSIX_VFS_FCHMODAT: u64 = 53;
pub const POSIX_VFS_FCHOWNAT: u64 = 54;
pub const POSIX_VFS_LINKAT: u64 = 55;
pub const POSIX_VFS_SYMLINKAT: u64 = 56;
pub const POSIX_VFS_READLINKAT: u64 = 57;
pub const POSIX_VFS_UTIMENSAT: u64 = 58;
pub const POSIX_VFS_FCHMOD: u64 = 59;
pub const POSIX_VFS_FCHOWN: u64 = 60;

// AT_* flags for *at() family
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
pub const AT_EMPTY_PATH: i32 = 0x1000;

// utimensat special values
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

// fcntl commands
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
pub const FD_CLOEXEC: i32 = 1;

// ioctl requests
pub const TIOCGPGRP: u64 = 0x540F;
pub const TIOCSPGRP: u64 = 0x5410;
pub const TIOCGWINSZ: u64 = 0x5413;

// Framebuffer ioctl requests
pub const FBIOGET_VSCREENINFO: u64 = 0x4600;
pub const FBIOGET_FSCREENINFO: u64 = 0x4602;

/// Process manager IPC protocol labels. Operations dispatched via
/// `Call(CAP_PROCMGR_EP, ...)`.
pub const POSIX_PM_SPAWN: u64 = 1;

// Spawn readiness modes (bits [1:0] of spawn_policy)
pub const SPAWN_READY_IMMEDIATE: u64 = 0;
pub const SPAWN_READY_NOTIFY: u64 = 1;

/// Build a spawn_policy bitfield from components.
///
/// Layout:
///   bits [1:0]  = readiness_mode (0=IMMEDIATE, 1=NOTIFY)
///   bit  [2]    = map_initrd
///   bit  [3]    = is_display
///   bits [15:8] = cnode_bits (0=default 10-bit)
///   bits [31:16] = memory_kb (0=procmgr default)
pub const fn spawn_policy_build(
    readiness_mode: u64,
    map_initrd: bool,
    is_display: bool,
    cnode_bits: u8,
    memory_kb: u16,
) -> u64 {
    let mut p = readiness_mode & 0x3;
    if map_initrd { p |= 1 << 2; }
    if is_display { p |= 1 << 3; }
    p |= (cnode_bits as u64) << 8;
    p |= (memory_kb as u64) << 16;
    p
}

pub const fn spawn_policy_readiness(policy: u64) -> u64 {
    policy & 0x3
}

pub const fn spawn_policy_map_initrd(policy: u64) -> bool {
    (policy & (1 << 2)) != 0
}

pub const fn spawn_policy_is_display(policy: u64) -> bool {
    (policy & (1 << 3)) != 0
}

pub const fn spawn_policy_cnode_bits(policy: u64) -> u8 {
    ((policy >> 8) & 0xFF) as u8
}

pub const fn spawn_policy_memory_kb(policy: u64) -> u16 {
    ((policy >> 16) & 0xFFFF) as u16
}

// Spawn flags (msg.regs[3] in POSIX_PM_SPAWN wire format)
pub const SPAWN_FLAG_USE_PRE_EP: u64 = 1 << 0;

pub const POSIX_PM_EXIT: u64 = 2;
pub const POSIX_PM_WAIT: u64 = 3;
pub const POSIX_PM_GETPID: u64 = 4;
pub const POSIX_PM_FORK: u64 = 5;
pub const POSIX_PM_EXEC: u64 = 6;
pub const POSIX_PM_GETPPID: u64 = 7;
pub const POSIX_PM_KILL: u64 = 8;
pub const POSIX_PM_SIGACTION: u64 = 9;
pub const POSIX_PM_GETUID: u64 = 10;
pub const POSIX_PM_GETGID: u64 = 11;
pub const POSIX_PM_SETPGID: u64 = 12;
pub const POSIX_PM_GETPGID: u64 = 13;
pub const POSIX_PM_SETSID: u64 = 14;
pub const POSIX_PM_GETEUID: u64 = 15;
pub const POSIX_PM_GETEGID: u64 = 16;
pub const POSIX_PM_GETGROUPS: u64 = 17;
pub const POSIX_PM_EXPAND_CSPACE: u64 = 18;
pub const POSIX_PM_EXPAND_CSPACE_ASYNC: u64 = 19;
pub const POSIX_PM_EXPAND_COLLECT: u64 = 20;
pub const POSIX_PM_REGISTER: u64 = 21;
// Deterministic CNode slots for untyped expansion (last 8 slots of 10-bit CNode)
pub const UT_EXPAND_BASE: u64 = 1016;
pub const MAX_UT_EXPANSIONS: usize = 8;

/// Name service IPC protocol labels (register/lookup endpoint by name).
pub const POSIX_NS_REGISTER: u64 = 1;
pub const POSIX_NS_LOOKUP: u64 = 2;

// O_* flags
pub const O_RDONLY: u64 = 0x0000;
pub const O_WRONLY: u64 = 0x0001;
pub const O_RDWR: u64 = 0x0002;
pub const O_CREAT: u64 = 0x0040;
pub const O_EXCL: u64 = 0x0080;
pub const O_TRUNC: u64 = 0x0200;
pub const O_APPEND: u64 = 0x0400;
pub const O_NONBLOCK: u64 = 0x0800;
pub const O_CLOEXEC: u64 = 0x80000;

// SEEK_* constants
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

// File type constants
pub const S_IFMT: u64 = 0o170000;
pub const S_IFDIR: u64 = 0o040000;
pub const S_IFCHR: u64 = 0o020000;
pub const S_IFREG: u64 = 0o100000;
pub const S_IFSOCK: u64 = 0o140000;
pub const S_IFIFO: u64 = 0o010000;

// Access mode flags
pub const F_OK: u64 = 0;
pub const R_OK: u64 = 4;

// Directory entry types
pub const DT_UNKNOWN: u8 = 0;
pub const DT_REG: u8 = 8;
pub const DT_DIR: u8 = 4;
pub const DT_CHR: u8 = 2;
pub const DT_SOCK: u8 = 12;
pub const DT_FIFO: u8 = 1;

// waitpid options
pub const WNOHANG: u64 = 1;

// Signal numbers
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGABRT: i32 = 6;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const NSIG: usize = 32;

// Signal disposition categories
pub const SIG_DISP_DFL: u64 = 0;
pub const SIG_DISP_IGN: u64 = 1;
pub const SIG_DISP_CATCH: u64 = 2;

// sigaction flags
pub const SA_RESETHAND: i32 = 0x80000000u32 as i32;

// PROT_* flags
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

// MAP_* flags
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;

// Memory management limits
pub const MM_MAX_REGIONS: usize = 32;
pub const MM_MAX_FRAME_SLOTS: u64 = 256;
pub const MM_MAX_PAGES_PER_REGION: usize = 64;

// Userland slot allocator auxv types
pub const AT_SALTY_SLOT_BASE: u64 = 0x1007;
pub const AT_SALTY_SLOT_COUNT: u64 = 0x1008;
pub const AT_SALTY_EXPAND_EP: u64 = 0x1009;

/// ELF format constants (class, data encoding, types, segment types, relocation types).
pub const ELF_PAGE_SIZE: u64 = 4096;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_STRTAB: i64 = 5;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const R_X86_64_RELATIVE: u32 = 8;

/// ELF loader error codes returned by `elf_load`.
pub const ELF_OK: i32 = 0;
pub const ELF_NOT_ELF: i32 = 1;
pub const ELF_NOT_64BIT: i32 = 2;
pub const ELF_NOT_LE: i32 = 3;
pub const ELF_BAD_TYPE: i32 = 4;
pub const ELF_BAD_ARCH: i32 = 5;
pub const ELF_NO_LOAD: i32 = 6;
pub const ELF_RELOC_FAILED: i32 = 7;
pub const ELF_OUT_OF_MEMORY: i32 = 8;
pub const ELF_TOO_SMALL: i32 = 9;
pub const ELF_MAP_FAILED: i32 = 11;

/// Socket constants (AF_UNIX, SOCK_STREAM, SCM_RIGHTS, shutdown modes).
pub const AF_UNIX: i32 = 1;
pub const SOCK_STREAM: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;
pub const SOL_SOCKET: i32 = 1;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// Poll event flags (POLLIN, POLLOUT, POLLERR, POLLHUP, POLLNVAL).
pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;

/// Epoll constants (CTL operations and event flags).
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

/// CPIO newc header size in bytes (magic + fixed fields).
pub const CPIO_HEADER_SIZE: usize = 110;
