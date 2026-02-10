//! SaltyOS system constants
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Syscall numbers, invoke labels, error codes, cap slots, address constants.
//! Must match kernel definitions.

// System call numbers (must match kernel/src/syscall/mod.rs Syscall enum)
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

// Clock IDs
pub const CLOCK_MONOTONIC: i32 = 0;
pub const CLOCK_REALTIME: i32 = 1;

// CNode operations (0x10-0x16)
pub const CNODE_COPY: u64 = 0x10;
pub const CNODE_MINT: u64 = 0x11;
pub const CNODE_MOVE: u64 = 0x12;
pub const CNODE_MUTATE: u64 = 0x13;
pub const CNODE_DELETE: u64 = 0x14;
pub const CNODE_REVOKE: u64 = 0x15;
pub const CNODE_SAVE_CALLER: u64 = 0x16;

// Untyped operations (0x20)
pub const UNTYPED_RETYPE: u64 = 0x20;

// SchedContext operations (0x30-0x34)
pub const SC_CONFIGURE: u64 = 0x30;
pub const SC_BIND: u64 = 0x31;

// TCB operations (0x40-0x4B)
pub const TCB_CONFIGURE: u64 = 0x40;
pub const TCB_RESUME: u64 = 0x41;
pub const TCB_SUSPEND: u64 = 0x42;
pub const TCB_SET_SPACE: u64 = 0x43;
pub const TCB_WRITE_REGISTERS: u64 = 0x46;
pub const TCB_SET_IPC_BUFFER: u64 = 0x48;
pub const TCB_BIND_NOTIFICATION: u64 = 0x49;
pub const TCB_SET_FAULT_HANDLER: u64 = 0x4B;

// VSpace operations (0x50-0x54)
pub const VSPACE_MAP: u64 = 0x50;
pub const VSPACE_UNMAP: u64 = 0x51;
pub const VSPACE_MAP_PT: u64 = 0x52;
pub const VSPACE_WALK: u64 = 0x53;
pub const VSPACE_COPY_PAGE: u64 = 0x54;

// IRQ operations (0x60-0x63)
pub const IRQ_HANDLER_ACK: u64 = 0x61;
pub const IRQ_HANDLER_SET_NOTIFICATION: u64 = 0x62;

// IoPort operations (0x70-0x73)
pub const IOPORT_IN8: u64 = 0x70;
pub const IOPORT_OUT8: u64 = 0x71;
pub const IOPORT_IN16: u64 = 0x72;
pub const IOPORT_OUT16: u64 = 0x73;

// Console IPC message labels
pub const CONSOLE_WRITE: u64 = 1;
pub const CONSOLE_READ: u64 = 2;

// Well-known cap slots
pub const CAP_SELF_TCB: u64 = 0;
pub const CAP_SELF_VSPACE: u64 = 1;
pub const CAP_SELF_CSPACE: u64 = 2;
pub const CAP_PROCMGR_EP: u64 = 3;
pub const CAP_VFS_EP: u64 = 4;
pub const CAP_NAMESERV_EP: u64 = 5;
pub const CAP_SIGNAL_NTFN: u64 = 6;
pub const CAP_UNTYPED: u64 = 7;
pub const CAP_COM1_IOPORT: u64 = 8;
pub const CAP_COM1_IRQ: u64 = 9;
pub const CAP_COM1_NTFN: u64 = 10;
pub const CAP_CONSOLE_EP: u64 = 11;
pub const CAP_READINESS_NTFN: u64 = 12;
pub const CAP_UNTYPED_START: u64 = 16;

// Addresses
pub const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
pub const SCRATCH_VADDR: u64 = 0x0000_0000_0200_0000;

// Capability rights
pub const CAP_RIGHTS_ALL: u64 = 0xFFFF_FFFF;

// Error codes
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

// VSpace map flags
pub const VSPACE_FLAG_WRITABLE: u64 = 1 << 0;
pub const VSPACE_FLAG_USER: u64 = 1 << 1;
pub const VSPACE_FLAG_EXECUTABLE: u64 = 1 << 2;

// Object types for Untyped_Retype
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

// POSIX VFS protocol labels
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

// Procmgr protocol labels
pub const POSIX_PM_SPAWN: u64 = 1;
pub const POSIX_PM_EXIT: u64 = 2;
pub const POSIX_PM_WAIT: u64 = 3;
pub const POSIX_PM_GETPID: u64 = 4;
pub const POSIX_PM_FORK: u64 = 5;
pub const POSIX_PM_EXEC: u64 = 6;
pub const POSIX_PM_GETPPID: u64 = 7;
pub const POSIX_PM_KILL: u64 = 8;
pub const POSIX_PM_SIGACTION: u64 = 9;

// Nameserv protocol labels
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
pub const MM_MAX_REGIONS: usize = 128;
pub const MM_MAX_FRAME_SLOTS: u64 = 1024;
pub const MM_MAX_PAGES_PER_REGION: usize = 256;

// ELF constants
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
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const R_X86_64_RELATIVE: u32 = 8;

// ELF load errors
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

// Socket constants
pub const AF_UNIX: i32 = 1;
pub const SOCK_STREAM: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;
pub const SOL_SOCKET: i32 = 1;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

// Poll event flags
pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;

// Epoll constants
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

// CPIO header size
pub const CPIO_HEADER_SIZE: usize = 110;
