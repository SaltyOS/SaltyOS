// SPDX-License-Identifier: GPL-2.0-only
//! PTY data structures: ring buffers, termios settings, and PTY instances.

// Capability layout: system roles flow through `trona_runtime::client::caps::*` (populated by
// libtrona's `__trona_cap_*` weak symbols). The service-local
// `Require=dispdrv-ep.socket` is resolved through the `trona_runtime::local_cap!`
// macro in `main.rs` (see `crate::dispdrv_ep`).
//
// Buffer sizes and limits
pub const RING_SIZE: usize = 16384;
pub const LINE_BUF_SIZE: usize = 256;
pub const MAX_PTYS: usize = 4;

// Local flags (c_lflag)
pub const ISIG: u32 = 0o000001;
pub const ICANON: u32 = 0o000002;
pub const ECHO: u32 = 0o000010;
pub const ECHOE: u32 = 0o000020;
pub const ECHOK: u32 = 0o000040;
pub const ECHONL: u32 = 0o000100;
pub const ECHOCTL: u32 = 0o001000;
pub const ECHOKE: u32 = 0o004000;
pub const IEXTEN: u32 = 0o100000;

// Input flags (c_iflag)
pub const ICRNL: u32 = 0o000400;
pub const IXON: u32 = 0o002000;

// Output flags (c_oflag)
pub const OPOST: u32 = 0o000001;
pub const ONLCR: u32 = 0o000004;

// Control flags (c_cflag)
pub const CS8: u32 = 0o000060;
pub const CREAD: u32 = 0o000200;
pub const CLOCAL: u32 = 0o004000;

// cc indices
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;

pub const B38400: u32 = 38400;

// POLLIN/POLLOUT/POLLHUP come from trona_posix::consts.

// Actual terminal dimensions (queried from display server at startup)
pub static mut WINSIZE_ROWS: u32 = 24;
pub static mut WINSIZE_COLS: u32 = 80;

pub struct RingBuf {
    buf: [u8; RING_SIZE],
    head: usize,
    tail: usize,
}

impl RingBuf {
    pub const fn new() -> Self {
        RingBuf {
            buf: [0; RING_SIZE],
            head: 0,
            tail: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }
    pub fn is_full(&self) -> bool {
        ((self.head + 1) % RING_SIZE) == self.tail
    }

    pub fn push(&mut self, c: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.buf[self.head] = c;
        self.head = (self.head + 1) % RING_SIZE;
        true
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let c = self.buf[self.tail];
        self.tail = (self.tail + 1) % RING_SIZE;
        Some(c)
    }

    pub fn len(&self) -> usize {
        (self.head + RING_SIZE - self.tail) % RING_SIZE
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}

pub struct InputLineBuf {
    pub buf: [u8; LINE_BUF_SIZE],
    pub len: usize,
}

impl InputLineBuf {
    pub const fn new() -> Self {
        InputLineBuf {
            buf: [0; LINE_BUF_SIZE],
            len: 0,
        }
    }

    pub fn push(&mut self, c: u8) -> bool {
        if self.len >= LINE_BUF_SIZE {
            return false;
        }
        self.buf[self.len] = c;
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.len -= 1;
        true
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

pub struct PtyTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl PtyTermios {
    pub const fn default() -> Self {
        let mut c_cc = [0u8; 32];
        c_cc[VINTR] = 3; // Ctrl-C
        c_cc[VQUIT] = 28; // Ctrl-backslash
        c_cc[VERASE] = 127; // DEL
        c_cc[VKILL] = 21; // Ctrl-U
        c_cc[VEOF] = 4; // Ctrl-D
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 17; // Ctrl-Q
        c_cc[VSTOP] = 19; // Ctrl-S
        c_cc[VSUSP] = 26; // Ctrl-Z
        PtyTermios {
            c_iflag: ICRNL | IXON,
            c_oflag: OPOST | ONLCR,
            c_cflag: CS8 | CREAD | CLOCAL,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN | ECHOCTL | ECHOKE,
            c_cc,
            c_ispeed: B38400,
            c_ospeed: B38400,
        }
    }
}

pub struct PtyInstance {
    pub active: bool,
    // Slave-side input ring (data from keyboard -> line disc -> here -> bash reads)
    pub slave_ring: RingBuf,
    // Overflow ring used when the primary slave ring is temporarily full.
    pub spill_ring: RingBuf,
    // Master-side read ring (data written by the slave, readable by ptmx).
    pub master_ring: RingBuf,
    // Canonical mode line accumulator
    pub line: InputLineBuf,
    // Per-PTY termios
    pub termios: PtyTermios,
    // Controlling terminal ownership + foreground process group
    pub has_ctty: bool,
    pub ctty_session_id: u64,
    pub fg_pgid: u32,
    // Whether VFS has a pending read for each PTY side (needs
    // VFS_PTY_READY on data). The ready wire is keyed by pty_id; VFS
    // fans out to the parked read ops and preserves the side there.
    pub vfs_pending_slave: bool,
    pub vfs_pending_master: bool,
    // Open-reference counts per side. A matching
    // `POSIX_TTYSRV_PTY_CLOSE` (issued by VFS's `release_backing` on
    // the last OFD reference for that side) decrements the matching
    // counter. The PTY slot is reset only when both counts reach
    // zero; PTY 0 is never reset so the console path stays alive.
    //
    // `handle_pty_alloc` initialises both counts to `1`, which
    // matches the legacy `master_closed=false, slave_closed=false`
    // semantics while letting `release_backing` notify exactly once
    // per side on last reference.
    pub master_open_count: u32,
    pub slave_open_count: u32,
    /// Monotonic generation counter incremented on every
    /// `reset_allocated_pty` call. VFS records the generation at
    /// `POSIX_TTYSRV_PTY_LOOKUP` time and passes it back on
    /// `POSIX_TTYSRV_PTY_OPEN_SLAVE` so stale vdata that points at a
    /// reallocated slot is rejected cleanly.
    pub generation: u32,
}

impl PtyInstance {
    pub const fn new() -> Self {
        PtyInstance {
            active: false,
            slave_ring: RingBuf::new(),
            spill_ring: RingBuf::new(),
            master_ring: RingBuf::new(),
            line: InputLineBuf::new(),
            termios: PtyTermios::default(),
            has_ctty: false,
            ctty_session_id: 0,
            fg_pgid: 0,
            vfs_pending_slave: false,
            vfs_pending_master: false,
            master_open_count: 0,
            slave_open_count: 0,
            generation: 0,
        }
    }
}
