// SPDX-License-Identifier: GPL-2.0-only
//! PTY data structures: ring buffers, termios settings, and PTY instances.

// Capability layout
pub const CAP_SELF_CSPACE: u64 = 2;
pub const CAP_PROCMGR_EP: u64 = 3;
pub const CAP_NAMESERV_EP: u64 = 5;
pub const CAP_READINESS_NTFN: u64 = 14;
pub const CAP_MMSRV_EP: u64 = 7;
pub const CAP_DISPLAY_EP: u64 = 65;
pub const CAP_VFS_NTFN: u64 = 66;
pub const CAP_SERVER_EP: u64 = 68;
pub const CAP_DISPLAY_RING_NTFN: u64 = 69;

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

// POLLIN/POLLOUT for PTY_POLL
pub const POLLIN: i16 = 0x0001;
pub const POLLOUT: i16 = 0x0004;
pub const POLLHUP: i16 = 0x0010;

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
        RingBuf { buf: [0; RING_SIZE], head: 0, tail: 0 }
    }

    pub fn is_empty(&self) -> bool { self.head == self.tail }
    pub fn is_full(&self) -> bool { ((self.head + 1) % RING_SIZE) == self.tail }

    pub fn push(&mut self, c: u8) -> bool {
        if self.is_full() { return false; }
        self.buf[self.head] = c;
        self.head = (self.head + 1) % RING_SIZE;
        true
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.is_empty() { return None; }
        let c = self.buf[self.tail];
        self.tail = (self.tail + 1) % RING_SIZE;
        Some(c)
    }

    pub fn len(&self) -> usize {
        (self.head + RING_SIZE - self.tail) % RING_SIZE
    }

    pub fn clear(&mut self) { self.head = 0; self.tail = 0; }
}

pub struct InputLineBuf {
    pub buf: [u8; LINE_BUF_SIZE],
    pub len: usize,
}

impl InputLineBuf {
    pub const fn new() -> Self {
        InputLineBuf { buf: [0; LINE_BUF_SIZE], len: 0 }
    }

    pub fn push(&mut self, c: u8) -> bool {
        if self.len >= LINE_BUF_SIZE { return false; }
        self.buf[self.len] = c;
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> bool {
        if self.len == 0 { return false; }
        self.len -= 1;
        true
    }

    pub fn clear(&mut self) { self.len = 0; }
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
        c_cc[VINTR] = 3;     // Ctrl-C
        c_cc[VQUIT] = 28;    // Ctrl-backslash
        c_cc[VERASE] = 127;  // DEL
        c_cc[VKILL] = 21;    // Ctrl-U
        c_cc[VEOF] = 4;      // Ctrl-D
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 17;   // Ctrl-Q
        c_cc[VSTOP] = 19;    // Ctrl-S
        c_cc[VSUSP] = 26;    // Ctrl-Z
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
    // Canonical mode line accumulator
    pub line: InputLineBuf,
    // Per-PTY termios
    pub termios: PtyTermios,
    // Controlling terminal ownership + foreground process group
    pub has_ctty: bool,
    pub ctty_session_id: u64,
    pub fg_pgid: u32,
    // Whether VFS has a pending read for this PTY (needs notification on data)
    pub vfs_pending: bool,
    // State tracking
    pub master_closed: bool,
    pub slave_closed: bool,
}

impl PtyInstance {
    pub const fn new() -> Self {
        PtyInstance {
            active: false,
            slave_ring: RingBuf::new(),
            spill_ring: RingBuf::new(),
            line: InputLineBuf::new(),
            termios: PtyTermios::default(),
            has_ctty: false,
            ctty_session_id: 0,
            fg_pgid: 0,
            vfs_pending: false,
            master_closed: false,
            slave_closed: false,
        }
    }
}
