// SPDX-License-Identifier: GPL-2.0-only
//! TCP (Transmission Control Protocol) implementation.
//!
//! Provides a connection-oriented, reliable byte-stream protocol over IPv4.
//! Implements the TCP state machine per RFC 793 with retransmission support.

use super::checksum;
use super::ipv4::{self, Ipv4Header, PROTO_TCP};
use besalt::consts::{
    INET_OP_ACCEPT, INET_OP_CONNECT, INET_OP_RECV, BESALT_CONN_REFUSED, BESALT_OK, BESALT_TIMED_OUT,
    SYS_CLOCK_GETTIME, SYS_GETRANDOM,
};
use besalt::types::Timespec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TCP_CONNS: usize = 16;
const TCP_RX_BUF_SIZE: usize = 8192;
const TCP_TX_BUF_SIZE: usize = 8192;
const MAX_LISTEN_BACKLOG: usize = 4;
const MAX_COMPLETIONS: usize = 8;
const TCP_HEADER_LEN: usize = 20;
const MAX_RETRIES: u32 = 5;
const INITIAL_RTO_MS: u64 = 1000;
const MAX_RTO_MS: u64 = 64000;
const TIME_WAIT_NS: u64 = 60_000_000_000; // 60 seconds (simplified 2*MSL)
const DEFAULT_MSS: u16 = 1460;
const DEFAULT_WINDOW: u16 = 8192;
const NS_PER_MS: u64 = 1_000_000;

pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_SYN: u8 = 0x02;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
pub(crate) const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_ACK: u8 = 0x10;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Clone, Copy)]
struct PendingSyn {
    remote_ip: u32,
    remote_port: u16,
    irs: u32,
    iss: u32,
}

struct RingBuf {
    data: [u8; TCP_RX_BUF_SIZE],
    head: usize,
    tail: usize,
    len: usize,
    cap: usize,
}

impl RingBuf {
    const fn new(cap: usize) -> Self {
        RingBuf {
            data: [0u8; TCP_RX_BUF_SIZE],
            head: 0,
            tail: 0,
            len: 0,
            cap,
        }
    }

    fn available(&self) -> usize {
        self.cap - self.len
    }

    fn write(&mut self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.available());
        for i in 0..n {
            self.data[self.tail] = src[i];
            self.tail = (self.tail + 1) % self.cap;
        }
        self.len += n;
        n
    }

    fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.len);
        for i in 0..n {
            dst[i] = self.data[self.head];
            self.head = (self.head + 1) % self.cap;
        }
        self.len -= n;
        n
    }

    fn peek_all(&self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.len);
        let mut pos = self.head;
        for i in 0..n {
            dst[i] = self.data[pos];
            pos = (pos + 1) % self.cap;
        }
        n
    }

    fn drain(&mut self, count: usize) {
        let n = core::cmp::min(count, self.len);
        self.head = (self.head + n) % self.cap;
        self.len -= n;
    }

    fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }
}

struct TcpControlBlock {
    active: bool,
    state: TcpState,
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,

    // Sequence state
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u16,
    rcv_nxt: u32,
    rcv_wnd: u16,
    iss: u32,
    irs: u32,

    // Buffers
    rx_buf: RingBuf,
    tx_buf: RingBuf,

    // Retransmission
    rto_ms: u64,
    retx_deadline_ns: u64,
    retx_count: u32,

    mss: u16,

    // Pending async operations
    pending_connect: bool,
    pending_recv: bool,
    pending_recv_max: u16,
    pending_accept: bool,

    // Listen backlog
    backlog: [PendingSyn; MAX_LISTEN_BACKLOG],
    backlog_count: usize,
    max_backlog: usize,

    // Connection identifier
    conn_id: u32,
    // For accepted connections: the listen socket's conn_id
    parent_conn_id: u32,

    // TimeWait deadline
    timewait_deadline_ns: u64,

    // FIN sequence tracking
    fin_seq: u32,
}

static mut TCBS: [TcpControlBlock; MAX_TCP_CONNS] = {
    const INIT: TcpControlBlock = TcpControlBlock {
        active: false,
        state: TcpState::Closed,
        local_ip: 0,
        local_port: 0,
        remote_ip: 0,
        remote_port: 0,
        snd_una: 0,
        snd_nxt: 0,
        snd_wnd: 0,
        rcv_nxt: 0,
        rcv_wnd: DEFAULT_WINDOW,
        iss: 0,
        irs: 0,
        rx_buf: RingBuf {
            data: [0u8; TCP_RX_BUF_SIZE],
            head: 0,
            tail: 0,
            len: 0,
            cap: TCP_RX_BUF_SIZE,
        },
        tx_buf: RingBuf {
            data: [0u8; TCP_RX_BUF_SIZE],
            head: 0,
            tail: 0,
            len: 0,
            cap: TCP_TX_BUF_SIZE,
        },
        rto_ms: INITIAL_RTO_MS,
        retx_deadline_ns: 0,
        retx_count: 0,
        mss: DEFAULT_MSS,
        pending_connect: false,
        pending_recv: false,
        pending_recv_max: 0,
        pending_accept: false,
        backlog: [PendingSyn {
            remote_ip: 0,
            remote_port: 0,
            irs: 0,
            iss: 0,
        }; MAX_LISTEN_BACKLOG],
        backlog_count: 0,
        max_backlog: 0,
        conn_id: 0,
        parent_conn_id: 0,
        timewait_deadline_ns: 0,
        fin_seq: 0,
    };
    [INIT; MAX_TCP_CONNS]
};

static mut NEXT_CONN_ID: u32 = 1;
static mut EPHEMERAL_PORT: u16 = 49152;

static mut COMPLETIONS: [Completion; MAX_COMPLETIONS] = {
    const INIT: Completion = Completion {
        conn_id: 0,
        result: 0,
        op_type: 0,
        data: [0u8; 152],
        data_len: 0,
        extra_conn_id: 0,
        extra_ip: 0,
        extra_port: 0,
    };
    [INIT; MAX_COMPLETIONS]
};
static mut COMP_HEAD: usize = 0;
static mut COMP_TAIL: usize = 0;
static mut COMP_COUNT: usize = 0;

// ---------------------------------------------------------------------------
// Completion queue
// ---------------------------------------------------------------------------

pub(crate) struct Completion {
    pub(crate) conn_id: u32,
    pub(crate) result: u64,
    pub(crate) op_type: u8,
    pub(crate) data: [u8; 152],
    pub(crate) data_len: usize,
    pub(crate) extra_conn_id: u32,
    pub(crate) extra_ip: u32,
    pub(crate) extra_port: u16,
}

fn push_completion(c: Completion) {
    // SAFETY: Single-threaded driver; all statics accessed only from main thread.
    unsafe {
        let count = *(&raw const COMP_COUNT);
        if count >= MAX_COMPLETIONS {
            crate::puts(b"[netsrv] WARN: TCP completion queue full, dropping\n");
            return;
        }
        let tail = *(&raw const COMP_TAIL);
        let slot = &raw mut COMPLETIONS[tail];
        (*slot).conn_id = c.conn_id;
        (*slot).result = c.result;
        (*slot).op_type = c.op_type;
        (*slot).data = c.data;
        (*slot).data_len = c.data_len;
        (*slot).extra_conn_id = c.extra_conn_id;
        (*slot).extra_ip = c.extra_ip;
        (*slot).extra_port = c.extra_port;
        *(&raw mut COMP_TAIL) = (tail + 1) % MAX_COMPLETIONS;
        *(&raw mut COMP_COUNT) = count + 1;
    }
}

pub(crate) fn pop_completion() -> Option<Completion> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let count = *(&raw const COMP_COUNT);
        if count == 0 {
            return None;
        }
        let head = *(&raw const COMP_HEAD);
        let slot = &raw const COMPLETIONS[head];
        let c = Completion {
            conn_id: (*slot).conn_id,
            result: (*slot).result,
            op_type: (*slot).op_type,
            data: (*slot).data,
            data_len: (*slot).data_len,
            extra_conn_id: (*slot).extra_conn_id,
            extra_ip: (*slot).extra_ip,
            extra_port: (*slot).extra_port,
        };
        *(&raw mut COMP_HEAD) = (head + 1) % MAX_COMPLETIONS;
        *(&raw mut COMP_COUNT) = count - 1;
        Some(c)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ns() -> u64 {
    let mut ts = Timespec::zeroed();
    // SAFETY: Passing valid stack pointer for clock_gettime output.
    let _ =
        unsafe { besalt::syscall::syscall(SYS_CLOCK_GETTIME, 0, &raw mut ts as u64, 0, 0, 0, 0) };
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

fn generate_isn() -> u32 {
    let mut buf = [0u8; 4];
    // SAFETY: Passing valid stack buffer to GetRandom syscall.
    let _ =
        unsafe { besalt::syscall::syscall(SYS_GETRANDOM, buf.as_mut_ptr() as u64, 4, 0, 0, 0, 0) };
    let rnd = u32::from_ne_bytes(buf);
    let clock = (now_ns() / 4_000) as u32; // ~4us granularity
    rnd.wrapping_add(clock)
}

fn alloc_ephemeral_port() -> u16 {
    // SAFETY: Single-threaded driver.
    unsafe {
        let start = *(&raw const EPHEMERAL_PORT);
        let mut port = start;
        loop {
            if !port_in_use(port) {
                let next = if port >= 65535 { 49152 } else { port + 1 };
                *(&raw mut EPHEMERAL_PORT) = next;
                return port;
            }
            port = if port >= 65535 { 49152 } else { port + 1 };
            if port == start {
                return 0; // all ports exhausted
            }
        }
    }
}

fn port_in_use(port: u16) -> bool {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcbs = &raw const TCBS;
        for i in 0..MAX_TCP_CONNS {
            let tcb = &(*tcbs)[i];
            if tcb.active && tcb.local_port == port {
                return true;
            }
        }
    }
    false
}

fn alloc_conn_id() -> u32 {
    // SAFETY: Single-threaded driver.
    unsafe {
        let id = *(&raw const NEXT_CONN_ID);
        *(&raw mut NEXT_CONN_ID) = if id >= 999 { 1 } else { id + 1 };
        id
    }
}

fn find_free_tcb() -> Option<usize> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcbs = &raw const TCBS;
        for i in 0..MAX_TCP_CONNS {
            if !(*tcbs)[i].active {
                return Some(i);
            }
        }
    }
    None
}

fn find_tcb_by_conn_id(conn_id: u32) -> Option<usize> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcbs = &raw const TCBS;
        for i in 0..MAX_TCP_CONNS {
            if (*tcbs)[i].active && (*tcbs)[i].conn_id == conn_id {
                return Some(i);
            }
        }
    }
    None
}

fn find_tcb_by_tuple(local_port: u16, remote_ip: u32, remote_port: u16) -> Option<usize> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcbs = &raw const TCBS;
        for i in 0..MAX_TCP_CONNS {
            let t = &(*tcbs)[i];
            if t.active
                && t.local_port == local_port
                && t.remote_ip == remote_ip
                && t.remote_port == remote_port
                && t.state != TcpState::Listen
            {
                return Some(i);
            }
        }
    }
    None
}

fn find_listener(local_port: u16) -> Option<usize> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcbs = &raw const TCBS;
        for i in 0..MAX_TCP_CONNS {
            let t = &(*tcbs)[i];
            if t.active && t.local_port == local_port && t.state == TcpState::Listen {
                return Some(i);
            }
        }
    }
    None
}

fn reset_tcb(idx: usize) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        tcb.active = false;
        tcb.state = TcpState::Closed;
        tcb.local_ip = 0;
        tcb.local_port = 0;
        tcb.remote_ip = 0;
        tcb.remote_port = 0;
        tcb.snd_una = 0;
        tcb.snd_nxt = 0;
        tcb.snd_wnd = 0;
        tcb.rcv_nxt = 0;
        tcb.rcv_wnd = DEFAULT_WINDOW;
        tcb.iss = 0;
        tcb.irs = 0;
        tcb.rx_buf.reset();
        tcb.tx_buf.reset();
        tcb.rto_ms = INITIAL_RTO_MS;
        tcb.retx_deadline_ns = 0;
        tcb.retx_count = 0;
        tcb.mss = DEFAULT_MSS;
        tcb.pending_connect = false;
        tcb.pending_recv = false;
        tcb.pending_recv_max = 0;
        tcb.pending_accept = false;
        tcb.backlog_count = 0;
        tcb.max_backlog = 0;
        tcb.conn_id = 0;
        tcb.parent_conn_id = 0;
        tcb.timewait_deadline_ns = 0;
        tcb.fin_seq = 0;
    }
}

// ---------------------------------------------------------------------------
// Packet building / sending
// ---------------------------------------------------------------------------

fn build_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    buf: &mut [u8],
) -> usize {
    let total = TCP_HEADER_LEN + payload.len();
    if buf.len() < total {
        return 0;
    }

    // Source port
    buf[0] = (src_port >> 8) as u8;
    buf[1] = src_port as u8;
    // Dest port
    buf[2] = (dst_port >> 8) as u8;
    buf[3] = dst_port as u8;
    // Sequence number
    buf[4] = (seq >> 24) as u8;
    buf[5] = (seq >> 16) as u8;
    buf[6] = (seq >> 8) as u8;
    buf[7] = seq as u8;
    // Ack number
    buf[8] = (ack >> 24) as u8;
    buf[9] = (ack >> 16) as u8;
    buf[10] = (ack >> 8) as u8;
    buf[11] = ack as u8;
    // Data offset (5 words = 20 bytes) | reserved
    buf[12] = 0x50;
    // Flags
    buf[13] = flags;
    // Window
    buf[14] = (window >> 8) as u8;
    buf[15] = window as u8;
    // Checksum (zeroed, computed after)
    buf[16] = 0;
    buf[17] = 0;
    // Urgent pointer
    buf[18] = 0;
    buf[19] = 0;

    // Copy payload
    if !payload.is_empty() {
        buf[TCP_HEADER_LEN..total].copy_from_slice(payload);
    }

    total
}

fn send_tcp_segment(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) {
    let mut seg_buf = [0u8; 1480];
    let seg_len = build_tcp_header(
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
        &mut seg_buf,
    );
    if seg_len == 0 {
        return;
    }

    // Compute TCP checksum over pseudo-header + segment
    let cksum = checksum::transport_checksum(src_ip, dst_ip, PROTO_TCP, &seg_buf[..seg_len]);
    seg_buf[16] = (cksum >> 8) as u8;
    seg_buf[17] = cksum as u8;

    let mac = crate::mac_addr();
    super::ensure_arp(&mac, src_ip, dst_ip);
    super::send_ip_packet(&mac, src_ip, dst_ip, PROTO_TCP, &seg_buf[..seg_len]);
}

fn send_rst(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, seq: u32, ack: u32) {
    send_tcp_segment(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        0,
        &[],
    );
}

fn set_retx_timer(idx: usize) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        tcb.retx_deadline_ns = now_ns() + tcb.rto_ms * NS_PER_MS;
    }
}

fn cancel_retx_timer(idx: usize) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        tcb.retx_deadline_ns = 0;
        tcb.retx_count = 0;
        tcb.rto_ms = INITIAL_RTO_MS;
    }
}

// ---------------------------------------------------------------------------
// TCP segment parsing
// ---------------------------------------------------------------------------

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
}

fn parse_tcp_header(data: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if data.len() < TCP_HEADER_LEN {
        return None;
    }

    let src_port = ((data[0] as u16) << 8) | (data[1] as u16);
    let dst_port = ((data[2] as u16) << 8) | (data[3] as u16);
    let seq = ((data[4] as u32) << 24)
        | ((data[5] as u32) << 16)
        | ((data[6] as u32) << 8)
        | (data[7] as u32);
    let ack = ((data[8] as u32) << 24)
        | ((data[9] as u32) << 16)
        | ((data[10] as u32) << 8)
        | (data[11] as u32);
    let data_offset = (data[12] >> 4) * 4;
    let flags = data[13];
    let window = ((data[14] as u16) << 8) | (data[15] as u16);

    if (data_offset as usize) < TCP_HEADER_LEN || data.len() < data_offset as usize {
        return None;
    }

    let payload = &data[data_offset as usize..];

    Some((
        TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
        },
        payload,
    ))
}

// ---------------------------------------------------------------------------
// Sequence number arithmetic
// ---------------------------------------------------------------------------

fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub(crate) fn tcp_socket() -> i32 {
    let idx = match find_free_tcb() {
        Some(i) => i,
        None => return -1,
    };
    let cid = alloc_conn_id();
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        tcb.active = true;
        tcb.state = TcpState::Closed;
        tcb.conn_id = cid;
        tcb.rcv_wnd = DEFAULT_WINDOW;
        tcb.mss = DEFAULT_MSS;
    }
    cid as i32
}

pub(crate) fn tcp_bind(conn_id: u32, ip: u32, port: u16) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        if tcb.state != TcpState::Closed {
            return -1;
        }
        tcb.local_ip = if ip == 0 { ipv4::OUR_IP } else { ip };
        tcb.local_port = port;
    }
    0
}

pub(crate) fn tcp_listen(conn_id: u32, backlog: u8) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        if tcb.state != TcpState::Closed {
            return -1;
        }
        if tcb.local_port == 0 {
            return -1;
        }
        tcb.state = TcpState::Listen;
        tcb.max_backlog = core::cmp::min(backlog as usize, MAX_LISTEN_BACKLOG);
        if tcb.max_backlog == 0 {
            tcb.max_backlog = 1;
        }
    }
    0
}

pub(crate) fn tcp_accept(conn_id: u32) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &(*(&raw const TCBS))[idx];
        if tcb.state != TcpState::Listen {
            return -1;
        }

        // Check if there's a completed connection in the backlog
        if tcb.backlog_count > 0 {
            let pending = tcb.backlog[0];
            // Create new TCB for the accepted connection
            let new_idx = match find_free_tcb() {
                Some(i) => i,
                None => return -1,
            };
            let new_cid = alloc_conn_id();
            let listen_tcb = &mut (*(&raw mut TCBS))[idx];

            // Shift backlog
            let bc = listen_tcb.backlog_count;
            for j in 0..bc - 1 {
                listen_tcb.backlog[j] = listen_tcb.backlog[j + 1];
            }
            listen_tcb.backlog_count = bc - 1;

            let listen_cid = listen_tcb.conn_id;

            let new_tcb = &mut (*(&raw mut TCBS))[new_idx];
            new_tcb.active = true;
            new_tcb.state = TcpState::SynReceived;
            new_tcb.conn_id = new_cid;
            new_tcb.parent_conn_id = listen_cid;
            new_tcb.local_ip = listen_tcb.local_ip;
            new_tcb.local_port = listen_tcb.local_port;
            new_tcb.remote_ip = pending.remote_ip;
            new_tcb.remote_port = pending.remote_port;
            new_tcb.irs = pending.irs;
            new_tcb.rcv_nxt = pending.irs.wrapping_add(1);
            new_tcb.iss = pending.iss;
            new_tcb.snd_nxt = pending.iss.wrapping_add(1);
            new_tcb.snd_una = pending.iss;
            new_tcb.rcv_wnd = DEFAULT_WINDOW;
            new_tcb.mss = DEFAULT_MSS;
            new_tcb.pending_accept = true;

            // SYN-ACK was already sent; wait for client's ACK to complete
            // the handshake. Completion fires when SynReceived->Established.
            return -1;
        }
    }
    // No pending connections, defer
    -1
}

pub(crate) fn tcp_connect(conn_id: u32, ip: u32, port: u16) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        if tcb.state != TcpState::Closed {
            return -1;
        }
        if tcb.local_port == 0 {
            tcb.local_port = alloc_ephemeral_port();
            if tcb.local_port == 0 {
                return -1;
            }
        }
        if tcb.local_ip == 0 {
            tcb.local_ip = ipv4::OUR_IP;
        }
        tcb.remote_ip = ip;
        tcb.remote_port = port;
        tcb.iss = generate_isn();
        tcb.snd_nxt = tcb.iss.wrapping_add(1);
        tcb.snd_una = tcb.iss;
        tcb.state = TcpState::SynSent;
        tcb.pending_connect = true;

        // Send SYN
        send_tcp_segment(
            tcb.local_ip,
            tcb.remote_ip,
            tcb.local_port,
            tcb.remote_port,
            tcb.iss,
            0,
            TCP_FLAG_SYN,
            tcb.rcv_wnd,
            &[],
        );
        set_retx_timer(idx);
    }
    -1 // pending
}

pub(crate) fn tcp_send(conn_id: u32, data: &[u8]) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
            return -1;
        }
        let written = tcb.tx_buf.write(data);
        if written > 0 {
            flush_tx(idx);
        }
        written as i32
    }
}

fn flush_tx(idx: usize) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        if tcb.tx_buf.len == 0 {
            return;
        }
        // Determine how much we can send (limited by remote window and MSS)
        let in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
        let wnd = tcb.snd_wnd as usize;
        let can_send = if wnd > in_flight { wnd - in_flight } else { 0 };
        let send_len = core::cmp::min(core::cmp::min(tcb.tx_buf.len, tcb.mss as usize), can_send);
        if send_len == 0 {
            return;
        }

        let mut payload = [0u8; 1460];
        let n = tcb.tx_buf.peek_all(&mut payload[..send_len]);

        send_tcp_segment(
            tcb.local_ip,
            tcb.remote_ip,
            tcb.local_port,
            tcb.remote_port,
            tcb.snd_nxt,
            tcb.rcv_nxt,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            tcb.rcv_wnd,
            &payload[..n],
        );
        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(n as u32);
        if tcb.retx_deadline_ns == 0 {
            set_retx_timer(idx);
        }
    }
}

pub(crate) fn tcp_recv(conn_id: u32, buf: &mut [u8]) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        // If connection is in a state where no more data will arrive and
        // buffer is empty, return EOF
        match tcb.state {
            TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                if tcb.rx_buf.len == 0 {
                    return 0; // EOF
                }
            }
            TcpState::Closed => return -1,
            _ => {}
        }

        if tcb.rx_buf.len > 0 {
            let n = tcb.rx_buf.read(buf);
            // Update receive window
            tcb.rcv_wnd = tcb.rx_buf.available() as u16;
            return n as i32;
        }

        // No data available, defer
        -1
    }
}

pub(crate) fn tcp_close(conn_id: u32) -> i32 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        match tcb.state {
            TcpState::Closed => {
                reset_tcb(idx);
                return 0;
            }
            TcpState::Listen | TcpState::SynSent => {
                reset_tcb(idx);
                return 0;
            }
            TcpState::SynReceived | TcpState::Established => {
                // Send FIN
                tcb.fin_seq = tcb.snd_nxt;
                send_tcp_segment(
                    tcb.local_ip,
                    tcb.remote_ip,
                    tcb.local_port,
                    tcb.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                    tcb.rcv_wnd,
                    &[],
                );
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                tcb.state = TcpState::FinWait1;
                set_retx_timer(idx);
                return 0;
            }
            TcpState::CloseWait => {
                // Send FIN
                tcb.fin_seq = tcb.snd_nxt;
                send_tcp_segment(
                    tcb.local_ip,
                    tcb.remote_ip,
                    tcb.local_port,
                    tcb.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                    tcb.rcv_wnd,
                    &[],
                );
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                tcb.state = TcpState::LastAck;
                set_retx_timer(idx);
                return 0;
            }
            TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => {
                // Already closing
                return 0;
            }
        }
    }
}

pub(crate) fn tcp_shutdown(conn_id: u32, how: i32) -> i32 {
    // how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
    if how == 1 || how == 2 {
        return tcp_close(conn_id);
    }
    // SHUT_RD: just discard receive buffer
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return -1,
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        tcb.rx_buf.reset();
    }
    0
}

pub(crate) fn tcp_getsockname(conn_id: u32) -> (u32, u16) {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return (0, 0),
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &(*(&raw const TCBS))[idx];
        (tcb.local_ip, tcb.local_port)
    }
}

pub(crate) fn tcp_getpeername(conn_id: u32) -> (u32, u16) {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return (0, 0),
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &(*(&raw const TCBS))[idx];
        (tcb.remote_ip, tcb.remote_port)
    }
}

/// Query poll readiness for a TCP connection.
///
/// Returns a revents bitmask matching POSIX poll semantics:
///   POLLIN  (0x001) = data available to read, or peer closed (EOF)
///   POLLOUT (0x004) = can write without blocking
///   POLLHUP (0x010) = peer closed
///   POLLERR (0x008) = connection error (RST)
pub(crate) fn tcp_poll_status(conn_id: u32, events: u16) -> u16 {
    let idx = match find_tcb_by_conn_id(conn_id) {
        Some(i) => i,
        None => return 0x020, // POLLNVAL
    };
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &(*(&raw const TCBS))[idx];
        let mut rev: u16 = 0;

        match tcb.state {
            TcpState::Established => {
                if events & 0x001 != 0 && tcb.rx_buf.len > 0 {
                    rev |= 0x001; // POLLIN
                }
                if events & 0x004 != 0 && tcb.tx_buf.available() > 0 {
                    rev |= 0x004; // POLLOUT
                }
            }
            TcpState::CloseWait => {
                // Peer sent FIN: readable (EOF), writable
                if events & 0x001 != 0 {
                    rev |= 0x001; // POLLIN (EOF)
                }
                if events & 0x004 != 0 && tcb.tx_buf.available() > 0 {
                    rev |= 0x004; // POLLOUT
                }
                rev |= 0x010; // POLLHUP
            }
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::TimeWait => {
                if events & 0x001 != 0 && tcb.rx_buf.len > 0 {
                    rev |= 0x001; // POLLIN (remaining data)
                }
                rev |= 0x010; // POLLHUP
            }
            TcpState::Listen => {
                if events & 0x001 != 0 && tcb.backlog_count > 0 {
                    rev |= 0x001; // POLLIN (pending connection)
                }
            }
            TcpState::SynSent | TcpState::SynReceived => {
                // Connecting, not yet ready
            }
            TcpState::LastAck | TcpState::Closed => {
                rev |= 0x010; // POLLHUP
            }
        }

        rev
    }
}

pub(crate) fn set_pending_recv(conn_id: u32, max_len: u16) {
    if let Some(idx) = find_tcb_by_conn_id(conn_id) {
        // SAFETY: Single-threaded driver.
        unsafe {
            let tcb = &mut (*(&raw mut TCBS))[idx];
            tcb.pending_recv = true;
            tcb.pending_recv_max = max_len;
        }
    }
}

pub(crate) fn set_pending_accept(conn_id: u32) {
    if let Some(idx) = find_tcb_by_conn_id(conn_id) {
        // SAFETY: Single-threaded driver.
        unsafe {
            let tcb = &mut (*(&raw mut TCBS))[idx];
            tcb.pending_accept = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Incoming segment processing
// ---------------------------------------------------------------------------

pub(crate) fn handle_segment(ip_hdr: &Ipv4Header, data: &[u8]) {
    // Validate TCP checksum
    let cksum = checksum::transport_checksum(ip_hdr.src, ip_hdr.dst, PROTO_TCP, data);
    if cksum != 0 {
        return;
    }

    let (hdr, payload) = match parse_tcp_header(data) {
        Some(v) => v,
        None => return,
    };

    // Try exact match first (established/connecting connections)
    let idx = find_tcb_by_tuple(hdr.dst_port, ip_hdr.src, hdr.src_port);

    if let Some(i) = idx {
        dispatch_segment(i, ip_hdr, &hdr, payload);
        return;
    }

    // Try listen socket
    if let Some(i) = find_listener(hdr.dst_port) {
        dispatch_segment(i, ip_hdr, &hdr, payload);
        return;
    }

    // No matching TCB and not RST: send RST
    if (hdr.flags & TCP_FLAG_RST) == 0 {
        if (hdr.flags & TCP_FLAG_ACK) != 0 {
            send_rst(
                ip_hdr.dst,
                ip_hdr.src,
                hdr.dst_port,
                hdr.src_port,
                hdr.ack,
                0,
            );
        } else {
            let ack_num = hdr.seq.wrapping_add(segment_len(&hdr, payload));
            send_rst(
                ip_hdr.dst,
                ip_hdr.src,
                hdr.dst_port,
                hdr.src_port,
                0,
                ack_num,
            );
        }
    }
}

fn segment_len(hdr: &TcpHeader, payload: &[u8]) -> u32 {
    let mut len = payload.len() as u32;
    if (hdr.flags & TCP_FLAG_SYN) != 0 {
        len += 1;
    }
    if (hdr.flags & TCP_FLAG_FIN) != 0 {
        len += 1;
    }
    len
}

fn dispatch_segment(idx: usize, ip_hdr: &Ipv4Header, hdr: &TcpHeader, payload: &[u8]) {
    // SAFETY: Single-threaded driver. We read state to dispatch.
    let state = unsafe { (*(&raw const TCBS))[idx].state };

    match state {
        TcpState::Listen => handle_listen(idx, ip_hdr, hdr),
        TcpState::SynSent => handle_syn_sent(idx, ip_hdr, hdr),
        TcpState::SynReceived => handle_syn_received(idx, hdr),
        TcpState::Established => handle_established(idx, hdr, payload),
        TcpState::FinWait1 => handle_fin_wait1(idx, hdr, payload),
        TcpState::FinWait2 => handle_fin_wait2(idx, hdr, payload),
        TcpState::CloseWait => handle_close_wait(idx, hdr, payload),
        TcpState::Closing => handle_closing(idx, hdr),
        TcpState::LastAck => handle_last_ack(idx, hdr),
        TcpState::TimeWait => handle_time_wait(idx, hdr),
        TcpState::Closed => {}
    }
}

// ---------------------------------------------------------------------------
// State handlers
// ---------------------------------------------------------------------------

fn handle_listen(idx: usize, ip_hdr: &Ipv4Header, hdr: &TcpHeader) {
    // RST on listen: ignore
    if (hdr.flags & TCP_FLAG_RST) != 0 {
        return;
    }
    // ACK on listen: RST
    if (hdr.flags & TCP_FLAG_ACK) != 0 {
        send_rst(
            ip_hdr.dst,
            ip_hdr.src,
            hdr.dst_port,
            hdr.src_port,
            hdr.ack,
            0,
        );
        return;
    }
    // SYN on listen: process
    if (hdr.flags & TCP_FLAG_SYN) == 0 {
        return;
    }

    let iss = generate_isn();

    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        // Check if accept is pending -- create a new TCB directly
        if tcb.pending_accept {
            let listen_cid = tcb.conn_id;
            let new_idx = match find_free_tcb() {
                Some(i) => i,
                None => return,
            };
            let new_cid = alloc_conn_id();
            let new_tcb = &mut (*(&raw mut TCBS))[new_idx];
            new_tcb.active = true;
            new_tcb.state = TcpState::SynReceived;
            new_tcb.conn_id = new_cid;
            new_tcb.parent_conn_id = listen_cid;
            new_tcb.local_ip = tcb.local_ip;
            new_tcb.local_port = tcb.local_port;
            new_tcb.remote_ip = ip_hdr.src;
            new_tcb.remote_port = hdr.src_port;
            new_tcb.irs = hdr.seq;
            new_tcb.rcv_nxt = hdr.seq.wrapping_add(1);
            new_tcb.iss = iss;
            new_tcb.snd_nxt = iss.wrapping_add(1);
            new_tcb.snd_una = iss;
            new_tcb.snd_wnd = hdr.window;
            new_tcb.rcv_wnd = DEFAULT_WINDOW;
            new_tcb.mss = DEFAULT_MSS;
            new_tcb.pending_accept = true;

            // Send SYN-ACK
            send_tcp_segment(
                new_tcb.local_ip,
                new_tcb.remote_ip,
                new_tcb.local_port,
                new_tcb.remote_port,
                iss,
                new_tcb.rcv_nxt,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
                new_tcb.rcv_wnd,
                &[],
            );
            set_retx_timer(new_idx);

            // Clear pending_accept on listener; it will be re-set if another
            // accept() call comes in.
            let listen_tcb = &mut (*(&raw mut TCBS))[idx];
            listen_tcb.pending_accept = false;
            return;
        }

        // No accept pending: queue in backlog
        if tcb.backlog_count >= tcb.max_backlog {
            return; // Backlog full, drop SYN silently
        }
        tcb.backlog[tcb.backlog_count] = PendingSyn {
            remote_ip: ip_hdr.src,
            remote_port: hdr.src_port,
            irs: hdr.seq,
            iss,
        };
        tcb.backlog_count += 1;

        // Send SYN-ACK
        send_tcp_segment(
            tcb.local_ip,
            ip_hdr.src,
            tcb.local_port,
            hdr.src_port,
            iss,
            hdr.seq.wrapping_add(1),
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            tcb.rcv_wnd,
            &[],
        );
    }
}

fn handle_syn_sent(idx: usize, ip_hdr: &Ipv4Header, hdr: &TcpHeader) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        // Check ACK validity
        if (hdr.flags & TCP_FLAG_ACK) != 0 {
            if seq_le(hdr.ack, tcb.iss) || seq_gt(hdr.ack, tcb.snd_nxt) {
                if (hdr.flags & TCP_FLAG_RST) == 0 {
                    send_rst(
                        ip_hdr.dst,
                        ip_hdr.src,
                        hdr.dst_port,
                        hdr.src_port,
                        hdr.ack,
                        0,
                    );
                }
                return;
            }
        }

        // RST
        if (hdr.flags & TCP_FLAG_RST) != 0 {
            if (hdr.flags & TCP_FLAG_ACK) != 0 {
                // Connection refused
                if tcb.pending_connect {
                    tcb.pending_connect = false;
                    push_completion(Completion {
                        conn_id: tcb.conn_id,
                        result: BESALT_CONN_REFUSED,
                        op_type: INET_OP_CONNECT,
                        data: [0u8; 152],
                        data_len: 0,
                        extra_conn_id: 0,
                        extra_ip: 0,
                        extra_port: 0,
                    });
                }
                reset_tcb(idx);
            }
            return;
        }

        // SYN
        if (hdr.flags & TCP_FLAG_SYN) == 0 {
            return;
        }

        tcb.irs = hdr.seq;
        tcb.rcv_nxt = hdr.seq.wrapping_add(1);
        tcb.snd_wnd = hdr.window;

        if (hdr.flags & TCP_FLAG_ACK) != 0 {
            tcb.snd_una = hdr.ack;
        }

        if seq_gt(tcb.snd_una, tcb.iss) {
            // SYN has been ACKed -> Established
            tcb.state = TcpState::Established;
            cancel_retx_timer(idx);

            // Send ACK
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                tcb.rcv_wnd,
                &[],
            );

            if tcb.pending_connect {
                tcb.pending_connect = false;
                push_completion(Completion {
                    conn_id: tcb.conn_id,
                    result: BESALT_OK,
                    op_type: INET_OP_CONNECT,
                    data: [0u8; 152],
                    data_len: 0,
                    extra_conn_id: 0,
                    extra_ip: 0,
                    extra_port: 0,
                });
            }
        } else {
            // Simultaneous open: SYN-ACK
            tcb.state = TcpState::SynReceived;
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.iss,
                tcb.rcv_nxt,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
                tcb.rcv_wnd,
                &[],
            );
        }
    }
}

fn handle_syn_received(idx: usize, hdr: &TcpHeader) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        // RST
        if (hdr.flags & TCP_FLAG_RST) != 0 {
            if tcb.pending_accept {
                tcb.pending_accept = false;
                push_completion(Completion {
                    conn_id: tcb.parent_conn_id,
                    result: BESALT_CONN_REFUSED,
                    op_type: INET_OP_ACCEPT,
                    data: [0u8; 152],
                    data_len: 0,
                    extra_conn_id: 0,
                    extra_ip: 0,
                    extra_port: 0,
                });
            }
            reset_tcb(idx);
            return;
        }

        // ACK
        if (hdr.flags & TCP_FLAG_ACK) == 0 {
            return;
        }

        // Validate ACK
        if !seq_le(tcb.snd_una, hdr.ack) || !seq_le(hdr.ack, tcb.snd_nxt) {
            return;
        }

        tcb.snd_una = hdr.ack;
        tcb.snd_wnd = hdr.window;
        tcb.state = TcpState::Established;
        cancel_retx_timer(idx);

        // Push accept completion (keyed by listen socket's conn_id)
        if tcb.pending_accept {
            tcb.pending_accept = false;
            push_completion(Completion {
                conn_id: tcb.parent_conn_id,
                result: BESALT_OK,
                op_type: INET_OP_ACCEPT,
                data: [0u8; 152],
                data_len: 0,
                extra_conn_id: tcb.conn_id,
                extra_ip: tcb.remote_ip,
                extra_port: tcb.remote_port,
            });
        }
    }
}

fn handle_established(idx: usize, hdr: &TcpHeader, payload: &[u8]) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        // RST
        if (hdr.flags & TCP_FLAG_RST) != 0 {
            complete_pending_with_error(idx, BESALT_CONN_REFUSED);
            reset_tcb(idx);
            return;
        }

        // SYN in established is invalid
        if (hdr.flags & TCP_FLAG_SYN) != 0 {
            send_rst(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                hdr.ack,
                0,
            );
            complete_pending_with_error(idx, BESALT_CONN_REFUSED);
            reset_tcb(idx);
            return;
        }

        // Must have ACK
        if (hdr.flags & TCP_FLAG_ACK) == 0 {
            return;
        }

        // Process ACK
        process_ack(idx, hdr);

        // Process data
        if !payload.is_empty() {
            process_data(idx, hdr, payload);
        }

        // FIN
        if (hdr.flags & TCP_FLAG_FIN) != 0 {
            tcb.rcv_nxt = hdr.seq.wrapping_add(payload.len() as u32).wrapping_add(1);
            tcb.state = TcpState::CloseWait;

            // ACK the FIN
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                tcb.rcv_wnd,
                &[],
            );

            // If recv is pending, deliver EOF
            if tcb.pending_recv {
                tcb.pending_recv = false;
                push_completion(Completion {
                    conn_id: tcb.conn_id,
                    result: BESALT_OK,
                    op_type: INET_OP_RECV,
                    data: [0u8; 152],
                    data_len: 0,
                    extra_conn_id: 0,
                    extra_ip: 0,
                    extra_port: 0,
                });
            }
        }
    }
}

fn handle_fin_wait1(idx: usize, hdr: &TcpHeader, payload: &[u8]) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        if (hdr.flags & TCP_FLAG_RST) != 0 {
            reset_tcb(idx);
            return;
        }

        if (hdr.flags & TCP_FLAG_ACK) == 0 {
            return;
        }

        process_ack(idx, hdr);

        // Process data even in FinWait1
        if !payload.is_empty() {
            process_data(idx, hdr, payload);
        }

        let tcb = &mut (*(&raw mut TCBS))[idx];
        let fin_acked = seq_gt(hdr.ack, tcb.fin_seq);

        if (hdr.flags & TCP_FLAG_FIN) != 0 {
            tcb.rcv_nxt = hdr.seq.wrapping_add(payload.len() as u32).wrapping_add(1);
            if fin_acked {
                // FIN + ACK of our FIN: go to TimeWait
                tcb.state = TcpState::TimeWait;
                tcb.timewait_deadline_ns = now_ns() + TIME_WAIT_NS;
                cancel_retx_timer(idx);
            } else {
                // Simultaneous close
                tcb.state = TcpState::Closing;
            }
            // ACK the FIN
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                tcb.rcv_wnd,
                &[],
            );
        } else if fin_acked {
            // Our FIN was ACKed, no FIN from remote yet
            tcb.state = TcpState::FinWait2;
            cancel_retx_timer(idx);
        }
    }
}

fn handle_fin_wait2(idx: usize, hdr: &TcpHeader, payload: &[u8]) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        if (hdr.flags & TCP_FLAG_RST) != 0 {
            reset_tcb(idx);
            return;
        }

        if (hdr.flags & TCP_FLAG_ACK) != 0 {
            process_ack(idx, hdr);
        }

        if !payload.is_empty() {
            process_data(idx, hdr, payload);
        }

        let tcb = &mut (*(&raw mut TCBS))[idx];
        if (hdr.flags & TCP_FLAG_FIN) != 0 {
            tcb.rcv_nxt = hdr.seq.wrapping_add(payload.len() as u32).wrapping_add(1);
            tcb.state = TcpState::TimeWait;
            tcb.timewait_deadline_ns = now_ns() + TIME_WAIT_NS;

            // ACK the FIN
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                tcb.rcv_wnd,
                &[],
            );
        }
    }
}

fn handle_close_wait(idx: usize, hdr: &TcpHeader, payload: &[u8]) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &(*(&raw const TCBS))[idx];

        if (hdr.flags & TCP_FLAG_RST) != 0 {
            reset_tcb(idx);
            return;
        }

        if (hdr.flags & TCP_FLAG_ACK) != 0 {
            process_ack(idx, hdr);
        }

        // Ignore data and FIN in CloseWait (we already got FIN from remote)
        let _ = payload;
        let _ = tcb;
    }
}

fn handle_closing(idx: usize, hdr: &TcpHeader) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        if (hdr.flags & TCP_FLAG_RST) != 0 {
            reset_tcb(idx);
            return;
        }

        if (hdr.flags & TCP_FLAG_ACK) != 0 && seq_gt(hdr.ack, tcb.fin_seq) {
            tcb.state = TcpState::TimeWait;
            tcb.timewait_deadline_ns = now_ns() + TIME_WAIT_NS;
            cancel_retx_timer(idx);
        }
    }
}

fn handle_last_ack(idx: usize, hdr: &TcpHeader) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &(*(&raw const TCBS))[idx];

        if (hdr.flags & TCP_FLAG_RST) != 0 {
            reset_tcb(idx);
            return;
        }

        if (hdr.flags & TCP_FLAG_ACK) != 0 && seq_gt(hdr.ack, tcb.fin_seq) {
            reset_tcb(idx);
        }
    }
}

fn handle_time_wait(idx: usize, hdr: &TcpHeader) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        if (hdr.flags & TCP_FLAG_RST) != 0 {
            reset_tcb(idx);
            return;
        }

        // Restart 2MSL timer on any valid segment
        if (hdr.flags & TCP_FLAG_FIN) != 0 {
            tcb.timewait_deadline_ns = now_ns() + TIME_WAIT_NS;
            // Re-ACK the FIN
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                0,
                &[],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Common segment processing helpers
// ---------------------------------------------------------------------------

fn process_ack(idx: usize, hdr: &TcpHeader) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        if seq_gt(hdr.ack, tcb.snd_nxt) {
            // ACK for data we haven't sent: ignore (could send ACK back)
            return;
        }

        if seq_gt(hdr.ack, tcb.snd_una) {
            // New data acknowledged
            let acked = hdr.ack.wrapping_sub(tcb.snd_una) as usize;
            tcb.snd_una = hdr.ack;
            tcb.tx_buf.drain(acked);

            // If all outstanding data is ACKed, cancel retransmit timer
            if tcb.snd_una == tcb.snd_nxt {
                cancel_retx_timer(idx);
            } else {
                // Reset timer for remaining data
                tcb.rto_ms = INITIAL_RTO_MS;
                tcb.retx_count = 0;
                set_retx_timer(idx);
            }

            // Try to send more data from tx buffer
            if tcb.tx_buf.len > 0 {
                flush_tx(idx);
            }
        }

        let tcb = &mut (*(&raw mut TCBS))[idx];
        tcb.snd_wnd = hdr.window;
    }
}

fn process_data(idx: usize, hdr: &TcpHeader, payload: &[u8]) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];

        // Check sequence number: only accept in-order data
        if hdr.seq != tcb.rcv_nxt {
            // Out of order: send duplicate ACK
            send_tcp_segment(
                tcb.local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                tcb.rcv_wnd,
                &[],
            );
            return;
        }

        let written = tcb.rx_buf.write(payload);
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
        // TCP window field is 16 bits (max 65535). Our rx_buf capacity is
        // TCP_RX_BUF_SIZE (8192) which fits in u16. Window scaling (RFC
        // 7323) is not implemented.
        tcb.rcv_wnd = tcb.rx_buf.available() as u16;

        // Send ACK
        send_tcp_segment(
            tcb.local_ip,
            tcb.remote_ip,
            tcb.local_port,
            tcb.remote_port,
            tcb.snd_nxt,
            tcb.rcv_nxt,
            TCP_FLAG_ACK,
            tcb.rcv_wnd,
            &[],
        );

        // If recv is pending, deliver data
        if tcb.pending_recv && tcb.rx_buf.len > 0 {
            tcb.pending_recv = false;
            let max = core::cmp::min(tcb.pending_recv_max as usize, 152);
            let mut comp = Completion {
                conn_id: tcb.conn_id,
                result: BESALT_OK,
                op_type: INET_OP_RECV,
                data: [0u8; 152],
                data_len: 0,
                extra_conn_id: 0,
                extra_ip: 0,
                extra_port: 0,
            };
            let n = tcb.rx_buf.read(&mut comp.data[..max]);
            comp.data_len = n;
            // TCP window field is 16 bits (max 65535). Our rx_buf capacity is
            // TCP_RX_BUF_SIZE (8192) which fits in u16. Window scaling (RFC
            // 7323) is not implemented.
            tcb.rcv_wnd = tcb.rx_buf.available() as u16;
            push_completion(comp);
        }
    }
}

fn complete_pending_with_error(idx: usize, err_code: u64) {
    // SAFETY: Single-threaded driver.
    unsafe {
        let tcb = &mut (*(&raw mut TCBS))[idx];
        if tcb.pending_connect {
            tcb.pending_connect = false;
            push_completion(Completion {
                conn_id: tcb.conn_id,
                result: err_code,
                op_type: INET_OP_CONNECT,
                data: [0u8; 152],
                data_len: 0,
                extra_conn_id: 0,
                extra_ip: 0,
                extra_port: 0,
            });
        }
        if tcb.pending_recv {
            tcb.pending_recv = false;
            push_completion(Completion {
                conn_id: tcb.conn_id,
                result: err_code,
                op_type: INET_OP_RECV,
                data: [0u8; 152],
                data_len: 0,
                extra_conn_id: 0,
                extra_ip: 0,
                extra_port: 0,
            });
        }
        if tcb.pending_accept {
            tcb.pending_accept = false;
            push_completion(Completion {
                conn_id: tcb.parent_conn_id,
                result: err_code,
                op_type: INET_OP_ACCEPT,
                data: [0u8; 152],
                data_len: 0,
                extra_conn_id: 0,
                extra_ip: 0,
                extra_port: 0,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Timer management
// ---------------------------------------------------------------------------

pub(crate) fn next_timer_deadline_ns() -> u64 {
    let mut earliest = u64::MAX;

    // SAFETY: Single-threaded driver.
    unsafe {
        let tcbs = &raw const TCBS;
        for i in 0..MAX_TCP_CONNS {
            let t = &(*tcbs)[i];
            if !t.active {
                continue;
            }
            if t.retx_deadline_ns != 0 && t.retx_deadline_ns < earliest {
                earliest = t.retx_deadline_ns;
            }
            if t.state == TcpState::TimeWait
                && t.timewait_deadline_ns != 0
                && t.timewait_deadline_ns < earliest
            {
                earliest = t.timewait_deadline_ns;
            }
        }
    }

    earliest
}

pub(crate) fn process_timers() {
    let current = now_ns();

    // SAFETY: Single-threaded driver.
    unsafe {
        for i in 0..MAX_TCP_CONNS {
            let active = (*(&raw const TCBS))[i].active;
            if !active {
                continue;
            }

            let state = (*(&raw const TCBS))[i].state;

            // TimeWait expiration
            if state == TcpState::TimeWait {
                let deadline = (*(&raw const TCBS))[i].timewait_deadline_ns;
                if deadline != 0 && current >= deadline {
                    reset_tcb(i);
                    continue;
                }
            }

            // Retransmission timeout
            let retx_deadline = (*(&raw const TCBS))[i].retx_deadline_ns;
            if retx_deadline == 0 || current < retx_deadline {
                continue;
            }

            let tcb = &mut (*(&raw mut TCBS))[i];
            tcb.retx_count += 1;

            if tcb.retx_count > MAX_RETRIES {
                // Give up: RST and notify
                send_rst(
                    tcb.local_ip,
                    tcb.remote_ip,
                    tcb.local_port,
                    tcb.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                );
                complete_pending_with_error(i, BESALT_TIMED_OUT);
                reset_tcb(i);
                continue;
            }

            // Double RTO (exponential backoff)
            tcb.rto_ms = core::cmp::min(tcb.rto_ms * 2, MAX_RTO_MS);

            // Retransmit based on state
            match tcb.state {
                TcpState::SynSent => {
                    // Retransmit SYN
                    send_tcp_segment(
                        tcb.local_ip,
                        tcb.remote_ip,
                        tcb.local_port,
                        tcb.remote_port,
                        tcb.iss,
                        0,
                        TCP_FLAG_SYN,
                        tcb.rcv_wnd,
                        &[],
                    );
                }
                TcpState::SynReceived => {
                    // Retransmit SYN-ACK
                    send_tcp_segment(
                        tcb.local_ip,
                        tcb.remote_ip,
                        tcb.local_port,
                        tcb.remote_port,
                        tcb.iss,
                        tcb.rcv_nxt,
                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                }
                TcpState::Established | TcpState::CloseWait => {
                    // Retransmit unacknowledged data
                    if tcb.tx_buf.len > 0 {
                        let send_len = core::cmp::min(tcb.tx_buf.len, tcb.mss as usize);
                        let mut payload = [0u8; 1460];
                        let n = tcb.tx_buf.peek_all(&mut payload[..send_len]);
                        // Reset snd_nxt to snd_una so the retransmitted segment starts at
                        // the first unacknowledged byte. tx_buf.peek_all reads from the
                        // buffer head (which corresponds to snd_una). After sending,
                        // snd_nxt advances by the retransmitted byte count.
                        tcb.snd_nxt = tcb.snd_una;
                        send_tcp_segment(
                            tcb.local_ip,
                            tcb.remote_ip,
                            tcb.local_port,
                            tcb.remote_port,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            TCP_FLAG_ACK | TCP_FLAG_PSH,
                            tcb.rcv_wnd,
                            &payload[..n],
                        );
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(n as u32);
                    }
                }
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => {
                    // Retransmit FIN
                    send_tcp_segment(
                        tcb.local_ip,
                        tcb.remote_ip,
                        tcb.local_port,
                        tcb.remote_port,
                        tcb.fin_seq,
                        tcb.rcv_nxt,
                        TCP_FLAG_FIN | TCP_FLAG_ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                }
                _ => {}
            }

            set_retx_timer(i);
        }
    }
}
