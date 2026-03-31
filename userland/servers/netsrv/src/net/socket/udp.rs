// SPDX-License-Identifier: GPL-2.0-only
//! UDP socket management — connection pool, rx buffering, completions.
//!
//! Provides connectionless datagram sockets with optional connect() for
//! default destination. Buffers incoming datagrams per-socket and supports
//! async completion for pending recvfrom operations.
//!
//! Stateless header parsing and construction live in `crate::net::proto::udp`;
//! this module handles the stateful socket layer.

use trona::consts::{
    TRONA_INVALID_ARGUMENT, TRONA_NOT_CONNECTED, TRONA_NO_BUFS, TRONA_OK, INET_OP_RECV,
    INET_OP_RECVFROM, SOCK_DGRAM,
};

use crate::net::proto::ipv4;
use crate::net::proto::udp as udp_proto;
use crate::net::socket::options::{self, SocketOptions};

const MAX_UDP_SOCKETS: usize = 8;
const UDP_RX_BUF_SIZE: usize = 16384;
const MAX_UDP_RX_ENTRIES: usize = 32;
const MAX_COMPLETIONS: usize = 64;

#[derive(Clone, Copy)]
struct UdpRxEntry {
    active: bool,
    src_ip: u32,
    src_port: u16,
    offset: u16,
    len: u16,
    timestamp_ns: u64,
}

impl UdpRxEntry {
    const fn zeroed() -> Self {
        Self {
            active: false,
            src_ip: 0,
            src_port: 0,
            offset: 0,
            len: 0,
            timestamp_ns: options::TIMESTAMP_NONE_NS,
        }
    }
}

struct UdpSocket {
    active: bool,
    local_ip: u32,
    dynamic_local_ip: bool,
    keep_zero_source_ip: bool,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
    opts: SocketOptions,
    rx_buf: [u8; UDP_RX_BUF_SIZE],
    rx_head: u16,
    rx_entries: [UdpRxEntry; MAX_UDP_RX_ENTRIES],
    rx_entry_head: u8,
    rx_entry_tail: u8,
    pending_recv: bool,
    pending_recv_max_len: u16,
    pending_recv_op_type: u8,
    pending_recv_flags: u32,
    conn_id: u32,
}

impl UdpSocket {
    const fn zeroed() -> Self {
        Self {
            active: false,
            local_ip: 0,
            dynamic_local_ip: false,
            keep_zero_source_ip: false,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            opts: SocketOptions::new(1480, UDP_RX_BUF_SIZE as u32),
            rx_buf: [0u8; UDP_RX_BUF_SIZE],
            rx_head: 0,
            rx_entries: [UdpRxEntry::zeroed(); MAX_UDP_RX_ENTRIES],
            rx_entry_head: 0,
            rx_entry_tail: 0,
            pending_recv: false,
            pending_recv_max_len: 0,
            pending_recv_op_type: 0,
            pending_recv_flags: 0,
            conn_id: 0,
        }
    }
}

pub(crate) struct Completion {
    pub(crate) conn_id: u32,
    pub(crate) result: u64,
    pub(crate) op_type: u8,
    pub(crate) data: [u8; 152],
    pub(crate) data_len: usize,
    pub(crate) extra_conn_id: u32,
    pub(crate) extra_ip: u32,
    pub(crate) extra_port: u16,
    pub(crate) timestamp_ns: u64,
}

static mut UDP_SOCKETS: [UdpSocket; MAX_UDP_SOCKETS] = [
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
    UdpSocket::zeroed(),
];

static mut NEXT_UDP_CONN_ID: u32 = 1000;
static mut NEXT_EPHEMERAL_PORT: u16 = 49152;
static mut LOGGED_UDP_FRAMES: u8 = 0;
static mut LOGGED_UDP_DROPS: u8 = 0;

static mut COMPLETIONS: [Option<Completion>; MAX_COMPLETIONS] = [const { None }; MAX_COMPLETIONS];
static mut COMP_HEAD: usize = 0;
static mut COMP_TAIL: usize = 0;

fn log_ipv4(lb: &mut trona::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

fn push_completion(c: Completion) {
    // SAFETY: Single-threaded driver; COMPLETIONS/COMP_HEAD/COMP_TAIL only accessed here and pop.
    unsafe {
        let head = *(&raw const COMP_HEAD);
        let tail = *(&raw const COMP_TAIL);
        let next_head = (head + 1) % MAX_COMPLETIONS;
        if next_head == tail {
            crate::puts(b"[netsrv] WARN: UDP completion queue full, dropping\n");
            return;
        }
        let slot = (&raw mut COMPLETIONS)
            .cast::<Option<Completion>>()
            .add(head);
        slot.write(Some(c));
        *(&raw mut COMP_HEAD) = next_head;
    }
}

pub(crate) fn pop_completion() -> Option<Completion> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let head = *(&raw const COMP_HEAD);
        let tail = *(&raw const COMP_TAIL);
        if head == tail {
            return None;
        }
        let slot = (&raw mut COMPLETIONS)
            .cast::<Option<Completion>>()
            .add(tail);
        let c = (*slot).take();
        *(&raw mut COMP_TAIL) = (tail + 1) % MAX_COMPLETIONS;
        c
    }
}

/// Find socket index by conn_id.
fn find_socket(conn_id: u32) -> Option<usize> {
    // SAFETY: Single-threaded driver; reading socket state.
    unsafe {
        let sockets = &raw const UDP_SOCKETS;
        for i in 0..MAX_UDP_SOCKETS {
            if (*sockets)[i].active && (*sockets)[i].conn_id == conn_id {
                return Some(i);
            }
        }
    }
    None
}

/// Find socket index by local port.
fn find_by_port(port: u16) -> Option<usize> {
    // SAFETY: Single-threaded driver; reading socket state.
    unsafe {
        let sockets = &raw const UDP_SOCKETS;
        for i in 0..MAX_UDP_SOCKETS {
            if (*sockets)[i].active && (*sockets)[i].local_port == port {
                return Some(i);
            }
        }
    }
    None
}

/// Allocate next ephemeral port, skipping ports already in use.
fn alloc_ephemeral_port() -> u16 {
    // SAFETY: Single-threaded driver.
    unsafe {
        let start = *(&raw const NEXT_EPHEMERAL_PORT);
        let mut port = start;
        loop {
            if find_by_port(port).is_none() {
                *(&raw mut NEXT_EPHEMERAL_PORT) = if port == 65535 { 49152 } else { port + 1 };
                return port;
            }
            port = if port == 65535 { 49152 } else { port + 1 };
            if port == start {
                // All ports exhausted; return start anyway (best effort)
                *(&raw mut NEXT_EPHEMERAL_PORT) = if port == 65535 { 49152 } else { port + 1 };
                return port;
            }
        }
    }
}

/// Create a new UDP socket. Returns conn_id (>= 1000) or -1 on failure.
pub(crate) fn udp_socket() -> i32 {
    // SAFETY: Single-threaded driver; mutating socket table.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        for i in 0..MAX_UDP_SOCKETS {
            if !(*sockets)[i].active {
                let conn_id = *(&raw const NEXT_UDP_CONN_ID);
                *(&raw mut NEXT_UDP_CONN_ID) = conn_id + 1;

                (*sockets)[i] = UdpSocket::zeroed();
                (*sockets)[i].active = true;
                (*sockets)[i].conn_id = conn_id;
                return conn_id as i32;
            }
        }
    }
    -1
}

/// Bind a UDP socket to a local address and port.
pub(crate) fn udp_bind(conn_id: u32, ip: u32, port: u16) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };

    // Check port not already bound by another socket
    if let Some(existing) = find_by_port(port) {
        if existing != idx {
            return -(TRONA_INVALID_ARGUMENT as i32);
        }
    }

    // SAFETY: Single-threaded driver; idx is valid.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        (*sockets)[idx].local_ip = ip;
        (*sockets)[idx].dynamic_local_ip = ip == 0;
        (*sockets)[idx].keep_zero_source_ip = ip == 0 && port == 68;
        (*sockets)[idx].local_port = port;
    }
    0
}

/// Set default destination for send(). Always succeeds immediately for UDP.
pub(crate) fn udp_connect(conn_id: u32, ip: u32, port: u16) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; idx is valid.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        (*sockets)[idx].remote_ip = ip;
        (*sockets)[idx].remote_port = port;

        // Auto-bind if not yet bound
        if (*sockets)[idx].local_port == 0 {
            let port = alloc_ephemeral_port();
            (*sockets)[idx].local_port = port;
            (*sockets)[idx].local_ip = ipv4::our_ip();
            (*sockets)[idx].dynamic_local_ip = true;
        }
    }
    0
}

/// Send a datagram to a specific destination.
pub(crate) fn udp_sendto(conn_id: u32, data: &[u8], dst_ip: u32, dst_port: u16) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; reading/writing socket state.
    let (local_port, local_ip) = unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        // Auto-bind ephemeral port if not yet bound
        if (*sockets)[idx].local_port == 0 {
            let port = alloc_ephemeral_port();
            (*sockets)[idx].local_port = port;
            (*sockets)[idx].local_ip = ipv4::our_ip();
            (*sockets)[idx].dynamic_local_ip = true;
            (*sockets)[idx].keep_zero_source_ip = false;
        }
        ((*sockets)[idx].local_port, (*sockets)[idx].local_ip)
    };

    let keep_zero_source_ip = unsafe {
        let sockets = &raw const UDP_SOCKETS;
        (*sockets)[idx].keep_zero_source_ip
    };
    let src_ip = if local_ip == 0 {
        if keep_zero_source_ip { 0 } else { ipv4::our_ip() }
    } else {
        local_ip
    };

    // Check MTU limit: 1500 ethernet - 20 IP header = 1480 max UDP (header + payload)
    let udp_len = udp_proto::UDP_HEADER_LEN + data.len();
    if udp_len > 1480 {
        return -(TRONA_INVALID_ARGUMENT as i32);
    }

    // Build UDP packet using protocol helper
    let mut udp_buf = [0u8; 1480];
    let written = udp_proto::build(local_port, dst_port, data, src_ip, dst_ip, &mut udp_buf);
    if written == 0 {
        return -(TRONA_INVALID_ARGUMENT as i32);
    }
    let our_mac = crate::mac_addr();
    let ttl = unsafe {
        let sockets = &raw const UDP_SOCKETS;
        (*sockets)[idx].opts.ip_ttl
    };
    let allow_broadcast = unsafe {
        let sockets = &raw const UDP_SOCKETS;
        (*sockets)[idx].opts.broadcast
    };
    if crate::net::config::is_broadcast(dst_ip) && !allow_broadcast {
        return -(TRONA_INVALID_ARGUMENT as i32);
    }
    if crate::net::send_ip_packet_with_ttl(
        &our_mac,
        src_ip,
        dst_ip,
        ipv4::PROTO_UDP,
        ttl,
        &udp_buf[..written],
    ) {
        data.len() as i32
    } else {
        -(TRONA_NO_BUFS as i32)
    }
}

/// Send a datagram using the stored remote address (from connect).
pub(crate) fn udp_send(conn_id: u32, data: &[u8]) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; reading socket state.
    let (rip, rport) = unsafe {
        let sockets = &raw const UDP_SOCKETS;
        ((*sockets)[idx].remote_ip, (*sockets)[idx].remote_port)
    };

    if rip == 0 || rport == 0 {
        return -(TRONA_INVALID_ARGUMENT as i32);
    }

    udp_sendto(conn_id, data, rip, rport)
}

/// Receive a datagram, returning (bytes_copied, src_ip, src_port).
/// Returns (-1, 0, 0) if no data available.
pub(crate) fn udp_recvfrom(conn_id: u32, buf: &mut [u8], want_timestamp: bool) -> (i32, u32, u16, u64) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return (-1, 0, 0, options::TIMESTAMP_NONE_NS),
    };

    // SAFETY: Single-threaded driver; reading/writing socket rx state.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        let sock = &mut (*sockets)[idx];

        if sock.rx_entry_head == sock.rx_entry_tail {
            return (-1, 0, 0, options::TIMESTAMP_NONE_NS); // no data
        }

        let tail = sock.rx_entry_tail as usize;
        let entry = sock.rx_entries[tail];

        if !entry.active {
            return (-1, 0, 0, options::TIMESTAMP_NONE_NS);
        }

        let copy_len = core::cmp::min(entry.len as usize, buf.len());
        let offset = entry.offset as usize;

        // Copy data from rx_buf (handle wrap-around)
        for i in 0..copy_len {
            let src_idx = (offset + i) % UDP_RX_BUF_SIZE;
            buf[i] = sock.rx_buf[src_idx];
        }

        let src_ip = entry.src_ip;
        let src_port = entry.src_port;
        let timestamp_ns = if want_timestamp {
            entry.timestamp_ns
        } else {
            options::TIMESTAMP_NONE_NS
        };

        // Consume entry
        sock.rx_entries[tail].active = false;
        sock.rx_entry_tail = ((tail + 1) % MAX_UDP_RX_ENTRIES) as u8;

        (copy_len as i32, src_ip, src_port, timestamp_ns)
    }
}

/// Receive a datagram (connected socket, no source address returned).
pub(crate) fn udp_recv(conn_id: u32, buf: &mut [u8]) -> i32 {
    let (len, _, _, _) = udp_recvfrom(conn_id, buf, false);
    len
}

/// Close a UDP socket.
pub(crate) fn udp_close(conn_id: u32) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; deactivating socket.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        (*sockets)[idx].active = false;
    }
    0
}

pub(crate) fn handle_local_ip_change(new_ip: u32) {
    // SAFETY: Single-threaded driver; mutating socket state in-place.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        for i in 0..MAX_UDP_SOCKETS {
            let sock = &mut (*sockets)[i];
            if !sock.active || !sock.dynamic_local_ip {
                continue;
            }
            if sock.local_ip != 0 {
                sock.local_ip = new_ip;
            }
        }
    }
}

pub(crate) fn handle_local_ip_loss() {
    // SAFETY: Single-threaded driver; mutating socket state in-place.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        for i in 0..MAX_UDP_SOCKETS {
            let sock = &mut (*sockets)[i];
            if !sock.active || !sock.dynamic_local_ip {
                continue;
            }
            sock.local_ip = 0;
        }
    }
}

pub(crate) fn udp_set_keep_zero_source_ip(conn_id: u32, keep_zero_source_ip: bool) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; mutating socket state in-place.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        (*sockets)[idx].keep_zero_source_ip = keep_zero_source_ip;
    }
    0
}

/// Get local address of a socket.
pub(crate) fn udp_getsockname(conn_id: u32) -> (u32, u16) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return (0, 0),
    };

    // SAFETY: Single-threaded driver; reading socket state.
    unsafe {
        let sockets = &raw const UDP_SOCKETS;
        ((*sockets)[idx].local_ip, (*sockets)[idx].local_port)
    }
}

/// Get remote address of a connected socket.
pub(crate) fn udp_getpeername(conn_id: u32) -> Result<(u32, u16), u64> {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return Err(TRONA_INVALID_ARGUMENT),
    };

    // SAFETY: Single-threaded driver; reading socket state.
    unsafe {
        let sockets = &raw const UDP_SOCKETS;
        let remote_ip = (*sockets)[idx].remote_ip;
        let remote_port = (*sockets)[idx].remote_port;
        if remote_ip == 0 || remote_port == 0 {
            return Err(TRONA_NOT_CONNECTED);
        }
        Ok((remote_ip, remote_port))
    }
}

pub(crate) fn udp_setsockopt(
    conn_id: u32,
    level: i32,
    optname: i32,
    optval: u64,
    optlen: u32,
) -> u64 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return TRONA_INVALID_ARGUMENT,
    };
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        options::set_option(
            &mut (*sockets)[idx].opts,
            SOCK_DGRAM,
            level,
            optname,
            optval,
            optlen,
        )
    }
}

pub(crate) fn udp_getsockopt(conn_id: u32, level: i32, optname: i32) -> Result<(u64, u32), u64> {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return Err(TRONA_INVALID_ARGUMENT),
    };
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        options::get_option(
            &mut (*sockets)[idx].opts,
            SOCK_DGRAM,
            trona::consts::IPPROTO_UDP,
            level,
            optname,
        )
    }
}

/// Query poll readiness for a UDP socket.
///
/// UDP sockets are always writable. Readable if buffered datagrams exist.
pub(crate) fn udp_poll_status(conn_id: u32, events: u16) -> u16 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return 0x020, // POLLNVAL
    };
    // SAFETY: Single-threaded driver; reading socket state.
    unsafe {
        let sockets = &raw const UDP_SOCKETS;
        let sock = &(*sockets)[idx];
        let mut rev: u16 = 0;

        if events & 0x001 != 0 && sock.rx_entry_head != sock.rx_entry_tail {
            rev |= 0x001; // POLLIN
        }
        if events & 0x004 != 0 {
            rev |= 0x004; // POLLOUT (always writable)
        }

        rev
    }
}

/// Handle an incoming UDP datagram from the IP layer.
///
/// Parses the UDP header, finds the matching socket by destination port,
/// buffers the payload, and fires a completion if a recv is pending.
pub(crate) fn handle_datagram(ip_hdr: &ipv4::Ipv4Header, data: &[u8]) {
    let (src_port, dst_port, payload) = match udp_proto::parse(data) {
        Some(v) => v,
        None => {
            unsafe {
                if *(&raw const LOGGED_UDP_DROPS) < 8 {
                    *(&raw mut LOGGED_UDP_DROPS) += 1;
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] UDP parse failed len=");
                        _lb.dec(data.len() as u64);
                        _lb.putc(b'\n');
                    });
                }
            }
            return;
        }
    };

    let src_ip = ip_hdr.src;

    unsafe {
        if *(&raw const LOGGED_UDP_FRAMES) < 8 {
            *(&raw mut LOGGED_UDP_FRAMES) += 1;
            trona::udebug!(|_lb| {
                _lb.str(b"[netsrv] UDP datagram src=");
                log_ipv4(&mut _lb, src_ip);
                _lb.putc(b':');
                _lb.dec(src_port as u64);
                _lb.str(b" dst=");
                log_ipv4(&mut _lb, ip_hdr.dst);
                _lb.putc(b':');
                _lb.dec(dst_port as u64);
                _lb.str(b" payload=");
                _lb.dec(payload.len() as u64);
                _lb.putc(b'\n');
            });
        }
    }

    // Find a socket listening on dst_port
    let idx = match find_by_port(dst_port) {
        Some(i) => i,
        None => {
            unsafe {
                if *(&raw const LOGGED_UDP_DROPS) < 8 {
                    *(&raw mut LOGGED_UDP_DROPS) += 1;
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] UDP drop no socket dst_port=");
                        _lb.dec(dst_port as u64);
                        _lb.str(b" src=");
                        log_ipv4(&mut _lb, src_ip);
                        _lb.putc(b':');
                        _lb.dec(src_port as u64);
                        _lb.putc(b'\n');
                    });
                }
            }
            return;
        } // no matching socket, silently drop
    };

    // SAFETY: Single-threaded driver; mutating socket rx state.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        let sock = &mut (*sockets)[idx];

        // If a recv is pending, deliver directly via completion
        if sock.pending_recv {
            let op_type = sock.pending_recv_op_type;
            let want_timestamp = (sock.pending_recv_flags & trona::consts::INET_RECV_FLAG_WANT_TIMESTAMP) != 0;
            sock.pending_recv = false;
            let max_len = sock.pending_recv_max_len as usize;
            let copy_len = core::cmp::min(payload.len(), max_len);
            let copy_len = core::cmp::min(copy_len, if op_type == INET_OP_RECVFROM { 104 } else { 152 });

            let mut comp = Completion {
                conn_id: sock.conn_id,
                result: TRONA_OK,
                op_type,
                data: [0u8; 152],
                data_len: copy_len,
                extra_conn_id: 0,
                extra_ip: src_ip,
                extra_port: src_port,
                timestamp_ns: if want_timestamp {
                    options::sample_timestamp_ns(&sock.opts)
                } else {
                    options::TIMESTAMP_NONE_NS
                },
            };
            comp.data[..copy_len].copy_from_slice(&payload[..copy_len]);
            sock.pending_recv_op_type = 0;
            sock.pending_recv_flags = 0;
            push_completion(comp);
            return;
        }

        // Buffer the datagram in the socket's rx ring
        let was_empty = sock.rx_entry_head == sock.rx_entry_tail;
        let head = sock.rx_entry_head as usize;
        let next_head = (head + 1) % MAX_UDP_RX_ENTRIES;

        // Check if entry ring is full
        if next_head == sock.rx_entry_tail as usize {
            return; // drop packet, buffer full
        }

        // Check if we have space in rx_buf
        if payload.len() > UDP_RX_BUF_SIZE {
            return; // datagram too large for buffer
        }

        // Check available space in rx_buf by summing active entry lengths
        let mut used: usize = 0;
        let mut scan = sock.rx_entry_tail as usize;
        while scan != head {
            if sock.rx_entries[scan].active {
                used += sock.rx_entries[scan].len as usize;
            }
            scan = (scan + 1) % MAX_UDP_RX_ENTRIES;
        }
        if payload.len() > UDP_RX_BUF_SIZE - used {
            return; // drop packet, data buffer full
        }

        let offset = sock.rx_head;

        // Copy payload into rx_buf (circular)
        for i in 0..payload.len() {
            let dst_idx = (offset as usize + i) % UDP_RX_BUF_SIZE;
            sock.rx_buf[dst_idx] = payload[i];
        }

        sock.rx_entries[head] = UdpRxEntry {
            active: true,
            src_ip,
            src_port,
            offset,
            len: payload.len() as u16,
            timestamp_ns: options::sample_timestamp_ns(&sock.opts),
        };

        sock.rx_entry_head = next_head as u8;
        sock.rx_head = ((offset as usize + payload.len()) % UDP_RX_BUF_SIZE) as u16;
        if was_empty {
            push_completion(Completion {
                conn_id: sock.conn_id,
                result: TRONA_OK,
                op_type: INET_OP_RECV,
                data: [0u8; 152],
                data_len: 0,
                extra_conn_id: 0,
                extra_ip: 0,
                extra_port: 0,
                timestamp_ns: options::TIMESTAMP_NONE_NS,
            });
        }
    }
}

/// Mark a socket as waiting for incoming data. When a datagram arrives,
/// it will be delivered immediately as a Completion instead of being buffered.
pub(crate) fn set_pending_recv(conn_id: u32, max_len: u16) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return,
    };

    // SAFETY: Single-threaded driver; mutating socket state.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        let sock = &mut (*sockets)[idx];

        // If there is already buffered data, deliver it immediately
        if sock.rx_entry_head != sock.rx_entry_tail {
            let tail = sock.rx_entry_tail as usize;
            let entry = sock.rx_entries[tail];

            if entry.active {
                let copy_len = core::cmp::min(entry.len as usize, max_len as usize);
                let copy_len = core::cmp::min(copy_len, 152);

                let mut comp = Completion {
                    conn_id: sock.conn_id,
                    result: TRONA_OK,
                    op_type: INET_OP_RECV,
                    data: [0u8; 152],
                    data_len: copy_len,
                    extra_conn_id: 0,
                    extra_ip: entry.src_ip,
                    extra_port: entry.src_port,
                    timestamp_ns: options::TIMESTAMP_NONE_NS,
                };

                let offset = entry.offset as usize;
                for i in 0..copy_len {
                    let src_idx = (offset + i) % UDP_RX_BUF_SIZE;
                    comp.data[i] = sock.rx_buf[src_idx];
                }

                // Consume entry
                sock.rx_entries[tail].active = false;
                sock.rx_entry_tail = ((tail + 1) % MAX_UDP_RX_ENTRIES) as u8;

                push_completion(comp);
                return;
            }
        }

        // No data available yet; mark as pending
        sock.pending_recv = true;
        sock.pending_recv_max_len = max_len;
        sock.pending_recv_op_type = INET_OP_RECV;
        sock.pending_recv_flags = 0;
    }
}

pub(crate) fn set_pending_recvfrom(conn_id: u32, max_len: u16, flags: u32) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return,
    };

    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        let sock = &mut (*sockets)[idx];

        if sock.rx_entry_head != sock.rx_entry_tail {
            let tail = sock.rx_entry_tail as usize;
            let entry = sock.rx_entries[tail];

            if entry.active {
                let copy_len = core::cmp::min(entry.len as usize, max_len as usize);
                let copy_len = core::cmp::min(copy_len, 104);

                let mut comp = Completion {
                    conn_id: sock.conn_id,
                    result: TRONA_OK,
                    op_type: INET_OP_RECVFROM,
                    data: [0u8; 152],
                    data_len: copy_len,
                    extra_conn_id: 0,
                    extra_ip: entry.src_ip,
                    extra_port: entry.src_port,
                    timestamp_ns: if (flags & trona::consts::INET_RECV_FLAG_WANT_TIMESTAMP) != 0 {
                        entry.timestamp_ns
                    } else {
                        options::TIMESTAMP_NONE_NS
                    },
                };

                let offset = entry.offset as usize;
                for i in 0..copy_len {
                    let src_idx = (offset + i) % UDP_RX_BUF_SIZE;
                    comp.data[i] = sock.rx_buf[src_idx];
                }

                sock.rx_entries[tail].active = false;
                sock.rx_entry_tail = ((tail + 1) % MAX_UDP_RX_ENTRIES) as u8;

                push_completion(comp);
                return;
            }
        }

        sock.pending_recv = true;
        sock.pending_recv_max_len = max_len;
        sock.pending_recv_op_type = INET_OP_RECVFROM;
        sock.pending_recv_flags = flags;
    }
}
