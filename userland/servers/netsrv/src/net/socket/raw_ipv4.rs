// SPDX-License-Identifier: GPL-2.0-only
//! Raw IPv4 socket support for userland programs.
//!
//! Provides SOCK_RAW + AF_INET sockets filtered by protocol number.
//! Used for tools like `ping` (IPPROTO_ICMP) and extensible to other
//! IPv4 protocol numbers.

use trona_protocol::common::{
    TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_OK, TRONA_OUT_OF_MEMORY,
};
use trona_protocol::posix::{
    INET_OP_RECV, INET_OP_RECVFROM, INET_RECV_FLAG_WANT_TIMESTAMP, TRONA_NO_BUFS,
    TRONA_NOT_CONNECTED,
};
use trona_protocol::posix_abi::socket::SOCK_RAW;

use crate::net::proto::ipv4::{self, IPV4_HEADER_LEN, Ipv4Header, PROTO_ICMP};
use crate::net::socket::options::{self, SocketOptions};

const MAX_RAW_SOCKETS: usize = 4;
const MAX_COMPLETIONS: usize = 16;
const MAX_RX_PACKET: usize = 128;
const CONN_ID_BASE: u32 = 2000;

const POLLIN: u16 = 0x0001;
const POLLOUT: u16 = 0x0004;

#[derive(Clone, Copy)]
struct RawIpv4Socket {
    active: bool,
    conn_id: u32,
    protocol: u8,
    remote_ip: u32,
    opts: SocketOptions,
    rx_buf: [u8; MAX_RX_PACKET],
    rx_len: u16,
    rx_src_ip: u32,
    rx_timestamp_ns: u64,
    pending_recv: bool,
    pending_recv_max_len: u16,
    pending_recvfrom: bool,
    pending_recvfrom_max_len: u16,
    pending_recvfrom_flags: u32,
}

impl RawIpv4Socket {
    const fn zeroed() -> Self {
        Self {
            active: false,
            conn_id: 0,
            protocol: 0,
            remote_ip: 0,
            opts: SocketOptions::new(1480, MAX_RX_PACKET as u32),
            rx_buf: [0; MAX_RX_PACKET],
            rx_len: 0,
            rx_src_ip: 0,
            rx_timestamp_ns: options::TIMESTAMP_NONE_NS,
            pending_recv: false,
            pending_recv_max_len: 0,
            pending_recvfrom: false,
            pending_recvfrom_max_len: 0,
            pending_recvfrom_flags: 0,
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

static mut RAW_SOCKETS: [RawIpv4Socket; MAX_RAW_SOCKETS] = [
    RawIpv4Socket::zeroed(),
    RawIpv4Socket::zeroed(),
    RawIpv4Socket::zeroed(),
    RawIpv4Socket::zeroed(),
];
static mut NEXT_CONN_ID: u32 = CONN_ID_BASE;
static mut COMPLETIONS: [Option<Completion>; MAX_COMPLETIONS] = [const { None }; MAX_COMPLETIONS];
static mut COMP_HEAD: usize = 0;
static mut COMP_TAIL: usize = 0;
static mut LOGGED_RAW_SENDS: u8 = 0;
static mut LOGGED_RAW_DELIVERS: u8 = 0;
static mut LOGGED_RAW_COMPLETIONS: u8 = 0;
static mut LOGGED_RAW_BUFFERED: u8 = 0;

fn log_ipv4(lb: &mut trona_runtime::debug::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

fn push_completion(c: Completion) {
    // SAFETY: Single-threaded netsrv event loop — no concurrent access to
    // COMPLETIONS, COMP_HEAD, or COMP_TAIL.
    unsafe {
        let conn_id = c.conn_id;
        let op_type = c.op_type;
        let data_len = c.data_len;
        let head = *(&raw const COMP_HEAD);
        let tail = *(&raw const COMP_TAIL);
        let next_head = (head + 1) % MAX_COMPLETIONS;
        if next_head == tail {
            crate::puts(b"[netsrv] WARN: raw IPv4 completion queue full, dropping\n");
            return;
        }
        let slot = (&raw mut COMPLETIONS)
            .cast::<Option<Completion>>()
            .add(head);
        // SAFETY: `head` is always in [0, MAX_COMPLETIONS) and we checked
        // the queue is not full, so this slot is valid and not aliased.
        slot.write(Some(c));
        *(&raw mut COMP_HEAD) = next_head;
        if *(&raw const LOGGED_RAW_COMPLETIONS) < 24 {
            *(&raw mut LOGGED_RAW_COMPLETIONS) += 1;
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[netsrv] raw queued conn=");
                _lb.dec(conn_id as u64);
                _lb.str(b" op=");
                _lb.dec(op_type as u64);
                _lb.str(b" len=");
                _lb.dec(data_len as u64);
                _lb.str(b" head=");
                _lb.dec(head as u64);
                _lb.str(b" tail=");
                _lb.dec(tail as u64);
                _lb.putc(b'\n');
            });
        }
    }
}

/// Enqueue an `INET_OP_RECV` completion for a raw IPv4 socket whose
/// receive queue already held a datagram when `NET_RECV_WAIT` arrived.
/// See `tcp::push_immediate_recv_completion` for the ordering contract.
pub(crate) fn push_immediate_recv_completion(conn_id: u32, data: &[u8]) {
    let n = core::cmp::min(data.len(), 152);
    let mut comp = Completion {
        conn_id,
        result: TRONA_OK,
        op_type: INET_OP_RECV,
        data: [0u8; 152],
        data_len: n,
        extra_conn_id: 0,
        extra_ip: 0,
        extra_port: 0,
        timestamp_ns: 0,
    };
    comp.data[..n].copy_from_slice(&data[..n]);
    push_completion(comp);
}

/// Enqueue an `INET_OP_RECVFROM` completion for a raw IPv4 datagram
/// already buffered when `NET_RECVFROM_WAIT` arrived. Preserves source
/// address and optional timestamp for the POSIX `recvfrom()` reply.
pub(crate) fn push_immediate_recvfrom_completion(
    conn_id: u32,
    data: &[u8],
    src_ip: u32,
    src_port: u16,
    timestamp_ns: u64,
) {
    let n = core::cmp::min(data.len(), 152);
    let mut comp = Completion {
        conn_id,
        result: TRONA_OK,
        op_type: INET_OP_RECVFROM,
        data: [0u8; 152],
        data_len: n,
        extra_conn_id: 0,
        extra_ip: src_ip,
        extra_port: src_port,
        timestamp_ns,
    };
    comp.data[..n].copy_from_slice(&data[..n]);
    push_completion(comp);
}

pub(crate) fn pop_completion() -> Option<Completion> {
    // SAFETY: Single-threaded netsrv event loop — no concurrent access.
    unsafe {
        let head = *(&raw const COMP_HEAD);
        let tail = *(&raw const COMP_TAIL);
        if head == tail {
            return None;
        }
        let slot = (&raw mut COMPLETIONS)
            .cast::<Option<Completion>>()
            .add(tail);
        // SAFETY: `tail` is always in [0, MAX_COMPLETIONS) and the queue is
        // non-empty, so this slot contains a valid `Some(Completion)`.
        let c = (*slot).take();
        *(&raw mut COMP_TAIL) = (tail + 1) % MAX_COMPLETIONS;
        c
    }
}

fn find_socket(conn_id: u32) -> Option<usize> {
    // SAFETY: Single-threaded netsrv event loop — no concurrent access.
    unsafe {
        let sockets = &raw const RAW_SOCKETS;
        for i in 0..MAX_RAW_SOCKETS {
            if (*sockets)[i].active && (*sockets)[i].conn_id == conn_id {
                return Some(i);
            }
        }
    }
    None
}

/// Create a new raw IPv4 socket filtered by `protocol`.
///
/// Protocol 0 is treated as IPPROTO_ICMP (1) for backwards compatibility
/// with callers that pass `SOCK_RAW` without an explicit protocol number.
pub(crate) fn raw_socket(protocol: u8) -> i32 {
    let proto = if protocol == 0 { PROTO_ICMP } else { protocol };

    // SAFETY: Single-threaded netsrv event loop — no concurrent access to
    // RAW_SOCKETS or NEXT_CONN_ID.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        for i in 0..MAX_RAW_SOCKETS {
            if !(*sockets)[i].active {
                let conn_id = *(&raw const NEXT_CONN_ID);
                *(&raw mut NEXT_CONN_ID) = conn_id + 1;
                (*sockets)[i] = RawIpv4Socket::zeroed();
                (*sockets)[i].active = true;
                (*sockets)[i].conn_id = conn_id;
                (*sockets)[i].protocol = proto;
                return conn_id as i32;
            }
        }
    }
    -(TRONA_OUT_OF_MEMORY as i32)
}

pub(crate) fn raw_connect(conn_id: u32, ip: u32) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        (*sockets)[idx].remote_ip = ip;
    }
    0
}

pub(crate) fn raw_sendto(conn_id: u32, data: &[u8], dst_ip: u32) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };
    if dst_ip == 0 || data.is_empty() || data.len() > 1480 {
        return -(TRONA_INVALID_ARGUMENT as i32);
    }

    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    let proto = unsafe {
        let sockets = &raw const RAW_SOCKETS;
        (*sockets)[idx].protocol
    };

    unsafe {
        if *(&raw const LOGGED_RAW_SENDS) < 8 {
            *(&raw mut LOGGED_RAW_SENDS) += 1;
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[netsrv] raw send conn=");
                _lb.dec(conn_id as u64);
                _lb.str(b" proto=");
                _lb.dec(proto as u64);
                _lb.str(b" src=");
                log_ipv4(&mut _lb, ipv4::our_ip());
                _lb.str(b" dst=");
                log_ipv4(&mut _lb, dst_ip);
                _lb.str(b" len=");
                _lb.dec(data.len() as u64);
                _lb.putc(b'\n');
            });
        }
    }

    let our_mac = crate::mac_addr();
    let ttl = unsafe {
        let sockets = &raw const RAW_SOCKETS;
        (*sockets)[idx].opts.ip_ttl
    };
    let allow_broadcast = unsafe {
        let sockets = &raw const RAW_SOCKETS;
        (*sockets)[idx].opts.broadcast
    };
    if crate::net::config::is_broadcast(dst_ip) && !allow_broadcast {
        return -(TRONA_INVALID_OPERATION as i32);
    }
    if crate::net::send_ip_packet_with_ttl(&our_mac, ipv4::our_ip(), dst_ip, proto, ttl, data) {
        data.len() as i32
    } else {
        -(TRONA_NO_BUFS as i32)
    }
}

pub(crate) fn raw_send(conn_id: u32, data: &[u8]) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw const RAW_SOCKETS;
        let dst_ip = (*sockets)[idx].remote_ip;
        if dst_ip == 0 {
            return -(TRONA_INVALID_ARGUMENT as i32);
        }
        raw_sendto(conn_id, data, dst_ip)
    }
}

pub(crate) fn raw_recv(conn_id: u32, buf: &mut [u8]) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        let sock = &mut (*sockets)[idx];
        if sock.rx_len == 0 {
            return -1;
        }
        let copy_len = core::cmp::min(sock.rx_len as usize, buf.len());
        buf[..copy_len].copy_from_slice(&sock.rx_buf[..copy_len]);
        sock.rx_len = 0;
        sock.rx_timestamp_ns = options::TIMESTAMP_NONE_NS;
        copy_len as i32
    }
}

pub(crate) fn raw_recvfrom(
    conn_id: u32,
    buf: &mut [u8],
    want_timestamp: bool,
) -> (i32, u32, u16, u64) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => {
            return (
                -(TRONA_INVALID_ARGUMENT as i32),
                0,
                0,
                options::TIMESTAMP_NONE_NS,
            );
        }
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        let sock = &mut (*sockets)[idx];
        if sock.rx_len == 0 {
            return (-1, 0, 0, options::TIMESTAMP_NONE_NS);
        }
        let copy_len = core::cmp::min(sock.rx_len as usize, buf.len());
        buf[..copy_len].copy_from_slice(&sock.rx_buf[..copy_len]);
        let src_ip = sock.rx_src_ip;
        let timestamp_ns = if want_timestamp {
            sock.rx_timestamp_ns
        } else {
            options::TIMESTAMP_NONE_NS
        };
        sock.rx_len = 0;
        sock.rx_timestamp_ns = options::TIMESTAMP_NONE_NS;
        (copy_len as i32, src_ip, 0, timestamp_ns)
    }
}

pub(crate) fn set_pending_recv(conn_id: u32, max_len: u16) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return,
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        let sock = &mut (*sockets)[idx];
        if sock.rx_len != 0 {
            let copy_len = core::cmp::min(sock.rx_len as usize, max_len as usize);
            let copy_len = core::cmp::min(copy_len, 128);
            let mut comp = Completion {
                conn_id: sock.conn_id,
                result: TRONA_OK,
                op_type: INET_OP_RECV,
                data: [0; 152],
                data_len: copy_len,
                extra_conn_id: 0,
                extra_ip: sock.rx_src_ip,
                extra_port: 0,
                timestamp_ns: options::TIMESTAMP_NONE_NS,
            };
            comp.data[..copy_len].copy_from_slice(&sock.rx_buf[..copy_len]);
            sock.rx_len = 0;
            push_completion(comp);
            return;
        }
        sock.pending_recv = true;
        sock.pending_recv_max_len = max_len;
    }
}

pub(crate) fn set_pending_recvfrom(conn_id: u32, max_len: u16, flags: u32) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return,
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        let sock = &mut (*sockets)[idx];
        if sock.rx_len != 0 {
            let copy_len = core::cmp::min(sock.rx_len as usize, max_len as usize);
            let copy_len = core::cmp::min(copy_len, 104);
            let mut comp = Completion {
                conn_id: sock.conn_id,
                result: TRONA_OK,
                op_type: INET_OP_RECVFROM,
                data: [0; 152],
                data_len: copy_len,
                extra_conn_id: 0,
                extra_ip: sock.rx_src_ip,
                extra_port: 0,
                timestamp_ns: if (flags & INET_RECV_FLAG_WANT_TIMESTAMP) != 0 {
                    sock.rx_timestamp_ns
                } else {
                    options::TIMESTAMP_NONE_NS
                },
            };
            comp.data[..copy_len].copy_from_slice(&sock.rx_buf[..copy_len]);
            sock.rx_len = 0;
            sock.rx_timestamp_ns = options::TIMESTAMP_NONE_NS;
            push_completion(comp);
            return;
        }
        sock.pending_recvfrom = true;
        sock.pending_recvfrom_max_len = max_len;
        sock.pending_recvfrom_flags = flags;
    }
}

pub(crate) fn raw_getsockname(conn_id: u32) -> (u32, u16) {
    if find_socket(conn_id).is_none() {
        return (0, 0);
    }
    (ipv4::our_ip(), 0)
}

pub(crate) fn raw_getpeername(conn_id: u32) -> Result<(u32, u16), u64> {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return Err(TRONA_INVALID_ARGUMENT),
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw const RAW_SOCKETS;
        let remote_ip = (*sockets)[idx].remote_ip;
        if remote_ip == 0 {
            return Err(TRONA_NOT_CONNECTED);
        }
        Ok((remote_ip, 0))
    }
}

pub(crate) fn raw_setsockopt(
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
        let sockets = &raw mut RAW_SOCKETS;
        options::set_option(
            &mut (*sockets)[idx].opts,
            SOCK_RAW,
            level,
            optname,
            optval,
            optlen,
        )
    }
}

pub(crate) fn raw_getsockopt(conn_id: u32, level: i32, optname: i32) -> Result<(u64, u32), u64> {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return Err(TRONA_INVALID_ARGUMENT),
    };
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        let sock = &mut (*sockets)[idx];
        options::get_option(
            &mut sock.opts,
            SOCK_RAW,
            sock.protocol as i32,
            level,
            optname,
        )
    }
}

pub(crate) fn raw_poll_status(conn_id: u32, events: u16) -> u16 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return 0x020,
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw const RAW_SOCKETS;
        let sock = &(*sockets)[idx];
        let mut rev = 0u16;
        if events & POLLIN != 0 && sock.rx_len != 0 {
            rev |= POLLIN;
        }
        if events & POLLOUT != 0 {
            rev |= POLLOUT;
        }
        rev
    }
}

pub(crate) fn raw_close(conn_id: u32) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(TRONA_INVALID_ARGUMENT as i32),
    };
    // SAFETY: Single-threaded netsrv event loop — `idx` was validated above.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        (*sockets)[idx] = RawIpv4Socket::zeroed();
    }
    0
}

fn packet_matches(sock: &RawIpv4Socket, src_ip: u32) -> bool {
    sock.remote_ip == 0 || sock.remote_ip == src_ip
}

fn encode_ipv4_packet(ip_hdr: &Ipv4Header, payload: &[u8], out: &mut [u8; MAX_RX_PACKET]) -> usize {
    let payload_len = core::cmp::min(payload.len(), MAX_RX_PACKET.saturating_sub(IPV4_HEADER_LEN));
    let total_len = IPV4_HEADER_LEN + payload_len;

    out[0] = 0x45;
    out[1] = ip_hdr.tos;
    out[2] = (total_len >> 8) as u8;
    out[3] = total_len as u8;
    out[4] = (ip_hdr.id >> 8) as u8;
    out[5] = ip_hdr.id as u8;
    out[6] = (ip_hdr.flags_frag >> 8) as u8;
    out[7] = ip_hdr.flags_frag as u8;
    out[8] = ip_hdr.ttl;
    out[9] = ip_hdr.protocol;
    out[10] = (ip_hdr.checksum >> 8) as u8;
    out[11] = ip_hdr.checksum as u8;
    out[12] = (ip_hdr.src >> 24) as u8;
    out[13] = (ip_hdr.src >> 16) as u8;
    out[14] = (ip_hdr.src >> 8) as u8;
    out[15] = ip_hdr.src as u8;
    out[16] = (ip_hdr.dst >> 24) as u8;
    out[17] = (ip_hdr.dst >> 16) as u8;
    out[18] = (ip_hdr.dst >> 8) as u8;
    out[19] = ip_hdr.dst as u8;
    out[IPV4_HEADER_LEN..total_len].copy_from_slice(&payload[..payload_len]);
    total_len
}

/// Deliver an incoming IPv4 packet to all matching raw sockets.
///
/// A socket matches if its `protocol` field equals the IP header's protocol
/// number and the source IP matches the connected remote (or the socket is
/// unconnected, i.e. `remote_ip == 0`).
pub(crate) fn deliver(ip_hdr: &Ipv4Header, data: &[u8]) {
    // SAFETY: Single-threaded netsrv event loop — no concurrent access to
    // RAW_SOCKETS.
    unsafe {
        let sockets = &raw mut RAW_SOCKETS;
        for i in 0..MAX_RAW_SOCKETS {
            let sock = &mut (*sockets)[i];
            if !sock.active {
                continue;
            }
            if sock.protocol != ip_hdr.protocol {
                continue;
            }
            if !packet_matches(sock, ip_hdr.src) {
                continue;
            }

            let mut packet = [0u8; MAX_RX_PACKET];
            let packet_len = encode_ipv4_packet(ip_hdr, data, &mut packet);

            if *(&raw const LOGGED_RAW_DELIVERS) < 12 {
                *(&raw mut LOGGED_RAW_DELIVERS) += 1;
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[netsrv] raw deliver conn=");
                    _lb.dec(sock.conn_id as u64);
                    _lb.str(b" proto=");
                    _lb.dec(ip_hdr.protocol as u64);
                    _lb.str(b" src=");
                    log_ipv4(&mut _lb, ip_hdr.src);
                    _lb.str(b" dst=");
                    log_ipv4(&mut _lb, ip_hdr.dst);
                    _lb.str(b" payload=");
                    _lb.dec(data.len() as u64);
                    _lb.str(b" packet=");
                    _lb.dec(packet_len as u64);
                    _lb.str(b" pending_recv=");
                    _lb.dec(sock.pending_recv as u64);
                    _lb.str(b" pending_recvfrom=");
                    _lb.dec(sock.pending_recvfrom as u64);
                    _lb.putc(b'\n');
                });
            }

            if sock.pending_recv {
                sock.pending_recv = false;
                let copy_len = core::cmp::min(packet_len, sock.pending_recv_max_len as usize);
                let copy_len = core::cmp::min(copy_len, 128);
                let mut comp = Completion {
                    conn_id: sock.conn_id,
                    result: TRONA_OK,
                    op_type: INET_OP_RECV,
                    data: [0; 152],
                    data_len: copy_len,
                    extra_conn_id: 0,
                    extra_ip: ip_hdr.src,
                    extra_port: 0,
                    timestamp_ns: options::TIMESTAMP_NONE_NS,
                };
                comp.data[..copy_len].copy_from_slice(&packet[..copy_len]);
                if *(&raw const LOGGED_RAW_COMPLETIONS) < 12 {
                    *(&raw mut LOGGED_RAW_COMPLETIONS) += 1;
                    trona_runtime::udebug!(|_lb| {
                        _lb.str(b"[netsrv] raw completion recv conn=");
                        _lb.dec(sock.conn_id as u64);
                        _lb.str(b" len=");
                        _lb.dec(copy_len as u64);
                        _lb.putc(b'\n');
                    });
                }
                push_completion(comp);
                continue;
            }

            if sock.pending_recvfrom {
                sock.pending_recvfrom = false;
                let copy_len = core::cmp::min(packet_len, sock.pending_recvfrom_max_len as usize);
                let copy_len = core::cmp::min(copy_len, 104);
                let mut comp = Completion {
                    conn_id: sock.conn_id,
                    result: TRONA_OK,
                    op_type: INET_OP_RECVFROM,
                    data: [0; 152],
                    data_len: copy_len,
                    extra_conn_id: 0,
                    extra_ip: ip_hdr.src,
                    extra_port: 0,
                    timestamp_ns: if (sock.pending_recvfrom_flags & INET_RECV_FLAG_WANT_TIMESTAMP)
                        != 0
                    {
                        options::sample_timestamp_ns(&sock.opts)
                    } else {
                        options::TIMESTAMP_NONE_NS
                    },
                };
                comp.data[..copy_len].copy_from_slice(&packet[..copy_len]);
                sock.pending_recvfrom_flags = 0;
                if *(&raw const LOGGED_RAW_COMPLETIONS) < 12 {
                    *(&raw mut LOGGED_RAW_COMPLETIONS) += 1;
                    trona_runtime::udebug!(|_lb| {
                        _lb.str(b"[netsrv] raw completion recvfrom conn=");
                        _lb.dec(sock.conn_id as u64);
                        _lb.str(b" len=");
                        _lb.dec(copy_len as u64);
                        _lb.str(b" src=");
                        log_ipv4(&mut _lb, ip_hdr.src);
                        _lb.putc(b'\n');
                    });
                }
                push_completion(comp);
                continue;
            }

            let was_empty = sock.rx_len == 0;
            let copy_len = core::cmp::min(packet_len, MAX_RX_PACKET);
            sock.rx_buf[..copy_len].copy_from_slice(&packet[..copy_len]);
            sock.rx_len = copy_len as u16;
            sock.rx_src_ip = ip_hdr.src;
            sock.rx_timestamp_ns = options::sample_timestamp_ns(&sock.opts);
            if *(&raw const LOGGED_RAW_BUFFERED) < 12 {
                *(&raw mut LOGGED_RAW_BUFFERED) += 1;
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[netsrv] raw buffered conn=");
                    _lb.dec(sock.conn_id as u64);
                    _lb.str(b" len=");
                    _lb.dec(copy_len as u64);
                    _lb.str(b" was_empty=");
                    _lb.dec(was_empty as u64);
                    _lb.putc(b'\n');
                });
            }
            if was_empty {
                push_completion(Completion {
                    conn_id: sock.conn_id,
                    result: TRONA_OK,
                    op_type: INET_OP_RECV,
                    data: [0; 152],
                    data_len: 0,
                    extra_conn_id: 0,
                    extra_ip: 0,
                    extra_port: 0,
                    timestamp_ns: options::TIMESTAMP_NONE_NS,
                });
            }
        }
    }
}
