// SPDX-License-Identifier: GPL-2.0-only
//! UDP (User Datagram Protocol) implementation.
//!
//! Provides connectionless datagram sockets with optional connect() for
//! default destination. Buffers incoming datagrams per-socket and supports
//! async completion for pending recvfrom operations.

use salty::consts::{INET_OP_RECVFROM, SALTY_INVALID_ARGUMENT, SALTY_OK};

const MAX_UDP_SOCKETS: usize = 8;
const UDP_RX_BUF_SIZE: usize = 4096;
const MAX_UDP_RX_ENTRIES: usize = 8;
const MAX_COMPLETIONS: usize = 8;
const UDP_HEADER_LEN: usize = 8;

#[derive(Clone, Copy)]
struct UdpRxEntry {
    active: bool,
    src_ip: u32,
    src_port: u16,
    offset: u16,
    len: u16,
}

impl UdpRxEntry {
    const fn zeroed() -> Self {
        Self {
            active: false,
            src_ip: 0,
            src_port: 0,
            offset: 0,
            len: 0,
        }
    }
}

struct UdpSocket {
    active: bool,
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
    rx_buf: [u8; UDP_RX_BUF_SIZE],
    rx_head: u16,
    rx_entries: [UdpRxEntry; MAX_UDP_RX_ENTRIES],
    rx_entry_head: u8,
    rx_entry_tail: u8,
    pending_recv: bool,
    pending_recv_max_len: u16,
    conn_id: u32,
}

impl UdpSocket {
    const fn zeroed() -> Self {
        Self {
            active: false,
            local_ip: 0,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            rx_buf: [0u8; UDP_RX_BUF_SIZE],
            rx_head: 0,
            rx_entries: [UdpRxEntry::zeroed(); MAX_UDP_RX_ENTRIES],
            rx_entry_head: 0,
            rx_entry_tail: 0,
            pending_recv: false,
            pending_recv_max_len: 0,
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

static mut COMPLETIONS: [Option<Completion>; MAX_COMPLETIONS] =
    [None, None, None, None, None, None, None, None];
static mut COMP_HEAD: usize = 0;
static mut COMP_TAIL: usize = 0;

fn push_completion(c: Completion) {
    // SAFETY: Single-threaded driver; COMPLETIONS/COMP_HEAD/COMP_TAIL only accessed here and pop.
    unsafe {
        let head = *(&raw const COMP_HEAD);
        let tail = *(&raw const COMP_TAIL);
        let next_head = (head + 1) % MAX_COMPLETIONS;
        if next_head == tail {
            return; // queue full, drop
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
        None => return -(SALTY_INVALID_ARGUMENT as i32),
    };

    // Check port not already bound by another socket
    if let Some(existing) = find_by_port(port) {
        if existing != idx {
            return -(SALTY_INVALID_ARGUMENT as i32);
        }
    }

    // SAFETY: Single-threaded driver; idx is valid.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        (*sockets)[idx].local_ip = ip;
        (*sockets)[idx].local_port = port;
    }
    0
}

/// Set default destination for send(). Always succeeds immediately for UDP.
pub(crate) fn udp_connect(conn_id: u32, ip: u32, port: u16) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(SALTY_INVALID_ARGUMENT as i32),
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
            (*sockets)[idx].local_ip = super::ipv4::OUR_IP;
        }
    }
    0
}

/// Send a datagram to a specific destination.
pub(crate) fn udp_sendto(conn_id: u32, data: &[u8], dst_ip: u32, dst_port: u16) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(SALTY_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; reading/writing socket state.
    let (local_port, local_ip) = unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        // Auto-bind ephemeral port if not yet bound
        if (*sockets)[idx].local_port == 0 {
            let port = alloc_ephemeral_port();
            (*sockets)[idx].local_port = port;
            (*sockets)[idx].local_ip = super::ipv4::OUR_IP;
        }
        ((*sockets)[idx].local_port, (*sockets)[idx].local_ip)
    };

    let src_ip = if local_ip == 0 {
        super::ipv4::OUR_IP
    } else {
        local_ip
    };

    // Build UDP packet: header (8 bytes) + payload
    let udp_len = UDP_HEADER_LEN + data.len();
    if udp_len > 1480 {
        // MTU limit: 1500 ethernet - 20 IP header = 1480 max UDP (header + payload)
        return -(SALTY_INVALID_ARGUMENT as i32);
    }

    let mut udp_buf = [0u8; 1480]; // max UDP packet: 8 header + 1472 payload
                                   // Source port
    udp_buf[0] = (local_port >> 8) as u8;
    udp_buf[1] = local_port as u8;
    // Destination port
    udp_buf[2] = (dst_port >> 8) as u8;
    udp_buf[3] = dst_port as u8;
    // Length
    udp_buf[4] = (udp_len >> 8) as u8;
    udp_buf[5] = udp_len as u8;
    // Checksum placeholder
    udp_buf[6] = 0;
    udp_buf[7] = 0;
    // Payload
    udp_buf[UDP_HEADER_LEN..udp_len].copy_from_slice(data);

    // Compute UDP checksum
    let cksum = super::checksum::transport_checksum(
        src_ip,
        dst_ip,
        super::ipv4::PROTO_UDP,
        &udp_buf[..udp_len],
    );
    udp_buf[6] = (cksum >> 8) as u8;
    udp_buf[7] = cksum as u8;

    // Ensure ARP entry exists
    let our_mac = crate::mac_addr();
    super::ensure_arp(&our_mac, src_ip, dst_ip);

    // Send via IP layer
    super::send_ip_packet(
        &our_mac,
        src_ip,
        dst_ip,
        super::ipv4::PROTO_UDP,
        &udp_buf[..udp_len],
    );

    data.len() as i32
}

/// Send a datagram using the stored remote address (from connect).
pub(crate) fn udp_send(conn_id: u32, data: &[u8]) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(SALTY_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; reading socket state.
    let (rip, rport) = unsafe {
        let sockets = &raw const UDP_SOCKETS;
        ((*sockets)[idx].remote_ip, (*sockets)[idx].remote_port)
    };

    if rip == 0 || rport == 0 {
        return -(SALTY_INVALID_ARGUMENT as i32);
    }

    udp_sendto(conn_id, data, rip, rport)
}

/// Receive a datagram, returning (bytes_copied, src_ip, src_port).
/// Returns (-1, 0, 0) if no data available.
pub(crate) fn udp_recvfrom(conn_id: u32, buf: &mut [u8]) -> (i32, u32, u16) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return (-1, 0, 0),
    };

    // SAFETY: Single-threaded driver; reading/writing socket rx state.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        let sock = &mut (*sockets)[idx];

        if sock.rx_entry_head == sock.rx_entry_tail {
            return (-1, 0, 0); // no data
        }

        let tail = sock.rx_entry_tail as usize;
        let entry = sock.rx_entries[tail];

        if !entry.active {
            return (-1, 0, 0);
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

        // Consume entry
        sock.rx_entries[tail].active = false;
        sock.rx_entry_tail = ((tail + 1) % MAX_UDP_RX_ENTRIES) as u8;

        (copy_len as i32, src_ip, src_port)
    }
}

/// Receive a datagram (connected socket, no source address returned).
pub(crate) fn udp_recv(conn_id: u32, buf: &mut [u8]) -> i32 {
    let (len, _, _) = udp_recvfrom(conn_id, buf);
    len
}

/// Close a UDP socket.
pub(crate) fn udp_close(conn_id: u32) -> i32 {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return -(SALTY_INVALID_ARGUMENT as i32),
    };

    // SAFETY: Single-threaded driver; deactivating socket.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        (*sockets)[idx].active = false;
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
pub(crate) fn udp_getpeername(conn_id: u32) -> (u32, u16) {
    let idx = match find_socket(conn_id) {
        Some(i) => i,
        None => return (0, 0),
    };

    // SAFETY: Single-threaded driver; reading socket state.
    unsafe {
        let sockets = &raw const UDP_SOCKETS;
        ((*sockets)[idx].remote_ip, (*sockets)[idx].remote_port)
    }
}

/// Handle an incoming UDP datagram from the IP layer.
///
/// Parses the UDP header, finds the matching socket by destination port,
/// buffers the payload, and fires a completion if a recv is pending.
pub(crate) fn handle_datagram(ip_hdr: &super::ipv4::Ipv4Header, data: &[u8]) {
    if data.len() < UDP_HEADER_LEN {
        return;
    }

    let src_port = ((data[0] as u16) << 8) | (data[1] as u16);
    let dst_port = ((data[2] as u16) << 8) | (data[3] as u16);
    let udp_len = ((data[4] as u16) << 8) | (data[5] as u16);

    if (udp_len as usize) < UDP_HEADER_LEN || (udp_len as usize) > data.len() {
        return;
    }

    let payload = &data[UDP_HEADER_LEN..udp_len as usize];
    let src_ip = ip_hdr.src;

    // Find a socket listening on dst_port
    let idx = match find_by_port(dst_port) {
        Some(i) => i,
        None => return, // no matching socket, silently drop
    };

    // SAFETY: Single-threaded driver; mutating socket rx state.
    unsafe {
        let sockets = &raw mut UDP_SOCKETS;
        let sock = &mut (*sockets)[idx];

        // If a recv is pending, deliver directly via completion
        if sock.pending_recv {
            sock.pending_recv = false;
            let max_len = sock.pending_recv_max_len as usize;
            let copy_len = core::cmp::min(payload.len(), max_len);
            let copy_len = core::cmp::min(copy_len, 152); // Completion data buffer limit

            let mut comp = Completion {
                conn_id: sock.conn_id,
                result: SALTY_OK,
                op_type: INET_OP_RECVFROM,
                data: [0u8; 152],
                data_len: copy_len,
                extra_conn_id: 0,
                extra_ip: src_ip,
                extra_port: src_port,
            };
            comp.data[..copy_len].copy_from_slice(&payload[..copy_len]);
            push_completion(comp);
            return;
        }

        // Buffer the datagram in the socket's rx ring
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
        };

        sock.rx_entry_head = next_head as u8;
        sock.rx_head = ((offset as usize + payload.len()) % UDP_RX_BUF_SIZE) as u16;
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
                    result: SALTY_OK,
                    op_type: INET_OP_RECVFROM,
                    data: [0u8; 152],
                    data_len: copy_len,
                    extra_conn_id: 0,
                    extra_ip: entry.src_ip,
                    extra_port: entry.src_port,
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
    }
}
