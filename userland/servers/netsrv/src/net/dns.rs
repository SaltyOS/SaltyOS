// SPDX-License-Identifier: GPL-2.0-only
//! DNS protocol engine for netsrv.
//!
//! Builds RFC 1035 DNS queries (A and PTR records), sends them over a dedicated
//! internal UDP socket to the QEMU DNS forwarder at 10.0.2.3:53, and parses
//! responses including CNAME chasing.

use salty::consts::*;

const DNS_SERVER_IP: u32 = 0x0A00_0203; // 10.0.2.3 (QEMU DNS forwarder)
const DNS_PORT: u16 = 53;
const MAX_DNS_RESULTS: usize = 4;
const DNS_TIMEOUT_NS: u64 = 3_000_000_000; // 3 seconds per attempt
const DNS_MAX_RETRIES: usize = 2; // total 3 attempts
const DNS_MAX_QUERY_LEN: usize = 288; // 12 header + 256 max qname + 4 qtype/qclass + padding
const DNS_MAX_RESPONSE_LEN: usize = 512; // RFC 1035 UDP limit
const DNS_HEADER_LEN: usize = 12;

// DNS record types
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;

// DNS header flags
const DNS_FLAG_QR: u16 = 0x8000;
const DNS_FLAG_RD: u16 = 0x0100; // Recursion Desired

static mut DNS_SOCKET_ID: i32 = -1;

/// Result of a successful DNS A-record resolution.
pub(crate) struct DnsResult {
    pub(crate) ip_count: u8,
    pub(crate) ips: [u32; MAX_DNS_RESULTS],
    pub(crate) ttl: u32,
}

/// DNS resolution error with RCODE distinction.
#[derive(Clone, Copy)]
pub(crate) enum DnsError {
    NxDomain,
    ServerFail,
    Timeout,
    Other,
}

/// Initialize the internal DNS UDP socket. Call once during netsrv startup.
pub(crate) fn init_dns_socket() {
    let id = super::udp::udp_socket();
    if id < 0 {
        crate::puts(b"[netsrv] DNS: failed to allocate internal UDP socket\n");
        return;
    }
    // Bind to ephemeral port for DNS queries
    let bind_result = super::udp::udp_bind(id as u32, super::ipv4::OUR_IP, 0);
    if bind_result < 0 {
        // Binding to port 0 triggers ephemeral port allocation internally,
        // but udp_bind requires a non-zero port. Just connect instead which
        // will auto-bind an ephemeral port on first sendto.
    }
    // SAFETY: Single-threaded init; DNS_SOCKET_ID written once before event loop.
    unsafe {
        *(&raw mut DNS_SOCKET_ID) = id;
    }
    crate::puts(b"[netsrv] DNS: internal socket ready\n");
}

/// Get monotonic time in nanoseconds.
fn clock_monotonic_ns() -> u64 {
    let r = salty::syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as u64, 0, 0, 0, 0, 0);
    // error field holds seconds, value field holds nanoseconds
    (r.error * 1_000_000_000) + r.value
}

/// Generate a random transaction ID using the kernel RDRAND-backed GetRandom
/// syscall, matching the pattern used by `tcp::generate_isn()`.
fn generate_txn_id() -> u16 {
    let mut buf = [0u8; 2];
    // SAFETY: Passing valid stack buffer to GetRandom syscall.
    let _ = unsafe {
        salty::syscall::syscall(SYS_GETRANDOM, buf.as_mut_ptr() as u64, 2, 0, 0, 0, 0)
    };
    u16::from_ne_bytes(buf)
}

/// Encode a hostname into DNS wire format (length-prefixed labels).
///
/// Example: "google.com" -> "\x06google\x03com\x00"
/// Returns the number of bytes written, or 0 on error.
fn encode_hostname(hostname: &[u8], buf: &mut [u8]) -> usize {
    if hostname.is_empty() || hostname.len() > 253 {
        return 0;
    }

    let mut out_pos = 0usize;
    let mut label_start = 0usize;

    let mut i = 0;
    while i <= hostname.len() {
        let at_dot = i < hostname.len() && hostname[i] == b'.';
        let at_end = i == hostname.len();

        if at_dot || at_end {
            let label_len = i - label_start;
            if label_len == 0 && i != hostname.len() {
                return 0; // empty label (but allow trailing dot)
            }
            if label_len > 63 {
                return 0; // label too long
            }
            if label_len > 0 {
                if out_pos + 1 + label_len >= buf.len() {
                    return 0; // buffer overflow
                }
                buf[out_pos] = label_len as u8;
                out_pos += 1;
                let mut j = 0;
                while j < label_len {
                    buf[out_pos + j] = hostname[label_start + j];
                    j += 1;
                }
                out_pos += label_len;
            }
            label_start = i + 1;
        }
        i += 1;
    }

    // Null terminator
    if out_pos >= buf.len() {
        return 0;
    }
    buf[out_pos] = 0;
    out_pos += 1;

    out_pos
}

/// Build a DNS A-record query packet.
/// Returns the total query length, or 0 on error.
fn build_query(hostname: &[u8], txn_id: u16, buf: &mut [u8; DNS_MAX_QUERY_LEN]) -> usize {
    // Header (12 bytes)
    buf[0] = (txn_id >> 8) as u8;
    buf[1] = txn_id as u8;
    // Flags: RD=1, standard query
    buf[2] = (DNS_FLAG_RD >> 8) as u8;
    buf[3] = DNS_FLAG_RD as u8;
    // QDCOUNT = 1
    buf[4] = 0;
    buf[5] = 1;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;

    // QNAME
    let qname_len = encode_hostname(hostname, &mut buf[DNS_HEADER_LEN..]);
    if qname_len == 0 {
        return 0;
    }

    let pos = DNS_HEADER_LEN + qname_len;
    if pos + 4 > buf.len() {
        return 0;
    }

    // QTYPE = A (1)
    buf[pos] = 0;
    buf[pos + 1] = DNS_TYPE_A as u8;
    // QCLASS = IN (1)
    buf[pos + 2] = 0;
    buf[pos + 3] = 1;

    pos + 4
}

/// Build a DNS PTR query packet for reverse DNS lookup.
/// Converts IP a.b.c.d to "d.c.b.a.in-addr.arpa" query.
/// Returns the total query length, or 0 on error.
fn build_ptr_query(ip: u32, txn_id: u16, buf: &mut [u8; DNS_MAX_QUERY_LEN]) -> usize {
    // Build the in-addr.arpa hostname
    let a = ((ip >> 24) & 0xFF) as u8;
    let b = ((ip >> 16) & 0xFF) as u8;
    let c = ((ip >> 8) & 0xFF) as u8;
    let d = (ip & 0xFF) as u8;

    // Format: "d.c.b.a.in-addr.arpa"
    let mut hostname = [0u8; 64];
    let mut pos = 0;
    pos += write_decimal(d, &mut hostname[pos..]);
    hostname[pos] = b'.';
    pos += 1;
    pos += write_decimal(c, &mut hostname[pos..]);
    hostname[pos] = b'.';
    pos += 1;
    pos += write_decimal(b, &mut hostname[pos..]);
    hostname[pos] = b'.';
    pos += 1;
    pos += write_decimal(a, &mut hostname[pos..]);
    // ".in-addr.arpa"
    let suffix = b".in-addr.arpa";
    let mut i = 0;
    while i < suffix.len() {
        hostname[pos + i] = suffix[i];
        i += 1;
    }
    pos += suffix.len();

    // Header (12 bytes)
    buf[0] = (txn_id >> 8) as u8;
    buf[1] = txn_id as u8;
    buf[2] = (DNS_FLAG_RD >> 8) as u8;
    buf[3] = DNS_FLAG_RD as u8;
    buf[4] = 0;
    buf[5] = 1; // QDCOUNT=1
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;

    let qname_len = encode_hostname(&hostname[..pos], &mut buf[DNS_HEADER_LEN..]);
    if qname_len == 0 {
        return 0;
    }

    let off = DNS_HEADER_LEN + qname_len;
    if off + 4 > buf.len() {
        return 0;
    }

    // QTYPE = PTR (12)
    buf[off] = 0;
    buf[off + 1] = DNS_TYPE_PTR as u8;
    // QCLASS = IN (1)
    buf[off + 2] = 0;
    buf[off + 3] = 1;

    off + 4
}

/// Write a u8 decimal value into a buffer. Returns bytes written.
fn write_decimal(val: u8, buf: &mut [u8]) -> usize {
    if val >= 100 {
        if buf.len() < 3 {
            return 0;
        }
        buf[0] = b'0' + val / 100;
        buf[1] = b'0' + (val / 10) % 10;
        buf[2] = b'0' + val % 10;
        3
    } else if val >= 10 {
        if buf.len() < 2 {
            return 0;
        }
        buf[0] = b'0' + val / 10;
        buf[1] = b'0' + val % 10;
        2
    } else {
        if buf.is_empty() {
            return 0;
        }
        buf[0] = b'0' + val;
        1
    }
}

/// Decode a DNS name from a response packet, handling compression pointers.
///
/// Returns `(name_length_in_out, bytes_consumed_in_packet)`.
/// `out` receives the decoded dotted name (e.g., "google.com").
fn decode_name(data: &[u8], mut offset: usize, out: &mut [u8; 256]) -> (usize, usize) {
    let mut out_pos = 0usize;
    let mut consumed = 0usize;
    let mut followed_pointer = false;
    let mut depth = 0u8;

    loop {
        if offset >= data.len() || depth > 16 {
            return (0, 0);
        }
        depth += 1;

        let label_len = data[offset] as usize;

        if label_len == 0 {
            // End of name
            if !followed_pointer {
                consumed += 1;
            }
            break;
        }

        // Compression pointer: top 2 bits are 11
        if label_len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return (0, 0);
            }
            let ptr = (((data[offset] as usize) & 0x3F) << 8) | (data[offset + 1] as usize);
            if !followed_pointer {
                consumed += 2;
                followed_pointer = true;
            }
            offset = ptr;
            continue;
        }

        // Regular label
        if offset + 1 + label_len > data.len() {
            return (0, 0);
        }
        if !followed_pointer {
            consumed += 1 + label_len;
        }

        // Add dot separator (except before first label)
        if out_pos > 0 {
            if out_pos >= 255 {
                return (0, 0);
            }
            out[out_pos] = b'.';
            out_pos += 1;
        }

        // Copy label bytes
        let mut i = 0;
        while i < label_len {
            if out_pos >= 255 {
                return (0, 0);
            }
            out[out_pos] = data[offset + 1 + i];
            out_pos += 1;
            i += 1;
        }

        offset += 1 + label_len;
    }

    (out_pos, consumed)
}

/// Parse a DNS response and extract A records.
///
/// Returns a 3-way outcome:
/// - `None` — TXN mismatch or malformed packet (transient, keep polling)
/// - `Some(Ok(DnsResult))` — successful resolution
/// - `Some(Err(rcode))` — definitive DNS error (stop retrying)
fn parse_response(data: &[u8], expected_txn_id: u16) -> Option<Result<DnsResult, u8>> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }

    // Verify transaction ID
    let txn_id = ((data[0] as u16) << 8) | (data[1] as u16);
    if txn_id != expected_txn_id {
        return None;
    }

    // Check flags: QR must be 1 (response)
    let flags = ((data[2] as u16) << 8) | (data[3] as u16);
    if flags & DNS_FLAG_QR == 0 {
        return None;
    }

    // Check RCODE (bits 3:0 of byte 3)
    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return Some(Err(rcode));
    }

    let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
    let ancount = ((data[6] as u16) << 8) | (data[7] as u16);

    // Skip question section
    let mut offset = DNS_HEADER_LEN;
    let mut q = 0u16;
    while q < qdcount {
        let mut name_buf = [0u8; 256];
        let (_, consumed) = decode_name(data, offset, &mut name_buf);
        if consumed == 0 {
            return None;
        }
        offset += consumed;
        offset += 4; // QTYPE(2) + QCLASS(2)
        if offset > data.len() {
            return None;
        }
        q += 1;
    }

    // Parse answer records
    let mut result = DnsResult {
        ip_count: 0,
        ips: [0u32; MAX_DNS_RESULTS],
        ttl: u32::MAX,
    };

    let mut a = 0u16;
    while a < ancount {
        if offset >= data.len() {
            break;
        }

        // Decode record name
        let mut name_buf = [0u8; 256];
        let (_, consumed) = decode_name(data, offset, &mut name_buf);
        if consumed == 0 {
            break;
        }
        offset += consumed;

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if offset + 10 > data.len() {
            break;
        }

        let rtype = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        // let rclass = ((data[offset + 2] as u16) << 8) | (data[offset + 3] as u16);
        let ttl = ((data[offset + 4] as u32) << 24)
            | ((data[offset + 5] as u32) << 16)
            | ((data[offset + 6] as u32) << 8)
            | (data[offset + 7] as u32);
        let rdlength = ((data[offset + 8] as u16) << 8) | (data[offset + 9] as u16);
        offset += 10;

        if offset + rdlength as usize > data.len() {
            break;
        }

        if rtype == DNS_TYPE_A && rdlength == 4 {
            // A record: 4 bytes IPv4 address (big-endian -> host u32)
            let ip = ((data[offset] as u32) << 24)
                | ((data[offset + 1] as u32) << 16)
                | ((data[offset + 2] as u32) << 8)
                | (data[offset + 3] as u32);

            if (result.ip_count as usize) < MAX_DNS_RESULTS {
                result.ips[result.ip_count as usize] = ip;
                result.ip_count += 1;
            }
            if ttl < result.ttl {
                result.ttl = ttl;
            }
        }
        // Skip CNAME and other record types in the answer section;
        // the recursive DNS server should already resolve CNAMEs for us.

        offset += rdlength as usize;
        a += 1;
    }

    if result.ip_count == 0 {
        return None;
    }

    // Clamp TTL to reasonable range
    if result.ttl == u32::MAX {
        result.ttl = 300; // default 5 minutes
    }

    Some(Ok(result))
}

/// Parse a DNS PTR response and extract the hostname.
///
/// Returns a 3-way outcome:
/// - `None` — TXN mismatch or malformed packet (transient, keep polling)
/// - `Some(Ok(len))` — `out[..len]` contains the PTR hostname
/// - `Some(Err(rcode))` — definitive DNS error (stop retrying)
fn parse_ptr_response(
    data: &[u8],
    expected_txn_id: u16,
    out: &mut [u8; 256],
) -> Option<Result<usize, u8>> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }

    let txn_id = ((data[0] as u16) << 8) | (data[1] as u16);
    if txn_id != expected_txn_id {
        return None;
    }

    let flags = ((data[2] as u16) << 8) | (data[3] as u16);
    if flags & DNS_FLAG_QR == 0 {
        return None;
    }

    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return Some(Err(rcode));
    }

    let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
    let ancount = ((data[6] as u16) << 8) | (data[7] as u16);

    // Skip question section
    let mut offset = DNS_HEADER_LEN;
    let mut q = 0u16;
    while q < qdcount {
        let mut name_buf = [0u8; 256];
        let (_, consumed) = decode_name(data, offset, &mut name_buf);
        if consumed == 0 {
            return None;
        }
        offset += consumed + 4;
        if offset > data.len() {
            return None;
        }
        q += 1;
    }

    // Parse answer records looking for PTR
    let mut a = 0u16;
    while a < ancount {
        if offset >= data.len() {
            break;
        }

        let mut name_buf = [0u8; 256];
        let (_, consumed) = decode_name(data, offset, &mut name_buf);
        if consumed == 0 {
            break;
        }
        offset += consumed;

        if offset + 10 > data.len() {
            break;
        }

        let rtype = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let rdlength = ((data[offset + 8] as u16) << 8) | (data[offset + 9] as u16);
        offset += 10;

        if offset + rdlength as usize > data.len() {
            break;
        }

        if rtype == DNS_TYPE_PTR {
            // Decode the PTR target hostname
            let (name_len, _) = decode_name(data, offset, out);
            if name_len > 0 {
                return Some(Ok(name_len));
            }
        }

        offset += rdlength as usize;
        a += 1;
    }

    None
}

/// Map a raw DNS RCODE to a `DnsError`.
fn rcode_to_error(rcode: u8) -> DnsError {
    match rcode {
        3 => DnsError::NxDomain,
        2 => DnsError::ServerFail,
        _ => DnsError::Other,
    }
}

/// Synchronous DNS A-record resolution. Sends a query and waits for response.
///
/// Called from netsrv's IPC dispatch when handling NET_DNS_RESOLVE.
/// Blocks the netsrv event loop for up to ~9 seconds (3 attempts x 3s timeout).
pub(crate) fn dns_resolve_sync(hostname: &[u8]) -> Result<DnsResult, DnsError> {
    // SAFETY: Single-threaded server; DNS_SOCKET_ID set during init.
    let socket_id = unsafe { *(&raw const DNS_SOCKET_ID) };
    if socket_id < 0 {
        return Err(DnsError::Other);
    }

    let mut attempt = 0usize;
    while attempt <= DNS_MAX_RETRIES {
        let txn_id = generate_txn_id();

        // Build query
        let mut query_buf = [0u8; DNS_MAX_QUERY_LEN];
        let query_len = build_query(hostname, txn_id, &mut query_buf);
        if query_len == 0 {
            return Err(DnsError::Other);
        }

        // Ensure ARP entry exists for the DNS server (via gateway)
        let our_mac = crate::mac_addr();
        super::ensure_arp(&our_mac, super::ipv4::OUR_IP, DNS_SERVER_IP);

        // Send query via internal UDP socket
        super::udp::udp_sendto(socket_id as u32, &query_buf[..query_len], DNS_SERVER_IP, DNS_PORT);

        // Poll for response with timeout
        let start_ns = clock_monotonic_ns();
        let deadline_ns = start_ns + DNS_TIMEOUT_NS;

        loop {
            let now_ns = clock_monotonic_ns();
            if now_ns >= deadline_ns {
                break; // timeout, try next attempt
            }

            // Process any pending packets from SHM (drives UDP rx buffering)
            crate::process_rx_from_shm();

            // Check if our DNS socket received a response
            let mut resp_buf = [0u8; DNS_MAX_RESPONSE_LEN];
            let (len, src_ip, src_port) =
                super::udp::udp_recvfrom(socket_id as u32, &mut resp_buf);
            if len > 0 && src_ip == DNS_SERVER_IP && src_port == DNS_PORT {
                match parse_response(&resp_buf[..len as usize], txn_id) {
                    Some(Ok(result)) => return Ok(result),
                    Some(Err(rcode)) => return Err(rcode_to_error(rcode)),
                    None => {}
                }
            }

            // Yield CPU briefly to avoid busy-spinning
            salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }

        attempt += 1;
    }

    Err(DnsError::Timeout)
}

/// Synchronous DNS PTR resolution for reverse DNS.
///
/// Returns the hostname length written into `out` on success.
pub(crate) fn dns_resolve_ptr_sync(ip: u32, out: &mut [u8; 256]) -> Result<usize, DnsError> {
    // SAFETY: Single-threaded server; DNS_SOCKET_ID set during init.
    let socket_id = unsafe { *(&raw const DNS_SOCKET_ID) };
    if socket_id < 0 {
        return Err(DnsError::Other);
    }

    let mut attempt = 0usize;
    while attempt <= DNS_MAX_RETRIES {
        let txn_id = generate_txn_id();

        let mut query_buf = [0u8; DNS_MAX_QUERY_LEN];
        let query_len = build_ptr_query(ip, txn_id, &mut query_buf);
        if query_len == 0 {
            return Err(DnsError::Other);
        }

        let our_mac = crate::mac_addr();
        super::ensure_arp(&our_mac, super::ipv4::OUR_IP, DNS_SERVER_IP);
        super::udp::udp_sendto(socket_id as u32, &query_buf[..query_len], DNS_SERVER_IP, DNS_PORT);

        let start_ns = clock_monotonic_ns();
        let deadline_ns = start_ns + DNS_TIMEOUT_NS;

        loop {
            let now_ns = clock_monotonic_ns();
            if now_ns >= deadline_ns {
                break;
            }

            crate::process_rx_from_shm();

            let mut resp_buf = [0u8; DNS_MAX_RESPONSE_LEN];
            let (len, src_ip, src_port) =
                super::udp::udp_recvfrom(socket_id as u32, &mut resp_buf);
            if len > 0 && src_ip == DNS_SERVER_IP && src_port == DNS_PORT {
                match parse_ptr_response(&resp_buf[..len as usize], txn_id, out) {
                    Some(Ok(name_len)) => return Ok(name_len),
                    Some(Err(rcode)) => return Err(rcode_to_error(rcode)),
                    None => {}
                }
            }

            salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }

        attempt += 1;
    }

    Err(DnsError::Timeout)
}
