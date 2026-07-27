// SPDX-License-Identifier: GPL-2.0-only
//! DNS protocol engine for netsrv.
//!
//! Builds RFC 1035 DNS queries (A and PTR records), sends them over a dedicated
//! internal UDP socket to the runtime-configured recursive resolver, and parses
//! responses (CNAME resolution is delegated to the upstream recursive resolver).

const DNS_PORT: u16 = 53;
const MAX_DNS_RESULTS: usize = 4;
const DNS_TIMEOUT_NS: u64 = 3_000_000_000; // 3 seconds per attempt
const ARP_RETRY_NS: u64 = 200_000_000; // 200ms — short retry when waiting for ARP
const DNS_MAX_RETRIES: usize = 2; // total 3 attempts
const DNS_HARD_DEADLINE_NS: u64 = 10_000_000_000; // overall per-query budget: every saved reply target gets a terminal result within this even if a packet never reaches the wire
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
#[derive(Clone, Copy)]
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
    let id = super::socket::udp::udp_socket();
    if id < 0 {
        crate::puts(b"[netsrv] DNS: failed to allocate internal UDP socket\n");
        return;
    }
    // No explicit bind needed: leaving the UDP socket with local_port == 0
    // lets udp_sendto auto-assign an ephemeral port on first use.
    let _bind_result = super::socket::udp::udp_bind(id as u32, super::proto::ipv4::our_ip(), 0);
    // SAFETY: Single-threaded init; DNS_SOCKET_ID written once before event loop.
    unsafe {
        *(&raw mut DNS_SOCKET_ID) = id;
    }
    crate::puts(b"[netsrv] DNS: internal socket ready\n");
}

/// Get monotonic time in nanoseconds.
pub(crate) fn clock_monotonic_ns() -> u64 {
    trona_kernel::syscall::clock_read_monotonic(trona_runtime::client::caps::clock_cap().addr())
}

/// Generate a random transaction ID using the kernel RNG byte-read invocation,
/// matching the pattern used by `tcp::generate_isn()`.
fn generate_txn_id() -> u16 {
    let mut bytes = [0u8; 2];
    let r = trona_kernel::syscall::rng_read_bytes(
        trona_runtime::client::caps::kernel_rng_cap().addr(),
        bytes.as_mut_ptr(),
        bytes.len(),
    );
    let id = if r.error == 0 && r.value == bytes.len() as u64 {
        u16::from_le_bytes(bytes)
    } else {
        0
    };
    if id == 0 {
        // Fallback: clock-based ID if KernelRng is unavailable or returned zero.
        let t = clock_monotonic_ns();
        ((t >> 16) ^ t) as u16 | 1
    } else {
        id
    }
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
                if out_pos + 1 + label_len > buf.len() {
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
            if out_pos >= 256 {
                return (0, 0);
            }
            out[out_pos] = b'.';
            out_pos += 1;
        }

        // Copy label bytes
        let mut i = 0;
        while i < label_len {
            if out_pos >= 256 {
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

// ---------------------------------------------------------------------------
// Async DNS state machine
// ---------------------------------------------------------------------------

const MAX_PENDING_DNS: usize = 4;

/// Kept as a startup hook for the surrounding server; regular DNS
/// replies use the service MessagePipe endpoint saved with each
/// pending DNS request.
pub(crate) fn init_dns_reply_slots() {}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum DnsQueryType {
    A,
    Ptr,
}

struct PendingDns {
    active: bool,
    query_type: DnsQueryType,
    hostname: [u8; 120],
    hostname_len: usize,
    ptr_ip: u32,
    txn_id: u16,
    attempt: usize,
    deadline_ns: u64,
    /// Absolute wall-clock cap for the whole query. Once `now` passes this,
    /// `process_pending` fails the slot terminally regardless of per-attempt
    /// retry state — so a query that can never put a packet on the wire (e.g.
    /// ARP to the resolver never resolves) still completes instead of looping
    /// on the short ARP retry forever.
    hard_deadline_ns: u64,
    reply_target: trona_server::MpReplyTarget,
}

impl PendingDns {
    const fn zeroed() -> Self {
        PendingDns {
            active: false,
            query_type: DnsQueryType::A,
            hostname: [0u8; 120],
            hostname_len: 0,
            ptr_ip: 0,
            txn_id: 0,
            attempt: 0,
            deadline_ns: 0,
            hard_deadline_ns: 0,
            reply_target: trona_server::MpReplyTarget::none(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DnsCompletion {
    pub(crate) reply_target: trona_server::MpReplyTarget,
    pub(crate) query_type: DnsQueryType,
    pub(crate) success: bool,
    pub(crate) dns_result: DnsResult,
    pub(crate) error: DnsError,
    pub(crate) ptr_hostname: [u8; 256],
    pub(crate) ptr_hostname_len: usize,
}

impl DnsCompletion {
    const fn zeroed() -> Self {
        DnsCompletion {
            reply_target: trona_server::MpReplyTarget::none(),
            query_type: DnsQueryType::A,
            success: false,
            dns_result: DnsResult {
                ip_count: 0,
                ips: [0; MAX_DNS_RESULTS],
                ttl: 0,
            },
            error: DnsError::Other,
            ptr_hostname: [0u8; 256],
            ptr_hostname_len: 0,
        }
    }
}

fn current_reply_target(reply_mp: u64) -> trona_server::MpReplyTarget {
    unsafe {
        let ctx = trona_runtime::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            trona_server::MpReplyTarget::none()
        } else {
            trona_server::MpReplyTarget::from_ipc_buffer((*ctx).ipc_buffer as *const _, reply_mp)
        }
    }
}

static mut PENDING: [PendingDns; MAX_PENDING_DNS] = {
    const ZERO: PendingDns = PendingDns::zeroed();
    [ZERO, ZERO, ZERO, ZERO]
};

static mut COMPLETION_QUEUE: [DnsCompletion; MAX_PENDING_DNS] = {
    const ZERO: DnsCompletion = DnsCompletion::zeroed();
    [ZERO, ZERO, ZERO, ZERO]
};

static mut COMPLETION_COUNT: usize = 0;

fn find_free_slot() -> Option<usize> {
    // SAFETY: Single-threaded server.
    unsafe {
        let pending = &raw const PENDING;
        let mut i = 0;
        while i < MAX_PENDING_DNS {
            if !(*pending)[i].active {
                return Some(i);
            }
            i += 1;
        }
    }
    None
}

fn push_completion(c: DnsCompletion) {
    // SAFETY: Single-threaded server.
    unsafe {
        let count = *(&raw const COMPLETION_COUNT);
        if count >= MAX_PENDING_DNS {
            crate::puts(b"[netsrv] DNS: completion queue full, dropping result\n");
            return;
        }
        (*(&raw mut COMPLETION_QUEUE))[count] = c;
        *(&raw mut COMPLETION_COUNT) = count + 1;
    }
}

/// Outcome of attempting to put a DNS query on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// UDP datagram handed to the stack.
    Sent,
    /// Next-hop ARP entry missing — a request was issued; retry shortly.
    ArpBlocked,
    /// No resolver address configured (DHCP never provided one).
    NoUpstream,
}

/// Attempt to put the slot's DNS query on the wire, reporting whether it was
/// sent, is waiting on ARP, or has no resolver to send to.
fn send_query_for_slot(slot: &PendingDns) -> SendOutcome {
    // SAFETY: Single-threaded server; DNS_SOCKET_ID set during init.
    let socket_id = unsafe { *(&raw const DNS_SOCKET_ID) };
    if socket_id < 0 {
        return SendOutcome::NoUpstream;
    }

    let mut query_buf = [0u8; DNS_MAX_QUERY_LEN];
    let query_len = match slot.query_type {
        DnsQueryType::A => build_query(
            &slot.hostname[..slot.hostname_len],
            slot.txn_id,
            &mut query_buf,
        ),
        DnsQueryType::Ptr => build_ptr_query(slot.ptr_ip, slot.txn_id, &mut query_buf),
    };
    if query_len == 0 {
        // Caller already validated the query; nothing to encode here. Treat as
        // "on the wire" so the normal per-attempt timeout governs the slot.
        return SendOutcome::Sent;
    }
    let dns_server = super::config::dns_server();
    if dns_server == 0 {
        return SendOutcome::NoUpstream;
    }
    let next_hop = super::proto::ipv4::route(dns_server);
    if super::proto::arp::lookup(next_hop).is_none() {
        // ARP entry missing — issue the request; the caller uses a short retry
        // deadline instead of the full DNS_TIMEOUT_NS.
        let our_mac = crate::mac_addr();
        super::proto::arp::request(&our_mac, super::proto::ipv4::our_ip(), next_hop);
        return SendOutcome::ArpBlocked;
    }
    super::socket::udp::udp_sendto(
        socket_id as u32,
        &query_buf[..query_len],
        dns_server,
        DNS_PORT,
    );
    SendOutcome::Sent
}

/// Begin an async A-record resolution. Saves the caller's reply target and
/// sends the first DNS query. Returns the reply target on success, or
/// None if the hostname is invalid or all pending slots are busy.
pub(crate) fn start_resolve(hostname: &[u8]) -> Option<trona_server::MpReplyTarget> {
    let socket_id = unsafe { *(&raw const DNS_SOCKET_ID) };
    if socket_id < 0 {
        return None;
    }

    // Validate: build the query to catch encoding errors early
    let txn_id = generate_txn_id();
    let mut query_buf = [0u8; DNS_MAX_QUERY_LEN];
    let query_len = build_query(hostname, txn_id, &mut query_buf);
    if query_len == 0 {
        return None;
    }

    let slot_idx = find_free_slot()?;
    let reply_target = current_reply_target(trona_runtime::client::caps::service_recv_ep().addr());
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[netsrv] DNS start A slot=");
        _lb.dec(slot_idx as u64);
        _lb.str(b" host_len=");
        _lb.dec(hostname.len() as u64);
        _lb.str(b" txn=");
        _lb.hex(txn_id as u64);
        _lb.putc(b'\n');
    });

    let now = clock_monotonic_ns();

    // SAFETY: Single-threaded server.
    unsafe {
        let slot = &mut (*(&raw mut PENDING))[slot_idx];
        slot.active = true;
        slot.query_type = DnsQueryType::A;
        slot.hostname_len = hostname.len();
        let mut i = 0;
        while i < hostname.len() {
            slot.hostname[i] = hostname[i];
            i += 1;
        }
        slot.ptr_ip = 0;
        slot.txn_id = txn_id;
        slot.attempt = 0;
        slot.reply_target = reply_target;

        // Send the first query; use a short deadline if blocked on ARP. The
        // hard deadline caps the whole query so it always terminates.
        let outcome = send_query_for_slot(slot);
        slot.deadline_ns = now
            + if outcome == SendOutcome::Sent {
                DNS_TIMEOUT_NS
            } else {
                ARP_RETRY_NS
            };
        slot.hard_deadline_ns = now + DNS_HARD_DEADLINE_NS;
    }

    Some(reply_target)
}

/// Begin an async PTR resolution. Saves the caller's reply target and
/// sends the first DNS PTR query. Returns the reply target on success,
/// or None if all pending slots are busy.
pub(crate) fn start_resolve_ptr(ip: u32) -> Option<trona_server::MpReplyTarget> {
    let socket_id = unsafe { *(&raw const DNS_SOCKET_ID) };
    if socket_id < 0 {
        return None;
    }

    let txn_id = generate_txn_id();
    let mut query_buf = [0u8; DNS_MAX_QUERY_LEN];
    let query_len = build_ptr_query(ip, txn_id, &mut query_buf);
    if query_len == 0 {
        return None;
    }

    let slot_idx = find_free_slot()?;
    let reply_target = current_reply_target(trona_runtime::client::caps::service_recv_ep().addr());

    let now = clock_monotonic_ns();

    // SAFETY: Single-threaded server.
    unsafe {
        let slot = &mut (*(&raw mut PENDING))[slot_idx];
        slot.active = true;
        slot.query_type = DnsQueryType::Ptr;
        slot.hostname_len = 0;
        slot.hostname = [0u8; 120];
        slot.ptr_ip = ip;
        slot.txn_id = txn_id;
        slot.attempt = 0;
        slot.reply_target = reply_target;

        let outcome = send_query_for_slot(slot);
        slot.deadline_ns = now
            + if outcome == SendOutcome::Sent {
                DNS_TIMEOUT_NS
            } else {
                ARP_RETRY_NS
            };
        slot.hard_deadline_ns = now + DNS_HARD_DEADLINE_NS;
    }

    Some(reply_target)
}

/// Called when the ARP cache is updated. Immediately sends any pending
/// DNS queries that were blocked waiting for ARP resolution.
pub(crate) fn flush_arp_waiters() {
    // SAFETY: Single-threaded server.
    unsafe {
        let pending = &raw mut PENDING;
        let now = clock_monotonic_ns();
        let mut i = 0;
        while i < MAX_PENDING_DNS {
            if (*pending)[i].active {
                if send_query_for_slot(&(*pending)[i]) == SendOutcome::Sent {
                    // Query went out — set a real DNS timeout from now
                    (*pending)[i].deadline_ns = now + DNS_TIMEOUT_NS;
                }
            }
            i += 1;
        }
    }
}

/// Process pending DNS queries: drain the DNS UDP socket for responses,
/// match them against pending requests, and handle retries/timeouts.
///
/// Must be called from the event loop on each notification wakeup.
pub(crate) fn process_pending() {
    let socket_id = unsafe { *(&raw const DNS_SOCKET_ID) };
    if socket_id < 0 {
        return;
    }

    // 1. Drain DNS socket for responses
    loop {
        let mut resp_buf = [0u8; DNS_MAX_RESPONSE_LEN];
        let (len, src_ip, src_port, _) =
            super::socket::udp::udp_recvfrom(socket_id as u32, &mut resp_buf, false);
        if len <= 0 {
            break;
        }
        if src_ip != super::config::dns_server() || src_port != DNS_PORT {
            continue;
        }
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[netsrv] DNS recv len=");
            _lb.dec(len as u64);
            _lb.str(b" src=0x");
            _lb.hex(src_ip as u64);
            _lb.str(b" port=");
            _lb.dec(src_port as u64);
            _lb.putc(b'\n');
        });

        // Try to match against pending requests
        // SAFETY: Single-threaded server.
        unsafe {
            let pending = &raw mut PENDING;
            let mut i = 0;
            while i < MAX_PENDING_DNS {
                if !(*pending)[i].active {
                    i += 1;
                    continue;
                }

                let txn_id = (*pending)[i].txn_id;
                let matched = match (*pending)[i].query_type {
                    DnsQueryType::A => match parse_response(&resp_buf[..len as usize], txn_id) {
                        Some(Ok(result)) => {
                            trona_runtime::udebug!(|_lb| {
                                _lb.str(b"[netsrv] DNS match A slot=");
                                _lb.dec(i as u64);
                                _lb.str(b" txn=");
                                _lb.hex(txn_id as u64);
                                _lb.str(b" count=");
                                _lb.dec(result.ip_count as u64);
                                _lb.putc(b'\n');
                            });
                            push_completion(DnsCompletion {
                                reply_target: (*pending)[i].reply_target,
                                query_type: DnsQueryType::A,
                                success: true,
                                dns_result: result,
                                error: DnsError::Other,
                                ptr_hostname: [0; 256],
                                ptr_hostname_len: 0,
                            });
                            true
                        }
                        Some(Err(rcode)) => {
                            trona_runtime::udebug!(|_lb| {
                                _lb.str(b"[netsrv] DNS error A slot=");
                                _lb.dec(i as u64);
                                _lb.str(b" txn=");
                                _lb.hex(txn_id as u64);
                                _lb.str(b" rcode=");
                                _lb.dec(rcode as u64);
                                _lb.putc(b'\n');
                            });
                            push_completion(DnsCompletion {
                                reply_target: (*pending)[i].reply_target,
                                query_type: DnsQueryType::A,
                                success: false,
                                dns_result: DnsResult {
                                    ip_count: 0,
                                    ips: [0; MAX_DNS_RESULTS],
                                    ttl: 0,
                                },
                                error: rcode_to_error(rcode),
                                ptr_hostname: [0; 256],
                                ptr_hostname_len: 0,
                            });
                            true
                        }
                        None => false,
                    },
                    DnsQueryType::Ptr => {
                        let mut ptr_hostname = [0u8; 256];
                        match parse_ptr_response(
                            &resp_buf[..len as usize],
                            txn_id,
                            &mut ptr_hostname,
                        ) {
                            Some(Ok(name_len)) => {
                                push_completion(DnsCompletion {
                                    reply_target: (*pending)[i].reply_target,
                                    query_type: DnsQueryType::Ptr,
                                    success: true,
                                    dns_result: DnsResult {
                                        ip_count: 0,
                                        ips: [0; MAX_DNS_RESULTS],
                                        ttl: 0,
                                    },
                                    error: DnsError::Other,
                                    ptr_hostname,
                                    ptr_hostname_len: name_len,
                                });
                                true
                            }
                            Some(Err(rcode)) => {
                                push_completion(DnsCompletion {
                                    reply_target: (*pending)[i].reply_target,
                                    query_type: DnsQueryType::Ptr,
                                    success: false,
                                    dns_result: DnsResult {
                                        ip_count: 0,
                                        ips: [0; MAX_DNS_RESULTS],
                                        ttl: 0,
                                    },
                                    error: rcode_to_error(rcode),
                                    ptr_hostname: [0; 256],
                                    ptr_hostname_len: 0,
                                });
                                true
                            }
                            None => false,
                        }
                    }
                };

                if matched {
                    (*pending)[i].active = false;
                    break; // This response matched, move to next packet
                }
                i += 1;
            }
        }
    }

    // 2. Check deadlines for remaining active slots
    let now = clock_monotonic_ns();
    // SAFETY: Single-threaded server.
    unsafe {
        let pending = &raw mut PENDING;
        let mut i = 0;
        while i < MAX_PENDING_DNS {
            // Act when the per-attempt deadline OR the overall hard deadline
            // is due. The hard-deadline arm matters because `flush_arp_waiters`
            // can push `deadline_ns` forward on unrelated ARP-learn events; the
            // independent `hard_deadline_ns` check guarantees the slot still
            // terminates (`retry` below is false once it passes → failure).
            if (*pending)[i].active
                && (now >= (*pending)[i].deadline_ns || now >= (*pending)[i].hard_deadline_ns)
            {
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[netsrv] DNS deadline slot=");
                    _lb.dec(i as u64);
                    _lb.str(b" attempt=");
                    _lb.dec((*pending)[i].attempt as u64);
                    _lb.str(b" type=");
                    _lb.dec((*pending)[i].query_type as u64);
                    _lb.putc(b'\n');
                });
                // Retry only while the overall budget holds AND attempts
                // remain. A blocked-on-ARP attempt does not burn an attempt
                // count (transient ARP delay must not eat the retry budget),
                // but the hard deadline still caps it — so a query that can
                // never reach the wire terminates instead of looping on the
                // short ARP retry forever. Retransmits reuse the same txn_id
                // so a slightly-late earlier response still matches.
                let retry =
                    now < (*pending)[i].hard_deadline_ns && (*pending)[i].attempt < DNS_MAX_RETRIES;
                let outcome = if retry {
                    Some(send_query_for_slot(&(*pending)[i]))
                } else {
                    None
                };
                match outcome {
                    Some(SendOutcome::Sent) => {
                        // Query actually went out — count as a real attempt.
                        (*pending)[i].attempt += 1;
                        (*pending)[i].deadline_ns = now + DNS_TIMEOUT_NS;
                    }
                    Some(SendOutcome::ArpBlocked) => {
                        // Waiting on ARP — short retry, don't burn an attempt.
                        (*pending)[i].deadline_ns = now + ARP_RETRY_NS;
                    }
                    // No resolver (mid-flight), overall budget exhausted, or
                    // retries used up: hand the saved reply target a terminal
                    // failure so the caller never blocks indefinitely.
                    Some(SendOutcome::NoUpstream) | None => {
                        push_completion(DnsCompletion {
                            reply_target: (*pending)[i].reply_target,
                            query_type: (*pending)[i].query_type,
                            success: false,
                            dns_result: DnsResult {
                                ip_count: 0,
                                ips: [0; MAX_DNS_RESULTS],
                                ttl: 0,
                            },
                            error: DnsError::Timeout,
                            ptr_hostname: [0; 256],
                            ptr_hostname_len: 0,
                        });
                        (*pending)[i].active = false;
                    }
                }
            }
            i += 1;
        }
    }
}

/// Returns true if any DNS queries are in flight.
pub(crate) fn has_pending() -> bool {
    // SAFETY: Single-threaded server.
    unsafe {
        let pending = &raw const PENDING;
        let mut i = 0;
        while i < MAX_PENDING_DNS {
            if (*pending)[i].active {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// Returns the nearest deadline among all active pending DNS queries.
/// Used by the event loop to calculate recv_timed timeout.
pub(crate) fn nearest_deadline_ns() -> u64 {
    let mut nearest = u64::MAX;
    // SAFETY: Single-threaded server.
    unsafe {
        let pending = &raw const PENDING;
        let mut i = 0;
        while i < MAX_PENDING_DNS {
            if (*pending)[i].active {
                // Wake for whichever fires first — the per-attempt retry or
                // the overall hard cap — so the hard deadline is honored even
                // when `deadline_ns` was pushed forward.
                let slot_due =
                    core::cmp::min((*pending)[i].deadline_ns, (*pending)[i].hard_deadline_ns);
                if slot_due < nearest {
                    nearest = slot_due;
                }
            }
            i += 1;
        }
    }
    nearest
}

/// Pop a completed DNS query from the completion queue.
pub(crate) fn pop_completion() -> Option<DnsCompletion> {
    // SAFETY: Single-threaded server.
    unsafe {
        let count = *(&raw const COMPLETION_COUNT);
        if count == 0 {
            return None;
        }
        *(&raw mut COMPLETION_COUNT) = count - 1;
        Some((*(&raw const COMPLETION_QUEUE))[count - 1])
    }
}
