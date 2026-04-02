// SPDX-License-Identifier: GPL-2.0-only
//! Minimal IPv4 DHCP client used during netsrv bootstrap.

use crate::net::config;
use crate::net::socket::udp;
use trona::consts::posix::{SO_BROADCAST, SOL_SOCKET};
use trona_posix::consts::*;

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_MAGIC_COOKIE: u32 = 0x6382_5363;
const DHCP_BOOTREQUEST: u8 = 1;
const DHCP_BOOTREPLY: u8 = 2;
const DHCP_HTYPE_ETHERNET: u8 = 1;
const DHCP_HLEN_ETHERNET: u8 = 6;
const DHCP_FLAGS_BROADCAST: u16 = 0x8000;

const DHCP_OPTION_SUBNET_MASK: u8 = 1;
const DHCP_OPTION_ROUTER: u8 = 3;
const DHCP_OPTION_DNS_SERVER: u8 = 6;
const DHCP_OPTION_LEASE_TIME: u8 = 51;
const DHCP_OPTION_MAX_MESSAGE_SIZE: u8 = 57;
const DHCP_OPTION_REQUESTED_IP: u8 = 50;
const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
const DHCP_OPTION_SERVER_IDENTIFIER: u8 = 54;
const DHCP_OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
const DHCP_OPTION_RENEWAL_TIME: u8 = 58;
const DHCP_OPTION_REBINDING_TIME: u8 = 59;
const DHCP_OPTION_CLIENT_IDENTIFIER: u8 = 61;
const DHCP_OPTION_END: u8 = 255;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;

const DHCP_RETRY_NS: u64 = 1_000_000_000;
const DHCP_MAX_RETRIES: u8 = 3;
const DHCP_MSG_LEN: usize = 576;
const DHCP_MAX_MESSAGE_SIZE: u16 = 576;
const DHCP_RX_LEN: usize = 1536;
const DHCP_DEFAULT_SUBNET_MASK: u32 = 0xFFFF_FF00;

#[derive(Clone, Copy)]
enum DhcpState {
    Disabled,
    Discovering,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Failed,
}

#[derive(Clone, Copy)]
struct Offer {
    yiaddr: u32,
    subnet_mask: u32,
    router: u32,
    dns_server: u32,
    server_id: u32,
    lease_time_s: u32,
    renew_time_s: u32,
    rebind_time_s: u32,
}

impl Offer {
    const fn zeroed() -> Self {
        Self {
            yiaddr: 0,
            subnet_mask: 0,
            router: 0,
            dns_server: 0,
            server_id: 0,
            lease_time_s: 0,
            renew_time_s: 0,
            rebind_time_s: 0,
        }
    }
}

static mut DHCP_STATE: DhcpState = DhcpState::Disabled;
static mut DHCP_SOCKET_ID: i32 = -1;
static mut DHCP_XID: u32 = 0;
static mut DHCP_LAST_TX_NS: u64 = 0;
static mut DHCP_RETRIES: u8 = 0;
static mut DHCP_OFFER: Offer = Offer::zeroed();
static mut DHCP_LEASE_EXPIRES_NS: u64 = 0;
static mut DHCP_RENEW_AT_NS: u64 = 0;
static mut DHCP_REBIND_AT_NS: u64 = 0;
static mut LOGGED_DHCP_DISCOVER_BYTES: bool = false;

fn log_ipv4(lb: &mut trona::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

fn log_dhcp_send(prefix: &[u8], dst_ip: u32, socket_id: i32) {
    trona::udebug!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" sock=");
        _lb.dec(socket_id as u64);
        _lb.str(b" xid=");
        _lb.hex(unsafe { *(&raw const DHCP_XID) } as u64);
        _lb.str(b" dst=");
        log_ipv4(&mut _lb, dst_ip);
        _lb.str(b" retries=");
        _lb.dec(unsafe { *(&raw const DHCP_RETRIES) } as u64);
        _lb.putc(b'\n');
    });
}

fn log_dhcp_recv(prefix: &[u8], src_ip: u32, src_port: u16, len: i32) {
    trona::udebug!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" src=");
        log_ipv4(&mut _lb, src_ip);
        _lb.putc(b':');
        _lb.dec(src_port as u64);
        _lb.str(b" len=");
        _lb.dec(len as u64);
        _lb.putc(b'\n');
    });
}

fn log_dhcp_packet_bytes(prefix: &[u8], buf: &[u8]) {
    let dump_len = core::cmp::min(buf.len(), 96);
    trona::udebug!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" bytes=");
        let mut i = 0;
        while i < dump_len {
            if i > 0 {
                _lb.putc(b' ');
            }
            let b = buf[i];
            if b < 0x10 {
                _lb.putc(b'0');
            }
            _lb.hex(b as u64);
            i += 1;
        }
        if dump_len < buf.len() {
            _lb.str(b" ...");
        }
        _lb.putc(b'\n');
    });
}

fn now_ns() -> u64 {
    crate::net::dns::clock_monotonic_ns()
}

fn next_xid() -> u32 {
    let mut bytes = [0u8; 4];
    // SAFETY: Passing a valid stack buffer to the syscall.
    let r = unsafe {
        trona::syscall::syscall(
            trona::consts::SYS_GETRANDOM,
            bytes.as_mut_ptr() as u64,
            4,
            0,
            0,
            0,
            0,
        )
    };
    let xid = u32::from_ne_bytes(bytes);
    if r.error != 0 || xid == 0 {
        ((now_ns() >> 8) ^ now_ns()) as u32 | 1
    } else {
        xid
    }
}

fn write_u32_be(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = (val >> 24) as u8;
    buf[off + 1] = (val >> 16) as u8;
    buf[off + 2] = (val >> 8) as u8;
    buf[off + 3] = val as u8;
}

fn read_u32_be(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | (buf[off + 3] as u32)
}

fn append_option(buf: &mut [u8], pos: &mut usize, code: u8, value: &[u8]) -> bool {
    if *pos + 2 + value.len() > buf.len() {
        return false;
    }
    buf[*pos] = code;
    buf[*pos + 1] = value.len() as u8;
    let start = *pos + 2;
    let end = start + value.len();
    buf[start..end].copy_from_slice(value);
    *pos = end;
    true
}

fn build_common(msg_type: u8, ciaddr: u32, broadcast: bool, buf: &mut [u8; DHCP_MSG_LEN]) -> usize {
    buf.fill(0);
    buf[0] = DHCP_BOOTREQUEST;
    buf[1] = DHCP_HTYPE_ETHERNET;
    buf[2] = DHCP_HLEN_ETHERNET;
    write_u32_be(buf, 4, unsafe { *(&raw const DHCP_XID) });
    // Some DHCP servers are stricter than QEMU user-net and expect a
    // BOOTP-style request with a non-zero elapsed-seconds field.
    let secs = unsafe { core::cmp::max(*(&raw const DHCP_RETRIES) as u16, 1) };
    buf[8] = (secs >> 8) as u8;
    buf[9] = secs as u8;
    if broadcast {
        buf[10] = (DHCP_FLAGS_BROADCAST >> 8) as u8;
        buf[11] = DHCP_FLAGS_BROADCAST as u8;
    }
    write_u32_be(buf, 12, ciaddr);

    let mac = config::mac_addr();
    buf[28..34].copy_from_slice(&mac);
    write_u32_be(buf, 236, DHCP_MAGIC_COOKIE);

    let mut pos = 240usize;
    let _ = append_option(buf, &mut pos, DHCP_OPTION_MESSAGE_TYPE, &[msg_type]);
    let mut client_id = [0u8; 7];
    client_id[0] = DHCP_HTYPE_ETHERNET;
    client_id[1..].copy_from_slice(&mac);
    let _ = append_option(
        buf,
        &mut pos,
        DHCP_OPTION_CLIENT_IDENTIFIER,
        &client_id,
    );
    let max_message_size = DHCP_MAX_MESSAGE_SIZE.to_be_bytes();
    let _ = append_option(
        buf,
        &mut pos,
        DHCP_OPTION_MAX_MESSAGE_SIZE,
        &max_message_size,
    );
    pos
}

fn build_discover(buf: &mut [u8; DHCP_MSG_LEN]) -> usize {
    let mut pos = build_common(DHCPDISCOVER, 0, true, buf);
    let params = [
        DHCP_OPTION_SUBNET_MASK,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS_SERVER,
        DHCP_OPTION_LEASE_TIME,
        DHCP_OPTION_RENEWAL_TIME,
        DHCP_OPTION_REBINDING_TIME,
    ];
    let _ = append_option(buf, &mut pos, DHCP_OPTION_PARAMETER_REQUEST_LIST, &params);
    if pos < buf.len() {
        buf[pos] = DHCP_OPTION_END;
        pos += 1;
    }
    pos
}

fn build_request(
    buf: &mut [u8; DHCP_MSG_LEN],
    requested_ip: Option<u32>,
    server_id: Option<u32>,
    ciaddr: u32,
    broadcast: bool,
) -> usize {
    let mut pos = build_common(DHCPREQUEST, ciaddr, broadcast, buf);
    let params = [
        DHCP_OPTION_SUBNET_MASK,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS_SERVER,
        DHCP_OPTION_LEASE_TIME,
        DHCP_OPTION_RENEWAL_TIME,
        DHCP_OPTION_REBINDING_TIME,
    ];
    if let Some(ip) = requested_ip {
        let req_ip = ip.to_be_bytes();
        let _ = append_option(buf, &mut pos, DHCP_OPTION_REQUESTED_IP, &req_ip);
    }
    if let Some(ip) = server_id {
        let server_id = ip.to_be_bytes();
        let _ = append_option(buf, &mut pos, DHCP_OPTION_SERVER_IDENTIFIER, &server_id);
    }
    let _ = append_option(buf, &mut pos, DHCP_OPTION_PARAMETER_REQUEST_LIST, &params);
    if pos < buf.len() {
        buf[pos] = DHCP_OPTION_END;
        pos += 1;
    }
    pos
}

fn send_discover() -> bool {
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id < 0 {
        return false;
    }

    let mut buf = [0u8; DHCP_MSG_LEN];
    let _len = build_discover(&mut buf);
    log_dhcp_send(b"[netsrv] DHCP send discover", 0xFFFF_FFFF, socket_id);
    unsafe {
        if !*(&raw const LOGGED_DHCP_DISCOVER_BYTES) {
            *(&raw mut LOGGED_DHCP_DISCOVER_BYTES) = true;
            log_dhcp_packet_bytes(b"[netsrv] DHCP discover", &buf[..DHCP_MSG_LEN]);
        }
    }
    let sent = udp::udp_sendto(
        socket_id as u32,
        &buf[..DHCP_MSG_LEN],
        0xFFFF_FFFF,
        DHCP_SERVER_PORT,
    );
    if sent >= 0 {
        // SAFETY: Single-threaded bootstrap.
        unsafe {
            *(&raw mut DHCP_LAST_TX_NS) = now_ns();
            *(&raw mut DHCP_RETRIES) = (*(&raw const DHCP_RETRIES)).saturating_add(1);
        }
        true
    } else {
        false
    }
}

fn send_request(offer: Offer) -> bool {
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id < 0 {
        return false;
    }

    let mut buf = [0u8; DHCP_MSG_LEN];
    let _len = build_request(&mut buf, Some(offer.yiaddr), Some(offer.server_id), 0, true);
    log_dhcp_send(b"[netsrv] DHCP send request", 0xFFFF_FFFF, socket_id);
    let sent = udp::udp_sendto(
        socket_id as u32,
        &buf[..DHCP_MSG_LEN],
        0xFFFF_FFFF,
        DHCP_SERVER_PORT,
    );
    if sent >= 0 {
        // SAFETY: Single-threaded bootstrap.
        unsafe {
            *(&raw mut DHCP_LAST_TX_NS) = now_ns();
            *(&raw mut DHCP_RETRIES) = (*(&raw const DHCP_RETRIES)).saturating_add(1);
        }
        true
    } else {
        false
    }
}

fn send_renew_request(offer: Offer) -> bool {
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id < 0 {
        return false;
    }

    let current_ip = config::our_ip();
    if current_ip == 0 {
        return false;
    }

    let dst_ip = if offer.server_id != 0 {
        offer.server_id
    } else {
        0xFFFF_FFFF
    };
    let mut buf = [0u8; DHCP_MSG_LEN];
    let _len = build_request(
        &mut buf,
        None,
        None,
        current_ip,
        dst_ip == 0xFFFF_FFFF,
    );
    log_dhcp_send(b"[netsrv] DHCP send renew", dst_ip, socket_id);
    let sent = udp::udp_sendto(socket_id as u32, &buf[..DHCP_MSG_LEN], dst_ip, DHCP_SERVER_PORT);
    if sent >= 0 {
        unsafe {
            *(&raw mut DHCP_LAST_TX_NS) = now_ns();
        }
        true
    } else {
        false
    }
}

fn send_rebind_request() -> bool {
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id < 0 {
        return false;
    }

    let current_ip = config::our_ip();
    if current_ip == 0 {
        return false;
    }

    let mut buf = [0u8; DHCP_MSG_LEN];
    let _len = build_request(&mut buf, None, None, current_ip, true);
    log_dhcp_send(b"[netsrv] DHCP send rebind", 0xFFFF_FFFF, socket_id);
    let sent = udp::udp_sendto(
        socket_id as u32,
        &buf[..DHCP_MSG_LEN],
        0xFFFF_FFFF,
        DHCP_SERVER_PORT,
    );
    if sent >= 0 {
        unsafe {
            *(&raw mut DHCP_LAST_TX_NS) = now_ns();
        }
        true
    } else {
        false
    }
}

fn parse_offer(buf: &[u8]) -> Option<(u8, Offer)> {
    if buf.len() < 240 {
        return None;
    }
    if buf[0] != DHCP_BOOTREPLY || buf[1] != DHCP_HTYPE_ETHERNET || buf[2] != DHCP_HLEN_ETHERNET {
        return None;
    }
    if read_u32_be(buf, 4) != unsafe { *(&raw const DHCP_XID) } {
        return None;
    }
    if read_u32_be(buf, 236) != DHCP_MAGIC_COOKIE {
        return None;
    }

    let mac = config::mac_addr();
    if &buf[28..34] != mac.as_slice() {
        return None;
    }

    let yiaddr = read_u32_be(buf, 16);
    let mut msg_type = 0u8;
    let mut subnet_mask = 0u32;
    let mut router = 0u32;
    let mut dns_server = 0u32;
    let mut server_id = 0u32;
    let mut lease_time_s = 0u32;
    let mut renew_time_s = 0u32;
    let mut rebind_time_s = 0u32;

    let mut pos = 240usize;
    while pos < buf.len() {
        let code = buf[pos];
        pos += 1;
        if code == 0 {
            continue;
        }
        if code == DHCP_OPTION_END {
            break;
        }
        if pos >= buf.len() {
            break;
        }
        let len = buf[pos] as usize;
        pos += 1;
        if pos + len > buf.len() {
            break;
        }

        match code {
            DHCP_OPTION_MESSAGE_TYPE if len == 1 => {
                msg_type = buf[pos];
            }
            DHCP_OPTION_SUBNET_MASK if len >= 4 => {
                subnet_mask = read_u32_be(buf, pos);
            }
            DHCP_OPTION_ROUTER if len >= 4 => {
                router = read_u32_be(buf, pos);
            }
            DHCP_OPTION_DNS_SERVER if len >= 4 => {
                dns_server = read_u32_be(buf, pos);
            }
            DHCP_OPTION_LEASE_TIME if len >= 4 => {
                lease_time_s = read_u32_be(buf, pos);
            }
            DHCP_OPTION_SERVER_IDENTIFIER if len >= 4 => {
                server_id = read_u32_be(buf, pos);
            }
            DHCP_OPTION_RENEWAL_TIME if len >= 4 => {
                renew_time_s = read_u32_be(buf, pos);
            }
            DHCP_OPTION_REBINDING_TIME if len >= 4 => {
                rebind_time_s = read_u32_be(buf, pos);
            }
            _ => {}
        }
        pos += len;
    }

    Some((
        msg_type,
        Offer {
            yiaddr,
            subnet_mask,
            router,
            dns_server,
            server_id,
            lease_time_s,
            renew_time_s,
            rebind_time_s,
        },
    ))
}

fn apply_lease(offer: Offer, fallback_ip: u32) {
    let old_ip = config::our_ip();
    let our_ip = if offer.yiaddr != 0 {
        offer.yiaddr
    } else {
        fallback_ip
    };
    let subnet_mask = if offer.subnet_mask != 0 {
        offer.subnet_mask
    } else {
        DHCP_DEFAULT_SUBNET_MASK
    };
    let gateway = offer.router;
    let dns = if offer.dns_server != 0 {
        offer.dns_server
    } else {
        offer.server_id
    };

    let lease_time_s = if offer.lease_time_s != 0 {
        offer.lease_time_s
    } else {
        3600
    };
    let renew_time_s = if offer.renew_time_s != 0 {
        offer.renew_time_s
    } else {
        lease_time_s / 2
    };
    let rebind_time_s = if offer.rebind_time_s != 0 {
        offer.rebind_time_s
    } else {
        lease_time_s.saturating_mul(7) / 8
    };

    config::apply_dhcp(our_ip, subnet_mask, gateway, dns);
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id >= 0 {
        let _ = udp::udp_set_keep_zero_source_ip(socket_id as u32, false);
    }
    if our_ip != old_ip {
        crate::net::socket::udp::handle_local_ip_change(our_ip);
        crate::net::socket::tcp::handle_local_ip_change(our_ip);
    }
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] DHCP lease applied IP=");
        log_ipv4(&mut _lb, our_ip);
        _lb.str(b" GW=");
        log_ipv4(&mut _lb, gateway);
        _lb.str(b" DNS=");
        log_ipv4(&mut _lb, dns);
        _lb.putc(b'\n');
    });
    let now = now_ns();
    let lease_ns = (lease_time_s as u64).saturating_mul(1_000_000_000);
    let renew_ns = (renew_time_s as u64).saturating_mul(1_000_000_000);
    let rebind_ns = (rebind_time_s as u64).saturating_mul(1_000_000_000);

    unsafe {
        *(&raw mut DHCP_OFFER) = Offer {
            yiaddr: our_ip,
            subnet_mask,
            router: gateway,
            dns_server: dns,
            server_id: offer.server_id,
            lease_time_s,
            renew_time_s,
            rebind_time_s,
        };
        *(&raw mut DHCP_LAST_TX_NS) = 0;
        *(&raw mut DHCP_RETRIES) = 0;
        *(&raw mut DHCP_LEASE_EXPIRES_NS) = now.saturating_add(lease_ns);
        *(&raw mut DHCP_RENEW_AT_NS) = now.saturating_add(renew_ns);
        *(&raw mut DHCP_REBIND_AT_NS) = now.saturating_add(rebind_ns);
        *(&raw mut DHCP_STATE) = DhcpState::Bound;
    }
}

fn restart_discovery(clear_config: bool) -> bool {
    if clear_config {
        crate::net::socket::udp::handle_local_ip_loss();
        crate::net::socket::tcp::handle_local_ip_loss();
        config::begin_reconfigure();
    }
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id >= 0 {
        let _ = udp::udp_set_keep_zero_source_ip(socket_id as u32, true);
    }
    unsafe {
        *(&raw mut DHCP_XID) = next_xid();
        *(&raw mut DHCP_LAST_TX_NS) = 0;
        *(&raw mut DHCP_RETRIES) = 0;
        *(&raw mut DHCP_OFFER) = Offer::zeroed();
        *(&raw mut DHCP_LEASE_EXPIRES_NS) = 0;
        *(&raw mut DHCP_RENEW_AT_NS) = 0;
        *(&raw mut DHCP_REBIND_AT_NS) = 0;
        *(&raw mut DHCP_STATE) = DhcpState::Discovering;
    }
    send_discover()
}

pub(crate) fn start() -> bool {
    let mut socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id < 0 {
        socket_id = udp::udp_socket();
        if socket_id < 0 {
            trona::udebug!(|_lb| {
                _lb.str(b"[netsrv] DHCP start failed: udp_socket\n");
            });
            return false;
        }
        if udp::udp_bind(socket_id as u32, 0, DHCP_CLIENT_PORT) < 0 {
            trona::udebug!(|_lb| {
                _lb.str(b"[netsrv] DHCP start failed: udp_bind port 68\n");
            });
            let _ = udp::udp_close(socket_id as u32);
            return false;
        }
        trona::udebug!(|_lb| {
            _lb.str(b"[netsrv] DHCP socket bound to 0.0.0.0:68 sock=");
            _lb.dec(socket_id as u64);
            _lb.putc(b'\n');
        });
    }

    unsafe {
        *(&raw mut DHCP_SOCKET_ID) = socket_id;
        let _ = udp::udp_setsockopt(socket_id as u32, SOL_SOCKET, SO_BROADCAST, 1, 4);
        let _ = udp::udp_set_keep_zero_source_ip(socket_id as u32, true);
        *(&raw mut DHCP_XID) = next_xid();
        *(&raw mut DHCP_LAST_TX_NS) = 0;
        *(&raw mut DHCP_RETRIES) = 0;
        *(&raw mut DHCP_OFFER) = Offer::zeroed();
        *(&raw mut DHCP_LEASE_EXPIRES_NS) = 0;
        *(&raw mut DHCP_RENEW_AT_NS) = 0;
        *(&raw mut DHCP_REBIND_AT_NS) = 0;
        *(&raw mut DHCP_STATE) = DhcpState::Discovering;
    }

    send_discover()
}

pub(crate) fn process() {
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    if socket_id < 0 {
        return;
    }

    loop {
        let mut buf = [0u8; DHCP_RX_LEN];
        let (len, src_ip, src_port, _) = udp::udp_recvfrom(socket_id as u32, &mut buf, false);
        if len <= 0 {
            break;
        }
        log_dhcp_recv(b"[netsrv] DHCP recv datagram", src_ip, src_port, len);
        if src_port != DHCP_SERVER_PORT {
            continue;
        }

        let Some((msg_type, offer)) = parse_offer(&buf[..len as usize]) else {
            trona::udebug!(|_lb| {
                _lb.str(b"[netsrv] DHCP recv ignored: parse failed\n");
            });
            continue;
        };

        match unsafe { *(&raw const DHCP_STATE) } {
            DhcpState::Discovering if msg_type == DHCPOFFER && offer.yiaddr != 0 => {
                trona::udebug!(|_lb| {
                    _lb.str(b"[netsrv] DHCP offer yiaddr=");
                    log_ipv4(&mut _lb, offer.yiaddr);
                    _lb.putc(b'\n');
                });
                unsafe {
                    *(&raw mut DHCP_OFFER) = offer;
                    *(&raw mut DHCP_STATE) = DhcpState::Requesting;
                    *(&raw mut DHCP_RETRIES) = 0;
                }
                if !send_request(offer) {
                    unsafe { *(&raw mut DHCP_STATE) = DhcpState::Failed; }
                }
            }
            DhcpState::Requesting if msg_type == DHCPACK && offer.yiaddr != 0 => {
                trona::udebug!(|_lb| {
                    _lb.str(b"[netsrv] DHCP ack yiaddr=");
                    log_ipv4(&mut _lb, offer.yiaddr);
                    _lb.putc(b'\n');
                });
                apply_lease(offer, offer.yiaddr);
            }
            DhcpState::Renewing if msg_type == DHCPACK => {
                let fallback_ip = config::our_ip();
                if fallback_ip != 0 {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] DHCP renew ack\n");
                    });
                    apply_lease(offer, fallback_ip);
                }
            }
            DhcpState::Rebinding if msg_type == DHCPACK => {
                let fallback_ip = config::our_ip();
                if fallback_ip != 0 {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] DHCP rebind ack\n");
                    });
                    apply_lease(offer, fallback_ip);
                }
            }
            DhcpState::Requesting if msg_type == DHCPNAK => {
                unsafe {
                    *(&raw mut DHCP_STATE) = DhcpState::Failed;
                }
            }
            DhcpState::Renewing | DhcpState::Rebinding if msg_type == DHCPNAK => {
                if !restart_discovery(true) {
                    unsafe {
                        *(&raw mut DHCP_STATE) = DhcpState::Failed;
                    }
                }
            }
            _ => {}
        }
    }

    let now = now_ns();
    match unsafe { *(&raw const DHCP_STATE) } {
        DhcpState::Discovering => {
            let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
            let retries = unsafe { *(&raw const DHCP_RETRIES) };
            if last_tx != 0 && now.saturating_sub(last_tx) >= DHCP_RETRY_NS {
                if retries >= DHCP_MAX_RETRIES || !send_discover() {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] DHCP discover retries exhausted\n");
                    });
                    unsafe { *(&raw mut DHCP_STATE) = DhcpState::Failed; }
                }
            }
        }
        DhcpState::Requesting => {
            let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
            let retries = unsafe { *(&raw const DHCP_RETRIES) };
            if last_tx != 0 && now.saturating_sub(last_tx) >= DHCP_RETRY_NS {
                if retries >= DHCP_MAX_RETRIES {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] DHCP request retries exhausted\n");
                    });
                    unsafe { *(&raw mut DHCP_STATE) = DhcpState::Failed; }
                } else {
                    let offer = unsafe { *(&raw const DHCP_OFFER) };
                    if !send_request(offer) {
                        trona::udebug!(|_lb| {
                            _lb.str(b"[netsrv] DHCP request send failed\n");
                        });
                        unsafe { *(&raw mut DHCP_STATE) = DhcpState::Failed; }
                    }
                }
            }
        }
        DhcpState::Bound => {
            let renew_at = unsafe { *(&raw const DHCP_RENEW_AT_NS) };
            let lease_expires = unsafe { *(&raw const DHCP_LEASE_EXPIRES_NS) };
            if lease_expires != 0 && now >= lease_expires {
                if !restart_discovery(true) {
                    unsafe {
                        *(&raw mut DHCP_STATE) = DhcpState::Failed;
                    }
                }
            } else if renew_at != 0 && now >= renew_at {
                let offer = unsafe { *(&raw const DHCP_OFFER) };
                unsafe {
                    *(&raw mut DHCP_XID) = next_xid();
                    *(&raw mut DHCP_STATE) = DhcpState::Renewing;
                    *(&raw mut DHCP_LAST_TX_NS) = 0;
                }
                if !send_renew_request(offer) {
                    unsafe {
                        *(&raw mut DHCP_STATE) = DhcpState::Rebinding;
                        *(&raw mut DHCP_LAST_TX_NS) = 0;
                    }
                }
            }
        }
        DhcpState::Renewing => {
            let rebind_at = unsafe { *(&raw const DHCP_REBIND_AT_NS) };
            let lease_expires = unsafe { *(&raw const DHCP_LEASE_EXPIRES_NS) };
            if lease_expires != 0 && now >= lease_expires {
                if !restart_discovery(true) {
                    unsafe {
                        *(&raw mut DHCP_STATE) = DhcpState::Failed;
                    }
                }
            } else if rebind_at != 0 && now >= rebind_at {
                unsafe {
                    *(&raw mut DHCP_STATE) = DhcpState::Rebinding;
                    *(&raw mut DHCP_LAST_TX_NS) = 0;
                }
                if !send_rebind_request() {
                    unsafe {
                        *(&raw mut DHCP_LAST_TX_NS) = now;
                    }
                }
            } else {
                let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
                let offer = unsafe { *(&raw const DHCP_OFFER) };
                if last_tx == 0 || now.saturating_sub(last_tx) >= DHCP_RETRY_NS {
                    let _ = send_renew_request(offer);
                }
            }
        }
        DhcpState::Rebinding => {
            let lease_expires = unsafe { *(&raw const DHCP_LEASE_EXPIRES_NS) };
            if lease_expires != 0 && now >= lease_expires {
                if !restart_discovery(true) {
                    unsafe {
                        *(&raw mut DHCP_STATE) = DhcpState::Failed;
                    }
                }
            } else {
                let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
                if last_tx == 0 || now.saturating_sub(last_tx) >= DHCP_RETRY_NS {
                    let _ = send_rebind_request();
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn is_finished() -> bool {
    matches!(
        unsafe { *(&raw const DHCP_STATE) },
        DhcpState::Bound | DhcpState::Failed
    )
}

pub(crate) fn is_bound() -> bool {
    matches!(unsafe { *(&raw const DHCP_STATE) }, DhcpState::Bound)
}

pub(crate) fn finish() {
    let socket_id = unsafe { *(&raw const DHCP_SOCKET_ID) };
    let keep_socket = matches!(unsafe { *(&raw const DHCP_STATE) }, DhcpState::Bound);
    if socket_id >= 0 && !keep_socket {
        let _ = udp::udp_close(socket_id as u32);
    }
    unsafe {
        if !keep_socket {
            *(&raw mut DHCP_SOCKET_ID) = -1;
        }
        if !keep_socket {
            *(&raw mut DHCP_STATE) = DhcpState::Failed;
        }
    }
}

pub(crate) fn has_timer() -> bool {
    matches!(
        unsafe { *(&raw const DHCP_STATE) },
        DhcpState::Discovering
            | DhcpState::Requesting
            | DhcpState::Bound
            | DhcpState::Renewing
            | DhcpState::Rebinding
    )
}

pub(crate) fn nearest_deadline_ns() -> u64 {
    let now = now_ns();
    match unsafe { *(&raw const DHCP_STATE) } {
        DhcpState::Discovering | DhcpState::Requesting => {
            let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
            if last_tx == 0 {
                now
            } else {
                last_tx.saturating_add(DHCP_RETRY_NS)
            }
        }
        DhcpState::Bound => {
            let renew_at = unsafe { *(&raw const DHCP_RENEW_AT_NS) };
            let lease_expires = unsafe { *(&raw const DHCP_LEASE_EXPIRES_NS) };
            if renew_at != 0 {
                renew_at
            } else {
                lease_expires
            }
        }
        DhcpState::Renewing => {
            let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
            let rebind_at = unsafe { *(&raw const DHCP_REBIND_AT_NS) };
            let lease_expires = unsafe { *(&raw const DHCP_LEASE_EXPIRES_NS) };
            let retry_at = if last_tx == 0 {
                now
            } else {
                last_tx.saturating_add(DHCP_RETRY_NS)
            };
            core::cmp::min(core::cmp::min(retry_at, rebind_at), lease_expires)
        }
        DhcpState::Rebinding => {
            let last_tx = unsafe { *(&raw const DHCP_LAST_TX_NS) };
            let lease_expires = unsafe { *(&raw const DHCP_LEASE_EXPIRES_NS) };
            let retry_at = if last_tx == 0 {
                now
            } else {
                last_tx.saturating_add(DHCP_RETRY_NS)
            };
            core::cmp::min(retry_at, lease_expires)
        }
        _ => u64::MAX,
    }
}
