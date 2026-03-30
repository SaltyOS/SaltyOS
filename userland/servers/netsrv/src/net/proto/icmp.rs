// SPDX-License-Identifier: GPL-2.0-only
//! ICMP (Internet Control Message Protocol) — stateless packet handling.
//!
//! Handles ICMP echo request/reply (ping). Raw socket delivery is done
//! separately by `socket::raw_ipv4::deliver()` at the dispatch level.

use crate::net::checksum;
use super::ipv4;

pub(crate) const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub(crate) const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub(crate) const ICMP_HEADER_LEN: usize = 8;

/// Flag set when an echo reply is received, used by self-test for early break.
static mut ECHO_REPLY_RECEIVED: bool = false;

fn log_ipv4(lb: &mut besalt::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

/// Check if an echo reply has been received (for self-test early break).
pub(crate) fn echo_reply_received() -> bool {
    // SAFETY: Single-threaded server; read-only check.
    unsafe { *(&raw const ECHO_REPLY_RECEIVED) }
}

/// Reset the echo reply received flag.
pub(crate) fn reset_echo_reply_flag() {
    // SAFETY: Single-threaded server; written once before self-test.
    unsafe { *(&raw mut ECHO_REPLY_RECEIVED) = false; }
}

/// Handle an incoming ICMP packet (kernel-like behavior).
///
/// Responds to echo requests and sets the self-test flag on echo replies.
/// Does NOT deliver to raw sockets — that is done by the caller before
/// invoking this function.
pub(crate) fn handle(
    our_mac: &[u8; 6],
    our_ip: u32,
    ip_hdr: &ipv4::Ipv4Header,
    data: &[u8],
) {
    if data.len() < ICMP_HEADER_LEN {
        return;
    }

    let icmp_type = data[0];
    let ident = if data.len() >= 6 {
        ((data[4] as u16) << 8) | (data[5] as u16)
    } else {
        0
    };
    let seq = if data.len() >= 8 {
        ((data[6] as u16) << 8) | (data[7] as u16)
    } else {
        0
    };

    if icmp_type == ICMP_TYPE_ECHO_REQUEST {
        besalt::udebug!(|_lb| {
            _lb.str(b"[netsrv] ICMP echo request src=");
            log_ipv4(&mut _lb, ip_hdr.src);
            _lb.str(b" dst=");
            log_ipv4(&mut _lb, ip_hdr.dst);
            _lb.str(b" ident=");
            _lb.dec(ident as u64);
            _lb.str(b" seq=");
            _lb.dec(seq as u64);
            _lb.str(b" len=");
            _lb.dec(data.len() as u64);
            _lb.putc(b'\n');
        });
        send_echo_reply(our_mac, our_ip, ip_hdr.src, data);
    } else if icmp_type == ICMP_TYPE_ECHO_REPLY {
        besalt::udebug!(|_lb| {
            _lb.str(b"[netsrv] ICMP echo reply src=");
            log_ipv4(&mut _lb, ip_hdr.src);
            _lb.str(b" dst=");
            log_ipv4(&mut _lb, ip_hdr.dst);
            _lb.str(b" ident=");
            _lb.dec(ident as u64);
            _lb.str(b" seq=");
            _lb.dec(seq as u64);
            _lb.str(b" len=");
            _lb.dec(data.len() as u64);
            _lb.putc(b'\n');
        });
        // SAFETY: Single-threaded server; set flag for self-test early break.
        unsafe { *(&raw mut ECHO_REPLY_RECEIVED) = true; }
    }
}

/// Send an ICMP echo reply in response to the given echo request data.
fn send_echo_reply(our_mac: &[u8; 6], our_ip: u32, dst_ip: u32, request_data: &[u8]) {
    let icmp_len = request_data.len();
    if icmp_len > 1500 {
        return;
    }

    let mut icmp_buf = [0u8; 1500];
    // Type: echo reply
    icmp_buf[0] = ICMP_TYPE_ECHO_REPLY;
    // Code: 0
    icmp_buf[1] = 0;
    // Checksum: zeroed for calculation
    icmp_buf[2] = 0;
    icmp_buf[3] = 0;
    // Copy identifier, sequence, and data from request
    if icmp_len > 4 {
        icmp_buf[4..icmp_len].copy_from_slice(&request_data[4..]);
    }

    // Compute ICMP checksum
    let cksum = checksum::internet_checksum(&icmp_buf[..icmp_len]);
    icmp_buf[2] = (cksum >> 8) as u8;
    icmp_buf[3] = cksum as u8;

    let ident = if icmp_len >= 6 {
        ((icmp_buf[4] as u16) << 8) | (icmp_buf[5] as u16)
    } else {
        0
    };
    let seq = if icmp_len >= 8 {
        ((icmp_buf[6] as u16) << 8) | (icmp_buf[7] as u16)
    } else {
        0
    };
    besalt::udebug!(|_lb| {
        _lb.str(b"[netsrv] ICMP echo reply send dst=");
        log_ipv4(&mut _lb, dst_ip);
        _lb.str(b" ident=");
        _lb.dec(ident as u64);
        _lb.str(b" seq=");
        _lb.dec(seq as u64);
        _lb.str(b" len=");
        _lb.dec(icmp_len as u64);
        _lb.putc(b'\n');
    });

    crate::net::send_ip_packet(our_mac, our_ip, dst_ip, ipv4::PROTO_ICMP, &icmp_buf[..icmp_len]);
}

/// Send an ICMP echo request (ping) to `dst_ip` with the given sequence number.
pub(crate) fn send_echo_request(our_mac: &[u8; 6], our_ip: u32, dst_ip: u32, seq: u16) {
    let mut icmp_buf = [0u8; 64];
    // Type: echo request
    icmp_buf[0] = ICMP_TYPE_ECHO_REQUEST;
    // Code: 0
    icmp_buf[1] = 0;
    // Checksum: zeroed for calculation
    icmp_buf[2] = 0;
    icmp_buf[3] = 0;
    // Identifier: 0x5A17 ("SA" for SaltyOS)
    icmp_buf[4] = 0x5A;
    icmp_buf[5] = 0x17;
    // Sequence number
    icmp_buf[6] = (seq >> 8) as u8;
    icmp_buf[7] = seq as u8;
    // Payload: 56 bytes of pattern data (total ICMP = 64 bytes)
    let mut i = 0;
    while i < 56 {
        icmp_buf[8 + i] = i as u8;
        i += 1;
    }

    // Compute ICMP checksum
    let cksum = checksum::internet_checksum(&icmp_buf[..64]);
    icmp_buf[2] = (cksum >> 8) as u8;
    icmp_buf[3] = cksum as u8;

    crate::net::send_ip_packet(our_mac, our_ip, dst_ip, ipv4::PROTO_ICMP, &icmp_buf[..64]);
}
