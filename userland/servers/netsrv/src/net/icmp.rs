// SPDX-License-Identifier: GPL-2.0-only
//! ICMP (Internet Control Message Protocol) implementation.
//!
//! Handles ICMP echo request/reply (ping).

use super::{checksum, ipv4};

const ICMP_TYPE_ECHO_REPLY: u8 = 0;
const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_HEADER_LEN: usize = 8;

/// Flag set when an echo reply is received, used by self-test for early break.
static mut ECHO_REPLY_RECEIVED: bool = false;

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

/// Handle an incoming ICMP packet.
///
/// If it is an echo request for us, sends an echo reply with the same
/// identifier, sequence number, and data payload.
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
    let _code = data[1];

    if icmp_type == ICMP_TYPE_ECHO_REQUEST {
        besalt::udebug!(|_lb| {
            _lb.str(b"[netsrv] ICMP echo request received, sending reply\n");
        });
        send_echo_reply(our_mac, our_ip, ip_hdr.src, data);
    } else if icmp_type == ICMP_TYPE_ECHO_REPLY {
        let seq = ((data[6] as u16) << 8) | (data[7] as u16);
        besalt::udebug!(|_lb| {
            _lb.str(b"[netsrv] ICMP echo reply received seq=");
            _lb.dec(seq as u64);
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

    super::send_ip_packet(our_mac, our_ip, dst_ip, ipv4::PROTO_ICMP, &icmp_buf[..icmp_len]);
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

    super::send_ip_packet(our_mac, our_ip, dst_ip, ipv4::PROTO_ICMP, &icmp_buf[..64]);
}
