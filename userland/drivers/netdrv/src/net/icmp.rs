// SPDX-License-Identifier: GPL-2.0-only
//! ICMP (Internet Control Message Protocol) implementation.
//!
//! Handles ICMP echo request/reply (ping).

use crate::virtio;
use crate::puts;
use super::{arp, checksum, ethernet, ipv4};

const ICMP_TYPE_ECHO_REPLY: u8 = 0;
const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_HEADER_LEN: usize = 8;

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
        puts(b"[netdrv] ICMP echo request received, sending reply\n");
        send_echo_reply(our_mac, our_ip, ip_hdr.src, data);
    } else if icmp_type == ICMP_TYPE_ECHO_REPLY {
        let seq = ((data[6] as u16) << 8) | (data[7] as u16);
        let mut lb = salty::serial::LineBuf::new();
        lb.str(b"[netdrv] ICMP echo reply received seq=");
        lb.dec(seq as u64);
        lb.putc(b'\n');
        lb.flush();
    }
}

/// Send an ICMP echo reply in response to the given echo request data.
fn send_echo_reply(our_mac: &[u8; 6], our_ip: u32, dst_ip: u32, request_data: &[u8]) {
    // Build ICMP reply: type=0, code=0, same id/seq/data
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

    // Wrap in IPv4
    let mut ip_buf = [0u8; 1520];
    let ip_len = ipv4::build(our_ip, dst_ip, ipv4::PROTO_ICMP, &icmp_buf[..icmp_len], &mut ip_buf);
    if ip_len == 0 {
        return;
    }

    // Resolve destination MAC
    let next_hop = ipv4::route(dst_ip);
    let dst_mac = match arp::lookup(next_hop) {
        Some(mac) => mac,
        None => {
            // No ARP entry; reply will be dropped
            puts(b"[netdrv] ICMP reply: no ARP entry for next hop\n");
            return;
        }
    };

    // Wrap in Ethernet
    let mut frame = [0u8; 1536];
    let frame_len = ethernet::build(
        dst_mac,
        *our_mac,
        ethernet::ETHERTYPE_IPV4,
        &ip_buf[..ip_len],
        &mut frame,
    );
    if frame_len > 0 {
        virtio::tx_packet(&frame[..frame_len]);
    }
}

/// Send an ICMP echo request (ping) to `dst_ip` with the given sequence number.
pub(crate) fn send_echo_request(our_mac: &[u8; 6], our_ip: u32, dst_ip: u32, seq: u16) {
    // Build ICMP echo request
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
    for i in 0..56 {
        icmp_buf[8 + i] = i as u8;
    }

    // Compute ICMP checksum
    let cksum = checksum::internet_checksum(&icmp_buf[..64]);
    icmp_buf[2] = (cksum >> 8) as u8;
    icmp_buf[3] = cksum as u8;

    // Wrap in IPv4
    let mut ip_buf = [0u8; 128];
    let ip_len = ipv4::build(our_ip, dst_ip, ipv4::PROTO_ICMP, &icmp_buf[..64], &mut ip_buf);
    if ip_len == 0 {
        return;
    }

    // Resolve destination MAC via ARP
    let next_hop = ipv4::route(dst_ip);
    let dst_mac = match arp::lookup(next_hop) {
        Some(mac) => mac,
        None => {
            puts(b"[netdrv] ICMP echo: no ARP entry for next hop\n");
            return;
        }
    };

    // Wrap in Ethernet
    let mut frame = [0u8; 256];
    let frame_len = ethernet::build(
        dst_mac,
        *our_mac,
        ethernet::ETHERTYPE_IPV4,
        &ip_buf[..ip_len],
        &mut frame,
    );
    if frame_len > 0 {
        virtio::tx_packet(&frame[..frame_len]);
    }
}
