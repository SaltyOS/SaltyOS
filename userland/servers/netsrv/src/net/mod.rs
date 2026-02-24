// SPDX-License-Identifier: GPL-2.0-only
//! Network protocol stack modules.

pub(crate) mod arp;
pub(crate) mod checksum;
pub(crate) mod ethernet;
pub(crate) mod icmp;
pub(crate) mod ipv4;
pub(crate) mod tcp;
pub(crate) mod udp;

/// Send an IPv4 packet through the network stack.
///
/// Resolves the next-hop MAC via ARP, wraps payload in IPv4 + Ethernet, and
/// transmits via the SHM TX ring to netdrv. Returns silently if no ARP entry
/// exists for the next hop.
pub(crate) fn send_ip_packet(
    our_mac: &[u8; 6],
    our_ip: u32,
    dst_ip: u32,
    protocol: u8,
    payload: &[u8],
) {
    // Build IPv4 packet
    let mut ip_buf = [0u8; 1520];
    let ip_len = ipv4::build(our_ip, dst_ip, protocol, payload, &mut ip_buf);
    if ip_len == 0 {
        return;
    }

    // Resolve destination MAC via ARP
    let next_hop = ipv4::route(dst_ip);
    let dst_mac = match arp::lookup(next_hop) {
        Some(mac) => mac,
        None => return,
    };

    // Wrap in Ethernet and transmit via SHM
    let mut frame = [0u8; 1536];
    let frame_len = ethernet::build(
        dst_mac,
        *our_mac,
        ethernet::ETHERTYPE_IPV4,
        &ip_buf[..ip_len],
        &mut frame,
    );
    if frame_len > 0 {
        crate::shm_tx_enqueue(&frame[..frame_len]);
        crate::signal_netdrv_tx();
    }
}

/// Ensure an ARP entry exists for the next hop to `dst_ip`.
///
/// If no ARP entry exists, sends an ARP request. The caller should
/// process incoming packets to receive the reply before sending data.
pub(crate) fn ensure_arp(our_mac: &[u8; 6], our_ip: u32, dst_ip: u32) {
    let next_hop = ipv4::route(dst_ip);
    if arp::lookup(next_hop).is_none() {
        arp::request(our_mac, our_ip, next_hop);
    }
}
