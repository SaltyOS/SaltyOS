// SPDX-License-Identifier: GPL-2.0-only
//! Network protocol stack modules.
//!
//! Protocol parsing/construction lives in `proto/`, stateful socket
//! management in `socket/`. Shared utilities (`checksum`, `ethernet`)
//! and the DNS engine remain at this level.

pub(crate) mod checksum;
pub(crate) mod config;
pub(crate) mod dhcp;
pub(crate) mod dns;
pub(crate) mod ethernet;
pub(crate) mod proto;
pub(crate) mod socket;

const MAX_PENDING_IP_PACKETS: usize = 16;
const MAX_PENDING_IP_PAYLOAD: usize = 1480;

#[derive(Clone, Copy)]
struct PendingIpPacket {
    active: bool,
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    ttl: u8,
    payload_len: u16,
    payload: [u8; MAX_PENDING_IP_PAYLOAD],
}

impl PendingIpPacket {
    const fn zeroed() -> Self {
        Self {
            active: false,
            src_ip: 0,
            dst_ip: 0,
            protocol: 0,
            ttl: 64,
            payload_len: 0,
            payload: [0; MAX_PENDING_IP_PAYLOAD],
        }
    }
}

static mut PENDING_IP_PACKETS: [PendingIpPacket; MAX_PENDING_IP_PACKETS] =
    [PendingIpPacket::zeroed(); MAX_PENDING_IP_PACKETS];

fn send_ip_packet_now(
    our_mac: &[u8; 6],
    our_ip: u32,
    dst_ip: u32,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> bool {
    // Build IPv4 packet
    let mut ip_buf = [0u8; 1520];
    let ip_len = proto::ipv4::build_with_ttl(our_ip, dst_ip, protocol, ttl, payload, &mut ip_buf);
    if ip_len == 0 {
        return false;
    }

    // Resolve destination MAC via ARP
    let dst_mac = if config::is_broadcast(dst_ip) {
        ethernet::BROADCAST_MAC
    } else {
        let next_hop = proto::ipv4::route(dst_ip);
        match proto::arp::lookup(next_hop) {
            Some(mac) => mac,
            None => return false,
        }
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
        if !crate::shm_tx_enqueue(&frame[..frame_len]) {
            return false;
        }
        config::note_tx(frame_len);
        crate::signal_netdrv_tx();
        return true;
    }
    false
}

fn queue_pending_ip_packet(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> bool {
    if payload.len() > MAX_PENDING_IP_PAYLOAD {
        return false;
    }

    // SAFETY: Single-threaded netsrv event loop owns the pending queue.
    unsafe {
        let queue = &raw mut PENDING_IP_PACKETS;
        let mut i = 0;
        while i < MAX_PENDING_IP_PACKETS {
            if !(*queue)[i].active {
                let slot = &mut (*queue)[i];
                slot.active = true;
                slot.src_ip = src_ip;
                slot.dst_ip = dst_ip;
                slot.protocol = protocol;
                slot.ttl = ttl;
                slot.payload_len = payload.len() as u16;
                slot.payload[..payload.len()].copy_from_slice(payload);
                return true;
            }
            i += 1;
        }
    }

    crate::puts(b"[netsrv] WARN: pending IP packet queue full, dropping\n");
    false
}

/// Send an IPv4 packet through the network stack.
///
/// If the next-hop MAC is not known yet, queues the packet and kicks ARP so
/// the first outbound packet is not silently lost during address resolution.
pub(crate) fn send_ip_packet(
    our_mac: &[u8; 6],
    our_ip: u32,
    dst_ip: u32,
    protocol: u8,
    payload: &[u8],
) -> bool {
    send_ip_packet_with_ttl(our_mac, our_ip, dst_ip, protocol, 64, payload)
}

pub(crate) fn send_ip_packet_with_ttl(
    our_mac: &[u8; 6],
    our_ip: u32,
    dst_ip: u32,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> bool {
    if send_ip_packet_now(our_mac, our_ip, dst_ip, protocol, ttl, payload) {
        return true;
    }

    if !config::is_broadcast(dst_ip) {
        let next_hop = proto::ipv4::route(dst_ip);
        proto::arp::request(our_mac, our_ip, next_hop);
    }
    queue_pending_ip_packet(our_ip, dst_ip, protocol, ttl, payload)
}

/// Retry any queued IP packets whose next-hop MAC became available.
pub(crate) fn flush_pending_packets() {
    // SAFETY: Single-threaded netsrv event loop owns the pending queue.
    unsafe {
        let queue = &raw mut PENDING_IP_PACKETS;
        let mut i = 0;
        while i < MAX_PENDING_IP_PACKETS {
            if (*queue)[i].active {
                let slot = &(*queue)[i];
                let payload_len = slot.payload_len as usize;
                if send_ip_packet_now(
                    &crate::mac_addr(),
                    slot.src_ip,
                    slot.dst_ip,
                    slot.protocol,
                    slot.ttl,
                    &slot.payload[..payload_len],
                ) {
                    (*queue)[i].active = false;
                    (*queue)[i].payload_len = 0;
                }
            }
            i += 1;
        }
    }
}

/// Ensure an ARP entry exists for the next hop to `dst_ip`.
///
/// If no ARP entry exists, sends an ARP request. The caller should
/// process incoming packets to receive the reply before sending data.
pub(crate) fn ensure_arp(our_mac: &[u8; 6], our_ip: u32, dst_ip: u32) {
    if config::is_broadcast(dst_ip) {
        return;
    }
    let next_hop = proto::ipv4::route(dst_ip);
    if proto::arp::lookup(next_hop).is_none() {
        proto::arp::request(our_mac, our_ip, next_hop);
    }
}
