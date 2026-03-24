// SPDX-License-Identifier: GPL-2.0-only
//! ARP (Address Resolution Protocol) implementation.
//!
//! Maintains a static ARP table and handles ARP request/reply packets.

use super::ethernet;

const ARP_TABLE_SIZE: usize = 16;
static mut ARP_TABLE: [(u32, [u8; 6], bool); ARP_TABLE_SIZE] = [(0, [0; 6], false); ARP_TABLE_SIZE];

const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const ARP_PACKET_LEN: usize = 28; // Ethernet+IPv4 ARP

/// Look up a MAC address for the given IPv4 address.
pub(crate) fn lookup(ip: u32) -> Option<[u8; 6]> {
    // SAFETY: Single-threaded userland server; only this module accesses ARP_TABLE.
    unsafe {
        let table = &*(&raw const ARP_TABLE);
        for entry in table.iter() {
            if entry.2 && entry.0 == ip {
                return Some(entry.1);
            }
        }
    }
    None
}

/// Insert or update an ARP table entry.
fn arp_table_insert(ip: u32, mac: [u8; 6]) {
    // SAFETY: Single-threaded userland server; only this module accesses ARP_TABLE.
    unsafe {
        let table = &mut *(&raw mut ARP_TABLE);
        // Update existing entry
        for entry in table.iter_mut() {
            if entry.2 && entry.0 == ip {
                entry.1 = mac;
                return;
            }
        }
        // Insert into first free slot
        for entry in table.iter_mut() {
            if !entry.2 {
                entry.0 = ip;
                entry.1 = mac;
                entry.2 = true;
                return;
            }
        }
        // Table full: overwrite slot 0
        table[0] = (ip, mac, true);
    }
}

/// Handle an incoming ARP packet.
///
/// If it is an ARP request for our IP, sends a reply.
/// If it is an ARP reply, updates the cache.
pub(crate) fn handle_packet(our_mac: &[u8; 6], our_ip: u32, data: &[u8]) {
    if data.len() < ARP_PACKET_LEN {
        return;
    }

    let htype = ((data[0] as u16) << 8) | (data[1] as u16);
    let ptype = ((data[2] as u16) << 8) | (data[3] as u16);
    let hlen = data[4];
    let plen = data[5];
    let op = ((data[6] as u16) << 8) | (data[7] as u16);

    if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return;
    }

    let mut sha = [0u8; 6];
    sha.copy_from_slice(&data[8..14]);
    let spa = ((data[14] as u32) << 24)
        | ((data[15] as u32) << 16)
        | ((data[16] as u32) << 8)
        | (data[17] as u32);
    let tpa = ((data[24] as u32) << 24)
        | ((data[25] as u32) << 16)
        | ((data[26] as u32) << 8)
        | (data[27] as u32);

    // Always learn from the sender
    arp_table_insert(spa, sha);

    // ARP cache updated — flush any DNS queries waiting for this MAC
    super::dns::flush_arp_waiters();

    if op == ARP_OP_REQUEST && tpa == our_ip {
        // Send ARP reply
        send_reply(our_mac, our_ip, &sha, spa);
    }
}

/// Send an ARP reply via the SHM TX ring.
fn send_reply(our_mac: &[u8; 6], our_ip: u32, target_mac: &[u8; 6], target_ip: u32) {
    let mut arp = [0u8; ARP_PACKET_LEN];

    // Hardware type: Ethernet
    arp[0] = (ARP_HTYPE_ETHERNET >> 8) as u8;
    arp[1] = ARP_HTYPE_ETHERNET as u8;
    // Protocol type: IPv4
    arp[2] = (ARP_PTYPE_IPV4 >> 8) as u8;
    arp[3] = ARP_PTYPE_IPV4 as u8;
    // Hardware/protocol address lengths
    arp[4] = 6;
    arp[5] = 4;
    // Operation: reply
    arp[6] = (ARP_OP_REPLY >> 8) as u8;
    arp[7] = ARP_OP_REPLY as u8;
    // Sender hardware address (our MAC)
    arp[8..14].copy_from_slice(our_mac);
    // Sender protocol address (our IP)
    arp[14] = (our_ip >> 24) as u8;
    arp[15] = (our_ip >> 16) as u8;
    arp[16] = (our_ip >> 8) as u8;
    arp[17] = our_ip as u8;
    // Target hardware address
    arp[18..24].copy_from_slice(target_mac);
    // Target protocol address
    arp[24] = (target_ip >> 24) as u8;
    arp[25] = (target_ip >> 16) as u8;
    arp[26] = (target_ip >> 8) as u8;
    arp[27] = target_ip as u8;

    let mut frame = [0u8; 64];
    let len = ethernet::build(
        *target_mac,
        *our_mac,
        ethernet::ETHERTYPE_ARP,
        &arp,
        &mut frame,
    );
    if len > 0 {
        crate::shm_tx_enqueue(&frame[..len]);
        crate::signal_netdrv_tx();
    }
}

/// Send an ARP request for `target_ip` via the SHM TX ring.
pub(crate) fn request(our_mac: &[u8; 6], our_ip: u32, target_ip: u32) {
    let mut arp = [0u8; ARP_PACKET_LEN];

    // Hardware type: Ethernet
    arp[0] = (ARP_HTYPE_ETHERNET >> 8) as u8;
    arp[1] = ARP_HTYPE_ETHERNET as u8;
    // Protocol type: IPv4
    arp[2] = (ARP_PTYPE_IPV4 >> 8) as u8;
    arp[3] = ARP_PTYPE_IPV4 as u8;
    // Hardware/protocol address lengths
    arp[4] = 6;
    arp[5] = 4;
    // Operation: request
    arp[6] = (ARP_OP_REQUEST >> 8) as u8;
    arp[7] = ARP_OP_REQUEST as u8;
    // Sender hardware address (our MAC)
    arp[8..14].copy_from_slice(our_mac);
    // Sender protocol address (our IP)
    arp[14] = (our_ip >> 24) as u8;
    arp[15] = (our_ip >> 16) as u8;
    arp[16] = (our_ip >> 8) as u8;
    arp[17] = our_ip as u8;
    // Target hardware address (zeroed for request)
    // arp[18..24] already zero
    // Target protocol address
    arp[24] = (target_ip >> 24) as u8;
    arp[25] = (target_ip >> 16) as u8;
    arp[26] = (target_ip >> 8) as u8;
    arp[27] = target_ip as u8;

    let mut frame = [0u8; 64];
    let len = ethernet::build(
        ethernet::BROADCAST_MAC,
        *our_mac,
        ethernet::ETHERTYPE_ARP,
        &arp,
        &mut frame,
    );
    if len > 0 {
        crate::shm_tx_enqueue(&frame[..len]);
        crate::signal_netdrv_tx();
    }
}
