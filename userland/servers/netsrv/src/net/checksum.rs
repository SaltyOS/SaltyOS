// SPDX-License-Identifier: GPL-2.0-only
//! RFC 1071 internet checksum.

/// Compute the internet checksum (one's complement sum of 16-bit words).
///
/// Used for IP, ICMP, and other protocol header checksums.
pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }

    // Handle odd trailing byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum into 16-bit
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Compute checksum over IPv4 pseudo-header + transport-layer data.
///
/// Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + length(2)
/// Used for TCP and UDP checksum calculation.
pub(crate) fn transport_checksum(src_ip: u32, dst_ip: u32, protocol: u8, data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source IP (2 x 16-bit words)
    sum += (src_ip >> 16) as u32;
    sum += (src_ip & 0xFFFF) as u32;

    // Pseudo-header: destination IP (2 x 16-bit words)
    sum += (dst_ip >> 16) as u32;
    sum += (dst_ip & 0xFFFF) as u32;

    // Pseudo-header: zero + protocol
    sum += protocol as u32;

    // Pseudo-header: transport layer length
    sum += data.len() as u32;

    // Transport layer data (header + payload)
    let mut i = 0;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }

    // Handle odd trailing byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum into 16-bit
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
