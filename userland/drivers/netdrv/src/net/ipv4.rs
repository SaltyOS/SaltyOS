// SPDX-License-Identifier: GPL-2.0-only
//! IPv4 packet parsing and construction.

use super::checksum;

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const IPV4_HEADER_LEN: usize = 20;

/// Static IP configuration (QEMU user networking defaults).
pub(crate) const OUR_IP: u32 = 0x0A00_020F;    // 10.0.2.15
pub(crate) const GATEWAY_IP: u32 = 0x0A00_0202; // 10.0.2.2
pub(crate) const SUBNET_MASK: u32 = 0xFFFF_FF00; // 255.255.255.0

/// Monotonically increasing IP identification counter.
static mut IP_ID: u16 = 1;

pub(crate) struct Ipv4Header {
    pub(crate) version_ihl: u8,
    pub(crate) tos: u8,
    pub(crate) total_len: u16,
    pub(crate) id: u16,
    pub(crate) flags_frag: u16,
    pub(crate) ttl: u8,
    pub(crate) protocol: u8,
    pub(crate) checksum: u16,
    pub(crate) src: u32,
    pub(crate) dst: u32,
}

/// Parse an IPv4 packet. Returns header and payload slice.
pub(crate) fn parse(data: &[u8]) -> Option<(Ipv4Header, &[u8])> {
    if data.len() < IPV4_HEADER_LEN {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) as usize;

    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = ihl * 4;
    if data.len() < header_len {
        return None;
    }

    let total_len = ((data[2] as u16) << 8) | (data[3] as u16);
    let actual_len = core::cmp::min(total_len as usize, data.len());

    let hdr = Ipv4Header {
        version_ihl,
        tos: data[1],
        total_len,
        id: ((data[4] as u16) << 8) | (data[5] as u16),
        flags_frag: ((data[6] as u16) << 8) | (data[7] as u16),
        ttl: data[8],
        protocol: data[9],
        checksum: ((data[10] as u16) << 8) | (data[11] as u16),
        src: ((data[12] as u32) << 24)
            | ((data[13] as u32) << 16)
            | ((data[14] as u32) << 8)
            | (data[15] as u32),
        dst: ((data[16] as u32) << 24)
            | ((data[17] as u32) << 16)
            | ((data[18] as u32) << 8)
            | (data[19] as u32),
    };

    if actual_len < header_len {
        return None;
    }

    Some((hdr, &data[header_len..actual_len]))
}

/// Build an IPv4 packet into `buf`. Returns total bytes written (header + payload).
///
/// Computes the IP header checksum automatically.
pub(crate) fn build(src: u32, dst: u32, protocol: u8, payload: &[u8], buf: &mut [u8]) -> usize {
    let total_len = IPV4_HEADER_LEN + payload.len();
    if buf.len() < total_len {
        return 0;
    }

    // SAFETY: Single-threaded driver; IP_ID is only modified here.
    let id = unsafe {
        let val = *(&raw const IP_ID);
        *(&raw mut IP_ID) = val.wrapping_add(1);
        val
    };

    // Version=4, IHL=5 (20 bytes, no options)
    buf[0] = 0x45;
    // TOS = 0
    buf[1] = 0;
    // Total length
    buf[2] = (total_len >> 8) as u8;
    buf[3] = total_len as u8;
    // Identification
    buf[4] = (id >> 8) as u8;
    buf[5] = id as u8;
    // Flags (Don't Fragment) + Fragment offset = 0
    buf[6] = 0x40;
    buf[7] = 0;
    // TTL
    buf[8] = 64;
    // Protocol
    buf[9] = protocol;
    // Checksum (zeroed for calculation)
    buf[10] = 0;
    buf[11] = 0;
    // Source IP
    buf[12] = (src >> 24) as u8;
    buf[13] = (src >> 16) as u8;
    buf[14] = (src >> 8) as u8;
    buf[15] = src as u8;
    // Destination IP
    buf[16] = (dst >> 24) as u8;
    buf[17] = (dst >> 16) as u8;
    buf[18] = (dst >> 8) as u8;
    buf[19] = dst as u8;

    // Copy payload
    buf[IPV4_HEADER_LEN..total_len].copy_from_slice(payload);

    // Compute and fill IP header checksum
    let cksum = checksum::internet_checksum(&buf[..IPV4_HEADER_LEN]);
    buf[10] = (cksum >> 8) as u8;
    buf[11] = cksum as u8;

    total_len
}

/// Route a destination IP: if on the same subnet, return dst directly;
/// otherwise return the gateway IP.
pub(crate) fn route(dst: u32) -> u32 {
    if (dst & SUBNET_MASK) == (OUR_IP & SUBNET_MASK) {
        dst
    } else {
        GATEWAY_IP
    }
}
