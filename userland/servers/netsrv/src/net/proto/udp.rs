// SPDX-License-Identifier: GPL-2.0-only
//! UDP datagram parsing and construction — stateless helpers.
//!
//! This module contains only header constants and parse/build functions.
//! All stateful socket management lives in `socket::udp`.

use crate::net::checksum;

pub(crate) const UDP_HEADER_LEN: usize = 8;

/// Parse a UDP header. Returns (src_port, dst_port, payload).
pub(crate) fn parse(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < UDP_HEADER_LEN {
        return None;
    }

    let src_port = ((data[0] as u16) << 8) | (data[1] as u16);
    let dst_port = ((data[2] as u16) << 8) | (data[3] as u16);
    let length = ((data[4] as u16) << 8) | (data[5] as u16);

    if (length as usize) < UDP_HEADER_LEN || data.len() < length as usize {
        return None;
    }

    let payload = &data[UDP_HEADER_LEN..length as usize];
    Some((src_port, dst_port, payload))
}

/// Build a UDP datagram into `buf`. Returns total bytes written.
///
/// Computes the UDP checksum (with IPv4 pseudo-header) automatically.
pub(crate) fn build(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src_ip: u32,
    dst_ip: u32,
    buf: &mut [u8],
) -> usize {
    let total = UDP_HEADER_LEN + payload.len();
    if buf.len() < total {
        return 0;
    }

    // Source port
    buf[0] = (src_port >> 8) as u8;
    buf[1] = src_port as u8;
    // Dest port
    buf[2] = (dst_port >> 8) as u8;
    buf[3] = dst_port as u8;
    // Length
    buf[4] = (total >> 8) as u8;
    buf[5] = total as u8;
    // Checksum (zeroed for calculation)
    buf[6] = 0;
    buf[7] = 0;

    // Copy payload
    if !payload.is_empty() {
        buf[UDP_HEADER_LEN..total].copy_from_slice(payload);
    }

    // Compute UDP checksum over pseudo-header + segment
    let cksum = checksum::transport_checksum(
        src_ip,
        dst_ip,
        super::ipv4::PROTO_UDP,
        &buf[..total],
    );
    buf[6] = (cksum >> 8) as u8;
    buf[7] = cksum as u8;

    total
}
