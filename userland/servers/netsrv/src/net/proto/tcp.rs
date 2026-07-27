// SPDX-License-Identifier: GPL-2.0-only
//! TCP segment parsing and construction — stateless helpers.
//!
//! This module contains only constants, header parsing, header building,
//! and sequence number arithmetic. All stateful socket management lives
//! in `socket::tcp`.

pub(crate) const TCP_HEADER_LEN: usize = 20;

pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_SYN: u8 = 0x02;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
pub(crate) const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_ACK: u8 = 0x10;

pub(crate) struct TcpHeader {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) window: u16,
}

/// Parse a TCP header from raw data. Returns the header and payload slice.
pub(crate) fn parse(data: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if data.len() < TCP_HEADER_LEN {
        return None;
    }

    let src_port = ((data[0] as u16) << 8) | (data[1] as u16);
    let dst_port = ((data[2] as u16) << 8) | (data[3] as u16);
    let seq = ((data[4] as u32) << 24)
        | ((data[5] as u32) << 16)
        | ((data[6] as u32) << 8)
        | (data[7] as u32);
    let ack = ((data[8] as u32) << 24)
        | ((data[9] as u32) << 16)
        | ((data[10] as u32) << 8)
        | (data[11] as u32);
    let data_offset = (data[12] >> 4) * 4;
    let flags = data[13];
    let window = ((data[14] as u16) << 8) | (data[15] as u16);

    if (data_offset as usize) < TCP_HEADER_LEN || data.len() < data_offset as usize {
        return None;
    }

    let payload = &data[data_offset as usize..];

    Some((
        TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
        },
        payload,
    ))
}

/// Build a TCP header + payload into `buf`. Returns total bytes written.
///
/// The checksum field is left zeroed; the caller must compute and fill
/// the TCP checksum (including pseudo-header) after calling this.
pub(crate) fn build(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    buf: &mut [u8],
) -> usize {
    let total = TCP_HEADER_LEN + payload.len();
    if buf.len() < total {
        return 0;
    }

    // Source port
    buf[0] = (src_port >> 8) as u8;
    buf[1] = src_port as u8;
    // Dest port
    buf[2] = (dst_port >> 8) as u8;
    buf[3] = dst_port as u8;
    // Sequence number
    buf[4] = (seq >> 24) as u8;
    buf[5] = (seq >> 16) as u8;
    buf[6] = (seq >> 8) as u8;
    buf[7] = seq as u8;
    // Ack number
    buf[8] = (ack >> 24) as u8;
    buf[9] = (ack >> 16) as u8;
    buf[10] = (ack >> 8) as u8;
    buf[11] = ack as u8;
    // Data offset (5 words = 20 bytes) | reserved
    buf[12] = 0x50;
    // Flags
    buf[13] = flags;
    // Window
    buf[14] = (window >> 8) as u8;
    buf[15] = window as u8;
    // Checksum (zeroed, computed after)
    buf[16] = 0;
    buf[17] = 0;
    // Urgent pointer
    buf[18] = 0;
    buf[19] = 0;

    // Copy payload
    if !payload.is_empty() {
        buf[TCP_HEADER_LEN..total].copy_from_slice(payload);
    }

    total
}

/// Sequence number comparison: a <= b (wrapping-aware).
pub(crate) fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// Sequence number comparison: a > b (wrapping-aware).
pub(crate) fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Compute the logical length of a TCP segment (payload + SYN/FIN flags).
pub(crate) fn segment_len(hdr: &TcpHeader, payload: &[u8]) -> u32 {
    let mut len = payload.len() as u32;
    if (hdr.flags & TCP_FLAG_SYN) != 0 {
        len += 1;
    }
    if (hdr.flags & TCP_FLAG_FIN) != 0 {
        len += 1;
    }
    len
}
