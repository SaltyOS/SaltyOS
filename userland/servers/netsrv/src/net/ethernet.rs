// SPDX-License-Identifier: GPL-2.0-only
//! Ethernet frame parsing and construction.

pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;
pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;
pub(crate) const ETH_HEADER_LEN: usize = 14;
pub(crate) const ETH_MIN_FRAME_LEN: usize = 60; // Excludes the on-wire FCS
pub(crate) const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

pub(crate) struct EthHeader {
    pub(crate) dst: [u8; 6],
    pub(crate) src: [u8; 6],
    pub(crate) ethertype: u16,
}

/// Parse an Ethernet frame. Returns header and payload slice.
pub(crate) fn parse(data: &[u8]) -> Option<(EthHeader, &[u8])> {
    if data.len() < ETH_HEADER_LEN {
        return None;
    }

    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    src.copy_from_slice(&data[6..12]);
    let ethertype = ((data[12] as u16) << 8) | (data[13] as u16);

    Some((
        EthHeader {
            dst,
            src,
            ethertype,
        },
        &data[ETH_HEADER_LEN..],
    ))
}

/// Build an Ethernet frame into `buf`. Returns total bytes written.
///
/// Layout: dst(6) + src(6) + ethertype(2) + payload
pub(crate) fn build(
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: u16,
    payload: &[u8],
    buf: &mut [u8],
) -> usize {
    let payload_len = core::cmp::max(payload.len(), ETH_MIN_FRAME_LEN - ETH_HEADER_LEN);
    let total = ETH_HEADER_LEN + payload_len;
    if buf.len() < total {
        return 0;
    }

    buf[0..6].copy_from_slice(&dst);
    buf[6..12].copy_from_slice(&src);
    buf[12] = (ethertype >> 8) as u8;
    buf[13] = ethertype as u8;
    buf[ETH_HEADER_LEN..ETH_HEADER_LEN + payload.len()].copy_from_slice(payload);
    if payload_len > payload.len() {
        buf[ETH_HEADER_LEN + payload.len()..total].fill(0);
    }

    total
}
