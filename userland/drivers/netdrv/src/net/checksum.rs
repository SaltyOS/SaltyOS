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
