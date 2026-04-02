// SPDX-License-Identifier: GPL-2.0-only
//! Runtime network configuration owned by netsrv.

use trona::consts::server::{NETCFG_STATE_CONFIGURING, NETCFG_STATE_DOWN, NETCFG_STATE_READY};

pub(crate) const HOSTNAME: &[u8] = b"salty";
pub(crate) const IFACE_NAME: &[u8] = b"eth0";

#[derive(Clone, Copy)]
pub(crate) struct NetworkSnapshot {
    pub(crate) state: u8,
    pub(crate) our_ip: u32,
    pub(crate) subnet_mask: u32,
    pub(crate) gateway_ip: u32,
    pub(crate) dns_server: u32,
    pub(crate) rx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) tx_packets: u64,
}

#[derive(Clone, Copy)]
struct NetworkConfig {
    state: u8,
    our_ip: u32,
    subnet_mask: u32,
    gateway_ip: u32,
    dns_server: u32,
    mac: [u8; 6],
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
}

impl NetworkConfig {
    const fn zeroed() -> Self {
        Self {
            state: NETCFG_STATE_DOWN as u8,
            our_ip: 0,
            subnet_mask: 0,
            gateway_ip: 0,
            dns_server: 0,
            mac: [0; 6],
            rx_bytes: 0,
            rx_packets: 0,
            tx_bytes: 0,
            tx_packets: 0,
        }
    }
}

static mut CONFIG: NetworkConfig = NetworkConfig::zeroed();

pub(crate) fn init(mac: [u8; 6]) {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe {
        let cfg = &raw mut CONFIG;
        (*cfg).state = NETCFG_STATE_CONFIGURING as u8;
        (*cfg).our_ip = 0;
        (*cfg).subnet_mask = 0;
        (*cfg).gateway_ip = 0;
        (*cfg).dns_server = 0;
        (*cfg).mac = mac;
        (*cfg).rx_bytes = 0;
        (*cfg).rx_packets = 0;
        (*cfg).tx_bytes = 0;
        (*cfg).tx_packets = 0;
    }
}

pub(crate) fn begin_reconfigure() {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe {
        let cfg = &raw mut CONFIG;
        (*cfg).state = NETCFG_STATE_CONFIGURING as u8;
        (*cfg).our_ip = 0;
        (*cfg).subnet_mask = 0;
        (*cfg).gateway_ip = 0;
        (*cfg).dns_server = 0;
    }
}

fn apply(state: u8, our_ip: u32, subnet_mask: u32, gateway_ip: u32, dns_server: u32) {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe {
        let cfg = &raw mut CONFIG;
        (*cfg).state = state;
        (*cfg).our_ip = our_ip;
        (*cfg).subnet_mask = subnet_mask;
        (*cfg).gateway_ip = gateway_ip;
        (*cfg).dns_server = dns_server;
    }
}

pub(crate) fn apply_dhcp(our_ip: u32, subnet_mask: u32, gateway_ip: u32, dns_server: u32) {
    apply(
        NETCFG_STATE_READY as u8,
        our_ip,
        subnet_mask,
        gateway_ip,
        dns_server,
    );
}

pub(crate) fn state() -> u8 {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe { *(&raw const CONFIG.state) }
}

pub(crate) fn is_ready() -> bool {
    matches!(state() as u64, NETCFG_STATE_READY)
}

pub(crate) fn our_ip() -> u32 {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe { *(&raw const CONFIG.our_ip) }
}

pub(crate) fn subnet_mask() -> u32 {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe { *(&raw const CONFIG.subnet_mask) }
}

pub(crate) fn gateway_ip() -> u32 {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe { *(&raw const CONFIG.gateway_ip) }
}

pub(crate) fn dns_server() -> u32 {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe { *(&raw const CONFIG.dns_server) }
}

pub(crate) fn mac_addr() -> [u8; 6] {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe { *(&raw const CONFIG.mac) }
}

pub(crate) fn is_configured() -> bool {
    our_ip() != 0 && subnet_mask() != 0
}

pub(crate) fn is_broadcast(dst_ip: u32) -> bool {
    if dst_ip == 0xFFFF_FFFF {
        return true;
    }

    let mask = subnet_mask();
    let our_ip = our_ip();
    if our_ip == 0 || mask == 0 {
        return false;
    }

    dst_ip == ((our_ip & mask) | !mask)
}

pub(crate) fn route(dst_ip: u32) -> u32 {
    if is_broadcast(dst_ip) {
        return dst_ip;
    }

    let our_ip = our_ip();
    let mask = subnet_mask();
    let gateway = gateway_ip();
    if our_ip == 0 || mask == 0 {
        return dst_ip;
    }

    if (dst_ip & mask) == (our_ip & mask) || gateway == 0 {
        dst_ip
    } else {
        gateway
    }
}

pub(crate) fn note_rx(bytes: usize) {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe {
        let cfg = &raw mut CONFIG;
        (*cfg).rx_bytes = (*cfg).rx_bytes.wrapping_add(bytes as u64);
        (*cfg).rx_packets = (*cfg).rx_packets.wrapping_add(1);
    }
}

pub(crate) fn note_tx(bytes: usize) {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe {
        let cfg = &raw mut CONFIG;
        (*cfg).tx_bytes = (*cfg).tx_bytes.wrapping_add(bytes as u64);
        (*cfg).tx_packets = (*cfg).tx_packets.wrapping_add(1);
    }
}

pub(crate) fn snapshot() -> NetworkSnapshot {
    // SAFETY: Single-threaded netsrv owns the config.
    unsafe {
        let cfg = &raw const CONFIG;
        NetworkSnapshot {
            state: (*cfg).state,
            our_ip: (*cfg).our_ip,
            subnet_mask: (*cfg).subnet_mask,
            gateway_ip: (*cfg).gateway_ip,
            dns_server: (*cfg).dns_server,
            rx_bytes: (*cfg).rx_bytes,
            rx_packets: (*cfg).rx_packets,
            tx_bytes: (*cfg).tx_bytes,
            tx_packets: (*cfg).tx_packets,
        }
    }
}
