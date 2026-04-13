// SPDX-License-Identifier: GPL-2.0-only
//! Network-related /proc file generators (/proc/net/*, /etc/hosts, /etc/resolv.conf).

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::server::*;
use trona::types::core::*;

use crate::server::consts::*;
use crate::ipc_ctx;

use super::generators::{
    append_bytes, append_hex_u32_fixed, append_ipv4, append_mac, append_u64_dec,
};

pub(super) const MAX_NET_ARP_ENTRIES: usize = 16;

#[derive(Clone, Copy)]
pub(super) struct NetConfigInfo {
    pub(super) state: u8,
    pub(super) our_ip: u32,
    pub(super) subnet_mask: u32,
    pub(super) gateway_ip: u32,
    pub(super) dns_server: u32,
    pub(super) rx_bytes: u64,
    pub(super) rx_packets: u64,
    pub(super) tx_bytes: u64,
    pub(super) tx_packets: u64,
}

impl NetConfigInfo {
    pub(super) const fn zeroed() -> Self {
        Self {
            state: 0,
            our_ip: 0,
            subnet_mask: 0,
            gateway_ip: 0,
            dns_server: 0,
            rx_bytes: 0,
            rx_packets: 0,
            tx_bytes: 0,
            tx_packets: 0,
        }
    }
}

// SAFETY: caller must ensure VFS is single-threaded and the server EP is valid.
pub(super) unsafe fn netsrv_get_config(info: &mut NetConfigInfo) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = NET_GET_CONFIG;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }
        info.state = reply.regs[0] as u8;
        info.our_ip = reply.regs[1] as u32;
        info.subnet_mask = reply.regs[2] as u32;
        info.gateway_ip = reply.regs[3] as u32;
        info.dns_server = reply.regs[4] as u32;
        info.rx_bytes = reply.regs[5];
        info.rx_packets = reply.regs[6];
        info.tx_bytes = reply.regs[7];
        info.tx_packets = reply.regs[8];
        true
    }
}

// SAFETY: caller must ensure VFS is single-threaded and the server EP is valid.
pub(super) unsafe fn netsrv_get_arp_entry(index: usize, ip: &mut u32, mac: &mut [u8; 6]) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = NET_GET_ARP_ENTRY;
        msg.length = 1;
        msg.regs[0] = index as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK || reply.regs[0] == 0 {
            return false;
        }

        *ip = reply.regs[1] as u32;
        let packed = reply.regs[2];
        mac[0] = (packed >> 40) as u8;
        mac[1] = (packed >> 32) as u8;
        mac[2] = (packed >> 24) as u8;
        mac[3] = (packed >> 16) as u8;
        mac[4] = (packed >> 8) as u8;
        mac[5] = packed as u8;
        true
    }
}

pub(super) fn proc_gen_hosts(buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    append_bytes(buf, &mut pos, b"127.0.0.1\tlocalhost\n");
    let mut info = NetConfigInfo::zeroed();
    // SAFETY: VFS is single-threaded; the query uses a valid server EP.
    if unsafe { netsrv_get_config(&mut info) } && info.our_ip != 0 {
        append_ipv4(buf, &mut pos, info.our_ip);
        append_bytes(buf, &mut pos, b"\tsalty\n");
    }
    pos
}

pub(super) fn proc_gen_resolv_conf(buf: &mut [u8]) -> usize {
    let mut info = NetConfigInfo::zeroed();
    // SAFETY: VFS is single-threaded; the query uses a valid server EP.
    if !unsafe { netsrv_get_config(&mut info) } || info.dns_server == 0 {
        return 0;
    }

    let mut pos = 0usize;
    append_bytes(buf, &mut pos, b"nameserver ");
    append_ipv4(buf, &mut pos, info.dns_server);
    append_bytes(buf, &mut pos, b"\n");
    pos
}

pub(super) fn proc_gen_route(buf: &mut [u8]) -> usize {
    let mut info = NetConfigInfo::zeroed();
    // SAFETY: VFS is single-threaded; the query uses a valid server EP.
    if !unsafe { netsrv_get_config(&mut info) } {
        return 0;
    }

    let mut pos = 0usize;
    append_bytes(
        buf,
        &mut pos,
        b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
    );

    if info.our_ip != 0 && info.subnet_mask != 0 {
        append_bytes(buf, &mut pos, b"eth0\t");
        append_hex_u32_fixed(buf, &mut pos, (info.our_ip & info.subnet_mask).swap_bytes());
        append_bytes(buf, &mut pos, b"\t00000000\t0001\t0\t0\t0\t");
        append_hex_u32_fixed(buf, &mut pos, info.subnet_mask.swap_bytes());
        append_bytes(buf, &mut pos, b"\t0\t0\t0\n");
    }

    if info.gateway_ip != 0 {
        append_bytes(buf, &mut pos, b"eth0\t00000000\t");
        append_hex_u32_fixed(buf, &mut pos, info.gateway_ip.swap_bytes());
        append_bytes(buf, &mut pos, b"\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
    }

    pos
}

pub(super) fn proc_gen_arp(buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    append_bytes(buf, &mut pos, b"IP address\tHW type\tFlags\tHW address\tMask\tDevice\n");

    let mut idx = 0usize;
    while idx < MAX_NET_ARP_ENTRIES {
        let mut ip = 0u32;
        let mut mac = [0u8; 6];
        // SAFETY: VFS is single-threaded; the query uses a valid server EP.
        if unsafe { netsrv_get_arp_entry(idx, &mut ip, &mut mac) } {
            append_ipv4(buf, &mut pos, ip);
            append_bytes(buf, &mut pos, b"\t0x1\t0x2\t");
            append_mac(buf, &mut pos, &mac);
            append_bytes(buf, &mut pos, b"\t*\teth0\n");
        }
        idx += 1;
    }

    pos
}

pub(super) fn proc_gen_net_dev(buf: &mut [u8]) -> usize {
    let mut info = NetConfigInfo::zeroed();
    // SAFETY: VFS is single-threaded; the query uses a valid server EP.
    if !unsafe { netsrv_get_config(&mut info) } {
        return 0;
    }

    let mut pos = 0usize;
    append_bytes(buf, &mut pos, b"Inter-|   Receive                                                |  Transmit\n");
    append_bytes(buf, &mut pos, b" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
    append_bytes(buf, &mut pos, b" eth0:");
    append_u64_dec(buf, &mut pos, info.rx_bytes);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, info.rx_packets);
    append_bytes(buf, &mut pos, b" 0 0 0 0 0 0 ");
    append_u64_dec(buf, &mut pos, info.tx_bytes);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, info.tx_packets);
    append_bytes(buf, &mut pos, b" 0 0 0 0 0 0\n");
    pos
}
