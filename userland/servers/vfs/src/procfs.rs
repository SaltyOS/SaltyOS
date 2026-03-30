// SPDX-License-Identifier: GPL-2.0-only
//! /proc filesystem implementation.

use besalt::consts::*;
use besalt::ipc;
use besalt::types::*;

use crate::client::{get_client, get_client_noalloc};
use crate::consts::*;
use crate::ipc_ctx;
use crate::ramfs::{alloc_inode, inode_by_ino, inode_open};
use crate::types::*;

pub(crate) fn parse_pid(buf: &[u8]) -> (u32, bool) {
    if buf.is_empty() || buf.len() > 10 {
        return (0, false);
    }
    let mut val: u32 = 0;
    for &b in buf {
        if b < b'0' || b > b'9' {
            return (0, false);
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
    }
    (val, true)
}

/// Format u32 as decimal into buf. Returns number of bytes written.
pub(crate) fn fmt_u32(mut v: u32, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v > 0 && len < 10 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

/// Format u64 as hex into buf. Returns number of bytes written.
pub(crate) fn fmt_u64_hex(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if buf.len() >= 3 {
            buf[0] = b'0';
            buf[1] = b'x';
            buf[2] = b'0';
            return 3;
        }
        return 0;
    }
    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    while v > 0 && len < 16 {
        let d = (v & 0xf) as u8;
        tmp[len] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v >>= 4;
        len += 1;
    }
    if buf.len() < len + 2 {
        return 0;
    }
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..len {
        buf[2 + i] = tmp[len - 1 - i];
    }
    len + 2
}

const PROC_TEXT_BUF_SIZE: usize = 2048;
const MAX_NET_ARP_ENTRIES: usize = 16;

#[derive(Clone, Copy)]
struct NetConfigInfo {
    state: u8,
    our_ip: u32,
    subnet_mask: u32,
    gateway_ip: u32,
    dns_server: u32,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
}

impl NetConfigInfo {
    const fn zeroed() -> Self {
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

fn append_bytes(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
    let mut i = 0usize;
    while i < data.len() && *pos < buf.len() {
        buf[*pos] = data[i];
        *pos += 1;
        i += 1;
    }
}

fn append_u32_dec(buf: &mut [u8], pos: &mut usize, v: u32) {
    let mut tmp = [0u8; 16];
    let len = fmt_u32(v, &mut tmp);
    append_bytes(buf, pos, &tmp[..len]);
}

fn append_u64_dec(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    if v == 0 {
        append_bytes(buf, pos, b"0");
        return;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        append_bytes(buf, pos, &tmp[len..len + 1]);
    }
}

fn append_ipv4(buf: &mut [u8], pos: &mut usize, ip: u32) {
    append_u32_dec(buf, pos, (ip >> 24) & 0xFF);
    append_bytes(buf, pos, b".");
    append_u32_dec(buf, pos, (ip >> 16) & 0xFF);
    append_bytes(buf, pos, b".");
    append_u32_dec(buf, pos, (ip >> 8) & 0xFF);
    append_bytes(buf, pos, b".");
    append_u32_dec(buf, pos, ip & 0xFF);
}

fn append_mac(buf: &mut [u8], pos: &mut usize, mac: &[u8; 6]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0usize;
    while i < 6 {
        let b = mac[i];
        append_bytes(buf, pos, &[HEX[(b >> 4) as usize], HEX[(b & 0x0F) as usize]]);
        if i != 5 {
            append_bytes(buf, pos, b":");
        }
        i += 1;
    }
}

fn append_hex_u32_fixed(buf: &mut [u8], pos: &mut usize, mut v: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [0u8; 8];
    let mut i = 8usize;
    while i > 0 {
        i -= 1;
        out[i] = HEX[(v & 0x0F) as usize];
        v >>= 4;
    }
    append_bytes(buf, pos, &out);
}

unsafe fn netsrv_get_config(info: &mut NetConfigInfo) -> bool {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = NET_GET_CONFIG;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != BESALT_OK {
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

unsafe fn netsrv_get_arp_entry(index: usize, ip: &mut u32, mac: &mut [u8; 6]) -> bool {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = NET_GET_ARP_ENTRY;
        msg.length = 1;
        msg.regs[0] = index as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != BESALT_OK || reply.regs[0] == 0 {
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

fn proc_gen_hosts(buf: &mut [u8]) -> usize {
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

fn proc_gen_resolv_conf(buf: &mut [u8]) -> usize {
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

fn proc_gen_route(buf: &mut [u8]) -> usize {
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

fn proc_gen_arp(buf: &mut [u8]) -> usize {
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

fn proc_gen_net_dev(buf: &mut [u8]) -> usize {
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

/// Query procmgr for list of PIDs. Returns count (up to 19).
unsafe fn proc_list_pids(pids: &mut [u32; 19]) -> usize {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = POSIX_PM_LIST_PIDS;
        msg.length = 0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != BESALT_OK {
            return 0;
        }
        let count = reply.regs[19] as usize;
        let n = if count > 19 { 19 } else { count };
        for i in 0..n {
            pids[i] = reply.regs[i] as u32;
        }
        n
    }
}

/// Query procmgr for process info. Returns true on success.
unsafe fn proc_get_info(
    pid: u32,
    ppid: &mut u32,
    pgid: &mut u32,
    sid: &mut u32,
    state: &mut u8,
    name: &mut [u8; 32],
) -> bool {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = POSIX_PM_GET_PROC_INFO;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != BESALT_OK {
            return false;
        }
        *ppid = reply.regs[1] as u32;
        *pgid = reply.regs[2] as u32;
        *sid = reply.regs[3] as u32;
        *state = reply.regs[4] as u8;
        let src = &reply.regs[5] as *const u64 as *const u8;
        for i in 0..32 {
            name[i] = *src.add(i);
        }
        true
    }
}

/// Query mmsrv for client memory stats. Returns true on success.
unsafe fn proc_get_mem_stats(
    pid: u32,
    heap_base: &mut u64,
    heap_current: &mut u64,
    region_count: &mut u64,
    total_pages: &mut u64,
) -> bool {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = MM_GET_CLIENT_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != BESALT_OK {
            return false;
        }
        *heap_base = reply.regs[0];
        *heap_current = reply.regs[1];
        *region_count = reply.regs[2];
        *total_pages = reply.regs[3];
        true
    }
}

/// Generate /proc/<pid>/status content. Returns bytes written.
unsafe fn proc_gen_status(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        if !proc_get_info(pid, &mut ppid, &mut pgid, &mut sid, &mut state, &mut name) {
            return 0;
        }

        // Find name length
        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            name[0] = b'?';
            name_len = 1;
        }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "Name:\t<name>\n"
        let hdr = b"Name:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        for i in 0..name_len {
            if pos < buf_size {
                *buf.add(pos) = name[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "State:\t<R/Z/T>\n"
        let hdr = b"State:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let st_char = match state {
            1 => b'R',
            2 => b'Z',
            3 => b'T',
            _ => b'?',
        };
        if pos < buf_size {
            *buf.add(pos) = st_char;
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "Pid:\t<pid>\n"
        let hdr = b"Pid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "PPid:\t<ppid>\n"
        let hdr = b"PPid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "Pgid:\t<pgid>\n"
        let hdr = b"Pgid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "Sid:\t<sid>\n"
        let hdr = b"Sid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        pos
    }
}

/// Generate /proc/<pid>/stat content (single-line). Returns bytes written.
unsafe fn proc_gen_stat(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        if !proc_get_info(pid, &mut ppid, &mut pgid, &mut sid, &mut state, &mut name) {
            return 0;
        }

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            name[0] = b'?';
            name_len = 1;
        }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "<pid> (<name>) <state> <ppid> <pgid> <sid>\n"
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b'(';
            pos += 1;
        }
        for i in 0..name_len {
            if pos < buf_size {
                *buf.add(pos) = name[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b')';
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let st_char = match state {
            1 => b'R',
            2 => b'Z',
            3 => b'T',
            _ => b'?',
        };
        if pos < buf_size {
            *buf.add(pos) = st_char;
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        pos
    }
}

/// Handle open for /proc paths. Creates temporary proc file inode.
/// Returns true if handled (and reply is set), false if not a /proc path.
pub(crate) unsafe fn handle_proc_open(
    path: *const u8,
    path_len: u8,
    reply: *mut BesaltMsg,
    badge: u64,
) -> bool {
    unsafe {
        // Check if path starts with "/proc/"
        if path_len < 6 {
            return false;
        }
        let proc_prefix = b"/proc/";
        for i in 0..6 {
            if *path.add(i) != proc_prefix[i] {
                return false;
            }
        }

        let rest = path.add(6);
        let rest_len = path_len - 6;

        // Check for /proc/self -> resolve to client's PID
        let is_self_prefix = rest_len >= 4
            && *rest == b's'
            && *rest.add(1) == b'e'
            && *rest.add(2) == b'l'
            && *rest.add(3) == b'f';
        let is_net_prefix = rest_len >= 3
            && *rest == b'n'
            && *rest.add(1) == b'e'
            && *rest.add(2) == b't'
            && (rest_len == 3 || *rest.add(3) == b'/');

        if is_net_prefix {
            return false;
        }

        let (pid, file_offset) = if is_self_prefix && (rest_len == 4 || *rest.add(4) == b'/') {
            let cli = get_client_noalloc(badge);
            if cli.is_null() {
                (*reply).label = BESALT_NOT_FOUND;
                return true;
            }
            // Client badge encodes PID: badge = pid
            let client_pid = (badge & 0xFFFF) as u32;
            if rest_len == 4 {
                // /proc/self (just the dir itself)
                (client_pid, 4u8)
            } else {
                (client_pid, 5u8) // skip "self/"
            }
        } else {
            // /proc/<pid>/... — parse numeric PID
            let mut pid_end = 0u8;
            while (pid_end as usize) < rest_len as usize && *rest.add(pid_end as usize) != b'/' {
                pid_end += 1;
            }
            let mut pid_buf = [0u8; 10];
            for i in 0..pid_end as usize {
                if i < 10 {
                    pid_buf[i] = *rest.add(i);
                }
            }
            let (pid, ok) = parse_pid(&pid_buf[..pid_end as usize]);
            if !ok {
                return false;
            }
            (pid, pid_end)
        };

        // What file under /proc/<pid>/?
        let after_pid = rest.add(file_offset as usize);
        let after_len = if file_offset < rest_len {
            rest_len - file_offset
        } else {
            0
        };

        if after_len == 0 {
            // /proc/<pid> — the directory itself; open as dir
            let inode = alloc_inode();
            if inode.is_null() {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return true;
            }
            (*inode).ftype = FTYPE_PROC_FILE;
            (*inode).dev_type = PROC_FILE_PID_DIR;
            (*inode).mode = S_IFDIR_L | 0o555;
            (*inode).readonly = 1;
            (*inode).nlink = 0; // temp inode — freed when last FD closes
            (*inode).size = pid as u64; // store PID in size field

            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                (*inode).active = 0;
                return true;
            }
            for fd in 0..(*cli).fds_cap as usize {
                if (*(*cli).fds.add(fd)).active == 0 {
                    (*(*cli).fds.add(fd)).active = 1;
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                    (*(*cli).fds.add(fd)).inode = (*inode).ino;
                    (*(*cli).fds.add(fd)).offset = 0;
                    (*(*cli).fds.add(fd)).dir_cursor = 0;
                    inode_open((*inode).ino);
                    (*reply).label = BESALT_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return true;
                }
            }
            (*inode).active = 0;
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return true;
        }

        // Skip leading '/'
        let (file_name, file_name_len) = if after_len > 0 && *after_pid == b'/' {
            (after_pid.add(1), after_len - 1)
        } else {
            (after_pid, after_len)
        };

        // Determine file type
        let proc_type = if file_name_len == 6 && mem_eq(file_name, b"status".as_ptr(), 6) {
            PROC_FILE_STATUS
        } else if file_name_len == 4 && mem_eq(file_name, b"stat".as_ptr(), 4) {
            PROC_FILE_STAT
        } else if file_name_len == 4 && mem_eq(file_name, b"maps".as_ptr(), 4) {
            PROC_FILE_MAPS
        } else {
            (*reply).label = BESALT_NOT_FOUND;
            return true;
        };

        // Allocate temporary inode for this proc file
        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return true;
        }
        (*inode).ftype = FTYPE_PROC_FILE;
        (*inode).dev_type = proc_type;
        (*inode).mode = S_IFREG_L | 0o444;
        (*inode).readonly = 1;
        (*inode).nlink = 0; // temp inode — freed when last FD closes
        (*inode).size = pid as u64; // store PID in size field

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            (*inode).active = 0;
            return true;
        }
        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                (*(*cli).fds.add(fd)).flags = 0; // O_RDONLY
                inode_open((*inode).ino);
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return true;
            }
        }
        (*inode).active = 0;
        (*reply).label = BESALT_OUT_OF_MEMORY;
        true
    }
}

/// Simple memory comparison (no libc).
pub(crate) fn mem_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    for i in 0..len {
        unsafe {
            if *a.add(i) != *b.add(i) {
                return false;
            }
        }
    }
    true
}

/// Handle stat/lstat for /proc virtual paths that don't resolve as real inodes.
/// Returns true if the path was handled (even if error).
pub(crate) unsafe fn handle_proc_stat(
    path: *const u8,
    path_len: u8,
    reply: *mut BesaltMsg,
    badge: u64,
) -> bool {
    unsafe {
        // Path must start with "/proc/" (caller already checked)
        if path_len < 6 {
            return false;
        }

        let rest = path.add(6);
        let rest_len = path_len - 6;

        // Parse "self" or numeric PID
        let is_self_prefix = rest_len >= 4
            && *rest == b's'
            && *rest.add(1) == b'e'
            && *rest.add(2) == b'l'
            && *rest.add(3) == b'f';
        let is_net_prefix = rest_len >= 3
            && *rest == b'n'
            && *rest.add(1) == b'e'
            && *rest.add(2) == b't'
            && (rest_len == 3 || *rest.add(3) == b'/');

        if is_net_prefix {
            return false;
        }

        let (pid, file_offset) = if is_self_prefix && (rest_len == 4 || *rest.add(4) == b'/') {
            let client_pid = (badge & 0xFFFF) as u32;
            if rest_len == 4 {
                (client_pid, 4u8)
            } else {
                (client_pid, 5u8)
            }
        } else {
            let mut pid_end = 0u8;
            while (pid_end as usize) < rest_len as usize && *rest.add(pid_end as usize) != b'/' {
                pid_end += 1;
            }
            let (pid, ok) = parse_pid(&core::slice::from_raw_parts(rest, pid_end as usize));
            if !ok {
                return false;
            }
            (pid, pid_end)
        };

        let after_pid = rest.add(file_offset as usize);
        let after_len = if file_offset < rest_len {
            rest_len - file_offset
        } else {
            0
        };

        if after_len == 0 {
            // /proc/<pid> — directory
            (*reply).label = BESALT_OK;
            (*reply).length = 8;
            (*reply).regs[0] = pid as u64; // ino
            (*reply).regs[1] = (S_IFDIR_L | 0o555) as u64; // mode
            (*reply).regs[2] = 2; // nlink
            (*reply).regs[3] = 0; // size
            (*reply).regs[4] = 0; // uid
            (*reply).regs[5] = 0; // gid
            (*reply).regs[6] = 0; // mtime
            (*reply).regs[7] = FTYPE_PROC_FILE as u64;
            return true;
        }

        let (file_name, file_name_len) = if after_len > 0 && *after_pid == b'/' {
            (after_pid.add(1), after_len - 1)
        } else {
            (after_pid, after_len)
        };

        let is_known = (file_name_len == 6 && mem_eq(file_name, b"status".as_ptr(), 6))
            || (file_name_len == 4 && mem_eq(file_name, b"stat".as_ptr(), 4))
            || (file_name_len == 4 && mem_eq(file_name, b"maps".as_ptr(), 4));

        if !is_known {
            (*reply).label = BESALT_NOT_FOUND;
            return true;
        }

        // Regular file stat
        (*reply).label = BESALT_OK;
        (*reply).length = 8;
        (*reply).regs[0] = 0; // ino (virtual)
        (*reply).regs[1] = (S_IFREG_L | 0o444) as u64; // mode
        (*reply).regs[2] = 1; // nlink
        (*reply).regs[3] = 0; // size (unknown for virtual files)
        (*reply).regs[4] = 0; // uid
        (*reply).regs[5] = 0; // gid
        (*reply).regs[6] = 0; // mtime
        (*reply).regs[7] = FTYPE_PROC_FILE as u64;
        true
    }
}

/// Handle read for FTYPE_PROC_FILE inodes.
/// Generates content on-the-fly from procmgr/mmsrv.
pub(crate) unsafe fn handle_proc_read(inode: *const RamfsInode, offset: u64, reply: *mut BesaltMsg) {
    unsafe {
        let pid = (*inode).size as u32;
        let proc_type = (*inode).dev_type;

        // Generate content into a stack buffer
        let mut content = [0u8; PROC_TEXT_BUF_SIZE];
        let content_len = match proc_type {
            PROC_FILE_STATUS => proc_gen_status(pid, content.as_mut_ptr(), PROC_TEXT_BUF_SIZE),
            PROC_FILE_STAT => proc_gen_stat(pid, content.as_mut_ptr(), PROC_TEXT_BUF_SIZE),
            PROC_FILE_MAPS => {
                // /proc/<pid>/maps — query mmsrv for memory stats
                let mut heap_base: u64 = 0;
                let mut heap_current: u64 = 0;
                let mut region_count: u64 = 0;
                let mut total_pages: u64 = 0;
                if proc_get_mem_stats(
                    pid,
                    &mut heap_base,
                    &mut heap_current,
                    &mut region_count,
                    &mut total_pages,
                ) {
                    let mut pos = 0usize;
                    let mut tmp = [0u8; 20];
                    // "heap: <base>-<current> <pages> pages\n"
                    let hdr = b"heap: ";
                    for b in hdr {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = *b;
                            pos += 1;
                        }
                    }
                    let n = fmt_u64_hex(heap_base, &mut tmp);
                    for i in 0..n {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = tmp[i];
                            pos += 1;
                        }
                    }
                    if pos < PROC_TEXT_BUF_SIZE {
                        content[pos] = b'-';
                        pos += 1;
                    }
                    let n = fmt_u64_hex(heap_current, &mut tmp);
                    for i in 0..n {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = tmp[i];
                            pos += 1;
                        }
                    }
                    if pos < PROC_TEXT_BUF_SIZE {
                        content[pos] = b'\n';
                        pos += 1;
                    }
                    // "regions: <count>\n"
                    let hdr = b"regions: ";
                    for b in hdr {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = *b;
                            pos += 1;
                        }
                    }
                    let n = fmt_u32(region_count as u32, &mut tmp);
                    for i in 0..n {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = tmp[i];
                            pos += 1;
                        }
                    }
                    if pos < PROC_TEXT_BUF_SIZE {
                        content[pos] = b'\n';
                        pos += 1;
                    }
                    // "pages: <total>\n"
                    let hdr = b"pages: ";
                    for b in hdr {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = *b;
                            pos += 1;
                        }
                    }
                    let n = fmt_u32(total_pages as u32, &mut tmp);
                    for i in 0..n {
                        if pos < PROC_TEXT_BUF_SIZE {
                            content[pos] = tmp[i];
                            pos += 1;
                        }
                    }
                    if pos < PROC_TEXT_BUF_SIZE {
                        content[pos] = b'\n';
                        pos += 1;
                    }
                    pos
                } else {
                    0
                }
            }
            PROC_FILE_NET_ROUTE => proc_gen_route(&mut content),
            PROC_FILE_NET_ARP => proc_gen_arp(&mut content),
            PROC_FILE_NET_DEV => proc_gen_net_dev(&mut content),
            PROC_FILE_ETC_HOSTS => proc_gen_hosts(&mut content),
            PROC_FILE_ETC_RESOLV_CONF => proc_gen_resolv_conf(&mut content),
            _ => 0,
        };

        if offset as usize >= content_len {
            // EOF
            (*reply).label = BESALT_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let available = content_len - offset as usize;
        let max_ipc = 152; // 19 regs * 8 bytes
        let to_copy = if available < max_ipc {
            available
        } else {
            max_ipc
        };

        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        for i in 0..to_copy {
            *dst.add(i) = content[offset as usize + i];
        }
        (*reply).label = BESALT_OK;
        (*reply).length = 1 + ((to_copy as u64 + 7) / 8);
        (*reply).regs[0] = to_copy as u64;
    }
}

/// Handle readdir for /proc root — returns PID entries.
pub(crate) unsafe fn handle_proc_readdir(
    inode: *const RamfsInode,
    cursor: u32,
    reply: *mut BesaltMsg,
) {
    unsafe {
        if (*inode).dev_type == PROC_FILE_ROOT {
            // /proc root readdir: list "self", "net", then PIDs
            let mut pids = [0u32; 19];
            let count = proc_list_pids(&mut pids);

            // cursor 0 = "self", cursor 1 = "net", then PIDs
            if cursor == 0 {
                // Return "self" entry
                (*reply).label = BESALT_OK;
                (*reply).regs[0] = 4; // name_len = 4
                (*reply).regs[1] = cursor as u64 + 1; // next cursor
                (*reply).regs[2] = 0; // ino
                (*reply).regs[3] = 10; // DT_LNK
                let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
                *dst = b's';
                *dst.add(1) = b'e';
                *dst.add(2) = b'l';
                *dst.add(3) = b'f';
                (*reply).length = 5;
                return;
            }

            if cursor == 1 {
                (*reply).label = BESALT_OK;
                (*reply).regs[0] = 3;
                (*reply).regs[1] = 2;
                (*reply).regs[2] = 0;
                (*reply).regs[3] = 4;
                let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
                *dst = b'n';
                *dst.add(1) = b'e';
                *dst.add(2) = b't';
                (*reply).length = 5;
                return;
            }

            let idx = (cursor - 2) as usize;
            if idx >= count {
                // No more entries
                (*reply).label = BESALT_OK;
                (*reply).regs[0] = 0; // name_len = 0 → end
                (*reply).length = 1;
                return;
            }

            // Format PID as string
            let mut name_buf = [0u8; 10];
            let name_len = fmt_u32(pids[idx], &mut name_buf);

            (*reply).label = BESALT_OK;
            (*reply).regs[0] = name_len as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = pids[idx] as u64; // ino = pid
            (*reply).regs[3] = 4; // DT_DIR
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..name_len {
                *dst.add(i) = name_buf[i];
            }
            (*reply).length = 5;
        } else if (*inode).dev_type == PROC_FILE_NET_DIR {
            let entries: &[&[u8]] = &[b"route", b"arp", b"dev"];
            let cursor_idx = cursor as usize;
            if cursor_idx >= entries.len() {
                (*reply).label = BESALT_OK;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
            let entry = entries[cursor_idx];
            (*reply).label = BESALT_OK;
            (*reply).regs[0] = entry.len() as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = 0;
            (*reply).regs[3] = 8;
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..entry.len() {
                *dst.add(i) = entry[i];
            }
            (*reply).length = 5;
        } else if (*inode).dev_type == PROC_FILE_PID_DIR {
            // /proc/<pid> readdir: list status, stat, maps
            let entries: &[&[u8]] = &[b"status", b"stat", b"maps"];
            let cursor_idx = cursor as usize;
            if cursor_idx >= entries.len() {
                (*reply).label = BESALT_OK;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
            let entry = entries[cursor_idx];
            (*reply).label = BESALT_OK;
            (*reply).regs[0] = entry.len() as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = 0; // ino
            (*reply).regs[3] = 8; // DT_REG
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..entry.len() {
                *dst.add(i) = entry[i];
            }
            (*reply).length = 5;
        } else {
            (*reply).label = BESALT_NOT_FOUND;
        }
    }
}
