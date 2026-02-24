// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS Network Stack Server (netsrv)
//!
//! Runs as a userspace process and owns the full TCP/UDP/IP/ARP/ICMP protocol
//! stack. Communicates with netdrv (hardware driver) via SHM ring buffers and
//! notification signaling. Exposes a NET_* IPC interface for VFS to forward
//! POSIX socket operations.
//!
//! Cap layout:
//!   0  = self TCB
//!   2  = self CSpace
//!   5  = nameserv endpoint
//!   7  = mmsrv endpoint
//!   14 = readiness notification
//!   64 = netdrv endpoint (NeedEP=netdrv:64)
//!   65 = nameserv endpoint #2 (NeedEP=nameserv:65, for registration)
//!   68 = server endpoint (pre-created service EP)
//!   80 = RX notification (allocated via mmsrv)
//!   81 = RX notification badged (minted with badge 0x1, sent to netdrv)
//!   82 = TX notification (received from netdrv during DRIVER_REGISTER)
//!   83 = VFS callback endpoint (received from VFS via NET_REGISTER_VFS)

#![no_std]
#![no_main]

extern crate salty;

mod net;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

// ---------------------------------------------------------------------------
// Capability slot layout
// ---------------------------------------------------------------------------

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_MMSRV_EP: u64 = 7;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NETDRV_EP: u64 = 64;
const CAP_NAMESERV_EP2: u64 = 65;
const CAP_SERVER_EP: u64 = 68;
const CAP_RX_NOTIFICATION: u64 = 80;
const CAP_RX_NOTIFICATION_BADGED: u64 = 81;
const CAP_TX_NOTIFICATION: u64 = 82;
const CAP_VFS_CALLBACK_EP: u64 = 83;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;
const SHM_VADDR: u64 = 0x0000_0000_6000_0000;
const NET_SHM_ID: u64 = 0x4E455400; // "NET\0"
const NET_SHM_PAGES: u64 = 32;
const RX_BADGE: u64 = 0x1;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static mut MAC_ADDR: [u8; 6] = [0; 6];
static mut VFS_REGISTERED: bool = false;
static mut SHM_BASE: u64 = 0;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

pub(crate) fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

pub(crate) fn mac_addr() -> [u8; 6] {
    // SAFETY: MAC_ADDR is set during init before any use; single-threaded.
    unsafe { *(&raw const MAC_ADDR) }
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// SHM ring buffer access
// ---------------------------------------------------------------------------

/// Write a frame to the SHM TX ring. Returns true on success.
pub(crate) fn shm_tx_enqueue(frame: &[u8]) -> bool {
    // SAFETY: SHM_BASE is set during init; single-threaded.
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return false;
        }
        let hdr = base as *mut u32;
        let tx_head = *hdr.add(2); // offset 0x08
        let tx_tail = core::ptr::read_volatile(hdr.add(3)); // offset 0x0C, netdrv writes this
        let slot_count = *hdr.add(5); // offset 0x14
        if slot_count == 0 {
            return false;
        }
        let next = (tx_head + 1) % slot_count;
        if next == tx_tail {
            return false; // ring full
        }

        let slot_base = base + 0x11000 + (tx_head as u64) * 2048;
        let len = core::cmp::min(frame.len(), 1998);
        let len_ptr = slot_base as *mut u16;
        *len_ptr = len as u16;
        let data_ptr = (slot_base + 2) as *mut u8;
        core::ptr::copy_nonoverlapping(frame.as_ptr(), data_ptr, len);

        // Store fence: ensure frame data is visible before updating head
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(hdr.add(2), next);
        true
    }
}

/// Signal netdrv that TX frames are available.
pub(crate) fn signal_netdrv_tx() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_TX_NOTIFICATION, 1, 0, 0, 0, 0);
}

/// Read a frame from the SHM RX ring. Returns the frame length on success.
fn shm_rx_dequeue(buf: &mut [u8; 2048]) -> Option<usize> {
    // SAFETY: SHM_BASE is set during init; single-threaded.
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return None;
        }
        let hdr = base as *mut u32;
        let rx_head = core::ptr::read_volatile(hdr.add(0)); // netdrv writes this
        let rx_tail = *hdr.add(1);
        if rx_head == rx_tail {
            return None; // empty
        }

        let slot_base = base + 0x1000 + (rx_tail as u64) * 2048;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let len = *(slot_base as *const u16) as usize;
        let len = core::cmp::min(len, 1998);
        let data = (slot_base + 2) as *const u8;
        core::ptr::copy_nonoverlapping(data, buf.as_mut_ptr(), len);

        let slot_count = *hdr.add(4); // offset 0x10
        if slot_count == 0 {
            return None;
        }
        core::ptr::write_volatile(hdr.add(1), (rx_tail + 1) % slot_count);
        Some(len)
    }
}

// ---------------------------------------------------------------------------
// Startup: SHM allocation and mapping
// ---------------------------------------------------------------------------

fn setup_shm() -> bool {
    let ctx = ipc_ctx();

    // Create SHM
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.regs[0] = NET_SHM_ID;
    msg.regs[1] = NET_SHM_PAGES;
    msg.length = 2;
    let mut reply = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != SALTY_OK && reply.label != SALTY_ALREADY_EXISTS) {
        let mut lb = LineBuf::new();
        lb.str(b"[netsrv] SHM create failed: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Map SHM
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.regs[0] = NET_SHM_ID;
    msg.regs[1] = 0;
    msg.regs[2] = SHM_VADDR;
    msg.regs[3] = 0x3; // RW
    msg.length = 4;
    let mut reply = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != SALTY_OK {
        let mut lb = LineBuf::new();
        lb.str(b"[netsrv] SHM map failed: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Initialize SHM header
    // SAFETY: SHM is mapped at SHM_VADDR; single-threaded init.
    unsafe {
        *(&raw mut SHM_BASE) = SHM_VADDR;
        let hdr = SHM_VADDR as *mut u32;
        *hdr.add(0) = 0; // rx_head
        *hdr.add(1) = 0; // rx_tail
        *hdr.add(2) = 0; // tx_head
        *hdr.add(3) = 0; // tx_tail
        *hdr.add(4) = 32; // rx_slot_count
        *hdr.add(5) = 32; // tx_slot_count
    }

    puts(b"[netsrv] SHM allocated and mapped\n");
    true
}

// ---------------------------------------------------------------------------
// Startup: Notification allocation and binding
// ---------------------------------------------------------------------------

fn setup_notification() -> bool {
    let ctx = ipc_ctx();

    // Allocate Notification via mmsrv (MM_ALLOC_OBJECT with OBJ_NOTIFICATION)
    // SAFETY: IPC context is valid; set up receive slot for cap transfer.
    unsafe {
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_RX_NOTIFICATION, 0);
    }
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_ALLOC_OBJECT;
    msg.regs[0] = OBJ_NOTIFICATION;
    msg.regs[1] = 0;
    msg.length = 2;
    let mut reply = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != SALTY_OK {
        let mut lb = LineBuf::new();
        lb.str(b"[netsrv] Failed to allocate notification: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Bind notification to our TCB
    let err = invoke::tcb_bind_notification(CAP_SELF_TCB, CAP_RX_NOTIFICATION);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[netsrv] Failed to bind notification to TCB: ");
        lb.dec(err as u64);
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Mint badged copy (badge 0x1 = RX_BADGE)
    let err = invoke::cnode_mint(
        CAP_SELF_CSPACE,
        CAP_RX_NOTIFICATION,
        CAP_SELF_CSPACE,
        CAP_RX_NOTIFICATION_BADGED,
        RX_BADGE,
    );
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[netsrv] Failed to mint badged notification: ");
        lb.dec(err as u64);
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    puts(b"[netsrv] Notification allocated and bound\n");
    true
}

// ---------------------------------------------------------------------------
// Startup: Register with netdrv via DRIVER_REGISTER
// ---------------------------------------------------------------------------

fn driver_register() -> bool {
    let ctx = ipc_ctx();

    // Send DRIVER_REGISTER to netdrv EP (slot 64)
    // extra_caps=1: send badged RX notification (slot 81) to netdrv
    // SAFETY: IPC context is valid; setting up send/receive caps.
    unsafe {
        ipc::set_send_cap_ctx(ctx, 0, CAP_RX_NOTIFICATION_BADGED);
        // Set receive slot for TX notification from netdrv
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_TX_NOTIFICATION, 0);
    }

    let mut msg = SaltyMsg::zeroed();
    msg.label = DRIVER_REGISTER; // 0xC0
    msg.regs[0] = NET_SHM_ID;
    msg.length = 1;
    let mut reply = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to netdrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_NETDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != SALTY_OK {
        let mut lb = LineBuf::new();
        lb.str(b"[netsrv] DRIVER_REGISTER failed: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Extract MAC from reply: MR0 = mac[0..4] as u32, MR1 = mac[4..6] as u16
    let mac_lo = reply.regs[0] as u32;
    let mac_hi = reply.regs[1] as u16;
    // SAFETY: Single-threaded init; MAC_ADDR written once before use.
    unsafe {
        let mac = &raw mut MAC_ADDR;
        (*mac)[0] = (mac_lo >> 24) as u8;
        (*mac)[1] = (mac_lo >> 16) as u8;
        (*mac)[2] = (mac_lo >> 8) as u8;
        (*mac)[3] = mac_lo as u8;
        (*mac)[4] = (mac_hi >> 8) as u8;
        (*mac)[5] = mac_hi as u8;
    }

    let mut lb = LineBuf::new();
    lb.str(b"[netsrv] Registered with netdrv, MAC=");
    let mac = mac_addr();
    let mut i = 0;
    while i < 6 {
        lb.hex(mac[i] as u64);
        if i < 5 {
            lb.putc(b':');
        }
        i += 1;
    }
    lb.putc(b'\n');
    lb.flush();
    true
}

// ---------------------------------------------------------------------------
// Startup: Register with name service
// ---------------------------------------------------------------------------

fn register_nameserv() {
    let name = b"netsrv";
    let mut msg = SaltyMsg::zeroed();
    msg.label = POSIX_NS_REGISTER;
    msg.regs[0] = name.len() as u64;
    msg.length = 1 + (name.len() as u64 + 7) / 8;
    // SAFETY: Writing name bytes into message register space; IPC context is valid.
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        let mut i = 0;
        while i < name.len() {
            *dst.add(i) = name[i];
            i += 1;
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_NAMESERV_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            puts(b"[netsrv] nameserv registration failed\n");
        }
    }
}

// ---------------------------------------------------------------------------
// Packet processing
// ---------------------------------------------------------------------------

/// Dispatch a received Ethernet frame through the protocol stack.
fn process_packet(data: &[u8]) {
    if let Some((eth_hdr, payload)) = net::ethernet::parse(data) {
        match eth_hdr.ethertype {
            net::ethernet::ETHERTYPE_ARP => {
                net::arp::handle_packet(&mac_addr(), net::ipv4::OUR_IP, payload);
            }
            net::ethernet::ETHERTYPE_IPV4 => {
                if let Some((ip_hdr, ip_payload)) = net::ipv4::parse(payload) {
                    match ip_hdr.protocol {
                        net::ipv4::PROTO_ICMP => {
                            net::icmp::handle(
                                &mac_addr(),
                                net::ipv4::OUR_IP,
                                &ip_hdr,
                                ip_payload,
                            );
                        }
                        net::ipv4::PROTO_TCP => {
                            net::tcp::handle_segment(&ip_hdr, ip_payload);
                        }
                        net::ipv4::PROTO_UDP => {
                            net::udp::handle_datagram(&ip_hdr, ip_payload);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Process all pending received frames from the SHM RX ring.
fn process_rx_from_shm() {
    let mut frame_buf = [0u8; 2048];
    while let Some(len) = shm_rx_dequeue(&mut frame_buf) {
        process_packet(&frame_buf[..len]);
    }
}

// ---------------------------------------------------------------------------
// Self-test: ARP + ICMP ping
// ---------------------------------------------------------------------------

fn self_test_ping() {
    puts(b"[netsrv] Self-test: ARP request for 10.0.2.2\n");
    net::arp::request(&mac_addr(), net::ipv4::OUR_IP, net::ipv4::GATEWAY_IP);

    // Poll SHM for ARP reply (with early break)
    let mut i: u64 = 0;
    while i < 100_000 {
        if net::arp::lookup(net::ipv4::GATEWAY_IP).is_some() {
            break;
        }
        process_rx_from_shm();
        let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        i += 1;
    }

    match net::arp::lookup(net::ipv4::GATEWAY_IP) {
        Some(_) => {
            puts(b"[netsrv] ARP reply received for gateway\n");
            puts(b"[netsrv] Sending ICMP echo to 10.0.2.2 seq=1\n");
            net::icmp::reset_echo_reply_flag();
            net::icmp::send_echo_request(
                &mac_addr(),
                net::ipv4::OUR_IP,
                net::ipv4::GATEWAY_IP,
                1,
            );

            let mut j: u64 = 0;
            while j < 100_000 {
                if net::icmp::echo_reply_received() {
                    break;
                }
                process_rx_from_shm();
                let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
                j += 1;
            }
        }
        None => {
            puts(b"[netsrv] ARP timeout for gateway\n");
        }
    }
}

// ---------------------------------------------------------------------------
// IPC dispatch: handles all NET_* labels from VFS
// ---------------------------------------------------------------------------

/// Dispatch a single IPC request from VFS (or any client).
///
/// All operations return immediately: synchronous operations fill `reply`
/// with the result; asynchronous operations (connect, recv, accept) return
/// `SALTY_PENDING` and the TCP/UDP state machine will push a completion
/// later (delivered to VFS via the callback endpoint).
fn dispatch_ipc(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    match msg.label {
        NET_REGISTER_VFS => {
            // VFS registers its badged callback EP as an extra cap.
            // The cap was placed in our receive slot (CAP_VFS_CALLBACK_EP)
            // by the kernel during the IPC.
            // SAFETY: Single-threaded; written once.
            unsafe {
                *(&raw mut VFS_REGISTERED) = true;
            }
            puts(b"[netsrv] VFS callback EP registered\n");
            reply.label = SALTY_OK;
        }
        NET_SOCKET => {
            let sock_type = msg.regs[0] as i32;
            let id = if sock_type == SOCK_STREAM {
                net::tcp::tcp_socket()
            } else if sock_type == SOCK_DGRAM {
                net::udp::udp_socket()
            } else {
                -1
            };
            if id >= 0 {
                reply.label = SALTY_OK;
                reply.regs[0] = id as u64;
                reply.length = 1;
            } else {
                reply.label = SALTY_OUT_OF_MEMORY;
            }
        }
        NET_CONNECT => {
            let conn_id = msg.regs[0] as u32;
            let ip = msg.regs[1] as u32;
            let port = msg.regs[2] as u16;
            if conn_id >= 1000 {
                // UDP connect: store default destination, always immediate
                let result = net::udp::udp_connect(conn_id, ip, port);
                reply.label = if result == 0 {
                    SALTY_OK
                } else {
                    SALTY_INVALID_ARGUMENT
                };
            } else {
                // TCP connect: sends SYN, returns -1 (pending)
                let result = net::tcp::tcp_connect(conn_id, ip, port);
                if result == -1 {
                    reply.label = SALTY_PENDING;
                } else {
                    reply.label = SALTY_INVALID_ARGUMENT;
                }
            }
        }
        NET_BIND => {
            let conn_id = msg.regs[0] as u32;
            let ip = msg.regs[1] as u32;
            let port = msg.regs[2] as u16;
            let result = if conn_id >= 1000 {
                net::udp::udp_bind(conn_id, ip, port)
            } else {
                net::tcp::tcp_bind(conn_id, ip, port)
            };
            reply.label = if result == 0 {
                SALTY_OK
            } else {
                SALTY_INVALID_ARGUMENT
            };
        }
        NET_LISTEN => {
            let conn_id = msg.regs[0] as u32;
            let backlog = msg.regs[1] as u8;
            let result = net::tcp::tcp_listen(conn_id, backlog);
            reply.label = if result == 0 {
                SALTY_OK
            } else {
                SALTY_INVALID_ARGUMENT
            };
        }
        NET_ACCEPT => {
            let conn_id = msg.regs[0] as u32;
            let result = net::tcp::tcp_accept(conn_id);
            if result == -1 {
                // No pending connections -- tell VFS this is async
                net::tcp::set_pending_accept(conn_id);
                reply.label = SALTY_PENDING;
            } else if result > 0 {
                // Connection already in backlog, completed immediately
                let new_cid = result as u32;
                let (ip, port) = net::tcp::tcp_getpeername(new_cid);
                reply.label = SALTY_OK;
                reply.regs[0] = new_cid as u64;
                reply.regs[1] = ip as u64;
                reply.regs[2] = port as u64;
                reply.length = 3;
            } else {
                reply.label = SALTY_INVALID_ARGUMENT;
            }
        }
        NET_SEND => {
            let conn_id = msg.regs[0] as u32;
            let len = msg.regs[1] as usize;
            let actual_len = core::cmp::min(len, 144);
            // SAFETY: Reading data bytes from IPC message register area.
            let data = unsafe {
                let data_ptr = &msg.regs[2] as *const u64 as *const u8;
                core::slice::from_raw_parts(data_ptr, actual_len)
            };
            let sent = if conn_id >= 1000 {
                net::udp::udp_send(conn_id, data)
            } else {
                net::tcp::tcp_send(conn_id, data)
            };
            reply.label = SALTY_OK;
            reply.regs[0] = if sent >= 0 { sent as u64 } else { 0 };
            reply.length = 1;
        }
        NET_RECV => {
            let conn_id = msg.regs[0] as u32;
            let max_len = msg.regs[1] as u16;
            let capped = core::cmp::min(max_len, 152) as usize;
            // SAFETY: Writing data into reply register area.
            let buf = unsafe {
                let dst = &raw mut reply.regs[1] as *mut u8;
                core::slice::from_raw_parts_mut(dst, capped)
            };
            let result = if conn_id >= 1000 {
                net::udp::udp_recv(conn_id, buf)
            } else {
                net::tcp::tcp_recv(conn_id, buf)
            };
            if result == -1 {
                // No data available -- tell VFS this is async
                if conn_id >= 1000 {
                    net::udp::set_pending_recv(conn_id, capped as u16);
                } else {
                    net::tcp::set_pending_recv(conn_id, capped as u16);
                }
                reply.label = SALTY_PENDING;
            } else {
                reply.label = SALTY_OK;
                reply.regs[0] = result as u64;
                reply.length = 1 + ((result as u64 + 7) / 8);
            }
        }
        NET_SENDTO => {
            let conn_id = msg.regs[0] as u32;
            let ip = msg.regs[1] as u32;
            let port = msg.regs[2] as u16;
            let len = msg.regs[3] as usize;
            let actual = core::cmp::min(len, 128);
            // SAFETY: Reading data bytes from IPC message register area.
            let data = unsafe {
                let data_ptr = &msg.regs[4] as *const u64 as *const u8;
                core::slice::from_raw_parts(data_ptr, actual)
            };
            let sent = net::udp::udp_sendto(conn_id, data, ip, port);
            reply.label = SALTY_OK;
            reply.regs[0] = if sent >= 0 { sent as u64 } else { 0 };
            reply.length = 1;
        }
        NET_RECVFROM => {
            let conn_id = msg.regs[0] as u32;
            let max_len = msg.regs[1] as u16;
            let capped = core::cmp::min(max_len, 136) as usize;
            // SAFETY: Writing data into reply register area.
            let buf = unsafe {
                let dst = &raw mut reply.regs[3] as *mut u8;
                core::slice::from_raw_parts_mut(dst, capped)
            };
            let (result, src_ip, src_port) = net::udp::udp_recvfrom(conn_id, buf);
            if result == -1 {
                net::udp::set_pending_recv(conn_id, capped as u16);
                reply.label = SALTY_PENDING;
            } else {
                reply.label = SALTY_OK;
                reply.regs[0] = result as u64;
                reply.regs[1] = src_ip as u64;
                reply.regs[2] = src_port as u64;
                reply.length = 3 + ((result as u64 + 7) / 8);
            }
        }
        NET_CLOSE => {
            let conn_id = msg.regs[0] as u32;
            if conn_id >= 1000 {
                net::udp::udp_close(conn_id);
            } else {
                net::tcp::tcp_close(conn_id);
            }
            reply.label = SALTY_OK;
        }
        NET_SHUTDOWN => {
            let conn_id = msg.regs[0] as u32;
            let how = msg.regs[1] as i32;
            net::tcp::tcp_shutdown(conn_id, how);
            reply.label = SALTY_OK;
        }
        NET_GETSOCKNAME => {
            let conn_id = msg.regs[0] as u32;
            let (ip, port) = if conn_id >= 1000 {
                net::udp::udp_getsockname(conn_id)
            } else {
                net::tcp::tcp_getsockname(conn_id)
            };
            reply.label = SALTY_OK;
            reply.regs[0] = ip as u64;
            reply.regs[1] = port as u64;
            reply.length = 2;
        }
        NET_GETPEERNAME => {
            let conn_id = msg.regs[0] as u32;
            let (ip, port) = if conn_id >= 1000 {
                net::udp::udp_getpeername(conn_id)
            } else {
                net::tcp::tcp_getpeername(conn_id)
            };
            reply.label = SALTY_OK;
            reply.regs[0] = ip as u64;
            reply.regs[1] = port as u64;
            reply.length = 2;
        }
        NET_POLL_STATUS => {
            let conn_id = msg.regs[0] as u32;
            let events = msg.regs[1] as u16;
            let revents = if conn_id >= 1000 {
                net::udp::udp_poll_status(conn_id, events)
            } else {
                net::tcp::tcp_poll_status(conn_id, events)
            };
            reply.label = SALTY_OK;
            reply.regs[0] = revents as u64;
            reply.length = 1;
        }
        _ => {
            reply.label = SALTY_INVALID_OPERATION;
        }
    }
}

// ---------------------------------------------------------------------------
// Async completion delivery to VFS
// ---------------------------------------------------------------------------

/// Notify VFS that an async operation has completed by calling its badged
/// callback endpoint.
///
/// Message format sent to VFS:
///   label = NET_COMPLETE
///   regs[0] = conn_id (the connection this completion belongs to)
///   regs[1] = result  (SALTY_OK, SALTY_CONN_REFUSED, etc.)
///   regs[2] = op_type (INET_OP_CONNECT, INET_OP_RECV, etc.)
///   regs[3] = data_len / extra_conn_id (depends on op_type)
///   regs[4] = extra_ip / data start
///   regs[5] = extra_port
///   regs[6..] = data bytes (for recv/recvfrom)
fn notify_vfs_completion(
    conn_id: u32,
    result: u64,
    op_type: u8,
    data: &[u8],
    data_len: usize,
    extra_conn_id: u32,
    extra_ip: u32,
    extra_port: u16,
) {
    // SAFETY: Single-threaded server; VFS_REGISTERED is set once.
    let registered = unsafe { *(&raw const VFS_REGISTERED) };
    if !registered {
        return;
    }

    let mut msg = SaltyMsg::zeroed();
    msg.label = NET_COMPLETE;
    msg.regs[0] = conn_id as u64;
    msg.regs[1] = result;
    msg.regs[2] = op_type as u64;

    match op_type {
        INET_OP_CONNECT => {
            msg.length = 3;
        }
        INET_OP_RECV => {
            let max_data = core::cmp::min(data_len, 128);
            msg.regs[3] = max_data as u64;
            if max_data > 0 {
                // SAFETY: Writing data bytes into message register area.
                unsafe {
                    let dst = &raw mut msg.regs[4] as *mut u8;
                    let mut i = 0;
                    while i < max_data {
                        *dst.add(i) = data[i];
                        i += 1;
                    }
                }
            }
            msg.length = 4 + ((max_data as u64 + 7) / 8);
        }
        INET_OP_ACCEPT => {
            msg.regs[3] = extra_conn_id as u64;
            msg.regs[4] = extra_ip as u64;
            msg.regs[5] = extra_port as u64;
            msg.length = 6;
        }
        INET_OP_RECVFROM => {
            let max_data = core::cmp::min(data_len, 112);
            msg.regs[3] = max_data as u64;
            msg.regs[4] = extra_ip as u64;
            msg.regs[5] = extra_port as u64;
            if max_data > 0 {
                // SAFETY: Writing data bytes into message register area.
                unsafe {
                    let dst = &raw mut msg.regs[6] as *mut u8;
                    let mut i = 0;
                    while i < max_data {
                        *dst.add(i) = data[i];
                        i += 1;
                    }
                }
            }
            msg.length = 6 + ((max_data as u64 + 7) / 8);
        }
        _ => {
            msg.length = 3;
        }
    }

    let mut resp = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; VFS callback EP is in slot 83.
    unsafe {
        ipc::call_ctx(
            ipc_ctx(),
            CAP_VFS_CALLBACK_EP,
            &raw const msg,
            &raw mut resp,
        );
    }
}

/// Drain all pending completions from TCP and UDP modules, delivering each
/// to VFS via the callback endpoint.
///
/// Called after RX processing (when VFS is in its event loop, not blocked
/// on a netsrv call) and after timer processing.
fn drain_completion_queue() {
    while let Some(c) = net::tcp::pop_completion() {
        notify_vfs_completion(
            c.conn_id,
            c.result,
            c.op_type,
            &c.data[..c.data_len],
            c.data_len,
            c.extra_conn_id,
            c.extra_ip,
            c.extra_port,
        );
    }
    while let Some(c) = net::udp::pop_completion() {
        notify_vfs_completion(
            c.conn_id,
            c.result,
            c.op_type,
            &c.data[..c.data_len],
            c.data_len,
            c.extra_conn_id,
            c.extra_ip,
            c.extra_port,
        );
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Main event loop: wait for notification wakeups or IPC requests.
///
/// Uses a recv / reply_recv pattern:
/// - On notification wakeup (badge != 0): process RX frames from SHM,
///   run TCP timers, drain completion queue (callbacks to VFS), then recv.
/// - On IPC request (badge == 0): dispatch the request, fill reply, then
///   reply_recv (atomically reply and wait for next event).
fn event_loop() -> ! {
    puts(b"[netsrv] Entering event loop\n");

    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    // Set receive slot for VFS callback EP (slot 83).
    // VFS sends its badged EP via NET_REGISTER_VFS with extra_caps=1.
    // SAFETY: IPC context is valid.
    unsafe {
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_VFS_CALLBACK_EP, 0);
    }

    // Initial recv -- wait for first event
    // SAFETY: IPC context is valid; server EP was set up by procmgr.
    unsafe {
        ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge);
    }

    loop {
        if badge != 0 {
            // Woken by bound notification: RX frames available from netdrv
            process_rx_from_shm();
            net::tcp::process_timers();
            drain_completion_queue();

            // Wait for next event (no reply needed for notifications)
            msg = SaltyMsg::zeroed();
            badge = 0;
            // SAFETY: IPC context is valid.
            unsafe {
                ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge);
            }
        } else {
            // IPC request on server endpoint
            let mut reply = SaltyMsg::zeroed();
            dispatch_ipc(&msg, &mut reply);

            // Reply to caller AND wait for next event atomically
            msg = SaltyMsg::zeroed();
            badge = 0;
            // SAFETY: IPC context is valid.
            unsafe {
                ipc::reply_recv_ctx(
                    ctx,
                    CAP_SERVER_EP,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[netsrv] Network Stack Server starting\n");

    // Set IPC buffer
    let _ = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    // SAFETY: Setting up IPC buffer pointer for this thread.
    unsafe {
        (*ipc_ctx()).ipc_buffer = IPC_BUF_VADDR as *mut IpcBuffer;
    }

    // 1. Allocate and map SHM
    if !setup_shm() {
        puts(b"[netsrv] SHM setup failed, halting\n");
        idle();
    }

    // 2. Setup notification (allocate, bind to TCB, mint badged copy)
    if !setup_notification() {
        puts(b"[netsrv] Notification setup failed, halting\n");
        idle();
    }

    // 3. Register with netdrv (DRIVER_REGISTER: exchange SHM ID, caps, get MAC)
    if !driver_register() {
        puts(b"[netsrv] Driver register failed, halting\n");
        idle();
    }

    // 4. Self-test: ARP + ICMP ping
    puts(b"[netsrv] IP: 10.0.2.15/24, GW: 10.0.2.2\n");
    self_test_ping();

    // 5. Register with name service
    register_nameserv();

    // 6. Signal readiness to init
    signal_ready();

    // 7. Enter event loop (never returns)
    event_loop()
}

fn idle() -> ! {
    loop {
        let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
