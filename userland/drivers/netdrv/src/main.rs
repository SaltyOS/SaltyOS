// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS virtio-net Network Device Driver
//!
//! Discovers a virtio-net PCI device via pcisrv, initializes the virtio
//! transport (legacy PCI), sets up IRQ handling, and serves as the network
//! driver. Implements TCP/UDP over IPv4 and exposes a NET_* IPC interface
//! for VFS to forward POSIX socket operations.
//!
//! Cap layout:
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   68 = server endpoint (pre-created service EP)
//!   14 = readiness notification
//!   64 = pcisrv endpoint
//!   5  = nameserv endpoint
//!   7  = mmsrv endpoint
//!   80 = received BAR cap (IoPort or device untyped) from pcisrv
//!   81 = IRQ handler cap (received from pcisrv via PCI_GET_CAPS extra cap #1)
//!   82 = IRQ notification (retyped from untyped)
//!   83 = VFS callback endpoint (received from VFS via NET_REGISTER_VFS)

#![no_std]
#![no_main]

extern crate salty;

mod net;
mod virtio;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_MMSRV_EP: u64 = 7;
const CAP_IRQ_HANDLER: u64 = 81;
const CAP_IRQ_NOTIFICATION: u64 = 82;
const CAP_VFS_CALLBACK_EP: u64 = 83;

static mut IRQ_ENABLED: bool = false;
static mut VFS_REGISTERED: bool = false;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

pub(crate) fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Get our MAC address from the virtio driver.
fn mac_addr() -> [u8; 6] {
    // SAFETY: MAC_ADDR is set during init before any use.
    unsafe { *(&raw const virtio::MAC_ADDR) }
}

/// Register with name service as "netdrv".
fn register_nameserv() {
    let name = b"netdrv";
    let mut msg = SaltyMsg::zeroed();
    msg.label = POSIX_NS_REGISTER;
    msg.regs[0] = name.len() as u64;
    msg.length = 1 + (name.len() as u64 + 7) / 8;
    // SAFETY: Writing name bytes into message register space; IPC context is valid.
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            puts(b"[netdrv] nameserv registration failed\n");
        }
    }
}

/// Set up IRQ handling for the device.
///
/// Uses the IRQ handler cap received from pcisrv (slot 81) rather than
/// creating one via irq_control_get, following least-privilege principles.
///
/// 1. Retype a Notification from untyped memory
/// 2. Bind IRQ handler (from pcisrv) to notification
/// 3. Bind notification to our TCB for Recv wakeup
fn setup_irq(irq_line: u8, has_irq_handler: bool) -> bool {
    if !has_irq_handler {
        puts(b"[netdrv] No IRQ handler cap from pcisrv, skipping IRQ setup\n");
        return false;
    }

    // Step 1: Allocate a Notification object via mmsrv
    // SAFETY: IPC context is valid; set up receive slot for cap transfer.
    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_IRQ_NOTIFICATION, 0);
    }
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_ALLOC_OBJECT;
    msg.regs[0] = OBJ_NOTIFICATION;
    msg.regs[1] = 0;
    msg.length = 2;
    let mut alloc_reply = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe {
        ipc::call_ctx(
            ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut alloc_reply,
        )
    };
    if err != 0 || alloc_reply.label != SALTY_OK {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] Failed to allocate Notification via mmsrv: ");
        lb.dec(if err != 0 {
            err as u64
        } else {
            alloc_reply.label
        });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Step 2: Bind IRQ handler to notification
    let err = invoke::irq_handler_set_notification(CAP_IRQ_HANDLER, CAP_IRQ_NOTIFICATION);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] Failed to bind IRQ to notification: ");
        lb.dec(err as u64);
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Step 3: Bind notification to our TCB for Recv wakeup
    let err = invoke::tcb_bind_notification(CAP_SELF_TCB, CAP_IRQ_NOTIFICATION);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] Failed to bind notification to TCB: ");
        lb.dec(err as u64);
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    // Initial ACK to unmask the IRQ
    let _ = invoke::irq_handler_ack(CAP_IRQ_HANDLER);

    // SAFETY: Single-threaded init path; written once before event loop.
    unsafe {
        *(&raw mut IRQ_ENABLED) = true;
    }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] IRQ ");
        lb.dec(irq_line as u64);
        lb.str(b" handler configured\n");
        lb.flush();
    }
    true
}

/// Process all pending received packets.
fn drain_rx() {
    while let Some((buf_idx, len)) = virtio::rx_poll() {
        let data = virtio::rx_get_data(buf_idx, len);
        // Skip VirtioNetHdr (10 bytes) to get the Ethernet frame
        if len > virtio::VIRTIO_NET_HDR_SIZE {
            let pkt = &data[virtio::VIRTIO_NET_HDR_SIZE..];
            process_packet(pkt);
        }
        virtio::rx_repost(buf_idx);
    }
}

/// Handle an IRQ from the virtio device.
fn handle_irq() {
    let isr = virtio::read_isr();
    if isr == 0 {
        return;
    }
    drain_rx();
    // Acknowledge IRQ to re-enable it
    let _ = invoke::irq_handler_ack(CAP_IRQ_HANDLER);
}

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
                            net::icmp::handle(&mac_addr(), net::ipv4::OUR_IP, &ip_hdr, ip_payload);
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

/// Self-test: send ARP for gateway, then ping it.
fn self_test_ping() {
    // SAFETY: IRQ_ENABLED is set during init before this is called.
    let irq_enabled = unsafe { *(&raw const IRQ_ENABLED) };

    puts(b"[netdrv] Self-test: ARP request for 10.0.2.2\n");
    net::arp::request(&mac_addr(), net::ipv4::OUR_IP, net::ipv4::GATEWAY_IP);

    // Poll for ARP reply
    for _ in 0..1_000_000u64 {
        if net::arp::lookup(net::ipv4::GATEWAY_IP).is_some() {
            break;
        }
        let isr = virtio::read_isr();
        if isr != 0 {
            drain_rx();
            if irq_enabled {
                let _ = invoke::irq_handler_ack(CAP_IRQ_HANDLER);
            }
        }
        let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    match net::arp::lookup(net::ipv4::GATEWAY_IP) {
        Some(_mac) => {
            puts(b"[netdrv] ARP reply received for gateway\n");
            puts(b"[netdrv] Sending ICMP echo to 10.0.2.2 seq=1\n");
            net::icmp::send_echo_request(&mac_addr(), net::ipv4::OUR_IP, net::ipv4::GATEWAY_IP, 1);

            // Poll for ICMP reply
            for _ in 0..1_000_000u64 {
                let isr = virtio::read_isr();
                if isr != 0 {
                    drain_rx();
                    if irq_enabled {
                        let _ = invoke::irq_handler_ack(CAP_IRQ_HANDLER);
                    }
                }
                let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }
        None => {
            puts(b"[netdrv] ARP timeout for gateway\n");
        }
    }
}

// ---------------------------------------------------------------------------
// IPC dispatch — handles all NET_* labels from VFS
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
            puts(b"[netdrv] VFS callback EP registered\n");
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
                // No pending connections — tell VFS this is async
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
                // No data available — tell VFS this is async
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
        _ => {
            reply.label = SALTY_INVALID_OPERATION;
        }
    }
}

// ---------------------------------------------------------------------------
// Async completion delivery to VFS
// ---------------------------------------------------------------------------

/// Notify VFS that an async operation has completed by calling its badged
/// callback endpoint. VFS sees this as a NET_COMPLETE message with
/// badge == NETDRV_CALLBACK_BADGE.
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
    // SAFETY: Single-threaded driver; VFS_REGISTERED is set once.
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
            msg.regs[3] = data_len as u64;
            // Copy data into regs[4..]
            let max_data = core::cmp::min(data_len, 128);
            if max_data > 0 {
                // SAFETY: Writing data bytes into message register area.
                unsafe {
                    let dst = &raw mut msg.regs[4] as *mut u8;
                    for i in 0..max_data {
                        *dst.add(i) = data[i];
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
            msg.regs[3] = data_len as u64;
            msg.regs[4] = extra_ip as u64;
            msg.regs[5] = extra_port as u64;
            // Copy data into regs[6..]
            let max_data = core::cmp::min(data_len, 112);
            if max_data > 0 {
                // SAFETY: Writing data bytes into message register area.
                unsafe {
                    let dst = &raw mut msg.regs[6] as *mut u8;
                    for i in 0..max_data {
                        *dst.add(i) = data[i];
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
/// Called after IRQ processing (when VFS is in its event loop, not blocked
/// on a netdrv call) and after timer processing.
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

/// Main event loop: wait for IRQ notifications or IPC requests.
///
/// Uses a recv / reply_recv pattern:
/// - On IRQ notification (badge != 0): process packets, run TCP timers,
///   drain completion queue (callbacks to VFS), then recv again.
/// - On IPC request (badge == 0): dispatch the request, fill reply, then
///   reply_recv (atomically reply and wait for next event).
fn event_loop(device_ok: bool) -> ! {
    puts(b"[netdrv] Entering event loop\n");

    // SAFETY: IRQ_ENABLED is set during init before event loop starts.
    let irq_enabled = unsafe { *(&raw const IRQ_ENABLED) };

    if !irq_enabled {
        if device_ok {
            // Polling fallback: no IRQ, yield and poll ISR directly
            puts(b"[netdrv] No IRQ, using yield-based polling\n");
            loop {
                let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
                let isr = virtio::read_isr();
                if isr != 0 {
                    drain_rx();
                }
            }
        } else {
            // No device present — idle loop with no hardware access
            puts(b"[netdrv] No device, idling\n");
            loop {
                let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }
    }

    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    // Set up receive slot for VFS callback EP (slot 83).
    // VFS sends its badged EP via NET_REGISTER_VFS with extra_caps=1.
    // SAFETY: IPC context is valid.
    unsafe {
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_VFS_CALLBACK_EP, 0);
    }

    // Initial recv — wait for first event
    // SAFETY: IPC context is valid; server EP was set up by procmgr.
    unsafe {
        ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge);
    }

    loop {
        if badge != 0 {
            // Woken by bound notification (IRQ)
            handle_irq();
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[netdrv] virtio-net Network Driver starting\n");

    // Set IPC buffer
    let _ = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    // SAFETY: Setting up IPC buffer pointer for this thread.
    unsafe {
        (*ipc_ctx()).ipc_buffer = IPC_BUF_VADDR as *mut IpcBuffer;
    }

    // Discover and initialize virtio-net device
    let mut irq_line: u8 = 0;
    let mut has_irq_handler = false;
    let mut device_ok = false;

    match virtio::find_virtio_net() {
        Some((bus, dev, func, bar0, _bar0_full)) => {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[netdrv] Found virtio-net at ");
                lb.dec(bus as u64);
                lb.putc(b':');
                lb.dec(dev as u64);
                lb.str(b" BAR0=");
                lb.hex(bar0 as u64);
                lb.putc(b'\n');
                lb.flush();
            }

            match virtio::get_device_caps(bus, dev, func) {
                Some((_bar_phys, _bar_bits, bar_size, irq, _bar_is_io, has_irq)) => {
                    irq_line = irq;
                    has_irq_handler = has_irq;
                    {
                        let mut lb = LineBuf::new();
                        lb.str(b"[netdrv] IRQ=");
                        lb.dec(irq as u64);
                        lb.putc(b'\n');
                        lb.flush();
                    }

                    if virtio::init_virtio(bar0, bar_size) {
                        device_ok = true;
                    } else {
                        puts(b"[netdrv] Failed to init virtio transport\n");
                    }
                }
                None => {
                    puts(b"[netdrv] Failed to get PCI caps from pcisrv\n");
                }
            }
        }
        None => {
            puts(b"[netdrv] No virtio-net device found\n");
        }
    }

    // Set up IRQ handling
    if device_ok && irq_line > 0 {
        if setup_irq(irq_line, has_irq_handler) {
            puts(b"[netdrv] IRQ handling enabled\n");
        } else {
            puts(b"[netdrv] IRQ setup failed, using polling mode\n");
        }
    }

    // Print IP configuration
    if device_ok {
        puts(b"[netdrv] IP: 10.0.2.15/24, GW: 10.0.2.2\n");
        self_test_ping();
    }

    // Register with nameserv and signal readiness
    register_nameserv();
    signal_ready();

    event_loop(device_ok)
}
