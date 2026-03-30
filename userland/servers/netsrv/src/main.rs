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
//!   80 = RX notification (allocated via mmsrv, sent to netdrv via IPC)
//!   82 = TX notification (received from netdrv during DRIVER_REGISTER)
//!   83 = VFS callback endpoint (plain cap received from VFS via NET_REGISTER_VFS)
//!   84 = local badged alias of the VFS callback endpoint

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_posix;

mod net;

use trona::consts::*;
use trona::invoke;
use trona::ipc;
use trona::serial;
use trona::types::*;

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
const CAP_TX_NOTIFICATION: u64 = 82;
const CAP_VFS_CALLBACK_EP: u64 = 83;
const CAP_VFS_CALLBACK_BADGED_EP: u64 = 84;
const CAP_REPLY_TEMP: u64 = 89;
const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SHM_VADDR: u64 = 0x0000_0000_6000_0000;
const NET_SHM_ID: u64 = 0x4E455400; // "NET\0"
const SHM_HEADER_BYTES: u64 = 0x1000;
const SHM_SLOT_BYTES: u64 = 2048;
const SHM_RX_SLOT_COUNT: u64 = 32;
const SHM_TX_SLOT_COUNT: u64 = 32;
const SHM_TX_OFFSET: u64 = SHM_HEADER_BYTES + (SHM_RX_SLOT_COUNT * SHM_SLOT_BYTES);
const NET_SHM_BYTES: u64 = SHM_TX_OFFSET + (SHM_TX_SLOT_COUNT * SHM_SLOT_BYTES);
const NET_SHM_PAGES: u64 = (NET_SHM_BYTES + 4095) / 4096;
const DHCP_BOOTSTRAP_TIMEOUT_NS: u64 = 10_000_000_000;
const RX_BADGE: u64 = 0x1;
const TX_BADGE: u64 = 0x2;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static mut MAC_ADDR: [u8; 6] = [0; 6];
static mut VFS_REGISTERED: bool = false;
static mut SHM_BASE: u64 = 0;
static mut SELF_TEST_PHASE: u8 = 0;
static mut SELF_TEST_TICKS: u32 = 0;
static mut LOGGED_RX_FRAME: bool = false;
static mut LOGGED_UNKNOWN_ETHERTYPE: bool = false;
static mut LOGGED_IPV4_PACKETS: u8 = 0;
static mut LOGGED_INET_IPC: u8 = 0;
static mut LOGGED_INET_RECV_RESULTS: u8 = 0;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

pub(crate) fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

pub(crate) fn mac_addr() -> [u8; 6] {
    // SAFETY: MAC_ADDR is set during init before any use; single-threaded.
    unsafe { *(&raw const MAC_ADDR) }
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

fn log_ipv4(lb: &mut trona::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

fn log_network_config(prefix: &[u8]) {
    let cfg = net::config::snapshot();
    trona::uinfo!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" IP=");
        log_ipv4(&mut _lb, cfg.our_ip);
        _lb.str(b" MASK=");
        log_ipv4(&mut _lb, cfg.subnet_mask);
        _lb.str(b" GW=");
        log_ipv4(&mut _lb, cfg.gateway_ip);
        _lb.str(b" DNS=");
        log_ipv4(&mut _lb, cfg.dns_server);
        _lb.putc(b'\n');
    });
}

fn log_inet_ipc(op: &[u8], conn_id: u32, ip: u32, port: u16, len: usize) {
    unsafe {
        if *(&raw const LOGGED_INET_IPC) >= 24 {
            return;
        }
        *(&raw mut LOGGED_INET_IPC) += 1;
    }
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] ipc ");
        _lb.str(op);
        _lb.str(b" conn=");
        _lb.dec(conn_id as u64);
        if ip != 0 || port != 0 {
            _lb.str(b" ip=");
            log_ipv4(&mut _lb, ip);
            _lb.str(b" port=");
            _lb.dec(port as u64);
        }
        if len != 0 {
            _lb.str(b" len=");
            _lb.dec(len as u64);
        }
        _lb.putc(b'\n');
    });
}

fn log_inet_recv_result(op: &[u8], conn_id: u32, src_ip: u32, len: usize, data: &[u8]) {
    unsafe {
        if *(&raw const LOGGED_INET_RECV_RESULTS) >= 24 {
            return;
        }
        *(&raw mut LOGGED_INET_RECV_RESULTS) += 1;
    }
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] ipc ");
        _lb.str(op);
        _lb.str(b" conn=");
        _lb.dec(conn_id as u64);
        _lb.str(b" src=");
        log_ipv4(&mut _lb, src_ip);
        _lb.str(b" len=");
        _lb.dec(len as u64);
        let preview_len = core::cmp::min(data.len(), 8);
        if preview_len > 0 {
            _lb.str(b" bytes=");
            let mut i = 0;
            while i < preview_len {
                if i != 0 {
                    _lb.putc(b':');
                }
                _lb.hex(data[i] as u64);
                i += 1;
            }
        }
        _lb.putc(b'\n');
    });
}

fn log_frame_once(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let ethertype = ((frame[12] as u16) << 8) | (frame[13] as u16);
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] RX frame len=");
        _lb.dec(frame.len() as u64);
        _lb.str(b" ethertype=");
        _lb.hex(ethertype as u64);
        _lb.putc(b'\n');
    });
}

fn log_ipv4_packet(hdr: &net::proto::ipv4::Ipv4Header, payload_len: usize) {
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] IPv4 src=");
        log_ipv4(&mut _lb, hdr.src);
        _lb.str(b" dst=");
        log_ipv4(&mut _lb, hdr.dst);
        _lb.str(b" proto=");
        _lb.dec(hdr.protocol as u64);
        _lb.str(b" len=");
        _lb.dec(payload_len as u64);
        _lb.putc(b'\n');
    });
}

fn bootstrap_network_config() {
    net::config::init(mac_addr());

    trona::uinfo!(|_lb| {
        _lb.str(b"[netsrv] DHCP bootstrap starting\n");
    });

    let start_ns = net::dns::clock_monotonic_ns();
    let mut dhcp_started = false;

    if net::dhcp::start() {
        dhcp_started = true;
        loop {
            process_rx_from_shm();
            net::dhcp::process();
            if net::dhcp::is_bound() || net::dhcp::is_finished() {
                break;
            }
            if net::dns::clock_monotonic_ns().saturating_sub(start_ns) >= DHCP_BOOTSTRAP_TIMEOUT_NS {
                break;
            }
            let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }

    if net::dhcp::is_bound() {
        log_network_config(b"[netsrv] DHCP configured");
    } else {
        if dhcp_started && net::dhcp::is_finished() {
            let _ = net::dhcp::start();
        }
        trona::uwarn!(|_lb| {
            _lb.str(b"[netsrv] DHCP bootstrap incomplete, continuing without a fallback config\n");
        });
    }
}

// ---------------------------------------------------------------------------
// SHM ring buffer access
// ---------------------------------------------------------------------------

/// Write a frame to the SHM TX ring.
///
/// Applies sender-side backpressure when the shared ring is full so packets
/// are not silently dropped under SMP burst load.
pub(crate) fn shm_tx_enqueue(frame: &[u8]) -> bool {
    // SAFETY: SHM_BASE is set during init; single-threaded.
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return false;
        }
        let hdr = base as *mut u32;
        let len = core::cmp::min(frame.len(), 1998);
        loop {
            let tx_head = *hdr.add(2); // offset 0x08
            let tx_tail = core::ptr::read_volatile(hdr.add(3)); // offset 0x0C, netdrv writes this
            let slot_count = core::ptr::read_volatile(hdr.add(5)); // offset 0x14
            if slot_count == 0 {
                return false;
            }
            let next = (tx_head + 1) % slot_count;
            if next == tx_tail {
                signal_netdrv_tx();
                let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
                continue;
            }

            let slot_base = base + 0x11000 + (tx_head as u64) * 2048;
            let len_ptr = slot_base as *mut u16;
            *len_ptr = len as u16;
            let data_ptr = (slot_base + 2) as *mut u8;
            core::ptr::copy_nonoverlapping(frame.as_ptr(), data_ptr, len);

            // Store fence: ensure frame data is visible before updating head
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(hdr.add(2), next);
            return true;
        }
    }
}

/// Signal netdrv that TX frames are available.
///
/// The TX notification cap received from netdrv is unbadged (badge=0).
/// We pass TX_BADGE via the `bits` argument so netdrv sees badge & 0x2 != 0
/// in its event loop (kernel computes: notification.signal(cap.badge | bits)).
pub(crate) fn signal_netdrv_tx() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_TX_NOTIFICATION, TX_BADGE, 0, 0, 0, 0);
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

        let slot_count = core::ptr::read_volatile(hdr.add(4)); // offset 0x10
        if slot_count == 0 {
            return None;
        }
        // Release: data reads above must complete before the tail update
        // that publishes free space to the producer (ARM weak ordering).
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
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
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.regs[0] = NET_SHM_ID;
    msg.regs[1] = NET_SHM_PAGES;
    msg.length = 2;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != TRONA_OK && reply.label != TRONA_ALREADY_EXISTS) {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] SHM create failed: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
        return false;
    }

    // Map SHM
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.regs[0] = NET_SHM_ID;
    msg.regs[1] = 0;
    msg.regs[2] = SHM_VADDR;
    msg.regs[3] = 0x3; // RW
    msg.length = 4;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != TRONA_OK {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] SHM map failed: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
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
        *hdr.add(4) = SHM_RX_SLOT_COUNT as u32;
        *hdr.add(5) = SHM_TX_SLOT_COUNT as u32;
    }

    trona::uinfo!(|_lb| {
        _lb.str(b"[netsrv] SHM allocated and mapped\n");
    });
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
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_ALLOC_OBJECT;
    msg.regs[0] = OBJ_NOTIFICATION;
    msg.regs[1] = 0;
    msg.length = 2;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != TRONA_OK {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] Failed to allocate notification: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
        return false;
    }

    // Bind notification to our TCB
    let err = invoke::tcb_bind_notification(CAP_SELF_TCB, CAP_RX_NOTIFICATION);
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] Failed to bind notification to TCB: ");
            _lb.dec(err as u64);
            _lb.putc(b'\n');
        });
        return false;
    }

    trona::uinfo!(|_lb| {
        _lb.str(b"[netsrv] Notification allocated and bound\n");
    });
    true
}

// ---------------------------------------------------------------------------
// Startup: Register with netdrv via DRIVER_REGISTER
// ---------------------------------------------------------------------------

fn driver_register() -> bool {
    let ctx = ipc_ctx();

    // Send DRIVER_REGISTER to netdrv EP (slot 64)
    // extra_caps=1: send original RX notification (slot 80, retains GRANT
    // right so IPC cap transfer succeeds) to netdrv.  netdrv signals us
    // with bits=1 to indicate RX frames available.
    // SAFETY: IPC context is valid; setting up send/receive caps.
    unsafe {
        ipc::set_send_cap_ctx(ctx, 0, CAP_RX_NOTIFICATION);
        // Set receive slot for TX notification from netdrv
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_TX_NOTIFICATION, 0);
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = DRIVER_REGISTER; // 0xC0
    msg.regs[0] = NET_SHM_ID;
    msg.length = 1;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to netdrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_NETDRV_EP, &raw const msg, &raw mut reply) };
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] DRIVER_REGISTER call result=");
        _lb.dec(err as u64);
        _lb.str(b" label=");
        _lb.dec(reply.label);
        _lb.putc(b'\n');
    });
    if err != 0 || reply.label != TRONA_OK {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] DRIVER_REGISTER failed: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
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

    trona::uinfo!(|_lb| {
        _lb.str(b"[netsrv] Registered with netdrv, MAC=");
        let mac = mac_addr();
        let mut i = 0;
        while i < 6 {
            _lb.hex(mac[i] as u64);
            if i < 5 {
                _lb.putc(b':');
            }
            i += 1;
        }
        _lb.putc(b'\n');
    });
    true
}

// ---------------------------------------------------------------------------
// Startup: Register with name service
// ---------------------------------------------------------------------------

fn register_nameserv() {
    let name = b"netsrv";
    let mut msg = TronaMsg::zeroed();
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
        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_NAMESERV_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[netsrv] nameserv registration failed\n");
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Packet processing
// ---------------------------------------------------------------------------

/// Dispatch a received Ethernet frame through the protocol stack.
fn process_packet(data: &[u8]) {
    let our_ip = net::proto::ipv4::our_ip();
    if let Some((eth_hdr, payload)) = net::ethernet::parse(data) {
        match eth_hdr.ethertype {
            net::ethernet::ETHERTYPE_ARP => {
                net::proto::arp::handle_packet(&mac_addr(), our_ip, payload);
            }
            net::ethernet::ETHERTYPE_IPV4 => {
                if let Some((ip_hdr, ip_payload)) = net::proto::ipv4::parse(payload) {
                    unsafe {
                        if *(&raw const LOGGED_IPV4_PACKETS) < 8 {
                            *(&raw mut LOGGED_IPV4_PACKETS) += 1;
                            log_ipv4_packet(&ip_hdr, ip_payload.len());
                        }
                    }
                    // Deliver to raw sockets first (fans out by protocol)
                    net::socket::raw_ipv4::deliver(&ip_hdr, ip_payload);

                    match ip_hdr.protocol {
                        net::proto::ipv4::PROTO_ICMP => {
                            net::proto::icmp::handle(&mac_addr(), our_ip, &ip_hdr, ip_payload);
                        }
                        net::proto::ipv4::PROTO_TCP => {
                            net::socket::tcp::handle_segment(&ip_hdr, ip_payload);
                        }
                        net::proto::ipv4::PROTO_UDP => {
                            net::socket::udp::handle_datagram(&ip_hdr, ip_payload);
                        }
                        _ => {}
                    }
                }
            }
            _ => unsafe {
                if !*(&raw const LOGGED_UNKNOWN_ETHERTYPE) {
                    *(&raw mut LOGGED_UNKNOWN_ETHERTYPE) = true;
                    trona::udebug!(|_lb| {
                        _lb.str(b"[netsrv] unhandled ethertype=");
                        _lb.hex(eth_hdr.ethertype as u64);
                        _lb.putc(b'\n');
                    });
                }
            },
        }
    }
}

/// Process all pending received frames from the SHM RX ring.
pub(crate) fn process_rx_from_shm() {
    let mut frame_buf = [0u8; 2048];
    while let Some(len) = shm_rx_dequeue(&mut frame_buf) {
        unsafe {
            if !*(&raw const LOGGED_RX_FRAME) {
                *(&raw mut LOGGED_RX_FRAME) = true;
                log_frame_once(&frame_buf[..len]);
            }
        }
        net::config::note_rx(len);
        process_packet(&frame_buf[..len]);
    }
}

// ---------------------------------------------------------------------------
// Self-test: gateway ARP
// ---------------------------------------------------------------------------

/// Non-blocking self-test state machine, called from the event loop.
///
/// Phase 0: waiting for ARP reply for gateway.
/// Phase 1+: done.
/// Each phase times out after 200 ticks.
fn check_self_test() {
    // SAFETY: Single-threaded server; globals written only here.
    let phase = unsafe { *(&raw const SELF_TEST_PHASE) };
    if phase >= 2 {
        return; // done
    }

    let ticks = unsafe { *(&raw const SELF_TEST_TICKS) };

    match phase {
        0 => {
            let gateway = net::proto::ipv4::gateway_ip();
            if gateway == 0 || net::proto::ipv4::our_ip() == 0 {
                unsafe {
                    *(&raw mut SELF_TEST_PHASE) = 2;
                }
                return;
            }

            if net::proto::arp::lookup(gateway).is_some() {
                trona::udebug!(|_lb| {
                    _lb.str(b"[netsrv] ARP reply received for gateway\n");
                });
                unsafe {
                    *(&raw mut SELF_TEST_PHASE) = 2;
                }
            } else {
                // SAFETY: Single-threaded server.
                unsafe {
                    *(&raw mut SELF_TEST_TICKS) = ticks + 1;
                }
                if ticks + 1 >= 200 {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[netsrv] ARP timeout for gateway\n");
                    });
                    // SAFETY: Single-threaded server.
                    unsafe {
                        *(&raw mut SELF_TEST_PHASE) = 2;
                    }
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Socket kind routing
// ---------------------------------------------------------------------------

enum SocketKind {
    Tcp,
    Udp,
    Raw,
}

fn socket_kind(conn_id: u32) -> SocketKind {
    if conn_id >= 2000 {
        SocketKind::Raw
    } else if conn_id >= 1000 {
        SocketKind::Udp
    } else {
        SocketKind::Tcp
    }
}

// ---------------------------------------------------------------------------
// IPC dispatch: handles all NET_* labels from VFS
// ---------------------------------------------------------------------------

/// Dispatch a single IPC request from VFS (or any client).
///
/// All operations return immediately: synchronous operations fill `reply`
/// with the result; asynchronous operations (connect, recv, accept) return
/// `TRONA_PENDING` and the TCP/UDP/raw state machine will push a completion
/// later (delivered to VFS via the callback endpoint).
///
/// Returns `true` if the reply is deferred (DNS async): the caller's reply
/// cap has been saved and will be replied to later via `drain_dns_completions`.
fn dispatch_ipc(msg: &TronaMsg, reply: &mut TronaMsg) -> bool {
    fn set_send_reply(reply: &mut TronaMsg, sent: i32) {
        if sent >= 0 {
            reply.label = TRONA_OK;
            reply.regs[0] = sent as u64;
            reply.length = 1;
        } else {
            trona::udebug!(|_lb| {
                _lb.str(b"[netsrv] send failed label=");
                _lb.dec((-sent) as u64);
                _lb.putc(b'\n');
            });
            reply.label = (-sent) as u64;
            reply.regs[0] = 0;
            reply.length = 0;
        }
    }

    match msg.label {
        NET_REGISTER_VFS => {
            // VFS transfers a plain, IPC-transferable endpoint cap. Rebadge it
            // locally so callbacks arrive with a distinctive badge on the VFS
            // side without relying on label-based fallback routing.
            let mint_err = invoke::cnode_mint(
                CAP_SELF_CSPACE,
                CAP_VFS_CALLBACK_EP,
                CAP_SELF_CSPACE,
                CAP_VFS_CALLBACK_BADGED_EP,
                NETSRV_CALLBACK_BADGE,
            );
            if mint_err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[netsrv] failed to mint local callback alias err=");
                    _lb.dec(mint_err as u64);
                    _lb.putc(b'\n');
                });
                reply.label = TRONA_INVALID_OPERATION;
            } else {
                unsafe {
                    *(&raw mut VFS_REGISTERED) = true;
                }
                trona::uinfo!(|_lb| {
                    _lb.str(b"[netsrv] VFS callback EP registered\n");
                });
                reply.label = TRONA_OK;
            }
        }
        NET_SOCKET => {
            let sock_type = msg.regs[0] as i32;
            let protocol = msg.regs[1] as i32;
            let id = if sock_type == SOCK_STREAM {
                net::socket::tcp::tcp_socket()
            } else if sock_type == SOCK_DGRAM {
                net::socket::udp::udp_socket()
            } else if sock_type == SOCK_RAW {
                net::socket::raw_ipv4::raw_socket(protocol as u8)
            } else {
                -(TRONA_PROTO_NOT_SUPPORTED as i32)
            };
            if id >= 0 {
                log_inet_ipc(b"socket", id as u32, 0, protocol as u16, 0);
                reply.label = TRONA_OK;
                reply.regs[0] = id as u64;
                reply.length = 1;
            } else {
                reply.label = if id == -(TRONA_PROTO_NOT_SUPPORTED as i32) {
                    TRONA_PROTO_NOT_SUPPORTED
                } else {
                    TRONA_OUT_OF_MEMORY
                };
            }
        }
        NET_CONNECT => {
            let conn_id = msg.regs[0] as u32;
            let ip = msg.regs[1] as u32;
            let port = msg.regs[2] as u16;
            log_inet_ipc(b"connect", conn_id, ip, port, 0);
            match socket_kind(conn_id) {
                SocketKind::Raw => {
                    let result = net::socket::raw_ipv4::raw_connect(conn_id, ip);
                    reply.label = if result == 0 {
                        TRONA_OK
                    } else {
                        TRONA_INVALID_ARGUMENT
                    };
                }
                SocketKind::Udp => {
                    let result = net::socket::udp::udp_connect(conn_id, ip, port);
                    reply.label = if result == 0 {
                        TRONA_OK
                    } else {
                        TRONA_INVALID_ARGUMENT
                    };
                }
                SocketKind::Tcp => {
                    let result = net::socket::tcp::tcp_connect(conn_id, ip, port);
                    if result == -1 {
                        reply.label = TRONA_PENDING;
                    } else {
                        reply.label = TRONA_INVALID_ARGUMENT;
                    }
                }
            }
        }
        NET_BIND => {
            let conn_id = msg.regs[0] as u32;
            let ip = msg.regs[1] as u32;
            let port = msg.regs[2] as u16;
            match socket_kind(conn_id) {
                SocketKind::Raw => {
                    reply.label = TRONA_INVALID_OPERATION;
                }
                SocketKind::Udp => {
                    let result = net::socket::udp::udp_bind(conn_id, ip, port);
                    reply.label = if result == 0 {
                        TRONA_OK
                    } else {
                        TRONA_INVALID_ARGUMENT
                    };
                }
                SocketKind::Tcp => {
                    let result = net::socket::tcp::tcp_bind(conn_id, ip, port);
                    reply.label = if result == 0 {
                        TRONA_OK
                    } else {
                        TRONA_INVALID_ARGUMENT
                    };
                }
            }
        }
        NET_LISTEN => {
            let conn_id = msg.regs[0] as u32;
            match socket_kind(conn_id) {
                SocketKind::Tcp => {
                    let backlog = msg.regs[1] as u8;
                    let result = net::socket::tcp::tcp_listen(conn_id, backlog);
                    reply.label = if result == 0 {
                        TRONA_OK
                    } else {
                        TRONA_INVALID_ARGUMENT
                    };
                }
                _ => {
                    reply.label = TRONA_INVALID_OPERATION;
                }
            }
        }
        NET_ACCEPT => {
            let conn_id = msg.regs[0] as u32;
            match socket_kind(conn_id) {
                SocketKind::Tcp => {
                    let result = net::socket::tcp::tcp_accept(conn_id);
                    if result == -1 {
                        // No pending connections -- tell VFS this is async
                        net::socket::tcp::set_pending_accept(conn_id);
                        reply.label = TRONA_PENDING;
                    } else if result > 0 {
                        // Connection already in backlog, completed immediately
                        let new_cid = result as u32;
                        match net::socket::tcp::tcp_getpeername(new_cid) {
                            Ok((ip, port)) => {
                                reply.label = TRONA_OK;
                                reply.regs[0] = new_cid as u64;
                                reply.regs[1] = ip as u64;
                                reply.regs[2] = port as u64;
                                reply.length = 3;
                            }
                            Err(label) => {
                                reply.label = label;
                            }
                        }
                    } else {
                        reply.label = TRONA_INVALID_ARGUMENT;
                    }
                }
                _ => {
                    reply.label = TRONA_INVALID_OPERATION;
                }
            }
        }
        NET_SEND => {
            let conn_id = msg.regs[0] as u32;
            let len = msg.regs[1] as usize;
            let actual_len = core::cmp::min(len, 144);
            log_inet_ipc(b"send", conn_id, 0, 0, actual_len);
            // SAFETY: Reading data bytes from IPC message register area.
            let data = unsafe {
                let data_ptr = &msg.regs[2] as *const u64 as *const u8;
                core::slice::from_raw_parts(data_ptr, actual_len)
            };
            let sent = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_send(conn_id, data),
                SocketKind::Udp => net::socket::udp::udp_send(conn_id, data),
                SocketKind::Tcp => net::socket::tcp::tcp_send(conn_id, data),
            };
            set_send_reply(reply, sent);
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
            let result = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_recv(conn_id, buf),
                SocketKind::Udp => net::socket::udp::udp_recv(conn_id, buf),
                SocketKind::Tcp => net::socket::tcp::tcp_recv(conn_id, buf),
            };
            if result == -1 {
                match socket_kind(conn_id) {
                    SocketKind::Raw => {
                        net::socket::raw_ipv4::set_pending_recv(conn_id, capped as u16);
                    }
                    SocketKind::Udp => {
                        net::socket::udp::set_pending_recv(conn_id, capped as u16);
                    }
                    SocketKind::Tcp => {
                        net::socket::tcp::set_pending_recv(conn_id, capped as u16);
                    }
                }
                reply.label = TRONA_PENDING;
            } else {
                reply.label = TRONA_OK;
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
            log_inet_ipc(b"sendto", conn_id, ip, port, actual);
            // SAFETY: Reading data bytes from IPC message register area.
            let data = unsafe {
                let data_ptr = &msg.regs[4] as *const u64 as *const u8;
                core::slice::from_raw_parts(data_ptr, actual)
            };
            let sent = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_sendto(conn_id, data, ip),
                SocketKind::Udp => net::socket::udp::udp_sendto(conn_id, data, ip, port),
                SocketKind::Tcp => net::socket::tcp::tcp_send(conn_id, data),
            };
            set_send_reply(reply, sent);
        }
        NET_RECVFROM => {
            let conn_id = msg.regs[0] as u32;
            let max_len = msg.regs[1] as u16;
            let flags = if msg.length >= 3 {
                msg.regs[2] as u32
            } else {
                INET_RECVMSG_WANT_ADDR
            };
            let want_timestamp = (flags & INET_RECVMSG_WANT_TIMESTAMP) != 0;
            let capped = core::cmp::min(max_len, 128) as usize;
            log_inet_ipc(b"recvfrom", conn_id, 0, 0, capped);
            // SAFETY: Writing data into reply register area.
            let buf = unsafe {
                let dst = &raw mut reply.regs[4] as *mut u8;
                core::slice::from_raw_parts_mut(dst, capped)
            };
            match socket_kind(conn_id) {
                SocketKind::Raw => {
                    let (result, src_ip, src_port, timestamp_ns) =
                        net::socket::raw_ipv4::raw_recvfrom(conn_id, buf, want_timestamp);
                    if result == -1 {
                        net::socket::raw_ipv4::set_pending_recvfrom(
                            conn_id,
                            capped as u16,
                            flags,
                        );
                        reply.label = TRONA_PENDING;
                    } else {
                        let data_len = result as usize;
                        reply.label = TRONA_OK;
                        reply.regs[0] = result as u64;
                        reply.regs[1] = src_ip as u64;
                        reply.regs[2] = src_port as u64;
                        reply.regs[3] = timestamp_ns;
                        reply.length = 4 + (((result as u64) + 7) / 8);
                        log_inet_recv_result(
                            b"recvfrom",
                            conn_id,
                            src_ip,
                            data_len,
                            &buf[..data_len],
                        );
                    }
                }
                SocketKind::Udp => {
                    let (result, src_ip, src_port, timestamp_ns) =
                        net::socket::udp::udp_recvfrom(conn_id, buf, want_timestamp);
                    if result == -1 {
                        net::socket::udp::set_pending_recvfrom(conn_id, capped as u16, flags);
                        reply.label = TRONA_PENDING;
                    } else {
                        reply.label = TRONA_OK;
                        reply.regs[0] = result as u64;
                        reply.regs[1] = src_ip as u64;
                        reply.regs[2] = src_port as u64;
                        reply.regs[3] = timestamp_ns;
                        reply.length = 4 + ((result as u64 + 7) / 8);
                    }
                }
                SocketKind::Tcp => {
                    reply.label = TRONA_INVALID_OPERATION;
                }
            }
        }
        NET_CLOSE => {
            let conn_id = msg.regs[0] as u32;
            match socket_kind(conn_id) {
                SocketKind::Raw => { net::socket::raw_ipv4::raw_close(conn_id); }
                SocketKind::Udp => { net::socket::udp::udp_close(conn_id); }
                SocketKind::Tcp => { net::socket::tcp::tcp_close(conn_id); }
            }
            reply.label = TRONA_OK;
        }
        NET_SHUTDOWN => {
            let conn_id = msg.regs[0] as u32;
            let how = msg.regs[1] as i32;
            match socket_kind(conn_id) {
                SocketKind::Raw => { net::socket::raw_ipv4::raw_close(conn_id); }
                SocketKind::Udp => { net::socket::udp::udp_close(conn_id); }
                SocketKind::Tcp => { net::socket::tcp::tcp_shutdown(conn_id, how); }
            }
            reply.label = TRONA_OK;
        }
        NET_GETSOCKNAME => {
            let conn_id = msg.regs[0] as u32;
            let (ip, port) = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_getsockname(conn_id),
                SocketKind::Udp => net::socket::udp::udp_getsockname(conn_id),
                SocketKind::Tcp => net::socket::tcp::tcp_getsockname(conn_id),
            };
            reply.label = TRONA_OK;
            reply.regs[0] = ip as u64;
            reply.regs[1] = port as u64;
            reply.length = 2;
        }
        NET_GETPEERNAME => {
            let conn_id = msg.regs[0] as u32;
            let result = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_getpeername(conn_id),
                SocketKind::Udp => net::socket::udp::udp_getpeername(conn_id),
                SocketKind::Tcp => net::socket::tcp::tcp_getpeername(conn_id),
            };
            match result {
                Ok((ip, port)) => {
                    reply.label = TRONA_OK;
                    reply.regs[0] = ip as u64;
                    reply.regs[1] = port as u64;
                    reply.length = 2;
                }
                Err(label) => {
                    reply.label = label;
                }
            }
        }
        NET_SETSOCKOPT => {
            let conn_id = msg.regs[0] as u32;
            let level = msg.regs[1] as i32;
            let optname = msg.regs[2] as i32;
            let optval = msg.regs[3];
            let optlen = msg.regs[4] as u32;
            reply.label = match socket_kind(conn_id) {
                SocketKind::Raw => {
                    net::socket::raw_ipv4::raw_setsockopt(conn_id, level, optname, optval, optlen)
                }
                SocketKind::Udp => {
                    net::socket::udp::udp_setsockopt(conn_id, level, optname, optval, optlen)
                }
                SocketKind::Tcp => {
                    net::socket::tcp::tcp_setsockopt(conn_id, level, optname, optval, optlen)
                }
            };
        }
        NET_GETSOCKOPT => {
            let conn_id = msg.regs[0] as u32;
            let level = msg.regs[1] as i32;
            let optname = msg.regs[2] as i32;
            let result = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_getsockopt(conn_id, level, optname),
                SocketKind::Udp => net::socket::udp::udp_getsockopt(conn_id, level, optname),
                SocketKind::Tcp => net::socket::tcp::tcp_getsockopt(conn_id, level, optname),
            };
            match result {
                Ok((value, len)) => {
                    reply.label = TRONA_OK;
                    reply.regs[0] = value;
                    reply.regs[1] = len as u64;
                    reply.length = 2;
                }
                Err(label) => {
                    reply.label = label;
                }
            }
        }
        NET_POLL_STATUS => {
            let conn_id = msg.regs[0] as u32;
            let events = msg.regs[1] as u16;
            let revents = match socket_kind(conn_id) {
                SocketKind::Raw => net::socket::raw_ipv4::raw_poll_status(conn_id, events),
                SocketKind::Udp => net::socket::udp::udp_poll_status(conn_id, events),
                SocketKind::Tcp => net::socket::tcp::tcp_poll_status(conn_id, events),
            };
            reply.label = TRONA_OK;
            reply.regs[0] = revents as u64;
            reply.length = 1;
        }
        NET_DNS_RESOLVE => {
            let hostname_len = msg.regs[0] as usize;
            if hostname_len == 0 || hostname_len > 120 {
                reply.label = TRONA_INVALID_ARGUMENT;
                return false;
            }
            // SAFETY: Reading hostname bytes from IPC message register area.
            // hostname_len is at most 120 bytes, which fits in regs[1..16] (indices 1..=15, i.e., 15 u64 registers = 120 bytes).
            let mut hostname = [0u8; 120];
            unsafe {
                let src = &msg.regs[1] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(src, hostname.as_mut_ptr(), hostname_len);
            }
            match net::dns::start_resolve(&hostname[..hostname_len]) {
                Some(_) => return true, // deferred
                None => {
                    reply.label = TRONA_OUT_OF_MEMORY;
                }
            }
        }
        NET_DNS_RESOLVE_PTR => {
            let ip = msg.regs[0] as u32;
            match net::dns::start_resolve_ptr(ip) {
                Some(_) => return true, // deferred
                None => {
                    reply.label = TRONA_OUT_OF_MEMORY;
                }
            }
        }
        NET_GET_CONFIG => {
            let cfg = net::config::snapshot();
            reply.label = TRONA_OK;
            reply.regs[0] = cfg.state as u64;
            reply.regs[1] = cfg.our_ip as u64;
            reply.regs[2] = cfg.subnet_mask as u64;
            reply.regs[3] = cfg.gateway_ip as u64;
            reply.regs[4] = cfg.dns_server as u64;
            reply.regs[5] = cfg.rx_bytes;
            reply.regs[6] = cfg.rx_packets;
            reply.regs[7] = cfg.tx_bytes;
            reply.regs[8] = cfg.tx_packets;
            reply.length = 9;
        }
        NET_GET_ARP_ENTRY => {
            let idx = msg.regs[0] as usize;
            if idx >= 16 {
                reply.label = TRONA_INVALID_ARGUMENT;
            } else if let Some((ip, mac)) = net::proto::arp::entry(idx) {
                reply.label = TRONA_OK;
                reply.regs[0] = 1;
                reply.regs[1] = ip as u64;
                reply.regs[2] = ((mac[0] as u64) << 40)
                    | ((mac[1] as u64) << 32)
                    | ((mac[2] as u64) << 24)
                    | ((mac[3] as u64) << 16)
                    | ((mac[4] as u64) << 8)
                    | (mac[5] as u64);
                reply.length = 3;
            } else {
                reply.label = TRONA_OK;
                reply.regs[0] = 0;
                reply.length = 1;
            }
        }
        _ => {
            reply.label = TRONA_INVALID_OPERATION;
        }
    }
    false
}

/// Map a DNS error to an IPC error label.
fn dns_error_to_label(err: net::dns::DnsError) -> u64 {
    match err {
        net::dns::DnsError::NxDomain => TRONA_DNS_NXDOMAIN,
        net::dns::DnsError::ServerFail => TRONA_DNS_SERVER_FAIL,
        net::dns::DnsError::Timeout => TRONA_TIMED_OUT,
        net::dns::DnsError::Other => TRONA_NOT_FOUND,
    }
}

/// Drain completed async DNS queries and send deferred replies to saved
/// caller caps.
fn drain_dns_completions(ctx: *mut IpcContext) {
    while let Some(c) = net::dns::pop_completion() {
        let mut reply = TronaMsg::zeroed();
        match c.query_type {
            net::dns::DnsQueryType::A => {
                if c.success {
                    reply.label = TRONA_OK;
                    reply.regs[0] = c.dns_result.ip_count as u64;
                    reply.regs[1] = c.dns_result.ttl as u64;
                    let mut i = 0;
                    while i < c.dns_result.ip_count as usize && i < 4 {
                        reply.regs[2 + i] = c.dns_result.ips[i] as u64;
                        i += 1;
                    }
                    reply.length = 2 + c.dns_result.ip_count as u64;
                } else {
                    reply.label = dns_error_to_label(c.error);
                }
            }
            net::dns::DnsQueryType::Ptr => {
                if c.success {
                    reply.label = TRONA_OK;
                    let copy_len = core::cmp::min(c.ptr_hostname_len, 152);
                    reply.regs[0] = copy_len as u64;
                    if copy_len > 0 {
                        // SAFETY: Writing hostname bytes into reply register area.
                        unsafe {
                            let dst = &raw mut reply.regs[1] as *mut u8;
                            core::ptr::copy_nonoverlapping(
                                c.ptr_hostname.as_ptr(),
                                dst,
                                copy_len,
                            );
                        }
                    }
                    reply.length = 1 + ((copy_len as u64 + 7) / 8);
                } else {
                    reply.label = dns_error_to_label(c.error);
                }
            }
        }
        // SAFETY: IPC context is valid; reply cap slot was saved by start_resolve*.
        unsafe {
            ipc::send_ctx(ctx, c.reply_cap_slot, &raw const reply);
        }
    }
}

/// Receive the next event on the server EP, with a timeout if DNS queries
/// are pending. On timeout, sets badge to 1 to trigger notification
/// processing (which calls `dns::process_pending` to check deadlines).
///
/// # Safety
///
/// `ctx` must be a valid IPC context. `msg` and `badge` must be valid pointers.
unsafe fn do_recv(ctx: *mut IpcContext, msg: *mut TronaMsg, badge: *mut u64) {
    unsafe {
        if net::dns::has_pending() || net::dhcp::has_timer() {
            let now = net::dns::clock_monotonic_ns();
            let dns_deadline = if net::dns::has_pending() {
                net::dns::nearest_deadline_ns()
            } else {
                u64::MAX
            };
            let dhcp_deadline = if net::dhcp::has_timer() {
                net::dhcp::nearest_deadline_ns()
            } else {
                u64::MAX
            };
            let deadline = core::cmp::min(dns_deadline, dhcp_deadline);
            if deadline <= now {
                // Deadline already passed; skip recv and process immediately
                *badge = 1;
                return;
            }
            let timeout = deadline.saturating_sub(now).max(100_000); // min 100us
            let r = trona::syscall::syscall(
                SYS_RECV_TIMED,
                CAP_SERVER_EP,
                timeout,
                0,
                0,
                0,
                0,
            );
            if r.error == 0 {
                *badge = r.value;
                // Read message from IPC buffer (same as recv_ctx does)
                let buf = (*ctx).ipc_buffer as *const TronaMsg;
                *msg = *buf;
            } else {
                // Timeout: trigger notification processing to check DNS deadlines
                *badge = 1;
            }
        } else {
            ipc::recv_ctx(ctx, CAP_SERVER_EP, msg, badge);
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
///   regs[1] = result  (TRONA_OK, TRONA_CONN_REFUSED, etc.)
///   regs[2] = op_type (INET_OP_CONNECT, INET_OP_RECV, etc.)
///   regs[3] = data_len / extra_conn_id (depends on op_type)
///   regs[4] = extra_ip / data start
///   regs[5] = extra_port
///   regs[6] = timestamp_ns_or_none (recvfrom only)
///   regs[7..] = data bytes (for recvfrom)
fn notify_vfs_completion(
    conn_id: u32,
    result: u64,
    op_type: u8,
    data: &[u8],
    data_len: usize,
    extra_conn_id: u32,
    extra_ip: u32,
    extra_port: u16,
    timestamp_ns: u64,
) {
    // SAFETY: Single-threaded server; VFS_REGISTERED is set once.
    let registered = unsafe { *(&raw const VFS_REGISTERED) };
    if !registered {
        trona::udebug!(|_lb| {
            _lb.str(b"[netsrv] notify skip conn=");
            _lb.dec(conn_id as u64);
            _lb.str(b" op=");
            _lb.dec(op_type as u64);
            _lb.str(b" registered=0\n");
        });
        return;
    }
    let mut msg = TronaMsg::zeroed();
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
            let max_data = core::cmp::min(data_len, 104);
            msg.regs[3] = max_data as u64;
            msg.regs[4] = extra_ip as u64;
            msg.regs[5] = extra_port as u64;
            msg.regs[6] = timestamp_ns;
            if max_data > 0 {
                // SAFETY: Writing data bytes into message register area.
                unsafe {
                    let dst = &raw mut msg.regs[7] as *mut u8;
                    let mut i = 0;
                    while i < max_data {
                        *dst.add(i) = data[i];
                        i += 1;
                    }
                }
            }
            msg.length = 7 + ((max_data as u64 + 7) / 8);
        }
        _ => {
            msg.length = 3;
        }
    }

    let mut resp = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; slot 84 holds the local badged alias.
    let call_err = unsafe {
        ipc::call_ctx(
            ipc_ctx(),
            CAP_VFS_CALLBACK_BADGED_EP,
            &raw const msg,
            &raw mut resp,
        )
    };
    trona::udebug!(|_lb| {
        _lb.str(b"[netsrv] notify conn=");
        _lb.dec(conn_id as u64);
        _lb.str(b" op=");
        _lb.dec(op_type as u64);
        _lb.str(b" len=");
        _lb.dec(data_len as u64);
        _lb.str(b" err=");
        _lb.hex(call_err as u64);
        _lb.str(b" resp=");
        _lb.hex(resp.label);
        _lb.putc(b'\n');
    });
}

/// Drain all pending completions from raw, TCP, and UDP modules, delivering each
/// to VFS via the callback endpoint.
///
/// Called after RX processing (when VFS is in its event loop, not blocked
/// on a netsrv call) and after timer processing.
fn drain_completion_queue() {
    while let Some(c) = net::socket::raw_ipv4::pop_completion() {
        trona::udebug!(|_lb| {
            _lb.str(b"[netsrv] drain raw conn=");
            _lb.dec(c.conn_id as u64);
            _lb.str(b" op=");
            _lb.dec(c.op_type as u64);
            _lb.str(b" len=");
            _lb.dec(c.data_len as u64);
            _lb.putc(b'\n');
        });
        notify_vfs_completion(
            c.conn_id,
            c.result,
            c.op_type,
            &c.data[..c.data_len],
            c.data_len,
            c.extra_conn_id,
            c.extra_ip,
            c.extra_port,
            c.timestamp_ns,
        );
    }
    while let Some(c) = net::socket::tcp::pop_completion() {
        notify_vfs_completion(
            c.conn_id,
            c.result,
            c.op_type,
            &c.data[..c.data_len],
            c.data_len,
            c.extra_conn_id,
            c.extra_ip,
            c.extra_port,
            trona::consts::INET_RECV_TIMESTAMP_NONE,
        );
    }
    while let Some(c) = net::socket::udp::pop_completion() {
        notify_vfs_completion(
            c.conn_id,
            c.result,
            c.op_type,
            &c.data[..c.data_len],
            c.data_len,
            c.extra_conn_id,
            c.extra_ip,
            c.extra_port,
            c.timestamp_ns,
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
    trona::uinfo!(|_lb| {
        _lb.str(b"[netsrv] Entering event loop\n");
    });

    let ctx = ipc_ctx();
    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;

    // Set receive slot for the plain VFS callback EP (slot 83).
    // We rebadge it locally into slot 84 after registration.
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
            // Woken by bound notification: RX/TX progress from netdrv.
            // Retry queued IP packets on every notification so packets queued
            // due to transient TX-ring pressure are not stranded waiting for
            // an unrelated ARP reply.
            process_rx_from_shm();
            net::flush_pending_packets();
            net::dhcp::process();
            net::socket::tcp::process_timers();
            net::dns::process_pending();
            drain_completion_queue();
            drain_dns_completions(ctx);
            check_self_test();

            // Wait for next event (with timeout if DNS queries are pending)
            msg = TronaMsg::zeroed();
            badge = 0;
            unsafe {
                do_recv(ctx, &raw mut msg, &raw mut badge);
            }
        } else {
            // IPC request on server endpoint
            let mut reply = TronaMsg::zeroed();
            let deferred = dispatch_ipc(&msg, &mut reply);
            badge = 0;

            if deferred {
                unsafe {
                    msg = TronaMsg::zeroed();
                    do_recv(ctx, &raw mut msg, &raw mut badge);
                }
            } else if net::dns::has_pending() || net::dhcp::has_timer() {
                // Non-deferred reply, but timer-driven work is pending: split
                // reply + recv so we can use a timed recv for DNS/DHCP deadlines.
                // SAFETY: IPC context is valid; reply cap saved then sent.
                unsafe {
                    let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, CAP_REPLY_TEMP);
                    if err == 0 {
                        ipc::send_ctx(ctx, CAP_REPLY_TEMP, &raw const reply);
                        msg = TronaMsg::zeroed();
                        do_recv(ctx, &raw mut msg, &raw mut badge);
                    } else {
                        ipc::reply_recv_ctx(
                            ctx,
                            CAP_SERVER_EP,
                            &raw const reply,
                            &raw mut msg,
                            &raw mut badge,
                        );
                    }
                }
            } else {
                // Normal path: reply + recv atomically
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
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[netsrv] Network Stack Server starting\n");
    });

    // 1. Allocate and map SHM
    if !setup_shm() {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] SHM setup failed, halting\n");
        });
        idle();
    }

    // 2. Setup notification (allocate, bind to TCB, mint badged copy)
    if !setup_notification() {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] Notification setup failed, halting\n");
        });
        idle();
    }

    // 3. Register with netdrv (DRIVER_REGISTER: exchange SHM ID, caps, get MAC)
    if !driver_register() {
        trona::uerror!(|_lb| {
            _lb.str(b"[netsrv] Driver register failed, halting\n");
        });
        idle();
    }

    // 4. Resolve initial network configuration via DHCP with a static fallback.
    bootstrap_network_config();

    // 4b. Fire-and-forget ARP request for the configured gateway.
    if net::proto::ipv4::our_ip() != 0 && net::proto::ipv4::gateway_ip() != 0 {
        trona::udebug!(|_lb| {
            _lb.str(b"[netsrv] Self-test: ARP request for configured gateway\n");
        });
        net::proto::arp::request(
            &mac_addr(),
            net::proto::ipv4::our_ip(),
            net::proto::ipv4::gateway_ip(),
        );
    } else {
        unsafe {
            *(&raw mut SELF_TEST_PHASE) = 2;
        }
    }

    // 5. Register with name service
    register_nameserv();

    // 5b. Initialize DNS protocol engine
    net::dns::init_dns_socket();

    // 6. Signal readiness to init
    signal_ready();

    // 7. Enter event loop (never returns)
    event_loop()
}

fn idle() -> ! {
    loop {
        let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
