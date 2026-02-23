// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS virtio-net Network Device Driver
//!
//! Discovers a virtio-net PCI device via pcisrv, initializes the virtio
//! transport (legacy PCI), sets up IRQ handling, and serves as the network
//! driver. Responds to ARP and ICMP (ping) automatically.
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

#![no_std]
#![no_main]

extern crate salty;

mod virtio;
mod net;

use salty::consts::*;
use salty::ipc;
use salty::invoke;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_IRQ_HANDLER: u64 = 81;
const CAP_IRQ_NOTIFICATION: u64 = 82;

static mut IRQ_ENABLED: bool = false;

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

    // Step 1: Retype a Notification object from untyped memory
    let err = invoke::untyped_retype(CAP_UNTYPED_START, OBJ_NOTIFICATION, 0, CAP_IRQ_NOTIFICATION);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] Failed to retype Notification: ");
        lb.dec(err as u64);
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
    unsafe { *(&raw mut IRQ_ENABLED) = true; }

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
                    if ip_hdr.protocol == net::ipv4::PROTO_ICMP {
                        net::icmp::handle(&mac_addr(), net::ipv4::OUR_IP, &ip_hdr, ip_payload);
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
            }
        }
        None => {
            puts(b"[netdrv] ARP timeout for gateway\n");
        }
    }
}

/// Main event loop: wait for IRQ notifications or IPC requests.
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

    // Initial recv
    // SAFETY: IPC context is valid; server EP was set up by procmgr.
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        if badge != 0 {
            // Woken by bound notification (IRQ)
            handle_irq();
        } else {
            // IPC request on server endpoint -- not yet implemented
        }

        // Wait for next event
        msg = SaltyMsg::zeroed();
        badge = 0;
        // SAFETY: IPC context is valid.
        unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }
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
