// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS virtio-net Hardware-Only Network Device Driver
//!
//! Discovers a virtio-net PCI device via pcisrv, initializes the virtio
//! transport (legacy PCI), sets up IRQ handling, and forwards raw Ethernet
//! frames between the hardware and netsrv via SHM ring buffers.
//!
//! netsrv owns the protocol stack (TCP/IP, ARP, ICMP, etc.). This driver
//! only does hardware I/O and frame forwarding.
//!
//! Communication with netsrv:
//!   - SHM ring buffers (128KB, 32 pages) for RX and TX frame exchange
//!   - Notification signaling: netdrv signals netsrv when RX frames are
//!     available; netsrv signals netdrv (via badged notification) when TX
//!     frames are queued.
//!
//! Cap layout:
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   5  = nameserv endpoint
//!   7  = mmsrv endpoint
//!   14 = readiness notification
//!   64 = pcisrv endpoint
//!   68 = server endpoint (pre-created service EP)
//!   84 = netsrv's RX notification cap (received during DRIVER_REGISTER)
//!   81 = IRQ handler cap (received from pcisrv via PCI_GET_CAPS extra cap #1)
//!   82 = IRQ notification (retyped from untyped, sent to netsrv via IPC)

#![no_std]
#![no_main]

extern crate salty;

mod virtio;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

// ---------------------------------------------------------------------------
// Capability slot constants
// ---------------------------------------------------------------------------

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_MMSRV_EP: u64 = 7;
const CAP_IRQ_HANDLER: u64 = 81;
const CAP_IRQ_NOTIFICATION: u64 = 82;
const CAP_NETSRV_RX_NTFN: u64 = 84;

// ---------------------------------------------------------------------------
// SHM ring buffer constants
// ---------------------------------------------------------------------------

const SHM_VADDR: u64 = 0x0000_0000_6000_0000;
const NET_SHM_ID: u64 = 0x4E455400;
const TX_BADGE: u64 = 0x2;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

static mut IRQ_ENABLED: bool = false;
static mut SHM_BASE: u64 = 0;
static mut NETSRV_RX_NTFN: u64 = 0;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// IRQ setup
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// SHM ring buffer operations
// ---------------------------------------------------------------------------

/// Enqueue a received Ethernet frame into the SHM RX ring for netsrv.
///
/// Returns true if the frame was enqueued, false if the ring is full or SHM
/// is not yet mapped.
fn shm_rx_enqueue(frame: &[u8]) -> bool {
    // SAFETY: SHM_BASE is set once during DRIVER_REGISTER before any enqueue
    // calls. Single-threaded driver. All pointer arithmetic is within the
    // mapped SHM region (header at offset 0, RX ring at offset 0x1000).
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return false;
        }
        let hdr = base as *mut u32;
        let rx_head = *hdr.add(0);
        let rx_tail = core::ptr::read_volatile(hdr.add(1));
        let slot_count = *hdr.add(4); // offset 0x10
        let next = (rx_head + 1) % slot_count;
        if next == rx_tail {
            return false;
        }

        let slot_base = base + 0x1000 + (rx_head as u64) * 2048;
        let len = core::cmp::min(frame.len(), 1998);
        let len_ptr = slot_base as *mut u16;
        *len_ptr = len as u16;
        let data_ptr = (slot_base + 2) as *mut u8;
        core::ptr::copy_nonoverlapping(frame.as_ptr(), data_ptr, len);

        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(hdr.add(0), next);
        true
    }
}

/// Dequeue a TX frame from the SHM TX ring (queued by netsrv).
///
/// Returns the frame length if a frame was dequeued, None if the ring is
/// empty or SHM is not yet mapped.
fn shm_tx_dequeue(buf: &mut [u8; 2048]) -> Option<usize> {
    // SAFETY: SHM_BASE is set once during DRIVER_REGISTER. Single-threaded
    // driver. All pointer arithmetic is within the mapped SHM region (header
    // at offset 0, TX ring at offset 0x11000).
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return None;
        }
        let hdr = base as *mut u32;
        let tx_head = core::ptr::read_volatile(hdr.add(2));
        let tx_tail = *hdr.add(3);
        if tx_head == tx_tail {
            return None;
        }

        let slot_base = base + 0x11000 + (tx_tail as u64) * 2048;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let len = *(slot_base as *const u16) as usize;
        let len = core::cmp::min(len, 1998);
        let data = (slot_base + 2) as *const u8;
        core::ptr::copy_nonoverlapping(data, buf.as_mut_ptr(), len);

        let slot_count = *hdr.add(5); // offset 0x14
        core::ptr::write_volatile(hdr.add(3), (tx_tail + 1) % slot_count);
        Some(len)
    }
}

/// Signal netsrv that RX frames are available in the SHM ring.
fn signal_netsrv_rx() {
    // SAFETY: NETSRV_RX_NTFN is set during DRIVER_REGISTER before any
    // signal calls. Single-threaded driver.
    let cap = unsafe { *(&raw const NETSRV_RX_NTFN) };
    if cap != 0 {
        let _ = salty::syscall::syscall(SYS_SIGNAL, cap, 1, 0, 0, 0, 0);
    }
}

// ---------------------------------------------------------------------------
// RX/TX frame processing
// ---------------------------------------------------------------------------

/// Process all pending received packets from virtio and enqueue them into
/// the SHM RX ring for netsrv.
fn drain_rx() {
    let mut any_enqueued = false;
    while let Some((buf_idx, len)) = virtio::rx_poll() {
        let data = virtio::rx_get_data(buf_idx, len);
        // Skip VirtioNetHdr (10 bytes) to get the Ethernet frame
        if len > virtio::VIRTIO_NET_HDR_SIZE {
            let pkt = &data[virtio::VIRTIO_NET_HDR_SIZE..];
            if shm_rx_enqueue(pkt) {
                any_enqueued = true;
            }
        }
        virtio::rx_repost(buf_idx);
    }
    if any_enqueued {
        signal_netsrv_rx();
    }
}

/// Drain all pending TX frames from the SHM TX ring (queued by netsrv) and
/// transmit them via virtio.
fn drain_tx_ring() {
    let mut buf = [0u8; 2048];
    while let Some(len) = shm_tx_dequeue(&mut buf) {
        virtio::tx_packet(&buf[..len]);
    }
}

// ---------------------------------------------------------------------------
// DRIVER_REGISTER IPC handler
// ---------------------------------------------------------------------------

/// Handle the DRIVER_REGISTER IPC from netsrv.
///
/// netsrv sends DRIVER_REGISTER with:
///   regs[0] = SHM ID (must match NET_SHM_ID)
///   extra_caps[0] = netsrv's badged RX notification cap
///
/// On success, replies with:
///   label = SALTY_OK
///   regs[0] = MAC address low 4 bytes (network order)
///   regs[1] = MAC address high 2 bytes (network order)
///   regs[2] = link status (1 = up)
///   extra_caps[0] = badged copy of our IRQ notification (badge=TX_BADGE)
fn handle_driver_register(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    let shm_id = msg.regs[0];
    if shm_id != NET_SHM_ID {
        reply.label = SALTY_INVALID_ARGUMENT;
        return;
    }

    // Store netsrv's RX notification cap (received as extra_cap from the Call).
    // The cap was placed in CAP_NETSRV_RX_NTFN by the receive slot setup.
    // SAFETY: Single-threaded driver; written once during registration.
    unsafe {
        *(&raw mut NETSRV_RX_NTFN) = CAP_NETSRV_RX_NTFN;
    }

    // Map the SHM into our address space via mmsrv
    let ctx = ipc_ctx();
    let mut map_msg = SaltyMsg::zeroed();
    map_msg.label = MM_SHM_MAP;
    map_msg.regs[0] = NET_SHM_ID;
    map_msg.regs[1] = 0; // client_badge: 0 = map into caller (netdrv)
    map_msg.regs[2] = SHM_VADDR;
    map_msg.regs[3] = 0x3; // RW permissions
    map_msg.length = 4;
    let mut map_reply = SaltyMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const map_msg, &raw mut map_reply) };
    if err != 0 || map_reply.label != SALTY_OK {
        puts(b"[netdrv] Failed to map SHM\n");
        reply.label = SALTY_INVALID_OPERATION;
        return;
    }
    // SAFETY: Single-threaded driver; written once during registration.
    unsafe {
        *(&raw mut SHM_BASE) = SHM_VADDR;
    }

    // Send our IRQ notification cap (unbadged, retains GRANT right) as extra
    // cap in reply.  netsrv will pass TX_BADGE via the `bits` argument of
    // SYS_SIGNAL instead of relying on cap.badge.
    // SAFETY: IPC context is valid; setting extra cap for reply.
    unsafe {
        ipc::set_send_cap_ctx(ctx, 0, CAP_IRQ_NOTIFICATION);
    }

    // Reply with MAC address
    let mac = mac_addr();
    let mac_lo = ((mac[0] as u32) << 24)
        | ((mac[1] as u32) << 16)
        | ((mac[2] as u32) << 8)
        | (mac[3] as u32);
    let mac_hi = ((mac[4] as u16) << 8) | (mac[5] as u16);
    reply.label = SALTY_OK;
    reply.regs[0] = mac_lo as u64;
    reply.regs[1] = mac_hi as u64;
    reply.regs[2] = 1; // link status: up
    reply.length = 3;

    puts(b"[netdrv] DRIVER_REGISTER complete, SHM mapped\n");
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Main event loop: wait for IRQ notifications or IPC requests.
///
/// Uses a recv / reply_recv pattern:
/// - On notification (badge != 0): check for hardware IRQ and/or TX badge
///   from netsrv, process accordingly, then recv again.
/// - On IPC request (badge == 0): dispatch DRIVER_REGISTER, fill reply,
///   then reply_recv (atomically reply and wait for next event).
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
            // No device present -- idle loop with no hardware access
            puts(b"[netdrv] No device, idling\n");
            loop {
                let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }
    }

    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    // Set receive slot for netsrv's notification cap during DRIVER_REGISTER
    // SAFETY: IPC context is valid.
    unsafe {
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_NETSRV_RX_NTFN, 0);
    }

    // Initial recv -- wait for first event
    // SAFETY: IPC context is valid; server EP was set up by procmgr.
    unsafe {
        ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge);
    }

    loop {
        if badge != 0 {
            // Woken by bound notification -- check for hardware IRQ
            let isr = virtio::read_isr();
            if isr != 0 {
                drain_rx();
                let _ = invoke::irq_handler_ack(CAP_IRQ_HANDLER);
            }
            // Check for TX notification from netsrv (badge bit 0x2)
            if badge & TX_BADGE != 0 {
                drain_tx_ring();
            }

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
            match msg.label {
                DRIVER_REGISTER => handle_driver_register(&msg, &mut reply),
                _ => {
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }

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
    puts(b"[netdrv] virtio-net Hardware Driver starting\n");

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

    if device_ok {
        puts(b"[netdrv] virtio-net device ready\n");
    }

    // Register with nameserv and signal readiness
    register_nameserv();
    signal_ready();

    event_loop(device_ok)
}
