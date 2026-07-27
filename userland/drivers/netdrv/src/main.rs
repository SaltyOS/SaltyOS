// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS virtio-net Hardware-Only Network Device Driver
//!
//! Discovers a virtio-net PCI device via pcidrv, initializes the virtio
//! transport (legacy PCI), sets up IRQ handling, and forwards raw Ethernet
//! frames between the hardware and netsrv via SHM ring buffers.
//!
//! netsrv owns the protocol stack (TCP/IP, ARP, ICMP, etc.). This driver
//! only does hardware I/O and frame forwarding.
//!
//! Communication with netsrv:
//!   - SHM ring buffers (header page + RX/TX slots) for frame exchange
//!   - MessagePipe kicks: netdrv sends `NETSRV_RX_KICK` after publishing
//!     RX frames; netsrv sends `NETDRV_TX_KICK` after publishing TX frames.
//!
//! Startup caps are role-based. System caps come from `trona_runtime::client::caps::*()`;
//! the service-local `pcidrv_ep` dependency is resolved through the
//! `trona_runtime::local_cap!` macro declared below, and a few IRQ/private
//! slots are runtime-local.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod virtio;
mod virtio_modern;

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::{TRONA_INVALID_OPERATION, TRONA_OK};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::netsrv::{NETDRV_REGISTER, NETDRV_TX_KICK, NETSRV_RX_KICK};
use trona_runtime::core::slot_alloc::{OwnedCap, OwnedSlot, TransferCap};

// Service-local cap: `Require=pcidrv-ep.socket` in `netdrv.service`
// (Provider=pcidrv, Alias=pcidrv_ep). Init hashes `"netdrv:pcidrv_ep"`
// into a LOCAL_ROLE id when building the startup cap_table.
trona_runtime::local_cap!(pub(crate) pcidrv_ep = "netdrv:pcidrv_ep");

// ---------------------------------------------------------------------------
// Capability slot constants
// ---------------------------------------------------------------------------

const CAP_SELF_CSPACE: u64 = 2;
// System roles still come from substrate `trona_runtime::client::caps::*`, while the driver's
// receive scratch slots are allocated from `trona_runtime::core::slot_alloc` so they do not
// collide with RTLD/runtime frame reservations.
static mut CAP_IRQ_HANDLER_SLOT: u64 = 0;
/// Stable receive scratch for the service-EP IPC dispatch loop.
/// Payload caps from inbound `MP_CALL` records are installed here.
/// Process-lifetime slot; allocated once and never freed.
static mut CAP_RECV_SCRATCH: Option<OwnedSlot> = None;

// ---------------------------------------------------------------------------
// SHM ring buffer constants
// ---------------------------------------------------------------------------

const SHM_MAP_HINT: u64 = 0;
const SHM_HEADER_BYTES: u64 = 0x1000;
const SHM_SLOT_BYTES: u64 = 2048;
const SHM_RX_SLOT_COUNT: u64 = 32;
const SHM_TX_SLOT_COUNT: u64 = 32;
const NET_SHM_BYTES: u64 =
    SHM_HEADER_BYTES + ((SHM_RX_SLOT_COUNT + SHM_TX_SLOT_COUNT) * SHM_SLOT_BYTES);
const NET_SHM_MAP_BYTES: u64 = (NET_SHM_BYTES + 4095) & !4095;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

static mut IRQ_ENABLED: bool = false;
pub(crate) static mut USING_MODERN_TRANSPORT: bool = false;
static mut SHM_BASE: u64 = 0;
static mut LOGGED_RX_FRAME: bool = false;
static mut LOGGED_TX_FRAME: bool = false;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn init_private_slots() {
    // Reserve one stable receive slot for NETDRV_REGISTER's SHM
    // memory-object cap.
    let slot = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"netdrv recv-scratch");
    // SAFETY: Single-threaded init; no other thread accesses CAP_RECV_SCRATCH yet.
    unsafe {
        *(&raw mut CAP_RECV_SCRATCH) = Some(slot);
    }
}

#[inline]
pub(crate) fn set_irq_handler_cap(slot: u64) {
    unsafe {
        *(&raw mut CAP_IRQ_HANDLER_SLOT) = slot;
    }
}

#[inline]
fn cap_irq_handler() -> u64 {
    unsafe { *(&raw const CAP_IRQ_HANDLER_SLOT) }
}

/// Returns the raw slot number for use as a receive slot target.
#[inline]
fn cap_recv_scratch_slot() -> u64 {
    // SAFETY: Written once during init; read-only afterwards.
    unsafe {
        match &*(&raw const CAP_RECV_SCRATCH) {
            Some(s) => s.borrow().addr(),
            None => 0,
        }
    }
}

fn idle() -> ! {
    loop {
        trona_kernel::syscall::yield_now();
    }
}

fn log_frame_bytes(prefix: &[u8], frame: &[u8]) {
    let dump_len = core::cmp::min(frame.len(), 32);
    let _ = (prefix, dump_len);
    trona_runtime::udebug!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" len=");
        _lb.dec(frame.len() as u64);
        _lb.str(b" bytes=");
        let mut i = 0;
        while i < dump_len {
            if i > 0 {
                _lb.putc(b' ');
            }
            let b = frame[i];
            if b < 0x10 {
                _lb.putc(b'0');
            }
            _lb.hex(b as u64);
            i += 1;
        }
        if dump_len < frame.len() {
            _lb.str(b" ...");
        }
        _lb.putc(b'\n');
    });
}

fn log_ethertype(prefix: &[u8], frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let ethertype = ((frame[12] as u16) << 8) | (frame[13] as u16);
    let _ = (prefix, ethertype);
    trona_runtime::udebug!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" len=");
        _lb.dec(frame.len() as u64);
        _lb.str(b" ethertype=");
        _lb.hex(ethertype as u64);
        _lb.putc(b'\n');
    });
}

/// Get our MAC address from the virtio driver.
fn mac_addr() -> [u8; 6] {
    // SAFETY: MAC_ADDR is set during init before any use.
    unsafe { *(&raw const virtio::MAC_ADDR) }
}

/// Register with name service as "netdrv".
fn register_namesrv() {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"netdrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let Some(publish_tc) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netdrv] No service client ep to publish\n");
        });
        return;
    };
    // SAFETY: Writing name bytes into message register space; IPC context is valid.
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.slot());
    }
    msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    msg.length = (REGISTER_FLAGS_REG + 1) as u64;
    unsafe {
        let mut reply = TronaMsg::zeroed();
        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        drop(publish_tc);
        if err != 0 || reply.label != TRONA_OK {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netdrv] namesrv registration failed\n");
            });
        }
    }
}

// ---------------------------------------------------------------------------
// IRQ setup
// ---------------------------------------------------------------------------

/// Set up IRQ handling for the device.
///
/// pcidrv may hand us an IRQ cap. RX IRQ events and TX kicks are both handled
/// by netdrv's EventQueue reactor; TX kicks are coalescable notifications from
/// netsrv, not synchronous RPCs.
fn setup_irq(irq_line: u8, has_irq_handler: bool) -> bool {
    if has_irq_handler && irq_line > 0 {
        let irq_handler = cap_irq_handler();
        if irq_handler == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netdrv] pcidrv did not provide an IRQ handler slot\n");
            });
            return false;
        }
        // SAFETY: single-threaded init before the reactor starts.
        unsafe {
            *(&raw mut IRQ_ENABLED) = true;
        }
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[netdrv] IRQ-driven wake path (virtqueue interrupts -> EventQueue)\n");
        });
    } else {
        // SAFETY: single-threaded init before the reactor starts.
        unsafe {
            *(&raw mut IRQ_ENABLED) = false;
        }
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[netdrv] device reports no IRQ handler; RX cannot be serviced\n");
        });
    }

    true
}

// ---------------------------------------------------------------------------
// SHM ring buffer operations
// ---------------------------------------------------------------------------

/// Enqueue a received Ethernet frame into the SHM RX ring for netsrv.
///
/// Applies sender-side backpressure when the shared ring is full so frames are
/// not silently dropped under SMP burst load.
fn shm_rx_enqueue(frame: &[u8]) -> bool {
    // SAFETY: SHM_BASE is set once during NETDRV_REGISTER before any enqueue
    // calls. Single-threaded driver. All pointer arithmetic is within the
    // mapped SHM region (header at offset 0, RX ring at offset 0x1000).
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return false;
        }
        let hdr = base as *mut u32;
        let len = core::cmp::min(frame.len(), 1998);
        loop {
            let rx_head = *hdr.add(0);
            let rx_tail = core::ptr::read_volatile(hdr.add(1));
            let slot_count = core::ptr::read_volatile(hdr.add(4)); // offset 0x10
            if slot_count == 0 {
                return false;
            }
            let next = (rx_head + 1) % slot_count;
            if next == rx_tail {
                signal_netsrv_rx();
                let _ = trona_kernel::syscall::yield_now();
                continue;
            }

            let slot_base = base + 0x1000 + (rx_head as u64) * 2048;
            let len_ptr = slot_base as *mut u16;
            *len_ptr = len as u16;
            let data_ptr = (slot_base + 2) as *mut u8;
            core::ptr::copy_nonoverlapping(frame.as_ptr(), data_ptr, len);

            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(hdr.add(0), next);
            return true;
        }
    }
}

/// Dequeue a TX frame from the SHM TX ring (queued by netsrv).
///
/// Returns the frame length if a frame was dequeued, None if the ring is
/// empty or SHM is not yet mapped.
fn shm_tx_peek(buf: &mut [u8; 2048]) -> Option<usize> {
    // SAFETY: SHM_BASE is set once during NETDRV_REGISTER. Single-threaded
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

        Some(len)
    }
}

/// Consume one TX frame from the SHM TX ring after a successful transmit.
fn shm_tx_consume() {
    // SAFETY: SHM_BASE is set once during NETDRV_REGISTER. Single-threaded
    // driver. All pointer arithmetic is within the mapped SHM region.
    unsafe {
        let base = *(&raw const SHM_BASE);
        if base == 0 {
            return;
        }
        let hdr = base as *mut u32;
        let tx_tail = *hdr.add(3);
        let slot_count = core::ptr::read_volatile(hdr.add(5)); // offset 0x14
        if slot_count == 0 {
            return;
        }
        // Release: frame consumption must complete before the tail update
        // that publishes free space to the producer (ARM weak ordering).
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(hdr.add(3), (tx_tail + 1) % slot_count);
    }
}

/// Signal netsrv that RX frames are available in the SHM ring.
fn signal_netsrv_rx() {
    let netsrv_ref = trona_runtime::client::caps::netsrv_ep();
    if netsrv_ref.is_null() {
        return;
    }
    let netsrv = netsrv_ref.addr();

    // Fire-and-forget notification, NOT an RPC. A blocking send deadlocks:
    // netsrv answers the kick with a progress sweep (no reply), and that sweep
    // can re-enter netdrv with a blocking TX kick while we are still parked in
    // the send. `mp_write_ctx` blocks when the peer pipe is full, so force a
    // zero timeout — the kernel then drops the kick instead of blocking when
    // netsrv is momentarily behind. netsrv drains all pending RX from the SHM
    // ring on its next sweep regardless, so a dropped/coalesced kick is
    // harmless. The buffer timeout is saved and restored so other netdrv IPC
    // (which relies on the default blocking policy) is unaffected.
    let mut msg = TronaMsg::zeroed();
    msg.label = NETSRV_RX_KICK;
    let ctx = ipc_ctx();
    unsafe {
        let _ = ipc::mp_write_ctx(ctx, netsrv, &raw const msg);
    }
}

// ---------------------------------------------------------------------------
// RX/TX frame processing
// ---------------------------------------------------------------------------

/// Process all pending received packets from virtio and enqueue them into
/// the SHM RX ring for netsrv.
fn drain_rx() -> bool {
    let mut any_polled = false;
    let mut any_enqueued = false;
    while let Some((buf_idx, len)) = virtio::rx_poll() {
        any_polled = true;
        let data = virtio::rx_get_data(buf_idx, len);
        // Skip VirtioNetHdr to get the Ethernet frame
        let hdr_sz = virtio::net_hdr_size();
        if len > hdr_sz {
            let pkt = &data[hdr_sz..];
            unsafe {
                if !*(&raw const LOGGED_RX_FRAME) {
                    *(&raw mut LOGGED_RX_FRAME) = true;
                    trona_runtime::udebug!(|_lb| {
                        _lb.str(b"[netdrv] RX header-skip=");
                        _lb.dec(hdr_sz as u64);
                        _lb.putc(b'\n');
                    });
                    log_frame_bytes(b"[netdrv] RX raw", data);
                    log_frame_bytes(b"[netdrv] RX pkt", pkt);
                    log_ethertype(b"[netdrv] RX pkt", pkt);
                }
            }
            if shm_rx_enqueue(pkt) {
                any_enqueued = true;
            }
        }
        virtio::rx_repost(buf_idx);
    }
    if any_enqueued {
        signal_netsrv_rx();
    }
    any_polled
}

/// Drain all pending TX frames from the SHM TX ring (queued by netsrv) and
/// transmit them via virtio.
fn drain_tx_ring() {
    let mut buf = [0u8; 2048];
    while let Some(len) = shm_tx_peek(&mut buf) {
        unsafe {
            if !*(&raw const LOGGED_TX_FRAME) {
                *(&raw mut LOGGED_TX_FRAME) = true;
                log_frame_bytes(b"[netdrv] TX pkt", &buf[..len]);
                log_ethertype(b"[netdrv] TX pkt", &buf[..len]);
            }
        }
        let ok = virtio::tx_packet(&buf[..len]);
        if !ok {
            break;
        }
        shm_tx_consume();
    }
}

/// Service a device IRQ event: drain RX + TX until the device reports no
/// further interrupt, then ack — which unmasks the level line at the
/// controller. Always acks: `dispatch_irq` masks the level line on dispatch,
/// so even a spurious shared-INTx wake (isr == 0) must ack to re-arm delivery.
fn service_irq_event() {
    loop {
        let _ = drain_rx();
        drain_tx_ring();
        // `read_isr` is destructive; loop so any interrupt asserted during the
        // drain is serviced before we ack (closes the lost-wakeup window).
        if virtio::read_isr() == 0 {
            break;
        }
    }
    let handler = cap_irq_handler();
    if handler != 0 {
        // SAFETY: `handler` is netdrv's bound IRQ-handler cap slot.
        let _ = invoke::irq_handler_ack(trona_runtime::core::slot_alloc::resolved_cap_ref(handler));
    }
}

// ---------------------------------------------------------------------------
// NETDRV_REGISTER IPC handler
// ---------------------------------------------------------------------------

/// Handle the NETDRV_REGISTER IPC from netsrv.
///
/// netsrv sends NETDRV_REGISTER with:
///   regs[0] = mmsrv SHM object index (`0` is valid)
///   caps[0] = SHM memory-object cap
///
/// On success, replies with:
///   label = TRONA_OK
///   regs[0] = MAC address low 4 bytes (network order)
///   regs[1] = MAC address high 2 bytes (network order)
///   regs[2] = link status (1 = up)
fn handle_driver_register(msg: &TronaMsg, reply: &mut TronaMsg) {
    let shm_idx = msg.regs[0];

    // Map the SHM into our address space via mmsrv. The cap transferred by
    // netsrv lands at receive scratch; adopt it as OwnedCap then convert to
    // TransferCap so shm_map can move it into mmsrv's tracking table.
    let recv_scratch = cap_recv_scratch_slot();
    if recv_scratch == 0 {
        reply.label = TRONA_INVALID_OPERATION;
        return;
    }
    // SAFETY: The kernel just installed a cap at `recv_scratch` via the IPC
    // receive path; we take sole ownership here.
    let shm_tc: TransferCap = unsafe { OwnedCap::adopt_received(recv_scratch).into_transfer() };
    let map_res =
        trona_runtime::client::mm::shm_map(shm_idx, shm_tc, SHM_MAP_HINT, NET_SHM_MAP_BYTES, 0x3);
    // shm_map consumed (or dropped) shm_tc; no manual delete needed.
    let mapped_base = match map_res {
        Ok(base) => base,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netdrv] Failed to map SHM label=");
                _lb.dec(label);
                _lb.putc(b'\n');
            });
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
    };
    if mapped_base == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netdrv] Failed to map SHM: base=0\n");
        });
        reply.label = TRONA_INVALID_OPERATION;
        return;
    }
    // SAFETY: Single-threaded driver; written once during registration.
    unsafe {
        *(&raw mut SHM_BASE) = mapped_base;
    }

    // Reply with MAC address
    let mac = mac_addr();
    let mac_lo = ((mac[0] as u32) << 24)
        | ((mac[1] as u32) << 16)
        | ((mac[2] as u32) << 8)
        | (mac[3] as u32);
    let mac_hi = ((mac[4] as u16) << 8) | (mac[5] as u16);
    reply.label = TRONA_OK;
    reply.regs[0] = mac_lo as u64;
    reply.regs[1] = mac_hi as u64;
    reply.regs[2] = 1; // link status: up
    reply.length = 3;

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netdrv] NETDRV_REGISTER complete, SHM mapped at ");
        _lb.hex(mapped_base);
        _lb.putc(b'\n');
    });
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Cookie for the service pipe's `STATE_READABLE` Watch (kind 0).
const NETDRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);
/// Cookie stamped on `EVENT_TYPE_IRQ` records from the bound NIC IRQ (kind 1).
const NETDRV_IRQ_COOKIE: u64 = trona_server::event_loop::encode_cookie(1, 0, 1);

/// Reactor dispatcher. The service pipe (`STATE_READABLE`) carries netsrv IPC
/// (`NETDRV_REGISTER` / `NETDRV_TX_KICK`); the NIC IRQ is bound onto the same
/// `EventQueue` and drains the device in `handle_other`.
struct NetdrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    recv_scratch: Cap,
}

impl trona_server::event_loop::EqDispatcher for NetdrvDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let mut reply = TronaMsg::zeroed();
        match msg.label {
            NETDRV_REGISTER => handle_driver_register(msg, &mut reply),
            NETDRV_TX_KICK => {
                drain_tx_ring();
                reply.label = TRONA_OK;
            }
            _ => reply.label = TRONA_INVALID_OPERATION,
        }
        // SAFETY: `ipc_ctx()` is this thread's IPC context; reply on the service pipe.
        let _ = unsafe { ipc::mp_write_reply_ctx(ipc_ctx(), self.recv_ep, &raw const reply) };
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        if self.recv_scratch != 0 {
            // SAFETY: re-arm the cap-receive scratch before each MP_READ.
            unsafe {
                trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                    ipc_ctx(),
                    CAP_SELF_CSPACE,
                    self.recv_scratch,
                    0,
                );
            }
        }
        true
    }

    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(self.watch_cap),
            trona_kernel::core_types::CapRef::flat(self.recv_ep),
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
            NETDRV_SERVICE_COOKIE,
        )
    }

    fn handle_other(&mut self, kind: u32, _cookie: u64) -> i32 {
        if kind == trona_kernel::uapi::KERNITE_EVENT_TYPE_IRQ {
            service_irq_event();
        }
        0
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

/// Reactor entry: binds the service pipe (IPC) and the NIC IRQ onto one
/// `EventQueue`, then blocks in `EQ_WAIT`. RX/TX are serviced from the IRQ
/// (`handle_other`); netsrv kicks TX via `NETDRV_TX_KICK`.
fn event_loop(device_ok: bool) -> ! {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netdrv] Entering reactor\n");
    });

    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();
    let recv_scratch = cap_recv_scratch_slot();
    if recv_scratch == 0 {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[netdrv] No private receive scratch slot reserved\n");
        });
    }

    // Self-provision the reactor's EventQueue + Watch from rsrcsrv.
    let eq = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_EVENT_QUEUE as u64,
        4,
    );
    let watch = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_WATCH as u64,
        0,
    );
    let (eq, watch) = match (eq, watch) {
        (Some(eq), Some(watch)) => (eq, watch),
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netdrv] reactor EventQueue/Watch alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();

    // Arm the service pipe's READABLE edge onto the reactor EQ.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        NETDRV_SERVICE_COOKIE,
    );

    // Bind the NIC IRQ to the same EQ FIRST, then re-enable virtqueue
    // interrupts — binding before enabling closes the pre-bind lost-wakeup
    // window. A prime drain services anything that arrived during init.
    let irq_enabled = unsafe { *(&raw const IRQ_ENABLED) };
    if device_ok && irq_enabled {
        let _ = trona_kernel::invoke::irq_bind_eq(
            trona_runtime::core::slot_alloc::resolved_cap_ref(cap_irq_handler()),
            trona_kernel::core_types::CapRef::flat(eq_cap),
            NETDRV_IRQ_COOKIE,
        );
        virtio::enable_queue_interrupts();
        service_irq_event();
    } else if device_ok {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[netdrv] device has no IRQ handler; RX cannot be serviced (IPC-only)\n");
        });
    } else {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[netdrv] no device; serving IPC only\n");
        });
    }

    core::mem::forget(eq);
    core::mem::forget(watch);

    let dispatcher = NetdrvDispatcher {
        recv_ep,
        watch_cap,
        eq_cap,
        recv_scratch,
    };
    let mut reactor = trona_server::event_loop::EventLoop::new(eq_cap, dispatcher);

    loop {
        // SAFETY: `ctx` is this thread's IPC context; block on the EQ and
        // dispatch one ready event (IPC via `dispatch_state`, NIC IRQ via
        // `handle_other`). The recv-slot scratch is re-armed in `prepare_mp_read`.
        unsafe {
            let _ = reactor.run_iteration(ctx);
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netdrv] virtio-net Hardware Driver starting\n");
    });
    init_private_slots();

    // Discover and initialize virtio-net device
    let mut irq_line: u8 = 0;
    let mut has_irq_handler = false;
    let mut device_ok = false;

    // Try modern virtio (device ID 0x1041) first
    if let Some((bus, dev, func)) = virtio_modern::find_virtio_net_modern() {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[netdrv] Found modern virtio-net device\n");
        });
        if virtio_modern::init_virtio_modern(bus, dev, func) {
            // USING_MODERN_TRANSPORT already set inside init_virtio_modern
            device_ok = true;
            // Get IRQ handler cap from pcidrv (resolves PCI INTx → GIC SPI on aarch64)
            match virtio::get_device_caps(bus, dev, func) {
                Some((_bar_phys, _bar_bits, _bar_size, irq, _bar_is_io, has_irq)) => {
                    irq_line = irq;
                    has_irq_handler = has_irq;
                    trona_runtime::uinfo!(|_lb| {
                        _lb.str(b"[netdrv] IRQ=");
                        _lb.dec(irq as u64);
                        _lb.str(b" available=");
                        _lb.dec(has_irq as u64);
                        _lb.str(b" mode=poll\n");
                    });
                }
                None => {}
            }
        }
    }

    // Fall back to legacy virtio (device ID 0x1000)
    if !device_ok {
        match virtio::find_virtio_net() {
            Some((bus, dev, func, bar0, _bar0_full)) => {
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[netdrv] Found virtio-net at ");
                    _lb.dec(bus as u64);
                    _lb.putc(b':');
                    _lb.dec(dev as u64);
                    _lb.str(b" BAR0=");
                    _lb.hex(bar0 as u64);
                    _lb.putc(b'\n');
                });

                match virtio::get_device_caps(bus, dev, func) {
                    Some((_bar_phys, _bar_bits, bar_size, irq, _bar_is_io, has_irq)) => {
                        irq_line = irq;
                        has_irq_handler = has_irq;
                        trona_runtime::uinfo!(|_lb| {
                            _lb.str(b"[netdrv] IRQ=");
                            _lb.dec(irq as u64);
                            _lb.str(b" available=");
                            _lb.dec(has_irq as u64);
                            _lb.str(b" mode=poll\n");
                        });

                        // Transitional device (0x1000): try modern transport
                        // first. Handles QEMU's disable-legacy=on where the
                        // device has modern PCI capabilities but legacy I/O
                        // is non-functional.
                        if virtio_modern::init_virtio_modern(bus, dev, func) {
                            device_ok = true;
                        } else if virtio::init_virtio(bar0, bar_size) {
                            device_ok = true;
                        } else {
                            trona_runtime::uerror!(|_lb| {
                                _lb.str(b"[netdrv] Failed to init virtio transport\n");
                            });
                        }
                    }
                    None => {
                        trona_runtime::uerror!(|_lb| {
                            _lb.str(b"[netdrv] Failed to get PCI caps from pcidrv\n");
                        });
                    }
                }
            }
            None => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[netdrv] No virtio-net device found\n");
                });
            }
        }
    }

    // Set up the device wake path. TX is explicit MP kick; RX is timed poll
    // plus NETSRV_RX_KICK after frames are published.
    if device_ok {
        if setup_irq(irq_line, has_irq_handler) {
            if unsafe { *(&raw const IRQ_ENABLED) } {
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[netdrv] IRQ handling enabled\n");
                });
            }
        } else {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[netdrv] IRQ setup failed, using polling mode\n");
            });
        }
    }

    if device_ok {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[netdrv] virtio-net device ready\n");
        });
    }

    // Register with namesrv; unit_mgr observes the publish event as readiness.
    register_namesrv();

    event_loop(device_ok)
}
