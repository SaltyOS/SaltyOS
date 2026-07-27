// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS Network Stack Server (netsrv)
//!
//! Runs as a userspace process and owns the full TCP/UDP/IP/ARP/ICMP protocol
//! stack. Communicates with netdrv (hardware driver) via SHM ring buffers and
//! MessagePipe kicks. Exposes a NET_* IPC interface for VFS to forward
//! POSIX socket operations.
//!
//! Startup caps are role-based. System caps come from `trona_runtime::client::caps::*()`;
//! the service-local `netdrv_ep` dependency is resolved through the
//! `trona_runtime::local_cap!` macro declared below, and a few runtime-allocated
//! callback and receive-scratch slots remain file-local.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod net;

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::{
    TRONA_ALREADY_EXISTS, TRONA_BUSY, TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION,
    TRONA_NOT_FOUND, TRONA_NOT_SUPPORTED, TRONA_OK, TRONA_OUT_OF_MEMORY, TRONA_PENDING,
    TRONA_TIMED_OUT,
};
use trona_protocol::correlation::{
    CORRELATION_BACKEND_NETSRV, CORRELATION_CLASS_NET, CORRELATION_HEADER_REG_COUNT,
    CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CORRELATION_KIND_REQUEST,
    CorrelationHeader, ensure_correlation_wire_length,
};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::netsrv::*;
use trona_protocol::posix::{
    INET_OP_ACCEPT, INET_OP_CONNECT, INET_OP_RECV, INET_OP_RECVFROM, INET_RECV_FLAG_PEEK,
    INET_RECV_FLAG_WANT_ADDR, INET_RECV_FLAG_WANT_TIMESTAMP, INET_RECV_TIMESTAMP_NONE,
    TRONA_CONN_REFUSED, TRONA_CONN_RESET, TRONA_DNS_NXDOMAIN, TRONA_DNS_SERVER_FAIL,
    TRONA_HOST_UNREACHABLE, TRONA_NET_UNREACHABLE, TRONA_NOT_CONNECTED, TRONA_PROTO_NOT_SUPPORTED,
};
use trona_protocol::posix_abi::socket::*;
use trona_protocol::vfs::backend::{
    BACKEND_FEATURE_ASYNC_V1, BACKEND_FEATURE_INCARNATION_SEQ, BACKEND_FEATURE_INLINE_TRANSFER,
    VFS_BACKEND_OPEN_SESSION, VFS_BACKEND_REPLY_BUSY, VFS_BACKEND_REPLY_INVALID,
    VFS_BACKEND_REPLY_IO_ERROR, VFS_BACKEND_REPLY_NO_SPACE, VFS_BACKEND_REPLY_NOT_FOUND,
    VFS_BACKEND_REPLY_NOT_SUPPORTED, VFS_BACKEND_REPLY_OK,
};
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::debug::serial;
use uapi::*;

// ---------------------------------------------------------------------------
// Capability slot layout
// ---------------------------------------------------------------------------

const CAP_SELF_CSPACE: u64 = 2;
// All cross-service caps are reached via the role-based startup capability
// table. System roles flow through `trona_runtime::client::caps::*`; the service-local
// `Require=netdrv-ep.socket` is resolved via the `trona_runtime::local_cap!`
// macro below (`netdrv_ep`).

// Service-local cap: `Require=netdrv-ep.socket` in `netsrv.service`.
trona_runtime::local_cap!(pub(crate) netdrv_ep = "netsrv:netdrv_ep");
//
// The slots below are server-private (VFS-facing callback endpoint,
// its badged minted copy, and receive scratch). They
// were previously hard-coded to slots 80..=84 inside RTLD's frame pool
// window, which silently depended on the shared-library loader not
// having claimed those exact slots yet. They are now dynamically
// allocated at startup from `trona_runtime::core::slot_alloc` and cached in
// `static mut` cells, so the server cannot collide with RTLD.
static mut CAP_VFS_CALLBACK_EP_SLOT: u64 = 0;
static mut CAP_VFS_CALLBACK_BADGED_EP_SLOT: u64 = 0;
/// Stable receive scratch for the service-EP IPC dispatch loop.
/// Sender payload caps (e.g. NET_REGISTER_VFS's VFS callback EP)
/// deposit here; replies go back through the service MessagePipe
/// endpoint with `reply-marked MP_WRITE`.
static mut CAP_RECV_SCRATCH_SLOT: u64 = 0;
const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;

/// Allocate the server-private slots from `trona_runtime::core::slot_alloc`
/// once at startup.
fn init_private_slots() {
    unsafe {
        *&raw mut CAP_VFS_CALLBACK_EP_SLOT =
            trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"netsrv vfs-callback-ep");
        *&raw mut CAP_VFS_CALLBACK_BADGED_EP_SLOT =
            trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"netsrv vfs-callback-badged-ep");
        // Reserve 2 consecutive slots for current and future
        // payload-cap receives.
        *&raw mut CAP_RECV_SCRATCH_SLOT =
            trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
                2,
                b"netsrv recv-scratch",
            );
    }
}

fn cap_vfs_callback_ep() -> u64 {
    unsafe { ::core::ptr::read_volatile(&raw const CAP_VFS_CALLBACK_EP_SLOT) }
}

#[inline]
fn cap_vfs_callback_badged_ep() -> u64 {
    unsafe { ::core::ptr::read_volatile(&raw const CAP_VFS_CALLBACK_BADGED_EP_SLOT) }
}

#[inline]
pub(crate) fn cap_recv_scratch_slot() -> u64 {
    unsafe { ::core::ptr::read_volatile(&raw const CAP_RECV_SCRATCH_SLOT) }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SHM_MAP_HINT: u64 = 0;
const NET_SHM_ID: u64 = 0x4E455400; // "NET\0"
const SHM_HEADER_BYTES: u64 = 0x1000;
const SHM_SLOT_BYTES: u64 = 2048;
const SHM_RX_SLOT_COUNT: u64 = 32;
const SHM_TX_SLOT_COUNT: u64 = 32;
const SHM_TX_OFFSET: u64 = SHM_HEADER_BYTES + (SHM_RX_SLOT_COUNT * SHM_SLOT_BYTES);
const NET_SHM_BYTES: u64 = SHM_TX_OFFSET + (SHM_TX_SLOT_COUNT * SHM_SLOT_BYTES);
const NET_SHM_PAGES: u64 = (NET_SHM_BYTES + 4095) / 4096;
/// Upper bound on how long the reactor's progress timer sleeps when no DNS/DHCP/TCP timer is
/// pending. The RX kick is sent non-blocking and may be dropped while our pipe
/// is full, so we never block forever: an idle loop still wakes at this cadence
/// to run a progress sweep that drains any stranded SHM RX.
const SAFETY_TICK_NS: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static mut MAC_ADDR: [u8; 6] = [0; 6];
static mut VFS_REGISTERED: bool = false;
static mut VFS_SESSION_ID: u32 = 0;
static mut VFS_SESSION_LIVE_GEN: u64 = 0;
static mut SHM_BASE: u64 = 0;
static mut SHM_IDX: u64 = 0;
static mut SHM_CAP: Option<OwnedCap> = None;
static mut SELF_TEST_PHASE: u8 = 0;
static mut SELF_TEST_TICKS: u32 = 0;
static mut LOGGED_RX_FRAME: bool = false;
static mut LOGGED_UNKNOWN_ETHERTYPE: bool = false;
static mut LOGGED_NETWORK_CONFIG: bool = false;
static mut LOGGED_IPV4_PACKETS: u8 = 0;
static mut LOGGED_INET_IPC: u8 = 0;
static mut LOGGED_INET_RECV_RESULTS: u8 = 0;

/// Duplicate `src` into a freshly-allocated slot and return it as an `OwnedCap`.
///
/// The caller converts to `TransferCap` (`.into_transfer()`) when passing the
/// copy to `shm_map` or IPC; Drop handles cleanup on both the success and
/// error paths.
fn copy_cap_to_temp(src: &OwnedCap, label: &'static [u8]) -> Option<OwnedCap> {
    let temp = trona_runtime::core::slot_alloc::alloc_slot_or_idle(label);
    let src_slot = src.as_raw();
    let err = invoke::cnode_copy_ref(
        CapRef::flat(CAP_SELF_CSPACE),
        trona_runtime::core::slot_alloc::resolved_cap_ref(src_slot),
        CapRef::flat(CAP_SELF_CSPACE),
        trona_runtime::core::slot_alloc::resolved_cap_ref(temp.addr()),
        KERNITE_RIGHT_ALL as u64,
    );
    if err != 0 {
        // copy failed: `temp` (OwnedSlot) Drop frees the empty slot.
        return None;
    }
    // The copy landed a cap; adopt the slot as an OwnedCap.
    Some(temp.assume_filled())
}

#[derive(Clone, Copy)]
struct PendingCorrelation {
    live: bool,
    conn_id: u32,
    op_type: u8,
    _pad: [u8; 3],
    header: CorrelationHeader,
}

impl PendingCorrelation {
    const EMPTY: Self = Self {
        live: false,
        conn_id: 0,
        op_type: 0,
        _pad: [0; 3],
        header: CorrelationHeader {
            class: 0,
            backend: 0,
            kind: 0,
            flags: 0,
            session: 0,
            opcode: 0,
            _reserved0: 0,
            token: 0,
            request_seq: 0,
            request_seq_secondary: 0,
        },
    };
}

const PENDING_CORRELATION_SLOTS: usize = 128;
static mut PENDING_CORRELATIONS: [PendingCorrelation; PENDING_CORRELATION_SLOTS] =
    [PendingCorrelation::EMPTY; PENDING_CORRELATION_SLOTS];

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

pub(crate) fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

pub(crate) fn mac_addr() -> [u8; 6] {
    // SAFETY: MAC_ADDR is set during init before any use; single-threaded.
    unsafe { *(&raw const MAC_ADDR) }
}

fn decode_request_correlation(msg: &TronaMsg) -> Option<CorrelationHeader> {
    if (msg.length as usize) < (CORRELATION_HEADER_REG_START + CORRELATION_HEADER_REG_COUNT) {
        return None;
    }
    let words = [
        msg.regs[CORRELATION_HEADER_REG_START],
        msg.regs[CORRELATION_HEADER_REG_START + 1],
        msg.regs[CORRELATION_HEADER_REG_START + 2],
        msg.regs[CORRELATION_HEADER_REG_START + 3],
    ];
    let header = CorrelationHeader::decode_words(words);
    if header.kind != CORRELATION_KIND_REQUEST
        || header.class != CORRELATION_CLASS_NET
        || header.backend != CORRELATION_BACKEND_NETSRV
        || header.token == 0
    {
        return None;
    }
    Some(header)
}

fn stamp_completion_correlation(reply: &mut TronaMsg, request: CorrelationHeader) {
    let words = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        ..request
    }
    .encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = words[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut reply.length);
}

fn save_pending_correlation(conn_id: u32, op_type: u8, header: CorrelationHeader) {
    unsafe {
        let table = &mut *(&raw mut PENDING_CORRELATIONS);
        let mut empty = PENDING_CORRELATION_SLOTS;
        let mut i = 0usize;
        while i < PENDING_CORRELATION_SLOTS {
            if table[i].live && table[i].conn_id == conn_id && table[i].op_type == op_type {
                table[i].header = header;
                return;
            }
            if !table[i].live && empty == PENDING_CORRELATION_SLOTS {
                empty = i;
            }
            i += 1;
        }
        if empty != PENDING_CORRELATION_SLOTS {
            table[empty] = PendingCorrelation {
                live: true,
                conn_id,
                op_type,
                _pad: [0; 3],
                header,
            };
        } else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netsrv] pending correlation table full conn=");
                _lb.dec(conn_id as u64);
                _lb.str(b" op=");
                _lb.dec(op_type as u64);
                _lb.putc(b'\n');
            });
        }
    }
}

fn take_pending_correlation(conn_id: u32, op_type: u8) -> Option<CorrelationHeader> {
    unsafe {
        let table = &mut *(&raw mut PENDING_CORRELATIONS);
        let mut i = 0usize;
        while i < PENDING_CORRELATION_SLOTS {
            if table[i].live && table[i].conn_id == conn_id && table[i].op_type == op_type {
                let header = table[i].header;
                table[i] = PendingCorrelation::EMPTY;
                return Some(header);
            }
            i += 1;
        }
    }
    None
}

fn backend_reply_label(label: u64) -> u64 {
    match label {
        TRONA_OK => VFS_BACKEND_REPLY_OK,
        TRONA_INVALID_ARGUMENT => VFS_BACKEND_REPLY_INVALID,
        TRONA_OUT_OF_MEMORY => VFS_BACKEND_REPLY_NO_SPACE,
        TRONA_NOT_FOUND | TRONA_NOT_CONNECTED => VFS_BACKEND_REPLY_NOT_FOUND,
        TRONA_BUSY | TRONA_ALREADY_EXISTS => VFS_BACKEND_REPLY_BUSY,
        TRONA_INVALID_OPERATION | TRONA_NOT_SUPPORTED | TRONA_PROTO_NOT_SUPPORTED => {
            VFS_BACKEND_REPLY_NOT_SUPPORTED
        }
        TRONA_CONN_REFUSED
        | TRONA_CONN_RESET
        | TRONA_HOST_UNREACHABLE
        | TRONA_NET_UNREACHABLE
        | TRONA_TIMED_OUT => VFS_BACKEND_REPLY_IO_ERROR,
        _ => VFS_BACKEND_REPLY_IO_ERROR,
    }
}

fn install_vfs_callback_cap(mint_badged_alias: bool) -> Result<(), u64> {
    let _ = trona_kernel::syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_DELETE as u64,
        cap_vfs_callback_ep(),
        0,
        0,
        0,
    );
    let _ = trona_kernel::syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_DELETE as u64,
        cap_vfs_callback_badged_ep(),
        0,
        0,
        0,
    );
    let move_r = trona_kernel::syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_MOVE as u64,
        cap_vfs_callback_ep(),
        CAP_SELF_CSPACE,
        cap_recv_scratch_slot(),
        0,
    );
    if move_r.error != 0 {
        return Err(move_r.error as u64);
    }
    if mint_badged_alias {
        let mint_r = trona_kernel::syscall::invoke(
            CAP_SELF_CSPACE,
            KERNITE_INV_CNODE_MINT as u64,
            cap_vfs_callback_ep(),
            CAP_SELF_CSPACE,
            cap_vfs_callback_badged_ep(),
            NETSRV_CALLBACK_BADGE,
        );
        if mint_r.error != 0 {
            return Err(mint_r.error as u64);
        }
    }
    Ok(())
}

fn handle_backend_open_session(msg: &TronaMsg, reply: &mut TronaMsg) {
    if install_vfs_callback_cap(false).is_err() {
        reply.label = VFS_BACKEND_REPLY_INVALID;
        reply.length = 0;
        return;
    }
    unsafe {
        *(&raw mut VFS_REGISTERED) = true;
        *(&raw mut VFS_SESSION_ID) = msg.regs[1] as u32;
        let cur = *(&raw const VFS_SESSION_LIVE_GEN);
        *(&raw mut VFS_SESSION_LIVE_GEN) = if cur == 0 { 1 } else { cur.wrapping_add(2) };
    }
    reply.label = VFS_BACKEND_REPLY_OK;
    reply.regs[0] = 64;
    reply.regs[1] = BACKEND_FEATURE_ASYNC_V1
        | BACKEND_FEATURE_INCARNATION_SEQ
        | BACKEND_FEATURE_INLINE_TRANSFER;
    reply.regs[2] = 0;
    reply.length = 3;
}

fn log_ipv4(lb: &mut trona_runtime::debug::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

fn log_mac(lb: &mut trona_runtime::debug::serial::LineBuf, mac: &[u8; 6]) {
    let mut i = 0;
    while i < mac.len() {
        if i != 0 {
            lb.putc(b':');
        }
        lb.hex(mac[i] as u64);
        i += 1;
    }
}

fn log_network_config(prefix: &[u8]) {
    let cfg = net::config::snapshot();
    trona_runtime::uinfo!(|_lb| {
        _lb.str(prefix);
        _lb.str(b" host=");
        _lb.str(net::config::HOSTNAME);
        _lb.str(b" if=");
        _lb.str(net::config::IFACE_NAME);
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

fn maybe_log_network_ready() {
    if !net::config::is_ready() || !net::config::is_configured() {
        return;
    }
    unsafe {
        if *(&raw const LOGGED_NETWORK_CONFIG) {
            return;
        }
        *(&raw mut LOGGED_NETWORK_CONFIG) = true;
    }
    log_network_config(b"[netsrv] network ready");
}

fn log_inet_ipc(op: &[u8], conn_id: u32, ip: u32, port: u16, len: usize) {
    unsafe {
        if *(&raw const LOGGED_INET_IPC) >= 24 {
            return;
        }
        *(&raw mut LOGGED_INET_IPC) += 1;
    }
    trona_runtime::udebug!(|_lb| {
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
    trona_runtime::udebug!(|_lb| {
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
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[netsrv] RX frame len=");
        _lb.dec(frame.len() as u64);
        _lb.str(b" ethertype=");
        _lb.hex(ethertype as u64);
        _lb.putc(b'\n');
    });
}

fn log_ipv4_packet(hdr: &net::proto::ipv4::Ipv4Header, payload_len: usize) {
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[netsrv] IPv4 src=");
        log_ipv4(&mut _lb, hdr.src);
        _lb.str(b" dst=");
        log_ipv4(&mut _lb, hdr.dst);
        _lb.str(b" proto=");
        _lb.dec(hdr.protocol as u64);
        _lb.str(b" ihl=");
        _lb.dec((hdr.version_ihl & 0x0F) as u64);
        _lb.str(b" total=");
        _lb.dec(hdr.total_len as u64);
        _lb.str(b" len=");
        _lb.dec(payload_len as u64);
        _lb.putc(b'\n');
    });
}

fn bootstrap_network_config() {
    net::config::init(mac_addr());

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netsrv] DHCP bootstrap starting\n");
    });

    if net::dhcp::start() {
        process_rx_from_shm();
        net::flush_pending_packets();
        net::dhcp::process();
    } else {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[netsrv] DHCP start failed, continuing without a fallback config\n");
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
                let _ = trona_kernel::syscall::yield_now();
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
pub(crate) fn signal_netdrv_tx() {
    let mut msg = TronaMsg::zeroed();
    msg.label = NETDRV_TX_KICK;
    // TX availability is edge-triggered but coalescable: the frame is already
    // published in SHM, so netsrv must not synchronously wait for netdrv here.
    let err = unsafe { ipc::mp_write_ctx(ipc_ctx(), netdrv_ep().addr(), &raw const msg) };
    if err != 0 && err != KERNITE_ERR_WOULD_BLOCK as i32 {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[netsrv] NETDRV_TX_KICK write failed err=");
            _lb.dec(err as u64);
            _lb.putc(b'\n');
        });
    }
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
    let shm_bytes = NET_SHM_PAGES * 4096;

    // Create the SHM MO (producer). netsrv retains SHM_CAP for the later
    // netdrv handoff and maps a disposable copy for its own view.
    let (shm_idx, shm_cap) = match trona_runtime::client::mm::shm_create(NET_SHM_ID, shm_bytes) {
        Ok(v) => v,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netsrv] SHM create failed label=");
                _lb.dec(label);
                _lb.putc(b'\n');
            });
            return false;
        }
    };
    unsafe {
        *(&raw mut SHM_IDX) = shm_idx;
        // shm_cap stored for netdrv handoff; replaced (Drop frees old) on any error path below.
        *(&raw mut SHM_CAP) = Some(shm_cap);
    }

    // Map into netsrv at an mmsrv-chosen VA (zero hint). Send a disposable
    // copy and keep SHM_CAP for the netdrv handoff.
    let shm_cap_ref = unsafe { (&*(&raw const SHM_CAP)).as_ref().unwrap() };
    let Some(map_cap) = copy_cap_to_temp(shm_cap_ref, b"netsrv shm map cap") else {
        unsafe {
            *(&raw mut SHM_IDX) = 0;
            *(&raw mut SHM_CAP) = None; // Drop frees the cap
        }
        return false;
    };
    let map_res = trona_runtime::client::mm::shm_map(
        shm_idx,
        map_cap.into_transfer(),
        SHM_MAP_HINT,
        shm_bytes,
        0x3,
    );
    let mapped_base = match map_res {
        Ok(base) => base,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netsrv] SHM map failed label=");
                _lb.dec(label);
                _lb.str(b" idx=");
                _lb.dec(shm_idx);
                _lb.putc(b'\n');
            });
            unsafe {
                *(&raw mut SHM_IDX) = 0;
                *(&raw mut SHM_CAP) = None; // Drop frees the cap
            }
            return false;
        }
    };
    if mapped_base == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netsrv] SHM map returned base=0 idx=");
            _lb.dec(shm_idx);
            _lb.putc(b'\n');
        });
        unsafe {
            *(&raw mut SHM_IDX) = 0;
            *(&raw mut SHM_CAP) = None; // Drop frees the cap
        }
        return false;
    }
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netsrv] SHM map ok base=");
        _lb.hex(mapped_base);
        _lb.putc(b'\n');
    });

    // Initialize SHM header
    // SAFETY: SHM is mapped at `mapped_base`; single-threaded init.
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netsrv] SHM header init base=");
        _lb.hex(mapped_base);
        _lb.putc(b'\n');
    });
    unsafe {
        *(&raw mut SHM_BASE) = mapped_base;
        let hdr = mapped_base as *mut u32;
        *hdr.add(0) = 0; // rx_head
        *hdr.add(1) = 0; // rx_tail
        *hdr.add(2) = 0; // tx_head
        *hdr.add(3) = 0; // tx_tail
        *hdr.add(4) = SHM_RX_SLOT_COUNT as u32;
        *hdr.add(5) = SHM_TX_SLOT_COUNT as u32;
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netsrv] SHM allocated idx=");
        _lb.dec(shm_idx);
        _lb.str(b" mapped at ");
        _lb.hex(mapped_base);
        _lb.putc(b'\n');
    });
    true
}

// ---------------------------------------------------------------------------
// Startup: event wake path
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Startup: Register with netdrv via NETDRV_REGISTER
// ---------------------------------------------------------------------------

fn driver_register() -> bool {
    let ctx = ipc_ctx();

    // Send NETDRV_REGISTER to netdrv with the mmsrv SHM index and an MO
    // cap copy. TX and RX wakeups use explicit MP labels.
    let shm_idx = unsafe { *(&raw const SHM_IDX) };
    let shm_cap_opt = unsafe { (&*(&raw const SHM_CAP)).as_ref() };
    let Some(shm_cap) = shm_cap_opt else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netsrv] NETDRV_REGISTER missing SHM cap\n");
        });
        return false;
    };

    let mut msg = TronaMsg::zeroed();
    msg.label = NETDRV_REGISTER;
    msg.regs[0] = shm_idx;
    msg.length = 1;
    let mut reply = TronaMsg::zeroed();
    let Some(register_cap) = copy_cap_to_temp(shm_cap, b"netsrv netdrv shm cap") else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netsrv] NETDRV_REGISTER SHM cap copy failed\n");
        });
        return false;
    };
    let register_tc = register_cap.into_transfer();
    // SAFETY: IPC context is valid; making RPC to netdrv.
    let err = unsafe {
        ipc::set_send_cap_ctx(ctx, 0, register_tc.slot());
        ipc::mp_call_ctx(
            ctx,
            netdrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    drop(register_tc);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[netsrv] NETDRV_REGISTER call result=");
        _lb.dec(err as u64);
        _lb.str(b" label=");
        _lb.dec(reply.label);
        _lb.putc(b'\n');
    });
    if err != 0 || reply.label != TRONA_OK {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netsrv] NETDRV_REGISTER failed: ");
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

    trona_runtime::uinfo!(|_lb| {
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

fn register_namesrv() {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"netsrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let publish_tc = trona_runtime::client::caps::service_client_ep_for_transfer();
    // SAFETY: Writing name bytes into message register space; IPC context is valid.
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        let mut i = 0;
        while i < name.len() {
            *dst.add(i) = name[i];
            i += 1;
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.as_ref().map_or(0, |t| t.slot()));
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
                _lb.str(b"[netsrv] namesrv registration failed\n");
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
        let our_mac = mac_addr();
        if eth_hdr.dst != our_mac && eth_hdr.dst != net::ethernet::BROADCAST_MAC {
            return;
        }

        match eth_hdr.ethertype {
            net::ethernet::ETHERTYPE_ARP => {
                net::proto::arp::handle_packet(&our_mac, our_ip, payload);
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
                    trona_runtime::udebug!(|_lb| {
                        _lb.str(b"[netsrv] unhandled ethertype=");
                        _lb.hex(eth_hdr.ethertype as u64);
                        _lb.str(b" src=");
                        log_mac(&mut _lb, &eth_hdr.src);
                        _lb.str(b" dst=");
                        log_mac(&mut _lb, &eth_hdr.dst);
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

fn service_network_progress(ctx: *mut IpcContext) {
    process_rx_from_shm();
    net::flush_pending_packets();
    net::dhcp::process();
    if net::dhcp::is_finished() && !net::dhcp::is_bound() {
        net::dhcp::finish();
    }
    maybe_log_network_ready();
    net::socket::tcp::process_timers();
    net::dns::process_pending();
    drain_completion_queue();
    drain_dns_completions(ctx);
    check_self_test();
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
                trona_runtime::udebug!(|_lb| {
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
                    trona_runtime::uwarn!(|_lb| {
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
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[netsrv] send failed label=");
                _lb.dec((-sent) as u64);
                _lb.putc(b'\n');
            });
            reply.label = (-sent) as u64;
            reply.regs[0] = 0;
            reply.length = 0;
        }
    }

    fn handle_net_accept(reply: &mut TronaMsg, conn_id: u32, arm_pending: bool) {
        // `arm_pending` path — `NET_ACCEPT_WAIT` under `mp_write_ctx`. Route
        // all outcomes through `push_completion`.
        if arm_pending {
            match socket_kind(conn_id) {
                SocketKind::Tcp => {
                    let result = net::socket::tcp::tcp_accept(conn_id);
                    if result == -1 {
                        net::socket::tcp::set_pending_accept(conn_id);
                    } else if result > 0 {
                        let new_cid = result as u32;
                        match net::socket::tcp::tcp_getpeername(new_cid) {
                            Ok((ip, port)) => {
                                net::socket::tcp::push_immediate_accept_completion(
                                    conn_id, new_cid, ip, port,
                                );
                            }
                            Err(_label) => {
                                net::socket::tcp::push_immediate_accept_completion(
                                    conn_id, 0, 0, 0,
                                );
                            }
                        }
                    } else {
                        net::socket::tcp::push_immediate_accept_completion(conn_id, 0, 0, 0);
                    }
                }
                _ => {
                    net::socket::tcp::push_immediate_accept_completion(conn_id, 0, 0, 0);
                }
            }
            reply.label = TRONA_PENDING;
            return;
        }

        // Synchronous `NET_ACCEPT` path for blocking `mp_call_ctx`.
        match socket_kind(conn_id) {
            SocketKind::Tcp => {
                let result = net::socket::tcp::tcp_accept(conn_id);
                if result == -1 {
                    reply.label = TRONA_PENDING;
                } else if result > 0 {
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

    fn handle_net_recv(
        reply: &mut TronaMsg,
        conn_id: u32,
        max_len: u16,
        flags: u32,
        arm_pending: bool,
    ) {
        let capped = core::cmp::min(max_len, 152) as usize;
        let kind = socket_kind(conn_id);
        let peek = (flags & INET_RECV_FLAG_PEEK) != 0;

        // `NET_RECV_WAIT` path. VFS has already parked the client via
        // `PendingInetOp` + `save_caller`, fired `mp_write_ctx`, and is not
        // waiting for this reply. The response VFS expects travels via
        // `push_completion` + the callback EP so `handle_netsrv_callback`
        // can match it to the saved client slot. The `reply` written
        // here carries only the courtesy `TRONA_PENDING` label and is
        // discarded — no reply cap was transferred.
        if arm_pending {
            let mut scratch = [0u8; 152];
            let result = match kind {
                SocketKind::Raw => net::socket::raw_ipv4::raw_recv(conn_id, &mut scratch[..capped]),
                SocketKind::Udp => net::socket::udp::udp_recv(conn_id, &mut scratch[..capped]),
                SocketKind::Tcp => {
                    if peek {
                        net::socket::tcp::tcp_recv_peek(conn_id, &mut scratch[..capped])
                    } else {
                        net::socket::tcp::tcp_recv(conn_id, &mut scratch[..capped])
                    }
                }
            };
            if result == -1 {
                match kind {
                    SocketKind::Raw => {
                        net::socket::raw_ipv4::set_pending_recv(conn_id, capped as u16);
                    }
                    SocketKind::Udp => {
                        net::socket::udp::set_pending_recv(conn_id, capped as u16);
                    }
                    SocketKind::Tcp => {
                        net::socket::tcp::set_pending_recv(conn_id, capped as u16, peek);
                    }
                }
            } else {
                let n = core::cmp::min(result as usize, 152);
                match kind {
                    SocketKind::Raw => {
                        net::socket::raw_ipv4::push_immediate_recv_completion(
                            conn_id,
                            &scratch[..n],
                        );
                    }
                    SocketKind::Udp => {
                        net::socket::udp::push_immediate_recv_completion(conn_id, &scratch[..n]);
                    }
                    SocketKind::Tcp => {
                        net::socket::tcp::push_immediate_recv_completion(conn_id, &scratch[..n]);
                    }
                }
            }
            reply.label = TRONA_PENDING;
            return;
        }

        // `NET_RECV` path (no arm). VFS is waiting for this reply with
        // `mp_call_ctx` — fill inline or return `TRONA_PENDING` so VFS
        // parks the client and re-asks via `NET_RECV_WAIT`.
        let buf = unsafe {
            let dst = &raw mut reply.regs[1] as *mut u8;
            core::slice::from_raw_parts_mut(dst, capped)
        };
        let result = match kind {
            SocketKind::Raw => net::socket::raw_ipv4::raw_recv(conn_id, buf),
            SocketKind::Udp => net::socket::udp::udp_recv(conn_id, buf),
            SocketKind::Tcp => {
                if peek {
                    net::socket::tcp::tcp_recv_peek(conn_id, buf)
                } else {
                    net::socket::tcp::tcp_recv(conn_id, buf)
                }
            }
        };
        if result == -1 {
            reply.label = TRONA_PENDING;
        } else {
            reply.label = TRONA_OK;
            reply.regs[0] = result as u64;
            reply.length = 1 + ((result as u64 + 7) / 8);
        }
    }

    fn handle_net_recvfrom(
        reply: &mut TronaMsg,
        conn_id: u32,
        max_len: u16,
        flags: u32,
        arm_pending: bool,
    ) {
        let want_timestamp = (flags & INET_RECV_FLAG_WANT_TIMESTAMP) != 0;
        let capped = core::cmp::min(max_len, 128) as usize;
        log_inet_ipc(b"recvfrom", conn_id, 0, 0, capped);
        let kind = socket_kind(conn_id);

        // `NET_RECVFROM_WAIT` path — same async contract as
        // `NET_RECV_WAIT`: VFS parked the client before firing
        // `mp_write_ctx`; all results travel via `push_completion`.
        if arm_pending {
            let mut scratch = [0u8; 152];
            match kind {
                SocketKind::Raw => {
                    let (result, src_ip, src_port, timestamp_ns) =
                        net::socket::raw_ipv4::raw_recvfrom(
                            conn_id,
                            &mut scratch[..capped],
                            want_timestamp,
                        );
                    if result == -1 {
                        net::socket::raw_ipv4::set_pending_recvfrom(conn_id, capped as u16, flags);
                    } else {
                        let n = core::cmp::min(result as usize, 152);
                        net::socket::raw_ipv4::push_immediate_recvfrom_completion(
                            conn_id,
                            &scratch[..n],
                            src_ip,
                            src_port,
                            timestamp_ns,
                        );
                    }
                }
                SocketKind::Udp => {
                    let (result, src_ip, src_port, timestamp_ns) = net::socket::udp::udp_recvfrom(
                        conn_id,
                        &mut scratch[..capped],
                        want_timestamp,
                    );
                    if result == -1 {
                        net::socket::udp::set_pending_recvfrom(conn_id, capped as u16, flags);
                    } else {
                        let n = core::cmp::min(result as usize, 152);
                        net::socket::udp::push_immediate_recvfrom_completion(
                            conn_id,
                            &scratch[..n],
                            src_ip,
                            src_port,
                            timestamp_ns,
                        );
                    }
                }
                SocketKind::Tcp => {
                    // TCP has no connectionless recvfrom. Push an error
                    // completion so VFS unparks the client with the
                    // correct errno.
                    net::socket::tcp::push_immediate_recv_completion(conn_id, &[]);
                }
            }
            reply.label = TRONA_PENDING;
            return;
        }

        // `NET_RECVFROM` path (no arm): synchronous response for the
        // blocking VFS `mp_call_ctx`.
        let buf = unsafe {
            let dst = &raw mut reply.regs[4] as *mut u8;
            core::slice::from_raw_parts_mut(dst, capped)
        };
        match kind {
            SocketKind::Raw => {
                let (result, src_ip, src_port, timestamp_ns) =
                    net::socket::raw_ipv4::raw_recvfrom(conn_id, buf, want_timestamp);
                if result == -1 {
                    reply.label = TRONA_PENDING;
                } else {
                    let data_len = result as usize;
                    reply.label = TRONA_OK;
                    reply.regs[0] = result as u64;
                    reply.regs[1] = src_ip as u64;
                    reply.regs[2] = src_port as u64;
                    reply.regs[3] = timestamp_ns;
                    reply.length = 4 + (((result as u64) + 7) / 8);
                    log_inet_recv_result(b"recvfrom", conn_id, src_ip, data_len, &buf[..data_len]);
                }
            }
            SocketKind::Udp => {
                let (result, src_ip, src_port, timestamp_ns) =
                    net::socket::udp::udp_recvfrom(conn_id, buf, want_timestamp);
                if result == -1 {
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

    let request_correlation = decode_request_correlation(msg);

    match msg.label {
        VFS_BACKEND_OPEN_SESSION => {
            handle_backend_open_session(msg, reply);
        }
        NETSRV_RX_KICK => {
            service_network_progress(ipc_ctx());
            reply.label = TRONA_OK;
        }
        NET_REGISTER_VFS => {
            // VFS transfers a plain, IPC-transferable endpoint cap.
            // Inbound payload caps deposit at `recv_scratch`; move
            // the cap to its permanent slot first, then rebadge it
            // locally so callbacks arrive with a distinctive badge on
            // the VFS side without relying on label-based fallback
            // routing.
            if let Err(err) = install_vfs_callback_cap(true) {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[netsrv] failed to move VFS callback EP into permanent slot err=");
                    _lb.dec(err);
                    _lb.putc(b'\n');
                });
                reply.label = TRONA_INVALID_OPERATION;
            } else {
                unsafe {
                    *(&raw mut VFS_REGISTERED) = true;
                }
                trona_runtime::uinfo!(|_lb| {
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
                        if let Some(header) = request_correlation {
                            save_pending_correlation(conn_id, INET_OP_CONNECT, header);
                        }
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
            handle_net_accept(reply, conn_id, false);
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
            let flags = if msg.length >= 3 {
                msg.regs[2] as u32
            } else {
                0
            };
            handle_net_recv(reply, conn_id, max_len, flags, false);
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
                INET_RECV_FLAG_WANT_ADDR
            };
            handle_net_recvfrom(reply, conn_id, max_len, flags, false);
        }
        NET_RECV_WAIT => {
            let conn_id = msg.regs[0] as u32;
            let max_len = msg.regs[1] as u16;
            let flags = if msg.length >= 3 {
                msg.regs[2] as u32
            } else {
                0
            };
            if let Some(header) = request_correlation {
                save_pending_correlation(conn_id, INET_OP_RECV, header);
            }
            handle_net_recv(reply, conn_id, max_len, flags, true);
        }
        NET_ACCEPT_WAIT => {
            let conn_id = msg.regs[0] as u32;
            if let Some(header) = request_correlation {
                save_pending_correlation(conn_id, INET_OP_ACCEPT, header);
            }
            handle_net_accept(reply, conn_id, true);
        }
        NET_RECVFROM_WAIT => {
            let conn_id = msg.regs[0] as u32;
            let max_len = msg.regs[1] as u16;
            let flags = if msg.length >= 3 {
                msg.regs[2] as u32
            } else {
                INET_RECV_FLAG_WANT_ADDR
            };
            if let Some(header) = request_correlation {
                save_pending_correlation(conn_id, INET_OP_RECVFROM, header);
            }
            handle_net_recvfrom(reply, conn_id, max_len, flags, true);
        }
        NET_CLOSE => {
            let conn_id = msg.regs[0] as u32;
            match socket_kind(conn_id) {
                SocketKind::Raw => {
                    net::socket::raw_ipv4::raw_close(conn_id);
                }
                SocketKind::Udp => {
                    net::socket::udp::udp_close(conn_id);
                }
                SocketKind::Tcp => {
                    net::socket::tcp::tcp_close(conn_id);
                }
            }
            reply.label = TRONA_OK;
        }
        NET_SHUTDOWN => {
            let conn_id = msg.regs[0] as u32;
            let how = msg.regs[1] as i32;
            match socket_kind(conn_id) {
                SocketKind::Raw => {
                    net::socket::raw_ipv4::raw_close(conn_id);
                }
                SocketKind::Udp => {
                    net::socket::udp::udp_close(conn_id);
                }
                SocketKind::Tcp => {
                    net::socket::tcp::tcp_shutdown(conn_id, how);
                }
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
            // Fail fast when no resolver is configured (DHCP never provided
            // one): deferring would block the caller until the per-query hard
            // deadline. Reply with a meaningful error now instead.
            if net::config::dns_server() == 0 {
                reply.label = TRONA_NOT_FOUND;
                return false;
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
            // Fail fast with a meaningful error when no resolver is configured.
            if net::config::dns_server() == 0 {
                reply.label = TRONA_NOT_FOUND;
                return false;
            }
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
/// caller reply targets.
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
                            core::ptr::copy_nonoverlapping(c.ptr_hostname.as_ptr(), dst, copy_len);
                        }
                    }
                    reply.length = 1 + ((copy_len as u64 + 7) / 8);
                } else {
                    reply.label = dns_error_to_label(c.error);
                }
            }
        }
        // SAFETY: IPC context is valid; reply target was stashed by the DNS start path.
        unsafe {
            let ipc_buf = if let Some(ctx_mut) = ctx.as_mut() {
                ctx_mut.ipc_buffer
            } else {
                core::ptr::null_mut()
            };
            let len = core::cmp::min(reply.length as usize, reply.regs.len());
            let err = trona_server::mp_write_reply_to(
                ipc_buf,
                c.reply_target,
                reply.label,
                &reply.regs[..len],
                0,
            );
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[netsrv] DNS mp_write_reply failed err=");
                    _lb.hex(err as u64);
                    _lb.putc(b'\n');
                });
            }
        }
    }
}

/// Compute the absolute monotonic deadline for the next progress-timer fire:
/// the nearest pending DNS/DHCP/TCP deadline, or `now + SAFETY_TICK_NS` when
/// none is pending (so stranded SHM RX is still swept on an idle heartbeat).
fn next_wake_deadline() -> u64 {
    let now = net::dns::clock_monotonic_ns();
    let tcp_deadline = net::socket::tcp::next_timer_deadline_ns();
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
    let deadline = core::cmp::min(core::cmp::min(dns_deadline, dhcp_deadline), tcp_deadline);
    if deadline == u64::MAX {
        now.saturating_add(SAFETY_TICK_NS)
    } else {
        // Clamp into the future so a just-passed deadline still fires promptly
        // (the kernel fires a past deadline on the next tick) without re-arming
        // in the past on every iteration.
        core::cmp::max(deadline, now.saturating_add(1))
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
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[netsrv] notify skip conn=");
            _lb.dec(conn_id as u64);
            _lb.str(b" op=");
            _lb.dec(op_type as u64);
            _lb.str(b" registered=0\n");
        });
        return;
    }

    if let Some(header) = take_pending_correlation(conn_id, op_type) {
        let mut msg = TronaMsg::zeroed();
        msg.label = backend_reply_label(result);
        if msg.label == VFS_BACKEND_REPLY_OK {
            match op_type {
                INET_OP_CONNECT => {
                    msg.regs[0] = conn_id as u64;
                    msg.regs[1] = 0;
                    msg.length = 2;
                }
                INET_OP_RECV => {
                    let max_data = core::cmp::min(data_len, 152);
                    msg.regs[0] = max_data as u64;
                    if max_data > 0 {
                        unsafe {
                            let dst = &raw mut msg.regs[1] as *mut u8;
                            let mut i = 0usize;
                            while i < max_data {
                                *dst.add(i) = data[i];
                                i += 1;
                            }
                        }
                    }
                    msg.length = 1 + ((max_data as u64 + 7) / 8);
                }
                INET_OP_ACCEPT => {
                    msg.regs[0] = extra_conn_id as u64;
                    msg.regs[1] = 8;
                    unsafe {
                        let dst = &raw mut msg.regs[2] as *mut u8;
                        let family = (AF_INET as u16).to_le_bytes();
                        *dst.add(0) = family[0];
                        *dst.add(1) = family[1];
                        let port = extra_port.to_be_bytes();
                        *dst.add(2) = port[0];
                        *dst.add(3) = port[1];
                        let ip = extra_ip.to_be_bytes();
                        *dst.add(4) = ip[0];
                        *dst.add(5) = ip[1];
                        *dst.add(6) = ip[2];
                        *dst.add(7) = ip[3];
                    }
                    msg.length = 3;
                }
                INET_OP_RECVFROM => {
                    let max_data = core::cmp::min(data_len, 104);
                    msg.regs[0] = max_data as u64;
                    msg.regs[1] = extra_ip as u64;
                    msg.regs[2] = extra_port as u64;
                    msg.regs[3] = timestamp_ns;
                    if max_data > 0 {
                        unsafe {
                            let dst = &raw mut msg.regs[4] as *mut u8;
                            let mut i = 0usize;
                            while i < max_data {
                                *dst.add(i) = data[i];
                                i += 1;
                            }
                        }
                    }
                    msg.length = 4 + ((max_data as u64 + 7) / 8);
                }
                _ => {
                    msg.length = 0;
                }
            }
        }
        stamp_completion_correlation(&mut msg, header);
        let ep = cap_vfs_callback_ep();
        let write_err = unsafe { ipc::mp_write_ctx(ipc_ctx(), ep, &raw const msg) };
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[netsrv] backend notify conn=");
            _lb.dec(conn_id as u64);
            _lb.str(b" op=");
            _lb.dec(op_type as u64);
            _lb.str(b" len=");
            _lb.dec(data_len as u64);
            _lb.str(b" err=");
            _lb.hex(write_err as u64);
            _lb.putc(b'\n');
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

    // One-way completion (the reply was only logged). Non-blocking so the
    // netsrv reactor never parks on VFS — that blocking call was the VFS↔netsrv
    // return-edge of the boot deadlock. Post-A1a a reply to a VFS that is parked
    // on netsrv enqueues on the callback ring (it was silently dropped before),
    // so the `IN_SYNC_HANDLER` guard that used to suppress this is retired.
    // SAFETY: IPC context is valid; slot 84 holds the local badged alias.
    let call_err =
        unsafe { ipc::mp_write_ctx(ipc_ctx(), cap_vfs_callback_badged_ep(), &raw const msg) };
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[netsrv] notify conn=");
        _lb.dec(conn_id as u64);
        _lb.str(b" op=");
        _lb.dec(op_type as u64);
        _lb.str(b" len=");
        _lb.dec(data_len as u64);
        _lb.str(b" err=");
        _lb.hex(call_err as u64);
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
        trona_runtime::udebug!(|_lb| {
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
            INET_RECV_TIMESTAMP_NONE,
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

fn shape_immediate_backend_completion(request: &TronaMsg, reply: &mut TronaMsg) {
    let original = reply.label;
    reply.label = backend_reply_label(original);
    if reply.label != VFS_BACKEND_REPLY_OK {
        reply.length = 0;
        return;
    }
    match request.label {
        NET_CONNECT => {
            reply.regs[0] = request.regs[0];
            reply.regs[1] = 0;
            reply.length = reply.length.max(2);
        }
        NET_BIND | NET_LISTEN | NET_SHUTDOWN => {
            reply.length = 0;
        }
        NET_SEND | NET_SENDTO => {
            reply.length = reply.length.max(1);
        }
        _ => {}
    }
}

fn send_immediate_backend_completion(
    ctx: *mut IpcContext,
    header: CorrelationHeader,
    request: &TronaMsg,
    reply: &mut TronaMsg,
) {
    shape_immediate_backend_completion(request, reply);
    stamp_completion_correlation(reply, header);
    let ep = cap_vfs_callback_ep();
    if ep == 0 {
        return;
    }
    let _ = unsafe { ipc::mp_write_ctx(ctx, ep, &raw const *reply) };
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Cookie for the service pipe's `STATE_READABLE` Watch (kind 0).
const NETSRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);
/// Cookie stamped on the progress `Timer`'s `EVENT_TYPE_TIMER` records (kind 2).
const NETSRV_TIMER_COOKIE: u64 = trona_server::event_loop::encode_cookie(2, 0, 1);

/// Reactor dispatcher. The service pipe (`STATE_READABLE`) carries client RPCs
/// (VFS socket ops, dnssrv DNS) and the netdrv `NETSRV_RX_KICK`; a kernel
/// `Timer` bound to the same `EventQueue` drives DNS/DHCP/TCP deadlines and the
/// idle SHM-RX sweep. The timer is re-armed after every event at the nearest
/// `next_wake_deadline()`.
struct NetsrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    timer_cap: Cap,
    recv_scratch: Cap,
}

impl NetsrvDispatcher {
    /// Re-arm the one-shot progress timer at the nearest pending deadline.
    fn rearm_timer(&self) {
        let _ = trona_kernel::invoke::timer_set(
            trona_kernel::core_types::CapRef::flat(self.timer_cap),
            next_wake_deadline(),
            0,
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            NETSRV_TIMER_COOKIE,
        );
    }
}

impl trona_server::event_loop::EqDispatcher for NetsrvDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let ctx = ipc_ctx();
        // The netdrv RX kick wants only a progress sweep, no reply.
        if msg.label == NETSRV_RX_KICK {
            service_network_progress(ctx);
            self.rearm_timer();
            return 0;
        }
        // Real client RPC: dispatch + route the reply (deferred / async-pending
        // via the VFS callback EP / direct), mirroring the former event loop.
        let request_correlation = decode_request_correlation(msg);
        let mut reply = TronaMsg::zeroed();
        let deferred = dispatch_ipc(msg, &mut reply);
        if deferred {
            // Parked: the completion is delivered later via the callback EP.
        } else if let Some(header) = request_correlation {
            if reply.label == TRONA_PENDING {
                drain_completion_queue();
            } else {
                send_immediate_backend_completion(ctx, header, msg, &mut reply);
            }
        } else {
            // SAFETY: `ctx` is this thread's IPC context.
            let _ = unsafe { ipc::mp_write_reply_ctx(ctx, self.recv_ep, &raw const reply) };
        }
        self.rearm_timer();
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // SAFETY: re-arm the cap-receive scratch before each MP_READ.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ipc_ctx(),
                CAP_SELF_CSPACE,
                self.recv_scratch,
                0,
            );
        }
        true
    }

    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(self.watch_cap),
            trona_kernel::core_types::CapRef::flat(self.recv_ep),
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
            NETSRV_SERVICE_COOKIE,
        )
    }

    fn continue_readable_drain(&mut self, _cookie: u64) -> bool {
        // One RPC per EQ_WAIT so the timer is re-armed (and a pending timer fire
        // observed) between messages, matching the former one-at-a-time loop.
        false
    }

    fn handle_timer(&mut self, _cookie: u64) {
        service_network_progress(ipc_ctx());
        self.rearm_timer();
    }

    fn handle_overflow(&mut self, _dropped: u64) {}
}

/// Reactor entry: binds the service pipe (client RPC + netdrv RX kick) and a
/// progress `Timer` onto one `EventQueue`, then blocks in `EQ_WAIT`. The timer
/// is re-armed after every event at the nearest DNS/DHCP/TCP deadline.
fn event_loop() -> ! {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[netsrv] Entering reactor\n");
    });

    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();
    let recv_scratch = cap_recv_scratch_slot();

    // Self-provision the reactor's EventQueue + Watch + progress Timer.
    let eq = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_EVENT_QUEUE as u64,
        4,
    );
    let watch = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_WATCH as u64,
        0,
    );
    let timer = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_TIMER as u64,
        0,
    );
    let (eq, watch, timer) = match (eq, watch, timer) {
        (Some(eq), Some(watch), Some(timer)) => (eq, watch, timer),
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[netsrv] reactor EventQueue/Watch/Timer alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let timer_cap = timer.borrow().addr();

    // Arm the service pipe's READABLE edge onto the reactor EQ.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        NETSRV_SERVICE_COOKIE,
    );

    // The reactor objects live for the process lifetime.
    core::mem::forget(eq);
    core::mem::forget(watch);
    core::mem::forget(timer);

    let dispatcher = NetsrvDispatcher {
        recv_ep,
        watch_cap,
        eq_cap,
        timer_cap,
        recv_scratch,
    };
    // Arm the progress timer for the first deadline (DNS/DHCP bootstrap may
    // already have pending work).
    dispatcher.rearm_timer();

    let mut reactor = trona_server::event_loop::EventLoop::new(eq_cap, dispatcher);
    loop {
        // SAFETY: `ctx` is this thread's IPC context; block on the EQ and
        // dispatch one ready event (client RPC / RX kick via `dispatch_state`,
        // progress timer via `handle_timer`).
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
        _lb.str(b"[netsrv] Network Stack Server starting\n");
    });

    // 0. Reserve the server-private CNode slots (VFS callback EP,
    //    VFS callback badged EP, receive scratch) out of the RTLD frame pool
    //    via `trona_runtime::core::slot_alloc`. Must run before any helper
    //    that reads `cap_*_slot()`. The DNS subsystem
    //    reserves its own `MAX_PENDING_DNS` consecutive reply cap slots
    //    in the same step so the whole server-private region is
    //    settled before any hardware / IPC setup.
    init_private_slots();
    net::dns::init_dns_reply_slots();

    // 1. Allocate and map SHM
    if !setup_shm() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netsrv] SHM setup failed, halting\n");
        });
        idle();
    }

    // 2. Register with netdrv (NETDRV_REGISTER: exchange SHM MO cap/index, get MAC)
    if !driver_register() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[netsrv] Driver register failed, halting\n");
        });
        idle();
    }

    // 4. Resolve initial network configuration via DHCP with a static fallback.
    bootstrap_network_config();

    // 4b. Fire-and-forget ARP request for the configured gateway.
    if net::proto::ipv4::our_ip() != 0 && net::proto::ipv4::gateway_ip() != 0 {
        trona_runtime::udebug!(|_lb| {
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

    // 5. Register with name service; unit_mgr observes the publish event as readiness.
    register_namesrv();

    // 5b. Initialize DNS protocol engine
    net::dns::init_dns_socket();

    // 7. Enter event loop (never returns)
    event_loop()
}

fn idle() -> ! {
    loop {
        let _ = trona_kernel::syscall::yield_now();
    }
}
