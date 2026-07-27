//! SaltyOS TTY daemon — PTY driver with line discipline
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides PTY (pseudo-terminal) instances with per-PTY line discipline,
//! termios state, and session/job control metadata.
//!
//! Data flow:
//!   Console input → console server → SHM input ring + MP kick →
//!   line discipline → slave ring buffer → VFS_PTY_READY MP kick →
//!   VFS collects → client (bash)
//!
//! Output flow:
//!   bash write → VFS → POSIX_TTYSRV_PTY_WRITE → OPOST processing →
//!   serial (DebugPutStr) + display (SHM ring + DISPLAY_PRESENT kick)

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod handlers;
mod input;
mod types;

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_kernel::uapi;
use trona_protocol::common::{TRONA_INVALID_OPERATION, TRONA_OK};
use trona_protocol::correlation::{
    CORRELATION_BACKEND_POSIX_TTYSRV, CORRELATION_CLASS_PTY, CORRELATION_HEADER_REG_COUNT,
    CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CORRELATION_KIND_REQUEST,
    CorrelationHeader, ensure_correlation_wire_length,
};
use trona_protocol::display::{DISPLAY_GET_INFO, DISPLAY_PRESENT, DISPLAY_SETUP_RING};
use trona_protocol::mm::{MM_SHM_DESTROY, MM_SHM_UNMAP};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::posix::*;
use trona_protocol::vfs::backend::{
    BACKEND_FEATURE_ASYNC_V1, VFS_BACKEND_OPEN_SESSION, VFS_BACKEND_REPLY_INVALID,
    VFS_BACKEND_REPLY_OK,
};
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf as SerialLB;

use types::*;

// Service-local cap: `Require=dispdrv-ep.socket` in `posix_ttysrv.service`.
trona_runtime::local_cap!(pub(crate) dispdrv_ep = "posix_ttysrv:dispdrv_ep");

// ======================================================================
// Global state
// ======================================================================

pub(crate) static mut PTYS: [PtyInstance; MAX_PTYS] = {
    const INIT: PtyInstance = PtyInstance::new();
    [INIT; MAX_PTYS]
};

// SHM ring buffer for terminal output to the display server.
// Replaces the old IPC-based TX queue: posix_ttysrv writes bytes to shared memory
// and kicks the display service endpoint.
const TERM_SHM_ID: u64 = 0x54524D00; // "TRM\0"
const TERM_RING_PAGES: u64 = 4;
const TERM_RING_HDR_SIZE: usize = 16;
static mut TERM_RING_BASE: *mut u8 = core::ptr::null_mut();
static mut TERM_RING_ACTIVE: bool = false;

// SHM ring buffer for raw input from the console server.
// Console (producer) creates the SHM and initialises the ring header;
// posix_ttysrv (consumer) maps it read-only and drains on POSIX_TTYSRV_INPUT_KICK.
// 'COIT' (COnsole Input Tty)
const CONSOLE_INPUT_SHM_ID: u64 = 0x434F4954;
const CONSOLE_INPUT_RING_PAGES: u64 = 4; // 16 KB — matches console producer
const CONSOLE_INPUT_RING_HDR_SIZE: usize = 16;
static mut CONSOLE_INPUT_RING_BASE: *mut u8 = core::ptr::null_mut();
static mut CONSOLE_INPUT_RING_ACTIVE: bool = false;

const RECV_SLOT_COUNT: u64 = 16;
const CAP_SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;
static mut RECV_SLOTS: trona_server::recv_slot::RecvSlotArena =
    trona_server::recv_slot::RecvSlotArena::new_empty();

static mut VFS_CALLBACK_EP: Option<OwnedCap> = None;
static mut VFS_SESSION_ID: u32 = 0;

// Serial TX queue. Decouples write bursts from IPC handlers, but the queue is
// drained fully before the server blocks again so prompt output never waits
// for a later input event to become visible.
const SERIAL_TX_BUF_SIZE: usize = 4096;
const SERIAL_TX_DRAIN_MAX: usize = 256;
static mut SERIAL_TX_BUF: [u8; SERIAL_TX_BUF_SIZE] = [0; SERIAL_TX_BUF_SIZE];
static mut SERIAL_TX_HEAD: usize = 0;
static mut SERIAL_TX_TAIL: usize = 0;

// ======================================================================
// Helper functions
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

/// Signal "PTY control plane is ready" on the unit readiness notification.
///
/// What "ready" means here: `POSIX_TTYSRV_PTY_ALLOC`, `POSIX_TTYSRV_PTY_LOOKUP`,
// ======================================================================
// SHM ring buffer helpers (producer side)
// ======================================================================

fn term_ring_data_size() -> usize {
    TERM_RING_PAGES as usize * 4096 - TERM_RING_HDR_SIZE
}

#[inline]
fn display_ring_active() -> bool {
    unsafe { core::ptr::read_volatile(&raw const TERM_RING_ACTIVE) }
}

fn teardown_display_ring(shm_live: bool) {
    // Capture the mmsrv-assigned ring VA before clearing the base so the
    // unmap below targets where the region was actually placed.
    let ring_va = unsafe { core::ptr::read_volatile(&raw const TERM_RING_BASE) } as u64;
    unsafe {
        *(&raw mut TERM_RING_BASE) = core::ptr::null_mut();
        *(&raw mut TERM_RING_ACTIVE) = false;
    }

    if !shm_live {
        return;
    }

    let ctx = ipc_ctx();
    let mmsrv = trona_runtime::client::caps::mmsrv_ep().addr();

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_SHM_UNMAP;
    msg.regs[0] = TERM_SHM_ID;
    msg.regs[1] = 0;
    msg.regs[2] = ring_va;
    msg.length = 3;
    let _ = unsafe {
        ipc::mp_call_ctx(
            ctx,
            mmsrv,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_SHM_DESTROY;
    msg.regs[0] = TERM_SHM_ID;
    msg.length = 1;
    let _ = unsafe {
        ipc::mp_call_ctx(
            ctx,
            mmsrv,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
}

fn refresh_display_ring_on_ready_signal() {
    if display_ring_active() {
        return;
    }

    teardown_display_ring(display_ring_active());
    let _ = setup_display_ring();
}

fn ensure_display_ring() -> bool {
    refresh_display_ring_on_ready_signal();
    if display_ring_active() {
        return true;
    }
    setup_display_ring()
}

/// Write bytes to the SHM ring. Returns number of bytes written.
///
/// # Safety
/// `base` must point to a valid, mapped SHM ring header page.
unsafe fn term_ring_push(base: *mut u8, ring_size: usize, data: &[u8]) -> usize {
    unsafe {
        let head = core::ptr::read_volatile(base as *const u32) as usize;
        let tail = core::ptr::read_volatile(base.add(4) as *const u32) as usize;
        // Acquire: observe consumer's tail update before computing free space.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let used = (head + ring_size - tail) % ring_size;
        let free = ring_size - 1 - used;
        let count = core::cmp::min(free, data.len());
        if count == 0 {
            return 0;
        }

        let dp = base.add(TERM_RING_HDR_SIZE);
        let mut i = 0usize;
        while i < count {
            core::ptr::write_volatile(dp.add((head + i) % ring_size), data[i]);
            i += 1;
        }
        // Release: all data writes above are visible before the head update
        // that publishes them to the consumer. Required on ARM (weak ordering);
        // x86 TSO provides this implicitly.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(base as *mut u32, ((head + count) % ring_size) as u32);
        count
    }
}

fn kick_display_ring() {
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = DISPLAY_PRESENT;
    let _ = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            crate::dispdrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
}

/// Forward output bytes to the display server via SHM ring and a
/// service-endpoint kick.
pub(crate) fn display_write(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    if !ensure_display_ring() {
        return;
    }
    unsafe {
        let base = TERM_RING_BASE;
        let ring_size = term_ring_data_size();
        let mut offset = 0usize;
        while offset < data.len() {
            let written = term_ring_push(base, ring_size, &data[offset..]);
            offset += written;
            if written > 0 {
                kick_display_ring();
            }
            if offset < data.len() {
                // Ring full — kick dispdrv to drain, yield, retry once.
                kick_display_ring();
                trona_kernel::syscall::yield_now();
            }
        }
    }
}

/// Set up the SHM ring buffer between posix_ttysrv and the display server.
///
/// Allocates the SHM region and maps it, then issues `DISPLAY_SETUP_RING`
/// to dispdrv. Later writes publish bytes into the ring and send
/// `DISPLAY_PRESENT` to wake the display owner loop. Returns
/// `false` on any failure; caller may retry later.
fn setup_display_ring() -> bool {
    let ctx = ipc_ctx();

    // 1. Create SHM (posix_ttysrv owns the display ring as producer). Shared
    //    `mm::shm_create` carries the size in bytes and receives the MO cap.
    let (shm_idx, shm_cap) =
        match trona_runtime::client::mm::shm_create(TERM_SHM_ID, TERM_RING_PAGES * 4096) {
            Ok(v) => v,
            Err(_) => {
                puts(b"[posix_ttysrv] SHM create failed\n");
                return false;
            }
        };
    let shm_live = true;

    // 2. Map SHM (RW — we publish head). `shm_map` takes ownership of the MO cap
    //    (mmsrv moves it into the published region); `into_transfer()` consumes
    //    `shm_cap` so no explicit free is needed. mmsrv places the region within
    //    the client's mmap window, so the ring lives wherever it returns — the
    //    fixed low VA is a name, not an address; use the returned VA for the
    //    header and base pointer.
    let map_res = trona_runtime::client::mm::shm_map(
        shm_idx,
        shm_cap.into_transfer(),
        0,
        TERM_RING_PAGES * 4096,
        0x3,
    );
    let ring_va = match map_res {
        Ok(va) => va,
        Err(_) => {
            puts(b"[posix_ttysrv] SHM map failed\n");
            teardown_display_ring(shm_live);
            return false;
        }
    };

    // 3. Initialize ring header at the placed address.
    // SAFETY: SHM is mapped at `ring_va`; single-threaded init.
    unsafe {
        let hdr = ring_va as *mut u32;
        core::ptr::write_volatile(hdr, 0); // head
        core::ptr::write_volatile(hdr.add(1), 0); // tail
        core::ptr::write_volatile(hdr.add(2), term_ring_data_size() as u32); // size
        core::ptr::write_volatile(hdr.add(3), 0); // reserved
        *(&raw mut TERM_RING_BASE) = ring_va as *mut u8;
    }

    // 4. Send `DISPLAY_SETUP_RING`; later writes kick dispdrv with
    // `DISPLAY_PRESENT` on its service endpoint.
    let mut msg = TronaMsg::zeroed();
    msg.label = DISPLAY_SETUP_RING;
    msg.regs[0] = TERM_SHM_ID;
    msg.length = 1;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; RPC to dispdrv.
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            crate::dispdrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || reply.label != TRONA_OK {
        // dispdrv not ready yet; ring stays inactive. Caller retries.
        teardown_display_ring(shm_live);
        return false;
    }

    // 5. Activate.
    unsafe {
        *(&raw mut TERM_RING_ACTIVE) = true;
    }
    puts(b"[posix_ttysrv] Display ring buffer active\n");
    true
}

/// Handle `POSIX_TTYSRV_SETUP_INPUT_RING` from console.
///
/// Console already created the SHM ring; we map it read-write (consumer
/// publishes `tail`). Console kicks us with `POSIX_TTYSRV_INPUT_KICK`
/// whenever it publishes raw input bytes.
fn handle_setup_input_ring(reply: &mut TronaMsg) {
    // Console produced the input ring under a well-known name; create-by-name
    // returns the same MO (with our own cap) so we can map it RW — the consumer
    // publishes `tail` at offset 4. `shm_map` consumes the cap, so the local
    // slot is freed afterward.
    let bytes = CONSOLE_INPUT_RING_PAGES * 4096;
    let (shm_idx, shm_cap) =
        match trona_runtime::client::mm::shm_create(CONSOLE_INPUT_SHM_ID, bytes) {
            Ok(v) => v,
            Err(_) => {
                puts(b"[posix_ttysrv] input ring: SHM create failed\n");
                reply.label = TRONA_INVALID_OPERATION;
                return;
            }
        };
    let map_res =
        trona_runtime::client::mm::shm_map(shm_idx, shm_cap.into_transfer(), 0, bytes, 0x3);
    let ring_va = match map_res {
        Ok(va) => va,
        Err(_) => {
            puts(b"[posix_ttysrv] input ring: SHM map failed\n");
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
    };

    // Mark ring active at the placed address.
    // SAFETY: Single-threaded init; written once.
    unsafe {
        *(&raw mut CONSOLE_INPUT_RING_BASE) = ring_va as *mut u8;
        *(&raw mut CONSOLE_INPUT_RING_ACTIVE) = true;
    }
    puts(b"[posix_ttysrv] Console input ring buffer active\n");

    reply.label = TRONA_OK;
    reply.regs[0] = 0;
    reply.length = 1;
}

// ======================================================================
// Serial TX ring buffer helpers
// ======================================================================

/// Queue bytes for deferred serial output.
pub(crate) fn serial_write_queued(data: &[u8]) {
    unsafe {
        for &b in data {
            let next = (SERIAL_TX_HEAD + 1) % SERIAL_TX_BUF_SIZE;
            if next == SERIAL_TX_TAIL {
                // Buffer full — drain synchronously to avoid dropping bytes
                serial_flush_until_empty();
                let next2 = (SERIAL_TX_HEAD + 1) % SERIAL_TX_BUF_SIZE;
                if next2 == SERIAL_TX_TAIL {
                    // Still full after flush — write directly as fallback
                    serial::serial_puts(&data[..]);
                    return;
                }
            }
            SERIAL_TX_BUF[SERIAL_TX_HEAD] = b;
            SERIAL_TX_HEAD = (SERIAL_TX_HEAD + 1) % SERIAL_TX_BUF_SIZE;
        }
    }
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
        || header.class != CORRELATION_CLASS_PTY
        || header.backend != CORRELATION_BACKEND_POSIX_TTYSRV
    {
        return None;
    }
    Some(header)
}

fn stamp_completion_correlation(reply: &mut TronaMsg, request: CorrelationHeader) {
    let words = CorrelationHeader {
        class: request.class,
        backend: request.backend,
        kind: CORRELATION_KIND_COMPLETION,
        flags: 0,
        session: request.session,
        opcode: request.opcode,
        _reserved0: 0,
        token: request.token,
        request_seq: request.request_seq,
        request_seq_secondary: request.request_seq_secondary,
    }
    .encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = words[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut reply.length);
}

fn handle_backend_open_session(msg: &TronaMsg, reply: &mut TronaMsg) {
    let incoming_slot = unsafe {
        let arena = &mut *(&raw mut RECV_SLOTS);
        trona_server::recv_slot::capture_transferred_cap(ipc_ctx(), arena)
    };
    let Some(slot) = incoming_slot else {
        reply.label = VFS_BACKEND_REPLY_INVALID;
        reply.length = 0;
        return;
    };
    // SAFETY: `slot` was just received into our arena via a cap transfer and is
    // now exclusively ours; adopt_received resolves the depth automatically.
    let incoming_owned = unsafe { OwnedCap::adopt_received(slot) };
    unsafe {
        // Replace any previously installed callback EP; Drop frees the old cap.
        *(&raw mut VFS_CALLBACK_EP) = Some(incoming_owned);
        *(&raw mut VFS_SESSION_ID) = msg.regs[1] as u32;
    }
    reply.label = VFS_BACKEND_REPLY_OK;
    reply.regs[0] = 32;
    reply.regs[1] = BACKEND_FEATURE_ASYNC_V1;
    reply.regs[2] = 0;
    reply.length = 3;
}

/// Drain up to SERIAL_TX_DRAIN_MAX bytes from the serial TX queue.
unsafe fn serial_try_flush_chunk() {
    unsafe {
        if SERIAL_TX_HEAD == SERIAL_TX_TAIL {
            return;
        }

        let mut buf = [0u8; SERIAL_TX_DRAIN_MAX];
        let mut n = 0usize;
        let mut idx = SERIAL_TX_TAIL;
        while idx != SERIAL_TX_HEAD && n < SERIAL_TX_DRAIN_MAX {
            buf[n] = SERIAL_TX_BUF[idx];
            idx = (idx + 1) % SERIAL_TX_BUF_SIZE;
            n += 1;
        }
        if n > 0 {
            serial::serial_puts(&buf[..n]);
            SERIAL_TX_TAIL = (SERIAL_TX_TAIL + n) % SERIAL_TX_BUF_SIZE;
        }
    }
}

unsafe fn serial_flush_until_empty() {
    unsafe {
        while SERIAL_TX_HEAD != SERIAL_TX_TAIL {
            serial_try_flush_chunk();
        }
    }
}

// ======================================================================
// Name service registration
// ======================================================================

fn register_with_namesrv() -> bool {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let mut reg_msg = TronaMsg::zeroed();
    let mut reg_reply = TronaMsg::zeroed();
    let svc_name = b"posix_ttysrv";

    reg_msg.label = NAMESRV_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    let publish_tc = trona_runtime::client::caps::service_client_ep_for_transfer();

    let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
    unsafe {
        for i in 0..svc_name.len() {
            *ns_dst.add(i) = svc_name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.as_ref().map_or(0, |t| t.slot()));
    }
    reg_msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    reg_msg.length = (REGISTER_FLAGS_REG + 1) as u64;
    unsafe {
        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const reg_msg,
            &raw mut reg_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        drop(publish_tc);
        if err == 0 && reg_reply.label == TRONA_OK {
            puts(b"[posix_ttysrv] registered with namesrv\n");
            return true;
        }
        let mut lb = SerialLB::new();
        lb.str(b"[posix_ttysrv] namesrv register failed: err=");
        lb.hex(err as u64);
        lb.str(b" label=");
        lb.hex(reg_reply.label);
        lb.str(b"\n");
        lb.flush();
    }
    false
}

// ======================================================================
// Entry point
// ======================================================================

/// Cookie for the service pipe's `STATE_READABLE` Watch (kind 0, slot 0, gen 1).
const TTYSRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Reactor dispatcher. Preserves the former server-loop body: each request is
/// dispatched by label, tty output is flushed, and the reply is routed to the
/// VFS callback EP (correlated) or the service pipe (direct) — except a
/// correlated PTY read that returned no bytes, whose completion is deferred to
/// the later input-drain callback.
struct TtysrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
}

impl trona_server::event_loop::EqDispatcher for TtysrvDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        refresh_display_ring_on_ready_signal();
        unsafe {
            serial_flush_until_empty();
        }

        let mut reply = TronaMsg::zeroed();
        let request_correlation = decode_request_correlation(msg);

        match msg.label {
            VFS_BACKEND_OPEN_SESSION => {
                handle_backend_open_session(msg, &mut reply);
            }
            POSIX_TTYSRV_PTY_ALLOC => {
                unsafe { handlers::handle_pty_alloc(&mut reply) };
            }
            POSIX_TTYSRV_PTY_READ => {
                unsafe { handlers::handle_pty_read(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_COLLECT => {
                unsafe { handlers::handle_pty_collect(msg, &mut reply) };
            }
            POSIX_TTYSRV_INPUT_KICK => {
                unsafe {
                    if CONSOLE_INPUT_RING_ACTIVE {
                        input::drain_console_input_ring(
                            CONSOLE_INPUT_RING_BASE,
                            CONSOLE_INPUT_RING_PAGES as usize * 4096 - CONSOLE_INPUT_RING_HDR_SIZE,
                            CONSOLE_INPUT_RING_HDR_SIZE,
                        );
                    }
                    serial_flush_until_empty();
                }
                reply.label = TRONA_OK;
            }
            POSIX_TTYSRV_PTY_WRITE => {
                unsafe { handlers::handle_pty_write(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_MASTER_WRITE => {
                unsafe { handlers::handle_pty_master_write(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_CLOSE => {
                unsafe { handlers::handle_pty_close(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_OPEN_SLAVE => {
                unsafe { handlers::handle_pty_open_slave(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_LOOKUP => {
                unsafe { handlers::handle_pty_lookup(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_TCGETATTR => {
                unsafe { handlers::handle_pty_tcgetattr(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_TCSETATTR => {
                unsafe { handlers::handle_pty_tcsetattr(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_IOCTL => {
                unsafe { handlers::handle_pty_ioctl(msg, &mut reply) };
            }
            POSIX_TTYSRV_PTY_POLL => {
                unsafe { handlers::handle_pty_poll(msg, &mut reply) };
            }
            POSIX_TTYSRV_CLIENT_EXIT => {
                let _dead_badge = msg.regs[0];
                reply.label = TRONA_OK;
                reply.length = 0;
            }
            POSIX_TTYSRV_SETUP_INPUT_RING => {
                handle_setup_input_ring(&mut reply);
            }
            POSIX_TTYSRV_CTTY_PTY_FOR_SID => {
                unsafe { handlers::handle_ctty_pty_for_sid(msg, &mut reply) };
            }
            POSIX_TTYSRV_CTTY_DUMP => {
                unsafe { handlers::handle_ctty_dump(&mut reply) };
            }
            // Legacy labels (backward compat, redirect to PTY 0)
            POSIX_TTYSRV_GET_FG_PGRP
            | POSIX_TTYSRV_SET_FG_PGRP
            | POSIX_TTYSRV_SET_CTTY
            | POSIX_TTYSRV_DROP_CTTY => {
                unsafe { handlers::handle_legacy(msg.label, msg, &mut reply) };
            }
            _ => {
                reply.label = TRONA_INVALID_OPERATION;
                reply.length = 0;
            }
        }

        // Flush queued tty output BEFORE replying so prompt/readline startup
        // bursts are fully visible without waiting for a later input.
        unsafe {
            serial_flush_until_empty();
        }

        let defer_correlated_reply = request_correlation.is_some()
            && msg.label == POSIX_TTYSRV_PTY_READ
            && reply.label == TRONA_OK
            && reply.length >= 1
            && reply.regs[0] == 0;

        let ctx = ipc_ctx();
        // SAFETY: `ctx` is this thread's IPC context. Mirrors the former
        // `finish_request` reply routing without the read (the reactor owns it).
        unsafe {
            if defer_correlated_reply {
                // Deferred PTY read: the completion is sent later by the
                // input-drain callback, not here.
            } else if let Some(header) = request_correlation {
                stamp_completion_correlation(&mut reply, header);
                let ep = (&*(&raw const VFS_CALLBACK_EP))
                    .as_ref()
                    .map_or(0, |c| c.as_raw());
                if ep != 0 {
                    let _ = ipc::mp_write_ctx(ctx, ep, &raw const reply);
                }
            } else {
                let _ = ipc::mp_write_reply_ctx(ctx, self.recv_ep, &raw const reply);
            }
        }
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // Recycle the recv-slot arena before the next MP_READ (cap receiving).
        // SAFETY: single-threaded reactor owns RECV_SLOTS.
        unsafe {
            (&mut *(&raw mut RECV_SLOTS)).recycle_for_next_recv(ipc_ctx(), CAP_SELF_CSPACE);
        }
        true
    }

    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(self.watch_cap),
            trona_kernel::core_types::CapRef::flat(self.recv_ep),
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
            TTYSRV_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    puts(b"[posix_ttysrv] SaltyOS PTY driver starting\n");

    // Query display server for actual framebuffer dimensions.
    unsafe {
        let mut qmsg = TronaMsg::zeroed();
        let mut qreply = TronaMsg::zeroed();
        qmsg.label = DISPLAY_GET_INFO;
        qmsg.length = 0;
        let err = trona_kernel::ipc::mp_call_ctx(
            ipc_ctx(),
            crate::dispdrv_ep().addr(),
            &raw const qmsg,
            &raw mut qreply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err == 0 && qreply.label == TRONA_OK {
            let fb_width = qreply.regs[0] as u32;
            let fb_height = qreply.regs[1] as u32;
            // GLYPH_WIDTH=8, GLYPH_HEIGHT=16
            let cols = fb_width / 8;
            let rows = fb_height / 16;
            if cols > 0 && rows > 0 {
                *(&raw mut types::WINSIZE_COLS) = cols;
                *(&raw mut types::WINSIZE_ROWS) = rows;
                let mut lb = SerialLB::new();
                lb.str(b"[posix_ttysrv] Display dimensions: ");
                lb.dec(cols as u64);
                lb.str(b"x");
                lb.dec(rows as u64);
                lb.str(b"\n");
                lb.flush();
            }
        } else {
            puts(b"[posix_ttysrv] WARN: display query failed, using 80x24\n");
        }
    }

    // Activate PTY 0 (the console PTY)
    unsafe {
        PTYS[0].active = true;
        PTYS[0].master_open_count = 1;
    }
    puts(b"[posix_ttysrv] PTY 0 (console) active\n");

    unsafe {
        let allocator = trona_server::recv_slot::SlotAllocator {
            alloc_consecutive: trona_runtime::core::slot_alloc::slot_alloc_consecutive_cb,
            invoke_depth: trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
        };
        let arena = &mut *(&raw mut RECV_SLOTS);
        if !arena.init_with_allocator(allocator, RECV_SLOT_COUNT) {
            puts(b"[posix_ttysrv] FATAL: recv-slot arena allocation failed\n");
            return -1;
        }
        arena.arm_first(ipc_ctx(), CAP_SELF_CSPACE);
    }

    register_with_namesrv();
    input::signal_vfs(0);

    // Attempt display ring setup once up front. If dispdrv is not yet
    // ready, we retry lazily on the first `display_write` call; see
    // `ensure_display_ring` below.
    if !setup_display_ring() {
        puts(b"[posix_ttysrv] display ring: dispdrv not ready yet, will retry\n");
    }

    puts(b"[posix_ttysrv] Ready\n");

    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();
    let ctx = ipc_ctx();

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
            puts(b"[posix_ttysrv] reactor EventQueue/Watch alloc failed\n");
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();

    // Arm the service pipe's READABLE edge onto the reactor EQ. The recv-slot
    // arena was `arm_first`-ed above; the reactor recycles it in
    // `prepare_mp_read` before each read.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        TTYSRV_SERVICE_COOKIE,
    );

    // The EQ / Watch live for the process lifetime; suppress their OwnedCap
    // drop so the caps are never torn down under the running reactor.
    core::mem::forget(eq);
    core::mem::forget(watch);

    let dispatcher = TtysrvDispatcher {
        recv_ep,
        watch_cap,
        eq_cap,
    };
    let mut reactor = trona_server::event_loop::EventLoop::new(eq_cap, dispatcher);

    loop {
        // SAFETY: `ctx` is this thread's IPC context; block on the EQ and
        // dispatch one ready event.
        unsafe {
            let _ = reactor.run_iteration(ctx);
        }
    }
}

fn idle() -> ! {
    loop {
        trona_kernel::syscall::yield_now();
    }
}
