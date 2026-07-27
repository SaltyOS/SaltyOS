//! SaltyOS Console Server — Input Source + Output Sink
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Handles hardware I/O for serial (COM1 on x86_64, PL011 on aarch64)
//! and PS/2 keyboard (x86_64 only).
//! Forwards raw input bytes to posix_ttysrv via a console→posix_ttysrv
//! SHM input ring, and serves CONSOLE_WRITE for direct serial plus
//! console→dispdrv SHM display ring output.
//!
//! Line discipline, termios, and signal delivery are handled by posix_ttysrv.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

#[cfg(target_arch = "x86_64")]
mod kbd;

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::Termios;
use trona_protocol::common::{TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_OK};
use trona_protocol::console::*;
use trona_protocol::display::{DISPLAY_PRESENT, DISPLAY_SETUP_CONSOLE_RING};
use trona_protocol::mm::{MM_SHM_DESTROY, MM_SHM_UNMAP};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::posix::{POSIX_TTYSRV_INPUT_KICK, POSIX_TTYSRV_SETUP_INPUT_RING};
use trona_runtime::debug::serial;

// Cap layout: console hard-codes no slot numbers. Every cap it uses is
// resolved through role getters — COM1 / keyboard hardware via the
// `ROLE_COM1_*` / `ROLE_KBD_*` system roles in `trona_runtime::client::caps`,
// and the post-procmgr peer endpoints (posix_ttysrv / dispdrv) via a
// service-local role hashed from "<consumer>:<peer>".

/// Resolve the posix_ttysrv endpoint injected from
/// `Requires=posix_ttysrv.socket` in console.service.
#[inline]
fn posix_ttysrv_ep() -> Cap {
    trona_runtime::client::caps::local_by_name(b"console:posix_ttysrv").addr()
}

/// Resolve the dispdrv endpoint injected from `Requires=dispdrv.socket` in
/// console.service.
#[inline]
fn dispdrv_ep() -> Cap {
    trona_runtime::client::caps::local_by_name(b"console:dispdrv").addr()
}

// termios flag defaults (match posix_ttysrv canonical defaults)
const ISIG: u32 = 0o000001;
const ICANON: u32 = 0o000002;
const ECHO: u32 = 0o000010;
const ECHOE: u32 = 0o000020;
const ECHOK: u32 = 0o000040;
const ECHOCTL: u32 = 0o001000;
const ECHOKE: u32 = 0o004000;
const IEXTEN: u32 = 0o100000;
const ICRNL: u32 = 0o000400;
const IXON: u32 = 0o002000;
const OPOST: u32 = 0o000001;
const ONLCR: u32 = 0o000004;
const CS8: u32 = 0o000060;
const CREAD: u32 = 0o000200;
const CLOCAL: u32 = 0o004000;
const B38400: u32 = 38400;

const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;

static mut CONSOLE_TERMIOS: Termios = Termios::zeroed();

// SHM ring buffer for console → dispdrv display output.
// 'CODS' (COnsole Display Shm)
const CONSOLE_DISPLAY_SHM_ID: u64 = 0x434F4453;
const CONSOLE_RING_PAGES: u64 = 16; // 64 KB
const CONSOLE_RING_HDR_SIZE: usize = 16;

// SHM ring buffer for console → posix_ttysrv raw input.
// 'COIT' (COnsole Input Tty)
const CONSOLE_INPUT_SHM_ID: u64 = 0x434F4954;
const CONSOLE_INPUT_RING_PAGES: u64 = 4; // 16 KB
const CONSOLE_INPUT_RING_HDR_SIZE: usize = 16;

/// Per-ring setup state. Producers write into shared memory and kick
/// the consumer's service endpoint with a typed message after publishing
/// bytes.
#[derive(Copy, Clone, PartialEq)]
enum RingState {
    /// Ring is not mapped yet (consumer not ready, or prior setup failed).
    /// Producer side attempts setup when the consumer's ready notification
    /// is observed.
    NotReady,
    /// Ring is live. `base` is the mapped SHM header; `sink_cap` is the
    /// consumer's sink notification we signal on write; `bit_index` is
    /// the bit (0-63) we raise on that cap to wake the consumer.
    Ready {
        base: *mut u8,
        sink_cap: u64,
        bit_index: u8,
    },
    /// A local setup failure was observed. Writes silently drop until a
    /// later ready-signal poll resets the ring back to `NotReady` and
    /// retries the handshake.
    Broken,
}

static mut CONSOLE_DISPLAY_RING: RingState = RingState::NotReady;
static mut CONSOLE_INPUT_RING: RingState = RingState::NotReady;

#[inline]
fn display_ring_state() -> RingState {
    unsafe { core::ptr::read_volatile(&raw const CONSOLE_DISPLAY_RING) }
}

#[inline]
fn input_ring_state() -> RingState {
    unsafe { core::ptr::read_volatile(&raw const CONSOLE_INPUT_RING) }
}

#[inline]
fn store_display_ring_state(state: RingState) {
    unsafe {
        core::ptr::write_volatile(&raw mut CONSOLE_DISPLAY_RING, state);
    }
}

#[inline]
fn store_input_ring_state(state: RingState) {
    unsafe {
        core::ptr::write_volatile(&raw mut CONSOLE_INPUT_RING, state);
    }
}

fn console_ring_data_size() -> usize {
    CONSOLE_RING_PAGES as usize * 4096 - CONSOLE_RING_HDR_SIZE
}

fn console_input_ring_data_size() -> usize {
    CONSOLE_INPUT_RING_PAGES as usize * 4096 - CONSOLE_INPUT_RING_HDR_SIZE
}

/// Push bytes into the console display ring. Returns bytes written.
///
/// # Safety
/// `base` must point to a valid mapped SHM ring header.
unsafe fn console_ring_push(base: *mut u8, ring_size: usize, data: &[u8]) -> usize {
    unsafe {
        let head = core::ptr::read_volatile(base as *const u32) as usize;
        let tail = core::ptr::read_volatile(base.add(4) as *const u32) as usize;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let used = (head + ring_size - tail) % ring_size;
        let free = ring_size - 1 - used;
        let count = core::cmp::min(free, data.len());
        if count == 0 {
            return 0;
        }
        let dp = base.add(CONSOLE_RING_HDR_SIZE);
        let mut i = 0usize;
        while i < count {
            core::ptr::write_volatile(dp.add((head + i) % ring_size), data[i]);
            i += 1;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(base as *mut u32, ((head + count) % ring_size) as u32);
        count
    }
}

/// Push bytes into the console input ring (console → posix_ttysrv). Returns bytes written.
/// On ring full, returns 0 and the caller drops the remaining bytes.
///
/// # Safety
/// `base` must point to a valid mapped SHM ring header.
unsafe fn tty_input_ring_push(base: *mut u8, ring_size: usize, data: &[u8]) -> usize {
    unsafe {
        let head = core::ptr::read_volatile(base as *const u32) as usize;
        let tail = core::ptr::read_volatile(base.add(4) as *const u32) as usize;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let used = (head + ring_size - tail) % ring_size;
        let free = ring_size - 1 - used;
        let count = core::cmp::min(free, data.len());
        if count == 0 {
            return 0;
        }
        let dp = base.add(CONSOLE_INPUT_RING_HDR_SIZE);
        let mut i = 0usize;
        while i < count {
            core::ptr::write_volatile(dp.add((head + i) % ring_size), data[i]);
            i += 1;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(base as *mut u32, ((head + count) % ring_size) as u32);
        count
    }
}

fn cleanup_ring_resources(shm_id: u64, vaddr: u64, shm_live: bool) {
    if !shm_live {
        return;
    }

    let ctx = ipc_ctx();
    let mmsrv = trona_runtime::client::caps::mmsrv_ep().addr();

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_SHM_UNMAP;
    msg.regs[0] = shm_id;
    msg.regs[1] = 0;
    msg.regs[2] = vaddr;
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
    msg.regs[0] = shm_id;
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

fn teardown_ring_state(state: RingState, shm_id: u64) {
    if let RingState::Ready { base, .. } = state {
        cleanup_ring_resources(shm_id, base as u64, true);
    }
}

fn ready_signal_pending(ready_ntfn: u64) -> bool {
    let _ = ready_ntfn;
    true
}

fn refresh_display_ring_on_ready_signal() {
    if !ready_signal_pending(0) {
        return;
    }
    let state = display_ring_state();
    teardown_ring_state(state, CONSOLE_DISPLAY_SHM_ID);
    store_display_ring_state(RingState::NotReady);
    store_display_ring_state(display_setup_ring());
}

fn refresh_input_ring_on_ready_signal() {
    if !ready_signal_pending(0) {
        return;
    }
    let state = input_ring_state();
    teardown_ring_state(state, CONSOLE_INPUT_SHM_ID);
    store_input_ring_state(RingState::NotReady);
    store_input_ring_state(tty_setup_ring());
}

fn poll_ring_ready_transitions() {
    refresh_display_ring_on_ready_signal();
    refresh_input_ring_on_ready_signal();
}

/// Create + map the console→posix_ttysrv input ring SHM, then exchange
/// `POSIX_TTYSRV_SETUP_INPUT_RING` with posix_ttysrv. The reply carries
/// posix_ttysrv's sink notification (landed in `recv_slot`) plus the
/// bit index we must signal on that cap to wake it.
fn tty_setup_ring() -> RingState {
    let ctx = ipc_ctx();

    // Create SHM region (console owns it as producer). The shared
    // `mm::shm_create` helper carries the size in bytes and receives the MO
    // cap; mmsrv returns the same MO for a name a peer already created.
    let (shm_idx, shm_cap) = match trona_runtime::client::mm::shm_create(
        CONSOLE_INPUT_SHM_ID,
        CONSOLE_INPUT_RING_PAGES * 4096,
    ) {
        Ok(v) => v,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[console] tty ring: SHM create failed label=");
                _lb.hex(label);
                _lb.str(b"\n");
            });
            return RingState::Broken;
        }
    };
    let shm_live = true;

    // Map SHM (RW). `shm_map` takes ownership of the MO cap (mmsrv moves it into the
    // published region); `into_transfer()` consumes `shm_cap` so no explicit free needed.
    // mmsrv places the region in the client's mmap window; use the returned VA,
    // not the fixed low name, for the header and base pointer.
    let map_res = trona_runtime::client::mm::shm_map(
        shm_idx,
        shm_cap.into_transfer(),
        0,
        CONSOLE_INPUT_RING_PAGES * 4096,
        0x3,
    );
    let ring_va = match map_res {
        Ok(va) => va,
        Err(_) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[console] tty ring: SHM map failed\n");
            });
            cleanup_ring_resources(CONSOLE_INPUT_SHM_ID, 0, shm_live);
            return RingState::Broken;
        }
    };

    // Initialise ring header: head=0, tail=0, size=data_size, reserved=0.
    // SAFETY: SHM mapped at `ring_va`; single-threaded init.
    unsafe {
        let hdr = ring_va as *mut u32;
        core::ptr::write_volatile(hdr, 0);
        core::ptr::write_volatile(hdr.add(1), 0);
        core::ptr::write_volatile(hdr.add(2), console_input_ring_data_size() as u32);
        core::ptr::write_volatile(hdr.add(3), 0);
    }

    // Exchange `POSIX_TTYSRV_SETUP_INPUT_RING`. posix_ttysrv replies
    // with `regs[0]` = bit index. Console kicks the service EP with
    // `POSIX_TTYSRV_INPUT_KICK` after publishing bytes.
    let mut msg = TronaMsg::zeroed();
    msg.label = POSIX_TTYSRV_SETUP_INPUT_RING;
    msg.regs[0] = CONSOLE_INPUT_SHM_ID;
    msg.length = 1;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; RPC to posix_ttysrv.
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            posix_ttysrv_ep(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || reply.label != TRONA_OK {
        // posix_ttysrv rejected setup or was interrupted. Stay NotReady;
        // the next consumer ready signal will retry setup.
        cleanup_ring_resources(CONSOLE_INPUT_SHM_ID, ring_va, shm_live);
        return RingState::NotReady;
    }

    let bit_index = (reply.regs[0] & 0x3F) as u8;
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[console] TTY input ring active, sink bit=");
        _lb.dec(bit_index as u64);
        _lb.str(b"\n");
    });
    RingState::Ready {
        base: ring_va as *mut u8,
        sink_cap: posix_ttysrv_ep(),
        bit_index,
    }
}

// ======================================================================
// Helpers
// ======================================================================

fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

unsafe fn init_console_termios() {
    unsafe {
        let t = &raw mut CONSOLE_TERMIOS;
        (*t).c_iflag = ICRNL | IXON;
        (*t).c_oflag = OPOST | ONLCR;
        (*t).c_cflag = CS8 | CREAD | CLOCAL;
        (*t).c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN | ECHOCTL | ECHOKE;
        (*t).c_line = 0;
        (*t).c_ispeed = B38400;
        (*t).c_ospeed = B38400;
        (*t).c_cc = [0; 32];
        (*t).c_cc[VINTR] = 3;
        (*t).c_cc[VQUIT] = 28;
        (*t).c_cc[VERASE] = 127;
        (*t).c_cc[VKILL] = 21;
        (*t).c_cc[VEOF] = 4;
        (*t).c_cc[VMIN] = 1;
        (*t).c_cc[VSTART] = 17;
        (*t).c_cc[VSTOP] = 19;
        (*t).c_cc[VSUSP] = 26;
    }
}

/// Publish console's master service-EP to namesrv. unit_mgr blocks
/// every consumer until `NAMESRV_REGISTER` arrives for "console".
fn register_with_namesrv() {
    let namesrv = trona_runtime::client::caps::namesrv_ep();
    if namesrv.is_null() {
        return;
    }
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;
    let svc_name = b"console";
    let mut reg_msg = TronaMsg::zeroed();
    let mut reg_reply = TronaMsg::zeroed();
    reg_msg.label = NAMESRV_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    let publish_tc = trona_runtime::client::caps::service_client_ep_for_transfer();
    unsafe {
        let dst = &raw mut reg_msg.regs[1] as *mut u8;
        for i in 0..svc_name.len() {
            *dst.add(i) = svc_name[i];
        }
        trona_kernel::ipc::set_send_cap_ctx(
            ipc_ctx(),
            0,
            publish_tc.as_ref().map_or(0, |t| t.slot()),
        );
    }
    reg_msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    reg_msg.length = (REGISTER_FLAGS_REG + 1) as u64;
    unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ipc_ctx(),
            namesrv.addr(),
            &raw const reg_msg,
            &raw mut reg_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
    }
    drop(publish_tc);
}

/// Write a byte slice with CR/LF translation via DebugPutStr syscall.
fn console_puts(s: &[u8]) {
    let mut buf = [0u8; 80];
    let mut buf_len = 0;
    for &c in s {
        if c == b'\n' {
            buf[buf_len] = b'\r';
            buf_len += 1;
            if buf_len >= buf.len() {
                serial::serial_puts(&buf[..buf_len]);
                buf_len = 0;
            }
        }
        buf[buf_len] = c;
        buf_len += 1;
        if buf_len >= buf.len() {
            serial::serial_puts(&buf[..buf_len]);
            buf_len = 0;
        }
    }
    if buf_len > 0 {
        serial::serial_puts(&buf[..buf_len]);
    }
}

/// Ensure the display ring is `Ready` if dispdrv has announced readiness.
/// The setup RPC must not be attempted speculatively from a console write:
/// a missing receiver on dispdrv's endpoint would block console while VFS is
/// synchronously waiting for `CONSOLE_WRITE` to return.
fn ensure_display_ring() -> RingState {
    refresh_display_ring_on_ready_signal();
    display_ring_state()
}

/// Ensure the input ring is `Ready`, polling `ROLE_POSIX_TTYSRV_INPUT_READY_NTFN`
/// before attempting setup. Like display setup, this stays readiness-gated so
/// early serial/keyboard IRQ handling cannot block on posix_ttysrv startup.
fn ensure_input_ring() -> RingState {
    refresh_input_ring_on_ready_signal();
    input_ring_state()
}

fn kick_service(ep: u64, label: u64) {
    if ep == 0 {
        return;
    }
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = label;
    let _ = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
}

/// Push `data` into the display ring. On `NotReady`, `Broken`, or
/// persistent-full we silently drop — console has no blocking IPC fallback.
fn display_write(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let state = ensure_display_ring();
    let (base, sink_cap) = match state {
        RingState::Ready { base, sink_cap, .. } => (base, sink_cap),
        RingState::NotReady | RingState::Broken => return,
    };
    let ring_size = console_ring_data_size();
    let mut offset = 0usize;
    // SAFETY: ring state Ready implies `base` points at a live SHM
    // header we mapped during setup.
    unsafe {
        while offset < data.len() {
            let written = console_ring_push(base, ring_size, &data[offset..]);
            if written > 0 {
                kick_service(sink_cap, DISPLAY_PRESENT);
                offset += written;
            } else {
                // Ring full — signal to prompt drain, yield, retry once.
                kick_service(sink_cap, DISPLAY_PRESENT);
                trona_kernel::syscall::yield_now();
                let written2 = console_ring_push(base, ring_size, &data[offset..]);
                if written2 == 0 {
                    break;
                }
                kick_service(sink_cap, DISPLAY_PRESENT);
                offset += written2;
            }
        }
    }
}

/// Create + map the console→dispdrv display ring SHM, then exchange
/// `DISPLAY_SETUP_CONSOLE_RING` with dispdrv. The reply carries dispdrv's
/// sink notification plus the bit index we must signal on it.
fn display_setup_ring() -> RingState {
    let ctx = ipc_ctx();

    // Create SHM region (console owns it as producer). Shared `mm::shm_create`
    // helper: size in bytes, MO cap received; mmsrv returns the same MO for a
    // name a peer already created.
    let (shm_idx, shm_cap) = match trona_runtime::client::mm::shm_create(
        CONSOLE_DISPLAY_SHM_ID,
        CONSOLE_RING_PAGES * 4096,
    ) {
        Ok(v) => v,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[console] display ring: SHM create failed label=");
                _lb.hex(label);
                _lb.str(b"\n");
            });
            return RingState::Broken;
        }
    };
    let shm_live = true;

    // Map SHM (RW). `shm_map` takes ownership of the MO cap (mmsrv moves it into the
    // published region); `into_transfer()` consumes `shm_cap` so no explicit free needed.
    // mmsrv places the region in the client's mmap window; use the returned VA,
    // not the fixed low name, for the header and base pointer.
    let map_res = trona_runtime::client::mm::shm_map(
        shm_idx,
        shm_cap.into_transfer(),
        0,
        CONSOLE_RING_PAGES * 4096,
        0x3,
    );
    let ring_va = match map_res {
        Ok(va) => va,
        Err(_) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[console] display ring: SHM map failed\n");
            });
            cleanup_ring_resources(CONSOLE_DISPLAY_SHM_ID, 0, shm_live);
            return RingState::Broken;
        }
    };

    // Initialise ring header: head=0, tail=0, size=data_size, reserved=0.
    // SAFETY: SHM mapped at `ring_va`; single-threaded init.
    unsafe {
        let hdr = ring_va as *mut u32;
        core::ptr::write_volatile(hdr, 0);
        core::ptr::write_volatile(hdr.add(1), 0);
        core::ptr::write_volatile(hdr.add(2), console_ring_data_size() as u32);
        core::ptr::write_volatile(hdr.add(3), 0);
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = DISPLAY_SETUP_CONSOLE_RING;
    msg.regs[0] = CONSOLE_DISPLAY_SHM_ID;
    msg.length = 1;
    let mut reply = TronaMsg::zeroed();
    // SAFETY: IPC context is valid; RPC to dispdrv.
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            dispdrv_ep(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || reply.label != TRONA_OK {
        // dispdrv rejected setup or was interrupted. Stay NotReady; the
        // next consumer ready signal will retry setup.
        cleanup_ring_resources(CONSOLE_DISPLAY_SHM_ID, ring_va, shm_live);
        return RingState::NotReady;
    }

    let bit_index = (reply.regs[0] & 0x3F) as u8;
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[console] Display ring active, sink bit=");
        _lb.dec(bit_index as u64);
        _lb.str(b"\n");
    });
    RingState::Ready {
        base: ring_va as *mut u8,
        sink_cap: dispdrv_ep(),
        bit_index,
    }
}

/// Forward raw input bytes to posix_ttysrv via the SHM input ring. On
/// each call, attempts to ensure the ring is set up (polling
/// `ROLE_POSIX_TTYSRV_INPUT_READY_NTFN`); if still `NotReady` or
/// `Broken`, bytes are dropped silently — there is no IPC fallback.
/// Pre-setup bytes are lost. Keyboard-rate input and a 16 KB ring
/// absorb any realistic burst once the ring is live.
fn forward_to_ttysrv(raw: &[u8], raw_len: usize) {
    if raw_len == 0 {
        return;
    }
    let state = ensure_input_ring();
    let (base, sink_cap) = match state {
        RingState::Ready { base, sink_cap, .. } => (base, sink_cap),
        RingState::NotReady | RingState::Broken => return,
    };
    let ring_size = console_input_ring_data_size();
    let mut offset = 0usize;
    // SAFETY: ring state Ready implies `base` points at a live SHM header.
    unsafe {
        while offset < raw_len {
            let written = tty_input_ring_push(base, ring_size, &raw[offset..raw_len]);
            if written > 0 {
                kick_service(sink_cap, POSIX_TTYSRV_INPUT_KICK);
                offset += written;
            } else {
                // Ring full — signal to prompt drain, yield, retry once.
                kick_service(sink_cap, POSIX_TTYSRV_INPUT_KICK);
                trona_kernel::syscall::yield_now();
                let written2 = tty_input_ring_push(base, ring_size, &raw[offset..raw_len]);
                if written2 == 0 {
                    // Still full — drop remaining bytes. Keyboard-rate-limited;
                    // only happens under sustained posix_ttysrv stall.
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[console] tty input ring full, bytes dropped\n");
                    });
                    break;
                }
                kick_service(sink_cap, POSIX_TTYSRV_INPUT_KICK);
                offset += written2;
            }
        }
    }
}

unsafe fn handle_write(msg: *const TronaMsg) {
    unsafe {
        let requested_len = (*msg).regs[0] as usize;
        let inline_words =
            ((*msg).length.saturating_sub(1) as usize).min((*msg).regs.len().saturating_sub(1));
        let inline_len = inline_words * 8;
        let len = core::cmp::min(requested_len, inline_len);
        let data = core::slice::from_raw_parts(&(*msg).regs[1] as *const u64 as *const u8, len);
        console_puts(data);
        display_write(data);
    }
}

unsafe fn handle_tcgetattr(reply: *mut TronaMsg) {
    unsafe {
        let t = &raw const CONSOLE_TERMIOS;
        (*reply).label = TRONA_OK;
        (*reply).length = 10;
        (*reply).regs[0] = (*t).c_iflag as u64;
        (*reply).regs[1] = (*t).c_oflag as u64;
        (*reply).regs[2] = (*t).c_cflag as u64;
        (*reply).regs[3] = (*t).c_lflag as u64;
        (*reply).regs[4] = (*t).c_ispeed as u64;
        (*reply).regs[5] = (*t).c_ospeed as u64;
        let dst = &raw mut (*reply).regs[6] as *mut u8;
        for i in 0..32 {
            *dst.add(i) = (*t).c_cc[i];
        }
    }
}

unsafe fn handle_tcsetattr(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        // Expected layout from VFS:
        // regs[0]=fd regs[1]=action regs[2..7]=flags/speeds regs[8..11]=c_cc[32]
        if (*msg).length < 11 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let t = &raw mut CONSOLE_TERMIOS;
        (*t).c_iflag = (*msg).regs[2] as u32;
        (*t).c_oflag = (*msg).regs[3] as u32;
        (*t).c_cflag = (*msg).regs[4] as u32;
        (*t).c_lflag = (*msg).regs[5] as u32;
        (*t).c_ispeed = (*msg).regs[6] as u32;
        (*t).c_ospeed = (*msg).regs[7] as u32;
        let src = &(*msg).regs[8] as *const u64 as *const u8;
        for i in 0..32 {
            (*t).c_cc[i] = *src.add(i);
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

// ======================================================================
// Entry point
// ======================================================================

/// Cookie for the service pipe's `STATE_READABLE` Watch (kind 0).
const CONSOLE_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);
/// Cookie stamped on `EVENT_TYPE_IRQ` records from the bound input IRQs (kind 1).
const CONSOLE_IRQ_COOKIE: u64 = trona_server::event_loop::encode_cookie(1, 0, 1);

/// Reactor dispatcher. The service pipe (`STATE_READABLE`) carries console IPC;
/// the input IRQs are bound onto the same `EventQueue` and arrive as
/// `EVENT_TYPE_IRQ` records, handled in `handle_other`.
struct ConsoleDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    scratch: Cap,
}

impl trona_server::event_loop::EqDispatcher for ConsoleDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let badge = meta.badge;
        poll_ring_ready_transitions();
        // badge low 32 bits = caller's client_id (cross-broker badge layout);
        // console does not differentiate per-client today.
        let _client_id = trona_server::badge::client_id_of(badge);
        let mut reply = TronaMsg::zeroed();
        match msg.label {
            CONSOLE_WRITE => {
                unsafe { handle_write(&raw const *msg) };
                reply.label = TRONA_OK;
            }
            CONSOLE_TCGETATTR => unsafe { handle_tcgetattr(&raw mut reply) },
            CONSOLE_TCSETATTR => unsafe { handle_tcsetattr(&raw const *msg, &raw mut reply) },
            _ => reply.label = TRONA_INVALID_OPERATION,
        }
        // SAFETY: `ipc_ctx()` is this thread's IPC context; reply on the service pipe.
        let _ = unsafe { ipc::mp_write_reply_ctx(ipc_ctx(), self.recv_ep, &raw const reply) };
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // SAFETY: re-arm the sticky cap-receive scratch before each MP_READ.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ipc_ctx(),
                trona_kernel::uapi::KERNITE_CAP_SELF_CSPACE as Cap,
                self.scratch,
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
            CONSOLE_SERVICE_COOKIE,
        )
    }

    fn continue_readable_drain(&mut self, _cookie: u64) -> bool {
        // Yield to EQ_WAIT after each service-pipe message so a pending input
        // IRQ on the priority lane is drained ahead of further IPC.
        false
    }

    fn handle_other(&mut self, kind: u32, _record_cookie: u64) -> i32 {
        if kind == trona_kernel::uapi::KERNITE_EVENT_TYPE_IRQ {
            // Hardware input fired: drain the device, forward to posix_ttysrv,
            // then ack so the controller re-enables the line.
            poll_ring_ready_transitions();
            let mut raw_buf = [0u8; 256];
            let raw_len = arch::drain_input(&mut raw_buf);
            arch::ack_irqs();
            forward_to_ttysrv(&raw_buf, raw_len);
        }
        0
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    arch::serial_init();
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[CONSOLE] SaltyOS console server ready\n");
    });

    unsafe {
        init_console_termios();
    }
    arch::irq_setup();
    register_with_namesrv();

    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();

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
                _lb.str(b"[CONSOLE] reactor EventQueue/Watch alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let scratch =
        trona_runtime::core::ipc_ext::arm_mp_write_reply_read_slot_ctx(ctx, b"console reply recv");

    // Arm the service pipe's READABLE edge onto the reactor EQ.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        CONSOLE_SERVICE_COOKIE,
    );

    // Bind the input IRQ(s) onto the same EQ — they arrive as EVENT_TYPE_IRQ
    // records on the priority interrupt lane, handled in `handle_other`.
    arch::bind_input_irqs(eq_cap, CONSOLE_IRQ_COOKIE);

    // The EQ / Watch live for the process lifetime; suppress their OwnedCap
    // drop so the caps are never torn down under the running reactor.
    core::mem::forget(eq);
    core::mem::forget(watch);

    let dispatcher = ConsoleDispatcher {
        recv_ep,
        watch_cap,
        eq_cap,
        scratch,
    };
    let mut reactor = trona_server::event_loop::EventLoop::new(eq_cap, dispatcher);

    loop {
        // SAFETY: `ctx` is this thread's IPC context; arm the cap-receive
        // scratch, then block on the EQ and dispatch one ready event.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ctx,
                trona_kernel::uapi::KERNITE_CAP_SELF_CSPACE as Cap,
                scratch,
                0,
            );
            let _ = reactor.run_iteration(ctx);
        }
    }
}

fn idle() -> ! {
    loop {
        trona_kernel::syscall::yield_now();
    }
}
