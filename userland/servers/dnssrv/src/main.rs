// SPDX-License-Identifier: GPL-2.0-only
//! SaltyOS DNS Resolver Service (dnssrv)
//!
//! Caching DNS resolver that sits between client applications and netsrv.
//! Clients send DNS_RESOLVE requests; dnssrv checks its cache first, then
//! forwards cache misses to netsrv via NET_DNS_RESOLVE / NET_DNS_RESOLVE_PTR.
//!
//! Startup caps are role-based. System caps come from `trona_runtime::client::caps::*()`;
//! the service-local `netsrv_ep` dependency is resolved through the
//! `trona_runtime::local_cap!` macro declared below.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::common::{
    TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_NOT_FOUND, TRONA_OK,
};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::netsrv::{NET_DNS_RESOLVE, NET_DNS_RESOLVE_PTR};
use trona_protocol::posix::{DNS_CACHE_FLUSH, DNS_RESOLVE, DNS_REVERSE_LOOKUP};
use trona_runtime::debug::serial;

// Service-local cap: `Require=netsrv-ep.socket` in `dnssrv.service`.
trona_runtime::local_cap!(pub(crate) netsrv_ep = "dnssrv:netsrv_ep");

// System roles (`namesrv`, `mmsrv`) via substrate `trona_runtime::client::caps::*` getters;
// the service-local `Require=netsrv-ep.socket` dependency is resolved
// through the `trona_runtime::local_cap!` macro above (`netsrv_ep`).

// ---------------------------------------------------------------------------
// DNS cache
// ---------------------------------------------------------------------------

const DNS_CACHE_SIZE: usize = 32;
const MAX_HOSTNAME_LEN: usize = 128;
const MAX_CACHED_IPS: usize = 4;

struct DnsCacheEntry {
    active: bool,
    hostname: [u8; MAX_HOSTNAME_LEN],
    hostname_len: u8,
    ips: [u32; MAX_CACHED_IPS],
    ip_count: u8,
    ttl_secs: u32,
    cached_at_ns: u64,
}

impl DnsCacheEntry {
    const fn zeroed() -> Self {
        DnsCacheEntry {
            active: false,
            hostname: [0u8; MAX_HOSTNAME_LEN],
            hostname_len: 0,
            ips: [0u32; MAX_CACHED_IPS],
            ip_count: 0,
            ttl_secs: 0,
            cached_at_ns: 0,
        }
    }
}

static mut DNS_CACHE: [DnsCacheEntry; DNS_CACHE_SIZE] = {
    const ZERO: DnsCacheEntry = DnsCacheEntry::zeroed();
    [
        ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
        ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
        ZERO, ZERO,
    ]
};

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn clock_monotonic_ns() -> u64 {
    trona_kernel::syscall::clock_read_monotonic(trona_runtime::client::caps::clock_cap().addr())
}

fn hostname_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        let ca = if a[i] >= b'A' && a[i] <= b'Z' {
            a[i] + 32
        } else {
            a[i]
        };
        let cb = if b[i] >= b'A' && b[i] <= b'Z' {
            b[i] + 32
        } else {
            b[i]
        };
        if ca != cb {
            return false;
        }
        i += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// Cache operations
// ---------------------------------------------------------------------------

fn cache_lookup(hostname: &[u8]) -> Option<(u8, [u32; MAX_CACHED_IPS])> {
    let now_ns = clock_monotonic_ns();

    // SAFETY: Single-threaded server; reading cache entries.
    unsafe {
        let cache = &raw const DNS_CACHE;
        let mut i = 0;
        while i < DNS_CACHE_SIZE {
            let entry = &(*cache)[i];
            if entry.active && entry.hostname_len as usize == hostname.len() {
                if hostname_eq(&entry.hostname[..entry.hostname_len as usize], hostname) {
                    let ttl_ns = (entry.ttl_secs as u64).saturating_mul(1_000_000_000);
                    let expiry_ns = entry.cached_at_ns.saturating_add(ttl_ns);
                    if now_ns < expiry_ns {
                        // Update timestamp for LRU eviction
                        let cache_mut = &raw mut DNS_CACHE;
                        (*cache_mut)[i].cached_at_ns = now_ns;
                        return Some((entry.ip_count, entry.ips));
                    }
                    // Expired: mark inactive
                    let cache_mut = &raw mut DNS_CACHE;
                    (*cache_mut)[i].active = false;
                    return None;
                }
            }
            i += 1;
        }
    }
    None
}

fn cache_insert(hostname: &[u8], ips: &[u32], ip_count: u8, ttl: u32) {
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LEN {
        return;
    }

    let now_ns = clock_monotonic_ns();

    // SAFETY: Single-threaded server; mutating cache entries.
    unsafe {
        let cache = &raw mut DNS_CACHE;

        let mut target_idx = 0usize;
        let mut oldest_ns = u64::MAX;

        let mut i = 0;
        while i < DNS_CACHE_SIZE {
            if !(*cache)[i].active {
                target_idx = i;
                break;
            }
            if (*cache)[i].cached_at_ns < oldest_ns {
                oldest_ns = (*cache)[i].cached_at_ns;
                target_idx = i;
            }
            i += 1;
        }

        let entry = &mut (*cache)[target_idx];
        entry.active = true;
        entry.hostname_len = hostname.len() as u8;
        let mut j = 0;
        while j < hostname.len() {
            entry.hostname[j] = hostname[j];
            j += 1;
        }
        entry.ip_count = core::cmp::min(ip_count, MAX_CACHED_IPS as u8);
        let mut k = 0;
        while k < entry.ip_count as usize {
            entry.ips[k] = ips[k];
            k += 1;
        }
        entry.ttl_secs = if ttl == 0 { 60 } else { ttl };
        entry.cached_at_ns = now_ns;
    }
}

fn cache_flush() {
    // SAFETY: Single-threaded server; clearing all cache entries.
    unsafe {
        let cache = &raw mut DNS_CACHE;
        let mut i = 0;
        while i < DNS_CACHE_SIZE {
            (*cache)[i].active = false;
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Name service registration
// ---------------------------------------------------------------------------

fn register_namesrv() {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"dnssrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let publish_tc = trona_runtime::client::caps::service_client_ep_for_transfer();
    // SAFETY: Writing name bytes into message register space; IPC context valid.
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
            puts(b"[dnssrv] namesrv registration failed\n");
        } else {
            puts(b"[dnssrv] Registered with namesrv\n");
        }
    }
}

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

fn handle_resolve(msg: &TronaMsg, reply: &mut TronaMsg) {
    let hostname_len = msg.regs[0] as usize;
    if hostname_len == 0 || hostname_len > 120 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return;
    }

    let mut hostname = [0u8; 120];
    // SAFETY: Reading hostname bytes from IPC message register area.
    unsafe {
        let src = &msg.regs[1] as *const u64 as *const u8;
        core::ptr::copy_nonoverlapping(src, hostname.as_mut_ptr(), hostname_len);
    }

    // 1. Check cache
    if let Some((ip_count, ips)) = cache_lookup(&hostname[..hostname_len]) {
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[dnssrv] cache hit host_len=");
            _lb.dec(hostname_len as u64);
            _lb.str(b" count=");
            _lb.dec(ip_count as u64);
            _lb.putc(b'\n');
        });
        reply.label = TRONA_OK;
        reply.regs[0] = ip_count as u64;
        reply.regs[1] = 0;
        let mut i = 0;
        while i < ip_count as usize && i < MAX_CACHED_IPS {
            reply.regs[2 + i] = ips[i] as u64;
            i += 1;
        }
        reply.length = 2 + ip_count as u64;
        return;
    }

    // 2. Cache miss: forward to netsrv
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[dnssrv] resolve miss host_len=");
        _lb.dec(hostname_len as u64);
        _lb.putc(b'\n');
    });
    let mut netsrv_msg = TronaMsg::zeroed();
    netsrv_msg.label = NET_DNS_RESOLVE;
    netsrv_msg.regs[0] = hostname_len as u64;
    // SAFETY: Writing hostname bytes into message register area for netsrv.
    unsafe {
        let dst = &raw mut netsrv_msg.regs[1] as *mut u8;
        core::ptr::copy_nonoverlapping(hostname.as_ptr(), dst, hostname_len);
    }
    netsrv_msg.length = 1 + ((hostname_len as u64 + 7) / 8);

    let mut netsrv_reply = TronaMsg::zeroed();
    // SAFETY: IPC context valid; CAP_NETSRV_EP is the netsrv endpoint.
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            netsrv_ep().addr(),
            &raw const netsrv_msg,
            &raw mut netsrv_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[dnssrv] netsrv reply err=");
        _lb.dec(err as u64);
        _lb.str(b" label=");
        _lb.dec(netsrv_reply.label);
        _lb.putc(b'\n');
    });
    if err != 0 || netsrv_reply.label != TRONA_OK {
        reply.label = if netsrv_reply.label != 0 {
            netsrv_reply.label
        } else {
            TRONA_NOT_FOUND
        };
        return;
    }

    // 3. Extract results and cache
    let ip_count = netsrv_reply.regs[0] as u8;
    let ttl = netsrv_reply.regs[1] as u32;
    let mut ips = [0u32; 4];
    let count = core::cmp::min(ip_count as usize, 4);
    let mut i = 0;
    while i < count {
        ips[i] = netsrv_reply.regs[2 + i] as u32;
        i += 1;
    }
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[dnssrv] resolve done count=");
        _lb.dec(ip_count as u64);
        _lb.str(b" ttl=");
        _lb.dec(ttl as u64);
        _lb.putc(b'\n');
    });
    cache_insert(&hostname[..hostname_len], &ips, ip_count, ttl);

    // 4. Return to client
    reply.label = TRONA_OK;
    reply.regs[0] = ip_count as u64;
    reply.regs[1] = ttl as u64;
    i = 0;
    while i < count {
        reply.regs[2 + i] = ips[i] as u64;
        i += 1;
    }
    reply.length = 2 + ip_count as u64;
}

fn handle_cache_flush(reply: &mut TronaMsg) {
    cache_flush();
    puts(b"[dnssrv] Cache flushed\n");
    reply.label = TRONA_OK;
}

fn handle_reverse(msg: &TronaMsg, reply: &mut TronaMsg) {
    let ip = msg.regs[0] as u32;

    // Forward to netsrv via NET_DNS_RESOLVE_PTR
    let mut netsrv_msg = TronaMsg::zeroed();
    netsrv_msg.label = NET_DNS_RESOLVE_PTR;
    netsrv_msg.regs[0] = ip as u64;
    netsrv_msg.length = 1;

    let mut netsrv_reply = TronaMsg::zeroed();
    // SAFETY: IPC context valid; CAP_NETSRV_EP is the netsrv endpoint.
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            netsrv_ep().addr(),
            &raw const netsrv_msg,
            &raw mut netsrv_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || netsrv_reply.label != TRONA_OK {
        reply.label = if netsrv_reply.label != 0 {
            netsrv_reply.label
        } else {
            TRONA_NOT_FOUND
        };
        return;
    }

    // Forward the PTR result back to the client
    let hostname_len = netsrv_reply.regs[0] as usize;
    reply.label = TRONA_OK;
    if hostname_len > 0 {
        let copy_len = core::cmp::min(hostname_len, 152);
        reply.regs[0] = copy_len as u64;
        // SAFETY: Copying hostname bytes from netsrv reply to client reply.
        unsafe {
            let src = &netsrv_reply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut reply.regs[1] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, copy_len);
        }
        reply.length = 1 + ((copy_len as u64 + 7) / 8);
    } else {
        reply.length = 1;
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Cookie for the single service-pipe `STATE_READABLE` Watch (kind 0, slot 0,
/// generation 1). dnssrv has one event source, so the cookie is constant.
const DNSSRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Single-source reactor dispatcher: routes the one armed event by DNS label
/// and replies on the same service pipe (txid-correlated). Cache misses call
/// netsrv synchronously inside the handler — fine on the single reactor thread.
struct DnssrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    scratch: Cap,
}

impl trona_server::event_loop::EqDispatcher for DnssrvDispatcher {
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
            DNS_RESOLVE => handle_resolve(msg, &mut reply),
            DNS_CACHE_FLUSH => handle_cache_flush(&mut reply),
            DNS_REVERSE_LOOKUP => handle_reverse(msg, &mut reply),
            _ => reply.label = TRONA_INVALID_OPERATION,
        }
        // SAFETY: `ipc_ctx()` is this thread's IPC context; the reply rides the
        // service pipe correlated to the just-read request's txid.
        let _ = unsafe { ipc::mp_write_reply_ctx(ipc_ctx(), self.recv_ep, &raw const reply) };
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // SAFETY: re-arm the sticky cap-receive scratch before each MP_READ.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ipc_ctx(),
                trona_kernel::uapi::KERNITE_CAP_SELF_CSPACE as u64,
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
            DNSSRV_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    puts(b"[dnssrv] DNS Resolver Service starting\n");

    // Register with name service; unit_mgr observes the publish event as readiness.
    register_namesrv();

    puts(b"[dnssrv] Entering event loop\n");

    // Single-source EventLoop reactor: block on a self-allocated EventQueue
    // (rsrcsrv-minted) with a Watch on the service pipe's READABLE edge, then
    // drain + dispatch. Replaces the former mp_write_reply_read loop, which
    // spun on WOULD_BLOCK once MP_READ became non-blocking.
    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();
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
            puts(b"[dnssrv] reactor EventQueue/Watch alloc failed\n");
            loop {
                let _ = trona_kernel::syscall::yield_now();
            }
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let scratch = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"dnssrv recv scratch");
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        DNSSRV_SERVICE_COOKIE,
    );
    core::mem::forget(eq);
    core::mem::forget(watch);
    let mut reactor = trona_server::event_loop::EventLoop::new(
        eq_cap,
        DnssrvDispatcher {
            recv_ep,
            watch_cap,
            eq_cap,
            scratch,
        },
    );
    loop {
        // SAFETY: `ctx` is this thread's IPC context; arm the cap-receive
        // scratch, then block on the EQ and dispatch one ready event.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ctx,
                trona_kernel::uapi::KERNITE_CAP_SELF_CSPACE as u64,
                scratch,
                0,
            );
            let _ = reactor.run_iteration(ctx);
        }
    }
}
