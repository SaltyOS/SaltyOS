// SPDX-License-Identifier: GPL-2.0-only
//! DNS client API for SaltyOS.
//!
//! Provides hostname resolution by communicating with the dnssrv service.
//! The dnssrv endpoint must be available at the cap slot specified by
//! the caller (typically injected via NeedEP in the process's .service file).

use crate::consts::*;
use crate::ipc;
use crate::tls;
use crate::types::*;

/// Default cap slot for dnssrv endpoint (injected via NeedEP=dnssrv:64).
const CAP_DNSSRV_DEFAULT: u64 = 64;

/// Resolve a hostname to IPv4 address(es).
///
/// `hostname` is a byte slice (NOT null-terminated) of the hostname to resolve.
/// `dnssrv_ep` is the capability slot of the dnssrv endpoint.
///
/// On success, returns the primary resolved IPv4 address (host byte order).
/// On failure, returns 0.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized and `dnssrv_ep` is a
/// valid endpoint capability slot connected to the dnssrv service.
pub unsafe fn dns_resolve_with_ep(hostname: &[u8], dnssrv_ep: u64) -> u32 {
    unsafe {
        if hostname.is_empty() || hostname.len() > 120 {
            return 0;
        }

        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();

        msg.label = DNS_RESOLVE;
        msg.regs[0] = hostname.len() as u64;

        // SAFETY: Pack hostname bytes into regs[1..]. The SaltyMsg regs array
        // has 20 entries (160 bytes), and hostname is at most 120 bytes, so
        // this copy stays within bounds.
        let dst = &raw mut msg.regs[1] as *mut u8;
        core::ptr::copy_nonoverlapping(hostname.as_ptr(), dst, hostname.len());
        msg.length = 1 + ((hostname.len() as u64 + 7) / 8);

        let err = ipc::call_ctx(
            tls::current_ipc_ctx(),
            dnssrv_ep,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }

        // reply.regs[0] = ip_count, reply.regs[1] = ttl, reply.regs[2] = primary IP
        if reply.regs[0] == 0 {
            return 0;
        }
        reply.regs[2] as u32
    }
}

/// Resolve a hostname using the default dnssrv endpoint (slot 64).
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized and the dnssrv endpoint
/// is available at capability slot 64.
pub unsafe fn dns_resolve(hostname: &[u8]) -> u32 {
    unsafe { dns_resolve_with_ep(hostname, CAP_DNSSRV_DEFAULT) }
}

/// Resolve a hostname and fill a DnsAddrInfo struct.
///
/// `node` is a null-terminated hostname string.
/// `result` receives the resolved address info.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
///
/// `node` must point to a valid null-terminated byte string.
/// `result` must point to a valid, writable `DnsAddrInfo`.
pub unsafe fn posix_getaddrinfo(node: *const u8, result: *mut DnsAddrInfo) -> i32 {
    unsafe {
        if node.is_null() || result.is_null() {
            return -1;
        }

        // Measure null-terminated string length
        let mut len = 0usize;
        while *node.add(len) != 0 && len < 120 {
            len += 1;
        }
        if len == 0 || len >= 120 {
            return -1;
        }

        let hostname = core::slice::from_raw_parts(node, len);
        let ip = dns_resolve(hostname);
        if ip == 0 {
            return -1;
        }

        (*result).family = AF_INET;
        (*result).socktype = SOCK_STREAM;
        (*result).protocol = IPPROTO_TCP;
        (*result).addr.family = AF_INET as u16;
        (*result).addr.port = 0;
        (*result).addr.addr = ip;
        0
    }
}

/// Resolve a null-terminated hostname to an IPv4 address.
///
/// Returns the IPv4 address in host byte order, or 0 on failure.
///
/// # Safety
///
/// `name` must point to a valid null-terminated byte string.
pub unsafe fn posix_gethostbyname(name: *const u8) -> u32 {
    unsafe {
        if name.is_null() {
            return 0;
        }
        let mut len = 0usize;
        while *name.add(len) != 0 && len < 120 {
            len += 1;
        }
        if len == 0 || len >= 120 {
            return 0;
        }
        let hostname = core::slice::from_raw_parts(name, len);
        dns_resolve(hostname)
    }
}

/// Resolve an IPv4 address to a hostname (reverse DNS).
///
/// `ip` is the IPv4 address in host byte order.
/// `hostname_out` receives the resolved hostname.
/// `hostname_max` is the buffer size.
/// Returns the hostname length on success, 0 on failure.
///
/// # Safety
///
/// `hostname_out` must point to a writable buffer of at least `hostname_max` bytes.
pub unsafe fn dns_reverse_lookup(ip: u32, hostname_out: *mut u8, hostname_max: usize) -> usize {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();

        msg.label = DNS_REVERSE_LOOKUP;
        msg.regs[0] = ip as u64;
        msg.length = 1;

        let err = ipc::call_ctx(
            tls::current_ipc_ctx(),
            CAP_DNSSRV_DEFAULT,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }

        let result_len = reply.regs[0] as usize;
        let copy_len = core::cmp::min(result_len, hostname_max);
        if copy_len > 0 {
            if hostname_out.is_null() {
                return 0;
            }
            // SAFETY: Reading hostname bytes packed in reply registers.
            let src = &reply.regs[1] as *const u64 as *const u8;
            core::ptr::copy_nonoverlapping(src, hostname_out, copy_len);
        }
        copy_len
    }
}

/// Flush the dnssrv DNS cache.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized and the dnssrv endpoint
/// is available at capability slot 64.
pub unsafe fn dns_cache_flush() {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();

        msg.label = DNS_CACHE_FLUSH;
        msg.length = 0;

        let _ = ipc::call_ctx(
            tls::current_ipc_ctx(),
            CAP_DNSSRV_DEFAULT,
            &raw const msg,
            &raw mut reply,
        );
    }
}
