// SPDX-License-Identifier: GPL-2.0-only
//! DNS resolution tests.
//!
//! Tests DNS resolution via the dnssrv service. Requires:
//! - dnssrv running and registered with nameserv
//! - netsrv running with network connectivity
//! - QEMU user networking with DNS forwarder at 10.0.2.3

use salty::consts::*;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

pub fn run() -> bool {
    serial::serial_puts(b"[TEST_DNS] Starting DNS tests\n");
    let mut all_pass = true;

    // Test 1: Resolve "google.com" (should succeed via QEMU DNS forwarder)
    {
        // SAFETY: IPC context is initialized; dnssrv endpoint at slot 64.
        let ip = unsafe { salty::dns::dns_resolve(b"google.com") };
        if ip != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"  dns: google.com -> ");
            lb.dec(((ip >> 24) & 0xFF) as u64);
            lb.putc(b'.');
            lb.dec(((ip >> 16) & 0xFF) as u64);
            lb.putc(b'.');
            lb.dec(((ip >> 8) & 0xFF) as u64);
            lb.putc(b'.');
            lb.dec((ip & 0xFF) as u64);
            lb.putc(b'\n');
            lb.flush();
        } else {
            serial::serial_puts(b"  dns: google.com resolution FAILED\n");
            all_pass = false;
        }
    }

    // Test 2: Resolve "nonexistent.invalid" (should fail with NXDOMAIN)
    {
        // SAFETY: IPC context is initialized; dnssrv endpoint at slot 64.
        let ip = unsafe { salty::dns::dns_resolve(b"nonexistent.invalid") };
        if ip == 0 {
            serial::serial_puts(b"  dns: NXDOMAIN test passed\n");
        } else {
            serial::serial_puts(b"  dns: NXDOMAIN test FAILED (got an IP)\n");
            all_pass = false;
        }
    }

    // Test 3: Cache test (resolve same hostname twice, second should be cached)
    {
        // SAFETY: IPC context is initialized; dnssrv endpoint at slot 64.
        let ip1 = unsafe { salty::dns::dns_resolve(b"example.com") };
        let ip2 = unsafe { salty::dns::dns_resolve(b"example.com") };
        if ip1 != 0 && ip1 == ip2 {
            serial::serial_puts(b"  dns: cache consistency test passed\n");
        } else if ip1 == 0 {
            serial::serial_puts(b"  dns: example.com resolution FAILED\n");
            all_pass = false;
        } else {
            serial::serial_puts(b"  dns: cache returned different IPs\n");
            all_pass = false;
        }
    }

    // Test 4: getaddrinfo API
    {
        let mut info = DnsAddrInfo::zeroed();
        // SAFETY: IPC context is initialized; passing valid pointers.
        let result = unsafe {
            salty::dns::posix_getaddrinfo(b"example.org\0".as_ptr(), &raw mut info)
        };
        if result == 0 && info.addr.addr != 0 && info.family == AF_INET {
            serial::serial_puts(b"  dns: getaddrinfo test passed\n");
        } else {
            serial::serial_puts(b"  dns: getaddrinfo test FAILED\n");
            all_pass = false;
        }
    }

    // Test 5: Reverse DNS lookup
    {
        // Resolve google.com first, then do reverse lookup on the IP
        // SAFETY: IPC context is initialized; dnssrv endpoint at slot 64.
        let ip = unsafe { salty::dns::dns_resolve(b"google.com") };
        if ip != 0 {
            let mut hostname = [0u8; 128];
            // SAFETY: hostname buffer is valid and large enough.
            let len = unsafe {
                salty::dns::dns_reverse_lookup(ip, hostname.as_mut_ptr(), 128)
            };
            if len > 0 {
                let mut lb = LineBuf::new();
                lb.str(b"  dns: reverse lookup -> ");
                let mut i = 0;
                while i < len {
                    lb.putc(hostname[i]);
                    i += 1;
                }
                lb.putc(b'\n');
                lb.flush();
            } else {
                serial::serial_puts(b"  dns: reverse lookup returned empty (non-fatal)\n");
                // Not a failure - many IPs don't have reverse DNS
            }
        }
    }

    all_pass
}
