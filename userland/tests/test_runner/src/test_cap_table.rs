//! Cap-table role resolution test.
//!
//! Verifies that the role-based capability delivery path populates
//! every role getter this process is supposed to receive. A regression
//! here means either the spawner failed to emit a role entry, or the
//! child-side installer (rtld / CRT) skipped it.
//!
//! The test is deliberately flexible: system roles that are not part of
//! a normal `test_runner` cspace (COM1 IRQ, keyboard, fb untyped, etc.)
//! are tolerated as `0`; only the process ABI roles and the sockets
//! declared by `test_runner.service` must be non-zero. This keeps the
//! test useful across arch and spawn-profile variations without forcing
//! the spawner to emit roles it has no cap for.
//! SPDX-License-Identifier: GPL-2.0-only

use trona_runtime::debug::serial;

fn report_role(label: &[u8], slot: u64) {
    let mut lb = serial::LineBuf::new();
    lb.str(b"[TEST_CAP_TABLE] ");
    lb.str(label);
    lb.str(b" slot=");
    lb.hex(slot);
    lb.str(b"\n");
    lb.flush();
}

pub fn run() -> bool {
    serial::serial_puts(b"[TEST_CAP_TABLE] starting\n");

    // Required: every test-runner process must reach these.
    let required: &[(&[u8], u64)] = &[
        (b"init_ep", trona_runtime::client::caps::init_ep().addr()),
        (b"vfs_ep", trona_runtime::client::caps::vfs_ep().addr()),
        (
            b"namesrv_ep",
            trona_runtime::client::caps::namesrv_ep().addr(),
        ),
        (b"mmsrv_ep", trona_runtime::client::caps::mmsrv_ep().addr()),
        (
            b"service_recv_ep",
            trona_runtime::client::caps::service_recv_ep().addr(),
        ),
        (
            b"service_client_ep",
            trona_runtime::client::caps::service_client_ep().addr(),
        ),
        (
            b"rsrcsrv_ep",
            trona_runtime::client::caps::rsrcsrv_ep().addr(),
        ),
        (b"sc_cap", trona_runtime::client::caps::sc_cap().addr()),
    ];
    let mut ok = true;
    for (name, slot) in required {
        report_role(name, *slot);
        if *slot == 0 {
            let mut lb = serial::LineBuf::new();
            lb.str(b"[TEST_CAP_TABLE] FAIL: required role ");
            lb.str(name);
            lb.str(b" unresolved\n");
            lb.flush();
            ok = false;
        }
    }

    // Optional: these may or may not be present depending on service
    // class. Report them for diagnostics but do not fail the test.
    let optional: &[(&[u8], u64)] = &[
        (
            b"signal_pipe",
            trona_runtime::client::caps::signal_pipe().addr(),
        ),
        (
            b"initrd_untyped",
            trona_runtime::client::caps::initrd_untyped().addr(),
        ),
        (
            b"console_ep",
            trona_runtime::client::caps::console_ep().addr(),
        ),
        (
            b"win32srv_ep",
            trona_runtime::client::caps::win32srv_ep().addr(),
        ),
        (
            b"fb_untyped",
            trona_runtime::client::caps::fb_untyped().addr(),
        ),
        (
            b"pci_ioport",
            trona_runtime::client::caps::pci_ioport().addr(),
        ),
        (
            b"com1_ioport",
            trona_runtime::client::caps::com1_ioport().addr(),
        ),
        (b"com1_irq", trona_runtime::client::caps::com1_irq().addr()),
        (
            b"com1_ntfn",
            trona_runtime::client::caps::com1_ntfn().addr(),
        ),
        (
            b"kbd_ioport",
            trona_runtime::client::caps::kbd_ioport().addr(),
        ),
        (b"kbd_irq", trona_runtime::client::caps::kbd_irq().addr()),
        (
            b"device_control",
            trona_runtime::client::caps::device_control().addr(),
        ),
    ];
    for (name, slot) in optional {
        report_role(name, *slot);
    }

    if ok {
        serial::serial_puts(b"[TEST_CAP_TABLE] PASS\n");
    } else {
        serial::serial_puts(b"[TEST_CAP_TABLE] FAIL\n");
    }
    ok
}
