//! Spawn-time controlling-tty stdio handoff.
//!
//! `StandardInput=tty` services currently bind to the system console tty
//! (the ttysrv-reserved console slot exposed as `/dev/console`), not a freshly
//! allocated hidden PTY. That matches
//! the rest of SaltyOS today: keyboard/display I/O is attached to the console
//! tty, and interactive login is expected to happen there.
//!
//! The flow is:
//!   1. Ask VFS to provision `/dev/console` directly into child slots 0/1/2.
//!   2. Before first resume, ask `posix_ttysrv` to install controlling-tty
//!      state for the reserved console terminal and seed procmgr's
//!      `(sid, pgid, ctty)` state for the child session leader.
//!
//! This keeps the public POSIX ABI (`/dev/console`, `/dev/tty`) intact while
//! avoiding the previous mismatch where getty tried to bootstrap its session on
//! top of a freshly allocated PTY that had no real console attachment.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::TronaMsg;
use trona_protocol::posix::server::POSIX_TTYSRV_PTY_IOCTL;
use trona_protocol::posix::vfs::VFS_PROVISION_TTY_STDIO_TO;
use trona_protocol::posix_abi::tty::{TIOCSCTTY, TIOCSPGRP, tty_dev_for_console};

/// Bitmap placed in the child's startup block when tty handoff succeeds:
/// stdin/stdout/stderr are already installed at slots 0/1/2.
pub(crate) const STDIO_PRE_BITS_TTY: u64 = 0b111;

#[derive(Clone, Copy)]
pub(crate) struct SpawnedTtyBinding {
    pub(crate) tty_dev: u64,
    pub(crate) pty_id: u32,
}

#[inline]
fn posix_ttysrv_provider_ep() -> trona_kernel::core_types::core::Cap {
    crate::service::registry::lookup_provider(b"posix_ttysrv").unwrap_or(0)
}

unsafe fn ttysrv_ioctl(pty_id: u32, cmd: u64, arg: u64, caller_sid: u64, caller_pgid: u64) -> bool {
    unsafe {
        let ep = posix_ttysrv_provider_ep();
        if ep == 0 {
            return false;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = POSIX_TTYSRV_PTY_IOCTL;
        msg.length = 5;
        msg.regs[0] = pty_id as u64;
        msg.regs[1] = cmd;
        msg.regs[2] = arg;
        msg.regs[3] = caller_sid;
        msg.regs[4] = caller_pgid;
        let err = trona_kernel::ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        err == 0 && reply.label == trona_protocol::common::TRONA_OK
    }
}

/// Install stdin/stdout/stderr for a tty-bound child. The current tty mode
/// maps to the system console, so VFS provisions `/dev/console` directly into
/// the target child's 0/1/2 slots as part of the spawn contract.
pub(crate) unsafe fn handoff_tty_stdio_to_child(child_badge: u64) -> Option<SpawnedTtyBinding> {
    unsafe {
        let self_ep = crate::base::cap_helpers::vfs_self_client_ep();
        if self_ep == 0 {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] tty-handoff: missing self VFS client ep provider_ep=");
                _lb.dec(crate::base::cap_helpers::vfs_provider_ep());
                _lb.str(b" self_ep=");
                _lb.dec(self_ep);
                _lb.str(b"\n");
            });
            return None;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_PROVISION_TTY_STDIO_TO;
        msg.length = 2;
        msg.regs[0] = child_badge;
        msg.regs[1] = tty_dev_for_console();
        let err =
            trona_kernel::ipc::call_ctx(crate::ipc_ctx(), self_ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] tty-handoff: provision console stdio failed child=");
                _lb.hex(child_badge);
                _lb.str(b" ipc_err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b" self_ep=");
                _lb.dec(self_ep);
                _lb.str(b"\n");
            });
            return None;
        }

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] tty-handoff: child=");
            _lb.hex(child_badge);
            _lb.str(b" console\n");
        });
        Some(SpawnedTtyBinding {
            tty_dev: tty_dev_for_console(),
            pty_id: 0,
        })
    }
}

/// Prime ttysrv's controlling-tty state for the child session leader before
/// first resume. This mirrors the user-visible `TIOCSCTTY` + `TIOCSPGRP`
/// sequence but keeps the bootstrap inside the spawn contract.
pub(crate) unsafe fn prime_child_controlling_tty(
    binding: SpawnedTtyBinding,
    sid: u32,
    pgid: u32,
) -> bool {
    unsafe {
        let sid64 = sid as u64;
        let pgid64 = pgid as u64;
        if !ttysrv_ioctl(binding.pty_id, TIOCSCTTY, 0, sid64, pgid64) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] tty-handoff: TIOCSCTTY prime failed pty_id=");
                _lb.dec(binding.pty_id as u64);
                _lb.str(b" sid=");
                _lb.dec(sid64);
                _lb.str(b" pgid=");
                _lb.dec(pgid64);
                _lb.str(b"\n");
            });
            return false;
        }
        if !ttysrv_ioctl(binding.pty_id, TIOCSPGRP, pgid64, sid64, 0) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] tty-handoff: TIOCSPGRP prime failed pty_id=");
                _lb.dec(binding.pty_id as u64);
                _lb.str(b" sid=");
                _lb.dec(sid64);
                _lb.str(b" pgid=");
                _lb.dec(pgid64);
                _lb.str(b"\n");
            });
            return false;
        }
        true
    }
}
