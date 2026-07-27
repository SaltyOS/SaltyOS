//! Exec handler
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::proc_table::{
    MAX_NAME_LEN, NSIG, SIG_DISP_CATCH, SIG_DISP_DFL, find_by_badge, proctab,
};
use crate::personality::PersonalityKind;

/// Cleanup for a failure that happens *before* `prepare_exec_transition`.
/// The client TCB is still Blocked in its `Call` IPC, so a normal reply
/// label unblocks it and the process continues running.
unsafe fn abort_preflight_exec(
    reply: &mut TronaMsg,
    label: u64,
    badged_vfs: Option<Cap>,
    vfs_source: &mut crate::loader::vfs_load::VfsExecSource,
) {
    unsafe {
        if let Some(ep) = badged_vfs {
            crate::loader::vfs_load::cleanup_exec_source_on(ep, vfs_source);
            crate::loader::vfs_load::release_badged_vfs_cap(ep);
        } else {
            crate::loader::vfs_load::cleanup_exec_source(vfs_source);
        }
        reply.label = label;
    }
}

/// Cleanup for a failure that happens *after* `prepare_exec_transition`.
/// The client TCB is Inactive and its reply linkage has been cleared by
/// `TCB_SUSPEND`, so the caller cannot be resumed — the only correct
/// action is to kill the process. `reply.label` is set to `0` so the
/// outer dispatcher does not spuriously fire a reply at a dead link.
unsafe fn abort_destroyed_exec(
    idx: usize,
    reply: &mut TronaMsg,
    badged_vfs: Option<Cap>,
    vfs_source: &mut crate::loader::vfs_load::VfsExecSource,
) {
    unsafe {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] EXEC: terminating PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" after destructive failure\n");
        });

        if let Some(ep) = badged_vfs {
            crate::loader::vfs_load::cleanup_exec_source_on(ep, vfs_source);
            crate::loader::vfs_load::release_badged_vfs_cap(ep);
        } else {
            crate::loader::vfs_load::cleanup_exec_source(vfs_source);
        }
        let _ = crate::personality::posix::signal::terminate_proc(
            idx,
            crate::personality::posix::PM_SIGKILL,
        );
        reply.label = 0;
    }
}

/// Move the target TCB into `Inactive` so subsequent `TCB_SET_STACK_BOUNDS`,
/// `TCB_CONFIGURE`, `TCB_SET_TLS_BASE`, `TCB_SET_IPC_BUFFER` and
/// `TCB_WRITE_REGISTERS` invocations succeed. The kernel requires those
/// ops to observe `ThreadState::Inactive`; without this step, a client in
/// `Blocked` state (waiting on its exec Call) trips `Busy(0x7)` when the
/// stack bounds are published.
///
/// Must be called exactly once, on the destructive boundary —
/// `quiesce_and_deregister_mmsrv_client` has succeeded and the first
/// `vspace_unmap` has not yet run. Before this call, exec may still fail
/// and return a reply to the caller. After this call the caller's reply
/// linkage is cleared (`TCB_SUSPEND` on a Blocked thread wipes
/// `saved_caller_msg`/`reply_tcb`), so any failure must route through
/// `abort_destroyed_exec`.
unsafe fn prepare_exec_transition(
    idx: usize,
    reply: &mut TronaMsg,
    badged_vfs: &mut Option<Cap>,
    vfs_source: &mut crate::loader::vfs_load::VfsExecSource,
) -> bool {
    unsafe {
        let err = trona_kernel::invoke::tcb_suspend(proctab(idx).tcb_cap);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: prepare tcb_suspend failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            abort_preflight_exec(
                reply,
                trona_protocol::posix::TRONA_IO_ERROR,
                badged_vfs.take(),
                vfs_source,
            );
            return false;
        }
        true
    }
}

unsafe fn set_exec_process_name(
    p: &mut crate::base::proc_table::Process,
    name: &[u8],
    name_len: usize,
) {
    let name_copy = if name_len > 31 { 31 } else { name_len };
    for i in 0..name_copy {
        p.name[i] = name[i];
    }
    for i in name_copy..32 {
        p.name[i] = 0;
    }
}

unsafe fn set_exec_path(
    p: &mut crate::base::proc_table::Process,
    exec_path: &[u8],
    exec_path_len: usize,
) {
    let exe_copy = if exec_path_len >= crate::base::proc_table::MAX_EXE_PATH_LEN {
        crate::base::proc_table::MAX_EXE_PATH_LEN - 1
    } else {
        exec_path_len
    };
    for i in 0..exe_copy {
        p.exe_path[i] = exec_path[i];
    }
    for i in exe_copy..crate::base::proc_table::MAX_EXE_PATH_LEN {
        p.exe_path[i] = 0;
    }
}

unsafe fn switch_exec_personality(idx: usize, target_kind: PersonalityKind) {
    unsafe {
        if proctab(idx).personality_kind() == target_kind {
            return;
        }

        let old_pid = proctab(idx).pid;
        let old_ppid = proctab(idx).ppid;
        let old_completion_observer_pid = proctab(idx).completion_observer_pid;
        let old_badge = proctab(idx).badge;
        let old_tcb = proctab(idx).tcb_cap;
        let old_vs = proctab(idx).vspace_cap;
        let old_cn = proctab(idx).cnode_cap;
        let old_sc = proctab(idx).sc_cap;
        let old_pgid = proctab(idx).pgid;
        let old_sid = proctab(idx).sid;
        let old_ctty_dev = proctab(idx).ctty_dev;
        let old_ctty_pgrp = proctab(idx).ctty_pgrp;
        let old_signal_ntfn = proctab(idx).signal_ntfn;
        let old_slot_base = proctab(idx).slot_base;
        let old_slot_count = proctab(idx).slot_count;
        let old_has_service_ep = proctab(idx).has_service_ep;
        let old_mmsrv_registered = proctab(idx).mmsrv_registered;
        let old_launch_pending = proctab(idx).launch_pending;
        let old_respawn = proctab(idx).respawn;
        let old_respawn_policy = proctab(idx).respawn_policy;
        let old_respawn_attempt_count = proctab(idx).respawn_attempt_count;
        let old_respawn_next_ready_tick = proctab(idx).respawn_next_ready_tick;
        let old_respawn_first_attempt_tick = proctab(idx).respawn_first_attempt_tick;
        let old_stdio_mode = proctab(idx).stdio_mode;
        let old_respawn_binary = proctab(idx).respawn_binary;
        let old_timer_interval_ns = proctab(idx).timer_interval_ns;
        let old_timer_deadline_ns = proctab(idx).timer_deadline_ns;
        let old_ready_badge_bit = proctab(idx).ready_badge_bit;
        let old_start_time_ns = proctab(idx).start_time_ns;
        let old_stop_status = proctab(idx).stop_status;
        let old_completion_event_kind = proctab(idx).completion_event_kind;
        let old_completion_event_status = proctab(idx).completion_event_status;
        let old_completion_event_cookie = proctab(idx).completion_event_cookie;
        let old_completion_wait_reply = proctab(idx).completion_wait_reply;
        let old_completion_wait_target_pid = proctab(idx).completion_wait_target_pid;
        let old_completion_wait_options = proctab(idx).completion_wait_options;
        let old_completion_wait_deadline_ns = proctab(idx).completion_wait_deadline_ns;
        let old_completion_wait_wake_retry_deadline_ns =
            proctab(idx).completion_wait_wake_retry_deadline_ns;
        let old_observer_event_count = proctab(idx).observer_event_count;
        let old_observer_events = proctab(idx).observer_events;
        let old_exe_path = proctab(idx).exe_path;
        let old_wait_ready_on_resume = proctab(idx).wait_ready_on_resume;
        let old_ready_timeout_ns = proctab(idx).ready_timeout_ns;
        let old_pending_ready_reply = proctab(idx).pending_ready_reply;
        let old_pending_ready_deadline_ns = proctab(idx).pending_ready_deadline_ns;

        let old_posix = if proctab(idx).is_posix() {
            Some(crate::base::proc_table::PosixState {
                sig_disposition: proctab(idx).posix().sig_disposition,
                umask: proctab(idx).posix().umask,
                uid: proctab(idx).posix().uid,
                gid: proctab(idx).posix().gid,
                euid: proctab(idx).posix().euid,
                egid: proctab(idx).posix().egid,
                suid: proctab(idx).posix().suid,
                sgid: proctab(idx).posix().sgid,
                ngroups: proctab(idx).posix().ngroups,
                groups: proctab(idx).posix().groups,
                rlimits: proctab(idx).posix().rlimits,
            })
        } else {
            None
        };

        proctab(idx).set_personality_kind(target_kind);
        let p = proctab(idx);
        p.pid = old_pid;
        p.ppid = old_ppid;
        p.completion_observer_pid = old_completion_observer_pid;
        p.badge = old_badge;
        p.tcb_cap = old_tcb;
        p.vspace_cap = old_vs;
        p.cnode_cap = old_cn;
        p.sc_cap = old_sc;
        p.pgid = old_pgid;
        p.sid = old_sid;
        p.ctty_dev = old_ctty_dev;
        p.ctty_pgrp = old_ctty_pgrp;
        p.signal_ntfn = old_signal_ntfn;
        p.slot_base = old_slot_base;
        p.slot_count = old_slot_count;
        p.has_service_ep = old_has_service_ep;
        p.mmsrv_registered = old_mmsrv_registered;
        p.launch_pending = old_launch_pending;
        p.respawn = old_respawn;
        p.respawn_policy = old_respawn_policy;
        p.respawn_attempt_count = old_respawn_attempt_count;
        p.respawn_next_ready_tick = old_respawn_next_ready_tick;
        p.respawn_first_attempt_tick = old_respawn_first_attempt_tick;
        p.stdio_mode = old_stdio_mode;
        p.respawn_binary = old_respawn_binary;
        p.timer_interval_ns = old_timer_interval_ns;
        p.timer_deadline_ns = old_timer_deadline_ns;
        p.ready_badge_bit = old_ready_badge_bit;
        p.start_time_ns = old_start_time_ns;
        p.stop_status = old_stop_status;
        p.completion_event_kind = old_completion_event_kind;
        p.completion_event_status = old_completion_event_status;
        p.completion_event_cookie = old_completion_event_cookie;
        p.completion_wait_reply = old_completion_wait_reply;
        p.completion_wait_target_pid = old_completion_wait_target_pid;
        p.completion_wait_options = old_completion_wait_options;
        p.completion_wait_deadline_ns = old_completion_wait_deadline_ns;
        p.completion_wait_wake_retry_deadline_ns = old_completion_wait_wake_retry_deadline_ns;
        p.observer_event_count = old_observer_event_count;
        p.observer_events = old_observer_events;
        p.exe_path = old_exe_path;
        p.wait_ready_on_resume = old_wait_ready_on_resume;
        p.ready_timeout_ns = old_ready_timeout_ns;
        p.pending_ready_reply = old_pending_ready_reply;
        p.pending_ready_deadline_ns = old_pending_ready_deadline_ns;

        if let (PersonalityKind::Posix, Some(old_posix)) = (target_kind, old_posix) {
            *p.posix_mut() = old_posix;
        }
    }
}

unsafe fn notify_vfs_client_exec(badge: u64) {
    if !crate::base::vfs_notify::enqueue_client_exec(badge) {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] VFS client-exec queue full badge=");
            _lb.hex(badge);
            _lb.str(b"\n");
        });
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn finalize_exec_transition(
    idx: usize,
    reply: &mut TronaMsg,
    badged_vfs: &mut Option<Cap>,
    vfs_source: &mut crate::loader::vfs_load::VfsExecSource,
    target_kind: PersonalityKind,
    entry: u64,
    rsp: u64,
    layout: trona_runtime::spawn::layout::VmLayoutPlan,
    shared_lib_base: u64,
    shared_lib_map: crate::base::proc_table::ProcLibMap,
    name: &[u8],
    name_len: usize,
    exec_path: &[u8],
    exec_path_len: usize,
    file_mode: u32,
    file_uid: u32,
    file_gid: u32,
    log_prefix: &[u8],
) {
    unsafe {
        // The target TCB was moved to `Inactive` by `prepare_exec_transition`
        // on the destructive boundary, so every TCB invocation below
        // observes the state the kernel requires.
        switch_exec_personality(idx, target_kind);

        if proctab(idx).is_posix() {
            for i in 0..NSIG {
                if proctab(idx).posix().sig_disposition[i] == SIG_DISP_CATCH {
                    proctab(idx).posix_mut().sig_disposition[i] = SIG_DISP_DFL;
                }
            }
        }

        if let Some(ep) = badged_vfs.take() {
            crate::loader::vfs_load::cleanup_exec_source_on(ep, vfs_source);
            crate::loader::vfs_load::release_badged_vfs_cap(ep);
        } else {
            crate::loader::vfs_load::cleanup_exec_source(vfs_source);
        }

        let err = trona_kernel::invoke::tcb_configure(proctab(idx).tcb_cap, entry, rsp, 0);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: tcb_configure failed err=");
                _lb.hex(err as u64);
                _lb.str(b" pid=");
                _lb.hex(proctab(idx).pid as u64);
                _lb.str(b" tcb=");
                _lb.hex(proctab(idx).tcb_cap);
                _lb.str(b"\n");
            });
            abort_destroyed_exec(idx, reply, badged_vfs.take(), vfs_source);
            return;
        }
        let err = trona_kernel::invoke::tcb_set_tls_base(proctab(idx).tcb_cap, 0);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: clear TLS base failed\n");
            });
            abort_destroyed_exec(idx, reply, badged_vfs.take(), vfs_source);
            return;
        }
        trona_kernel::invoke::tcb_set_ipc_buffer(proctab(idx).tcb_cap, layout.ipc_buf.base);
        notify_vfs_client_exec(proctab(idx).badge);

        let err = trona_kernel::invoke::tcb_resume(proctab(idx).tcb_cap);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: resume failed\n");
            });
            abort_destroyed_exec(idx, reply, badged_vfs.take(), vfs_source);
            return;
        }

        let p = proctab(idx);
        p.shared_lib_base = shared_lib_base;
        p.lib_map = shared_lib_map;
        p.layout = layout;
        set_exec_process_name(p, name, name_len);
        set_exec_path(p, exec_path, exec_path_len);
        if p.is_posix() {
            if (file_mode & 0o4000) != 0 {
                p.posix_mut().euid = file_uid;
                p.posix_mut().suid = file_uid;
            }
            if (file_mode & 0o2000) != 0 {
                p.posix_mut().egid = file_gid;
                p.posix_mut().sgid = file_gid;
            }
        }
        crate::base::trace_meta::emit_process_mapping(
            b"exec",
            p.pid,
            p.ppid,
            p.tcb_cap,
            p.vspace_cap,
            &p.name,
            &p.exe_path,
        );

        trona_runtime::udebug!(|_lb| {
            _lb.bytes(log_prefix);
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" -> entry=");
            _lb.hex(entry);
            _lb.str(b"\n");
        });
    }
}

/// Fallback path construction when VFS_POSIX_CANON_PATH is unavailable.
/// Bare names (no slash) get /bin/ prepended; absolute paths pass through.
fn derive_simple_exec_path<'a>(
    name: &[u8],
    name_len: usize,
    buf: &'a mut [u8; 256],
) -> (&'a [u8], usize) {
    if name_len == 0 {
        return (&[], 0);
    }
    if name[0] == b'/' {
        for i in 0..core::cmp::min(name_len, 256) {
            buf[i] = name[i];
        }
        return (&buf[..], core::cmp::min(name_len, 256));
    }
    let mut has_slash = false;
    for i in 0..name_len {
        if name[i] == b'/' {
            has_slash = true;
            break;
        }
    }
    if !has_slash {
        let prefix = b"/bin/";
        let total = prefix.len() + name_len;
        if total > 256 {
            return (&[], 0);
        }
        for i in 0..prefix.len() {
            buf[i] = prefix[i];
        }
        for i in 0..name_len {
            buf[prefix.len() + i] = name[i];
        }
        return (&buf[..], total);
    }
    // Relative path with slash — can't resolve without VFS
    for i in 0..core::cmp::min(name_len, 256) {
        buf[i] = name[i];
    }
    (&buf[..], core::cmp::min(name_len, 256))
}

pub(crate) unsafe fn handle_exec(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let alloc = &mut *(&raw mut crate::ALLOCATOR);

        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        if msg.regs[0] > 64 {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        // Snapshot argv/env payload before any helper IPC. The incoming
        // INIT_EXEC transfer uses this thread's IPC buffer reserved area, so
        // later VFS/mmsrv RPCs are free to reuse the same buffer.
        let path_regs = 1 + ((msg.regs[0] as usize + 7) / 8);
        let argc: u32;
        let envc: u32;
        let mut exec_str_data = [0u8; IPC_BUFFER_RESERVED_BYTES];
        let exec_str_len: usize;
        if msg.length as usize <= path_regs + 1 {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let packed = msg.regs[path_regs];
        argc = (packed >> 32) as u32;
        envc = (packed & 0xFFFF_FFFF) as u32;
        exec_str_len = msg.regs[path_regs + 1] as usize;
        if exec_str_len > exec_str_data.len() {
            reply.label = crate::TRONA_OUT_OF_RANGE;
            return;
        }
        if exec_str_len != 0 {
            let ctx = &*crate::ipc_ctx();
            if ctx.ipc_buffer.is_null() {
                reply.label = crate::TRONA_INVALID_ARGUMENT;
                return;
            }

            let src = (*ctx.ipc_buffer).reserved.as_ptr() as *const u8;
            for i in 0..exec_str_len {
                exec_str_data[i] = *src.add(i);
            }
        }

        let (name, name_len) = crate::extract_name(msg, 1);
        let mut exec_path = [0u8; crate::base::proc_table::MAX_EXE_PATH_LEN];

        // Mint badged VFS EP for the calling process so VFS resolves
        // paths relative to the caller's cwd and checks permissions.
        let mut badged_vfs = crate::loader::vfs_load::mint_badged_vfs_cap(badge);

        // Canonicalize path via VFS_POSIX_CANON_PATH on the badged EP.
        let mut canon_buf = [0u8; 256];
        let (resolved_path, resolved_len) = if let Some(ep) = badged_vfs {
            if let Some(len) =
                crate::loader::vfs_load::vfs_canon_path_on(ep, &name, name_len, &mut canon_buf)
            {
                (&canon_buf[..] as &[u8], len)
            } else {
                derive_simple_exec_path(&name, name_len, &mut canon_buf)
            }
        } else {
            derive_simple_exec_path(&name, name_len, &mut canon_buf)
        };

        // Stat for exec via badged EP: X_OK check + mode/uid/gid/size.
        // Done before releasing the badged cap.
        let mut vfs_stat = crate::loader::vfs_load::VfsExecStatResult {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
        };
        let have_vfs_stat = if let Some(ep) = badged_vfs {
            crate::loader::vfs_load::vfs_stat_for_exec_on(ep, resolved_path, resolved_len)
                .map(|s| {
                    vfs_stat = s;
                })
                .is_some()
        } else {
            false
        };

        let exec_path_len =
            core::cmp::min(resolved_len, crate::base::proc_table::MAX_EXE_PATH_LEN - 1);
        for i in 0..exec_path_len {
            exec_path[i] = resolved_path[i];
        }
        exec_path[exec_path_len] = 0;

        let mut argv0_len = 0usize;
        while argv0_len < exec_str_len && exec_str_data[argv0_len] != 0 {
            argv0_len += 1;
        }

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] EXEC PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" -> '");
            _lb.bytes(&resolved_path[..resolved_len]);
            _lb.str(b"' argc=");
            _lb.hex(argc as u64);
            _lb.str(b" envc=");
            _lb.hex(envc as u64);
            _lb.str(b" argv0='");
            if argv0_len != 0 {
                _lb.bytes(&exec_str_data[..argv0_len]);
            }
            _lb.str(b"'\n");
        });
        let initrd = crate::INITRD_VADDR as *const u8;
        let initrd_size = crate::read_boot_info_initrd_size();

        // Strip leading '/' for CPIO lookup — archive uses "bin/foo" keys
        let cpio_off = if resolved_len > 0 && resolved_path[0] == b'/' {
            1
        } else {
            0
        };
        let cpio_name_len = resolved_len - cpio_off;

        let mut elf_entry = CpioEntryExt::zeroed();
        let cpio_name = &resolved_path[cpio_off..cpio_off + cpio_name_len];
        let mut found = if let Some(e) =
            trona_loader::common::cpio::cpio_find_file_ext(initrd, initrd_size, cpio_name)
        {
            elf_entry.data = e.data;
            elf_entry.data_len = e.data_len;
            elf_entry.mode = e.mode;
            elf_entry.uid = e.uid;
            elf_entry.gid = e.gid;
            true
        } else {
            false
        };

        if !found && cpio_name_len + 4 <= MAX_NAME_LEN {
            let mut legacy = [0u8; MAX_NAME_LEN + 5];
            for i in 0..cpio_name_len {
                legacy[i] = resolved_path[cpio_off + i];
            }
            legacy[cpio_name_len] = b'.';
            legacy[cpio_name_len + 1] = b'e';
            legacy[cpio_name_len + 2] = b'l';
            legacy[cpio_name_len + 3] = b'f';
            found = if let Some(e) = trona_loader::common::cpio::cpio_find_file_ext(
                initrd,
                initrd_size,
                &legacy[..cpio_name_len + 4],
            ) {
                elf_entry.data = e.data;
                elf_entry.data_len = e.data_len;
                elf_entry.mode = e.mode;
                elf_entry.uid = e.uid;
                elf_entry.gid = e.gid;
                true
            } else {
                false
            };
        }

        // Track file mode/uid/gid for setuid/setgid application.
        // For initrd files, these come from the CPIO header.
        // For VFS files, they come from VFS_POSIX_STAT_FOR_EXEC (already done above).
        let mut file_mode: u32 = elf_entry.mode;
        let mut file_uid: u32 = elf_entry.uid;
        let mut file_gid: u32 = elf_entry.gid;

        // VFS fallback: keep path resolution, exec permission checks, and file
        // loading in the same client context.
        let mut vfs_source = crate::loader::vfs_load::VfsExecSource::none();
        if !found {
            if let Some(ep) = badged_vfs {
                if let Some(source) = crate::loader::vfs_load::try_open_exec_source_on(
                    ep,
                    resolved_path,
                    resolved_len,
                    core::ptr::null_mut(),
                ) {
                    if let Some((data, data_len)) = source.buffered_data() {
                        elf_entry.data = data;
                        elf_entry.data_len = data_len;
                    }
                    found = true;
                    vfs_source = source;
                    if have_vfs_stat {
                        file_mode = vfs_stat.mode;
                        file_uid = vfs_stat.uid;
                        file_gid = vfs_stat.gid;
                    }
                }
            } else if have_vfs_stat {
                if let Some(source) = crate::loader::vfs_load::try_open_exec_source_from_vfs(
                    resolved_path,
                    resolved_len,
                ) {
                    if let Some((data, data_len)) = source.buffered_data() {
                        elf_entry.data = data;
                        elf_entry.data_len = data_len;
                    }
                    found = true;
                    vfs_source = source;
                    file_mode = vfs_stat.mode;
                    file_uid = vfs_stat.uid;
                    file_gid = vfs_stat.gid;
                }
            } else {
                // No stat available — load without permission check (early boot)
                if let Some(source) = crate::loader::vfs_load::try_open_exec_source_from_vfs(
                    resolved_path,
                    resolved_len,
                ) {
                    if let Some((data, data_len)) = source.buffered_data() {
                        elf_entry.data = data;
                        elf_entry.data_len = data_len;
                    }
                    found = true;
                    vfs_source = source;
                }
            }
        }
        if !found {
            if let Some(ep) = badged_vfs.take() {
                crate::loader::vfs_load::release_badged_vfs_cap(ep);
            }
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: ELF not found in initrd or VFS\n");
            });
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        }

        // Read-only probes on `vfs_source` below use inline `.streamed()`
        // calls so the immutable borrows end at each expression boundary.
        // A long-lived `let vfs_stream = vfs_source.streamed()` binding
        // would overlap with the later `&mut vfs_source` passed to
        // `abort_preflight_exec` / `prepare_exec_transition`.
        let is_pe = vfs_source.streamed().is_none()
            && elf_entry.data_len >= 2
            && unsafe { *elf_entry.data == 0x4D && *elf_entry.data.add(1) == 0x5A };
        let is_dynamic = if is_pe {
            true
        } else if let Some(vfs) = vfs_source.streamed() {
            vfs.is_dynamic
        } else {
            unsafe {
                use trona_loader::common::elf::header::{has_interp, phdr_slice, validate_ehdr};
                if let Ok(ehdr) = validate_ehdr(elf_entry.data, elf_entry.data_len) {
                    if let Ok(phdrs) = phdr_slice(elf_entry.data, elf_entry.data_len, ehdr) {
                        has_interp(phdrs)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };
        let proc_vs = proctab(idx).vspace_cap;
        let pid = proctab(idx).pid;

        // 1. Deregister old mappings from mmsrv so it doesn't hold stale frame refs
        if !crate::base::mmsrv_ipc::quiesce_and_deregister_mmsrv_client(
            proctab(idx).tcb_cap,
            pid,
            badge,
        ) {
            abort_preflight_exec(
                reply,
                trona_protocol::posix::TRONA_IO_ERROR,
                badged_vfs.take(),
                &mut vfs_source,
            );
            return;
        }

        // Destructive boundary. The caller's vspace / cap-table / ipc buffer
        // are about to be torn down; suspend the target TCB now so that
        // later `TCB_SET_STACK_BOUNDS` / `TCB_CONFIGURE` / `TCB_SET_TLS_BASE`
        // see `ThreadState::Inactive`. Suspend clears the caller's reply
        // linkage, so from here on any failure must route through
        // `abort_destroyed_exec` and terminate the process.
        if !prepare_exec_transition(idx, reply, &mut badged_vfs, &mut vfs_source) {
            return;
        }

        // 2. Unmap existing user pages
        let mut walk_start: u64 = 0;
        loop {
            let err =
                trona_kernel::invoke::vspace_walk(proc_vs, walk_start, crate::VSPACE_WALK_BATCH);
            if err != 0 {
                break;
            }
            let Some((count, next_addr)) = trona_kernel::invoke::vspace_walk_result_header_ctx(
                trona_runtime::current_ipc_ctx(),
            ) else {
                break;
            };
            if count == 0 {
                break;
            }

            for i in 0..count {
                let Some((page_vaddr, _, _)) = trona_kernel::invoke::vspace_walk_result_entry_ctx(
                    trona_runtime::current_ipc_ctx(),
                    i as usize,
                ) else {
                    break;
                };
                trona_kernel::invoke::vspace_unmap(proc_vs, page_vaddr);
            }

            if next_addr == 0 {
                break;
            }
            walk_start = next_addr;
        }

        // 2a. Clean old RTLD/dynamic slots from child CSpace to prevent slot
        //     collision. The frame pool starts at the cursor-allocated
        //     `frame_slot_start`; the per-process layout (saved on the
        //     proctab) tells us exactly where it is.
        {
            let child_cn = proctab(idx).cnode_cap;
            let frame_floor = proctab(idx).cap_layout.frame_slot_start;
            let cnode_bits = crate::lifecycle::spawn::effective_child_cnode_bits(child_cn);
            let cnode_total = 1u64 << cnode_bits;
            for slot in frame_floor..cnode_total {
                trona_kernel::invoke::cnode_delete(child_cn, slot);
            }
        }

        // 2b. Free old procmgr-side frame slots beyond the fixed objects
        let old_slot_base = proctab(idx).slot_base;
        let old_slot_count = proctab(idx).slot_count as usize;
        let off_fixed = crate::lifecycle::spawn::OFF_FIXED_END;

        if old_slot_count > off_fixed {
            for i in off_fixed..old_slot_count {
                let slot = old_slot_base + i as u64;
                let err = trona_kernel::invoke::cnode_revoke(crate::CAP_SELF_CSPACE, slot);
                if err != 0 {
                    trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, slot);
                }
            }
            alloc.free_slots(old_slot_base + off_fixed as u64, old_slot_count - off_fixed);
            proctab(idx).slot_count = off_fixed as u16;
        }

        if is_pe {
            let pe_span = unsafe {
                match trona_loader::common::pe::header::validate(elf_entry.data, elf_entry.data_len)
                {
                    Ok(h) => h.opt.size_of_image as u64,
                    Err(_) => 0,
                }
            };
            if pe_span == 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] EXEC: invalid PE image\n");
                });
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }

            let Some(pe_support) =
                crate::loader::pe_load::plan_pe_runtime_support(initrd, initrd_size)
            else {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] EXEC: PE runtime support not found\n");
                });
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            };

            let layout = trona_runtime::spawn::layout::compute_vm_layout_randomized(
                pe_span,
                pe_support.pe_rtld_span,
                pe_support.kernel32_pages,
                false,
                0,
                trona_runtime::spawn::stack_plan::StackLayoutSpec::default_service(),
                || trona_kernel::syscall::sys_getrandom(),
            );
            if layout.stack_top == 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] EXEC: PE too large for VA layout\n");
                });
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }

            let heap_base = layout.heap_base();
            let mmap_base = trona_runtime::spawn::layout::compute_mmap_base(&layout, heap_base);
            if !crate::base::mmsrv_ipc::register_mmsrv_client(
                badge, pid, proc_vs, heap_base, mmap_base,
            ) {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] EXEC: mmsrv re-register failed\n");
                });
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }

            let kind = PersonalityKind::Win32;

            let Some(pe_loads) = crate::loader::pe_load::load_pe_runtime_support(
                &pe_support,
                elf_entry.data,
                elf_entry.data_len,
                &layout,
                initrd,
                initrd_size,
                pid,
                proc_vs,
            ) else {
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            };
            let pe_result = pe_loads.pe_result;
            let rtld_result = pe_loads.rtld_result;
            let kernel32_result = pe_loads.kernel32_result;

            let err = crate::base::mmsrv_ipc::exec_map_ipc_buf_mmsrv(pid, layout.ipc_buf.base);
            if err != 0 {
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }

            let exec_cap_layout = proctab(idx).cap_layout;

            if !kind.prepare_runtime(
                pid,
                proctab(idx).cnode_cap,
                Some(exec_cap_layout.win32srv_ep),
                badge,
            ) {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] EXEC: win32 personality prepare failed\n");
                });
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }

            let stack_pages = layout.stack.page_count();
            let Some(stack_stage) = crate::loader::stack_build::alloc_zeroed_exec_stack_page()
            else {
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            };

            let cspace_layout = crate::lifecycle::spawn::child_service_cspace_layout(
                proctab(idx).cnode_cap,
                exec_cap_layout.frame_slot_start,
            );

            let child_rsp = match crate::loader::stack_build::write_pe_stack(
                &pe_result,
                &rtld_result,
                &kernel32_result,
                stack_stage,
                layout.scratch.base,
                layout.ipc_buf.base,
                exec_cap_layout.win32srv_ep,
                argc,
                envc,
                &exec_str_data,
                exec_str_len,
                layout.stack_top,
                cspace_layout,
                &exec_cap_layout,
                // exec preserves the parent's cap_table — no fresh
                // Require= resolution (the local-role caps were minted at
                // the original spawn and are still in the child cspace).
                &[],
                0,
                0,
                // exec preserves VFS client slot state (VFS_CLIENT_EXEC only
                // closes CLOEXEC-marked slots), so stdio slots 0/1/2 that
                // were populated at the original spawn remain live.
                crate::base::pty_handoff::STDIO_PRE_BITS_TTY,
            ) {
                Ok(rsp) => rsp,
                Err(_) => {
                    crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                    abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                    return;
                }
            };

            if !crate::loader::stack_build::commit_exec_stack_page(
                pid,
                layout.stack_top,
                layout.stack_spec,
                stack_stage,
                proctab(idx).tcb_cap,
            ) {
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }
            let _ = stack_pages;
            crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
            if let Some(ep) = badged_vfs.take() {
                crate::loader::vfs_load::cleanup_exec_source_on(ep, &mut vfs_source);
                crate::loader::vfs_load::release_badged_vfs_cap(ep);
            } else {
                crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
            }

            finalize_exec_transition(
                idx,
                reply,
                &mut badged_vfs,
                &mut vfs_source,
                kind,
                rtld_result.entry,
                child_rsp,
                layout,
                kernel32_result.base,
                crate::base::proc_table::ProcLibMap::zeroed(),
                &name,
                name_len,
                &exec_path,
                exec_path_len,
                file_mode,
                file_uid,
                file_gid,
                b"[PROCMGR] EXEC: PE PID=",
            );
            return;
        }

        let Some(elf_runtime) = crate::loader::elf_load::plan_elf_runtime(
            elf_entry.data,
            elf_entry.data_len,
            vfs_source.streamed(),
            initrd,
            initrd_size,
            false,
        ) else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: ELF too large for VA layout\n");
            });
            abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
            return;
        };
        let layout = elf_runtime.layout;

        // 4. Re-register with mmsrv for the new exec image
        let heap_base = layout.heap_base();
        let mmap_base = trona_runtime::spawn::layout::compute_mmap_base(&layout, heap_base);
        if !crate::base::mmsrv_ipc::register_mmsrv_client(badge, pid, proc_vs, heap_base, mmap_base)
        {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: mmsrv re-register failed\n");
            });
            abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
            return;
        }

        let Some(elf_loads) = crate::loader::elf_load::load_elf_runtime(
            elf_entry.data,
            elf_entry.data_len,
            vfs_source.streamed(),
            &elf_runtime,
            initrd,
            initrd_size,
            pid,
            proc_vs,
        ) else {
            abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
            return;
        };
        let elf_result = elf_loads.elf_result;
        let rtld_result = elf_loads.rtld_result;
        // 6. Map initrd and boot info for dynamic executables
        if is_dynamic {
            let err = crate::base::mmsrv_ipc::exec_map_bootinfo_mmsrv(pid);
            if err != 0 {
                abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                return;
            }
        }

        // 7. Map IPC buffer via mmsrv
        let err = crate::base::mmsrv_ipc::exec_map_ipc_buf_mmsrv(pid, layout.ipc_buf.base);
        if err != 0 {
            abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
            return;
        }

        let shared_lib_base = elf_loads.shared_lib_base;
        let shared_lib_map = elf_loads.shared_lib_map;

        // 9. Build the stack top page locally, then materialize it in mmsrv.
        let stack_pages = layout.stack.page_count();
        let Some(stack_stage) = crate::loader::stack_build::alloc_zeroed_exec_stack_page() else {
            abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
            return;
        };

        // 10. Entry point and final stack image.
        let mut new_entry = elf_result.entry;
        let new_rsp: u64;
        let (phdr_vaddr, phent, phnum) = if let Some(vfs) = vfs_source.streamed() {
            (layout.elf_code.base + vfs.phdr_vaddr, vfs.phent, vfs.phnum)
        } else {
            match trona_loader::common::elf::loader::get_phdr_info(
                elf_entry.data,
                elf_entry.data_len,
                layout.elf_code.base,
            ) {
                Some(info) => (info.phdr_vaddr, info.phent as u64, info.phnum as u64),
                None => {
                    crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                    abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                    return;
                }
            }
        };

        if is_dynamic {
            let exec_cap_layout = proctab(idx).cap_layout;
            match crate::loader::stack_build::write_dynamic_stack(
                phdr_vaddr,
                phent,
                phnum,
                0,
                &elf_result,
                &rtld_result,
                &elf_loads.mapped_images[..elf_loads.mapped_image_count],
                layout.shared_libs.base,
                layout.shared_libs.size,
                argc,
                envc,
                &exec_str_data,
                exec_str_len,
                layout.scratch.base,
                layout.stack_top,
                crate::lifecycle::spawn::child_service_cspace_layout(
                    proctab(idx).cnode_cap,
                    exec_cap_layout.frame_slot_start,
                ),
                &exec_cap_layout,
                stack_stage,
                true,
                // exec preserves the parent's cap_table — no fresh
                // Require= resolution (the local-role caps were minted at
                // the original spawn and are still in the child cspace).
                &[],
                0,
                0,
                // exec preserves VFS client slot state; stdio 0/1/2 remain.
                crate::base::pty_handoff::STDIO_PRE_BITS_TTY,
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                    new_entry = rtld_result.entry;
                }
                Err(_) => {
                    crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                    abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                    return;
                }
            }
        } else {
            match crate::loader::stack_build::write_static_stack(
                0,
                argc,
                envc,
                &exec_str_data,
                exec_str_len,
                layout.scratch.base,
                layout.stack_top,
                stack_stage,
                true,
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                }
                Err(_) => {
                    crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                    abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
                    return;
                }
            }
        }

        if !crate::loader::stack_build::commit_exec_stack_page(
            pid,
            layout.stack_top,
            layout.stack_spec,
            stack_stage,
            proctab(idx).tcb_cap,
        ) {
            abort_destroyed_exec(idx, reply, badged_vfs, &mut vfs_source);
            return;
        }
        let _ = stack_pages;
        crate::loader::mem_util::free_staging_buffer(stack_stage, 1);

        // Capture the exec argv into the process entry before the image is
        // replaced. exec_str_data holds NUL-separated argv+envp bytes; store
        // only the argv portion (first argc NUL-terminated strings).
        {
            let p = proctab(idx);
            let argv_bytes = {
                // Walk through exec_str_data to find the end of argv strings.
                let mut pos = 0usize;
                let mut strings_seen = 0u32;
                while strings_seen < argc && pos < exec_str_len {
                    if exec_str_data[pos] == 0 {
                        strings_seen += 1;
                    }
                    pos += 1;
                }
                pos
            };
            let copy_len = if argv_bytes > crate::base::proc_table::ARGV_BUF_LEN {
                crate::base::proc_table::ARGV_BUF_LEN
            } else {
                argv_bytes
            };
            for i in 0..copy_len {
                p.argv_buf[i] = exec_str_data[i];
            }
            for i in copy_len..crate::base::proc_table::ARGV_BUF_LEN {
                p.argv_buf[i] = 0;
            }
            p.argv_len = copy_len as u16;
        }

        finalize_exec_transition(
            idx,
            reply,
            &mut badged_vfs,
            &mut vfs_source,
            PersonalityKind::Posix,
            new_entry,
            new_rsp,
            layout,
            shared_lib_base,
            shared_lib_map,
            &name,
            name_len,
            &exec_path,
            exec_path_len,
            file_mode,
            file_uid,
            file_gid,
            b"[PROCMGR] EXEC: PID=",
        );

        // Don't reply -- process image replaced and resumed.
    }
}
