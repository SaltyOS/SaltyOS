// SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::alloc::Allocator;
use crate::base::proc_table;
use crate::lifecycle::spawn::compute_ready_timeout_ns;
use crate::lifecycle::spawn::{
    SpawnPlan, SpawnSessionPolicy, compute_slot_budget, configure_spawn_scheduler,
    finalize_spawn_launch, prepare_spawn_child_base,
};
use crate::loader::mem_util::free_staging_buffer;
use crate::loader::pe_load::{load_pe_runtime_support, plan_pe_runtime_support};
use crate::loader::stack_build::{
    alloc_zeroed_staged_stack_page, commit_staged_top_stack_page, pack_spawn_argv_strings,
    write_pe_stack,
};
use crate::personality::PersonalityKind;

use trona_runtime::spawn::layout;

pub(crate) unsafe fn handle_pe_spawn_inner(
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    badge: u64,
    alloc: &mut Allocator,
    data: *const u8,
    data_len: usize,
    name: &[u8],
    name_len: usize,
    exec_path: &[u8],
    exec_path_len: usize,
    kind: PersonalityKind,
    readiness_mode: u64,
    requested_timeout_ns: u64,
    spawn_flags: u64,
    spawn_args_len: usize,
    args_reg_idx: usize,
    use_pre_ep: bool,
    start_suspended: bool,
    _policy_map_initrd: bool,
    policy_is_display: bool,
    policy_cnode_bits: u8,
    is_display: bool,
) -> bool {
    unsafe {
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PE spawn: '");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"'\n");
        });

        let base_start = crate::basename_of(name, name_len);

        let pe_headers = match trona_loader::common::pe::header::validate(data, data_len) {
            Ok(h) => h,
            Err(_) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] PE validation failed\n");
                });
                reply.label = trona_protocol::posix::TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let pe_span = pe_headers.opt.size_of_image as u64;
        if pe_span == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PE span is zero\n");
            });
            reply.label = trona_protocol::posix::TRONA_INVALID_ARGUMENT;
            return false;
        }

        let initrd = crate::INITRD_VADDR as *const u8;
        let initrd_size = crate::read_boot_info_initrd_size();

        let Some(pe_support) = plan_pe_runtime_support(initrd, initrd_size) else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PE runtime support not found\n");
            });
            reply.label = trona_protocol::posix::TRONA_NOT_FOUND;
            return false;
        };

        let layout = layout::compute_vm_layout_randomized(
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
                _lb.str(b"[PROCMGR] PE too large for VA layout\n");
            });
            reply.label = trona_protocol::posix::TRONA_INVALID_ARGUMENT;
            return false;
        }

        let effective_timeout_ns =
            if readiness_mode == trona_runtime::core::server_consts::SPAWN_READY_NOTIFY {
                compute_ready_timeout_ns(requested_timeout_ns, true, data_len, 0)
            } else {
                0
            };

        let plan = SpawnPlan {
            is_dynamic: true,
            readiness_mode,
            ready_timeout_ns: effective_timeout_ns,
            total_slots: compute_slot_budget(),
            is_display,
            lib_window_pages: 0,
            layout,
        };

        let basename = &name[base_start..name_len];
        if use_pre_ep {
            let _ = crate::service::registry::adopt_provider_from_scratch(basename);
        }

        let Some(base) = prepare_spawn_child_base(
            alloc,
            reply,
            badge,
            kind,
            &plan,
            policy_cnode_bits,
            use_pre_ep,
            basename,
        ) else {
            return false;
        };

        let slot_idx = base.slot_idx;
        let pid = base.pid;
        let child_tcb = base.child_tcb;
        let child_vs = base.child_vs;
        let child_cn = base.child_cn;
        let child_sc = base.child_sc;
        let child_sig_ntfn = base.child_sig_ntfn;
        let ready_badge_bit = base.ready_badge_bit;
        let cn_size_bits = base.cn_size_bits;
        let rtld_untyped_count = base.rtld_untyped_count;
        let cap_layout = base.cap_layout;

        if !kind.prepare_runtime(pid, child_cn, Some(cap_layout.win32srv_ep), pid as u64) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PE personality prepare failed\n");
            });
            crate::lifecycle::exit::abort_spawning_process(slot_idx);
            reply.label = trona_protocol::posix::TRONA_OUT_OF_MEMORY;
            return false;
        }

        let Some(pe_loads) = load_pe_runtime_support(
            &pe_support,
            data,
            data_len,
            &plan.layout,
            initrd,
            initrd_size,
            pid,
            child_vs,
        ) else {
            crate::lifecycle::exit::abort_spawning_process(slot_idx);
            reply.label = trona_protocol::posix::TRONA_NOT_FOUND;
            return false;
        };
        let pe_result = pe_loads.pe_result;
        let rtld_result = pe_loads.rtld_result;
        let kernel32_result = pe_loads.kernel32_result;

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PE layout pid=");
            _lb.hex(pid as u64);
            _lb.str(b" pe=[");
            _lb.hex(pe_result.base);
            _lb.str(b",");
            _lb.hex(pe_result.image_end);
            _lb.str(b") rtld=[");
            _lb.hex(rtld_result.base);
            _lb.str(b",");
            _lb.hex(rtld_result.base + rtld_result.brk);
            _lb.str(b") kernel32=[");
            _lb.hex(kernel32_result.base);
            _lb.str(b",");
            _lb.hex(kernel32_result.image_end);
            _lb.str(b") pe_entry=");
            _lb.hex(pe_result.entry);
            _lb.str(b" rtld_entry=");
            _lb.hex(rtld_result.entry);
            _lb.str(b"\n");
        });

        if !configure_spawn_scheduler(reply, slot_idx, child_tcb, child_sc) {
            return false;
        }

        let stack_pages = plan.layout.stack.page_count();
        let stack_stage = match alloc_zeroed_staged_stack_page(reply, slot_idx) {
            Some(stage) => stage,
            None => return false,
        };

        let cspace_layout = crate::lifecycle::spawn::service_cspace_layout(
            cn_size_bits as u64,
            cap_layout.frame_slot_start,
            rtld_untyped_count,
            crate::lifecycle::spawn::compute_rtld_untyped_size_bits(
                true,
                plan.layout.shared_libs.size,
            ),
        );

        let mut str_buf = [0u8; 256];
        let (argc, str_pos) = pack_spawn_argv_strings(
            msg,
            args_reg_idx,
            spawn_args_len,
            &name,
            name_len,
            &exec_path,
            exec_path_len,
            &mut str_buf,
            true,
        );

        let envc: u32 = 0;
        let win32srv_ep = cap_layout.win32srv_ep;

        // PE spawn follows the same stdio_mode dispatch as the ELF
        // path. The Win32 CRT is not yet taught to read the
        // preinstalled bitmap, so PE children currently always do a
        // lazy `/dev/console` bind on first stdio use. If PE-side
        // StandardInput=tty is ever exposed, the dispatch in spawn.rs
        // can be lifted into a shared helper; until then, PE spawn
        // always ships a zero bitmap.
        let preinstalled_stdio_bits = 0u64;

        let child_entry_rip;
        let child_rsp;
        match write_pe_stack(
            &pe_result,
            &rtld_result,
            &kernel32_result,
            stack_stage,
            plan.layout.scratch.base,
            plan.layout.ipc_buf.base,
            win32srv_ep,
            argc,
            envc,
            &str_buf,
            str_pos,
            plan.layout.stack_top,
            cspace_layout,
            &cap_layout,
            &name[base_start..name_len],
            pid,
            child_cn,
            preinstalled_stdio_bits,
        ) {
            Ok(rsp) => {
                child_rsp = rsp;
                child_entry_rip = rtld_result.entry;
            }
            Err(_) => {
                free_staging_buffer(stack_stage, 1);
                crate::lifecycle::exit::abort_spawning_process(slot_idx);
                reply.label = trona_protocol::posix::TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        if !commit_staged_top_stack_page(
            reply,
            slot_idx,
            plan.layout.stack_top,
            plan.layout.stack_spec,
            stack_stage,
            child_tcb,
        ) {
            return false;
        }
        let _ = stack_pages;
        free_staging_buffer(stack_stage, 1);

        return finalize_spawn_launch(
            reply,
            badge,
            kind,
            &plan,
            start_suspended,
            spawn_flags,
            slot_idx,
            pid,
            child_tcb,
            ready_badge_bit,
            child_sig_ntfn,
            kernel32_result.base,
            proc_table::ProcLibMap::zeroed(),
            use_pre_ep,
            &name,
            name_len,
            exec_path,
            exec_path_len,
            child_entry_rip,
            child_rsp,
            b"[PROCMGR] PE ",
            SpawnSessionPolicy::InheritCaller,
            cap_layout,
            msg,
            args_reg_idx,
            spawn_args_len,
        );
    }
}
