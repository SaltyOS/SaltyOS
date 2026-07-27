// SPDX-License-Identifier: GPL-2.0-only
//! Miscellaneous top-level syscall handlers.

use super::{SyscallError, SyscallResult, restore_irq, save_irq_disable};
use core::sync::atomic::Ordering;

pub(super) fn syscall_set_invoke_depths(depth0: u64, depth1: u64) -> SyscallResult {
    if depth0 > 64 || depth1 > 64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let tcb = &*current_tcb;
        tcb.tcb_lock();
        (*current_tcb).invoke_depth0 = depth0 as u8;
        (*current_tcb).invoke_depth1 = depth1 as u8;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_clock_gettime(clock_id: u64) -> SyscallResult {
    match clock_id {
        0 | 1 | 4 | 9 | 10 | 11 | 12 => {}
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    }
    SyscallResult::ok(crate::arch::now_ns())
}

pub(super) fn syscall_sysinfo(header_ptr: u64, cpu_array_ptr: u64, capacity: u64) -> SyscallResult {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Header {
        uptime_ns: u64,
        boot_time_ns: u64,
        cpu_count: u32,
        cpus_written: u32,
        context_switches_total: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CpuEntry {
        idle_time_ns: u64,
        user_time_ns: u64,
        system_time_ns: u64,
        reserved: u64,
    }

    if header_ptr == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let scheduler = crate::sched::scheduler::scheduler();
    let cpu_count = scheduler.online_cpus as u32;
    let max_cpus = crate::arch::MAX_CPUS as u32;
    let effective = cpu_count.min(max_cpus);

    let mut ctxsw_total: u64 = 0;
    for cpu in 0..(effective as usize) {
        ctxsw_total =
            ctxsw_total.saturating_add(scheduler.context_switches[cpu].load(Ordering::Acquire));
    }

    let to_write = if cpu_array_ptr == 0 {
        0u32
    } else {
        capacity.min(effective as u64) as u32
    };

    let header = Header {
        uptime_ns: crate::arch::now_ns(),
        boot_time_ns: crate::kernel::time::BOOT_TIME_NS.load(Ordering::Relaxed),
        cpu_count: effective,
        cpus_written: to_write,
        context_switches_total: ctxsw_total,
    };

    unsafe {
        if !crate::arch::uaccess::copy_to_user(header_ptr, &header) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
    }

    if to_write > 0 {
        let mut addr = cpu_array_ptr;
        for cpu in 0..(to_write as usize) {
            let entry = CpuEntry {
                idle_time_ns: scheduler.idle_runtime_ns[cpu].load(Ordering::Acquire),
                user_time_ns: scheduler.per_cpu_user_runtime_ns[cpu].load(Ordering::Acquire),
                system_time_ns: scheduler.per_cpu_system_runtime_ns[cpu].load(Ordering::Acquire),
                reserved: 0,
            };
            unsafe {
                if !crate::arch::uaccess::copy_to_user(addr, &entry) {
                    return SyscallResult::err(SyscallError::InvalidArgument);
                }
            }
            addr = addr.saturating_add(core::mem::size_of::<CpuEntry>() as u64);
        }
    }

    SyscallResult::ok(to_write as u64)
}

pub(super) fn syscall_sys_mem_info(out_ptr: u64) -> SyscallResult {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Out {
        pages_total: u64,
        pages_free: u64,
        pages_untyped_reserved: u64,
        pages_mo_data: u64,
        pages_mo_meta: u64,
        pages_page_cache: u64,
        pages_anon_private: u64,
        pages_anon_shared: u64,
        pages_file: u64,
        pages_kernel_pagetable: u64,
        pages_kernel_stack: u64,
        pages_kernel_slab: u64,
        pages_emergency_reserve: u64,
        pages_dirty_file: u64,
        pages_writeback_file: u64,
        pages_active: u64,
        pages_inactive: u64,
        page_size: u64,
        snapshot_ns: u64,
        reserved: [u64; 1],
    }

    if out_ptr == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Use the cached (≤1 s) activity snapshot so frequent mem-info reads do
    // not each trigger an uncached IRQ-disabled page-table sweep.
    let _ = crate::mm::vspace::global_activity_snapshot();
    let snap = crate::mm::pmm_memsnapshot();
    let slab = snap
        .pages_kernel_private
        .saturating_sub(snap.kmeta_pagetable)
        .saturating_sub(snap.kmeta_kernel_stack)
        .saturating_sub(snap.kmeta_cow_pool);
    let out = Out {
        pages_total: snap.pages_total as u64,
        pages_free: snap.pages_free as u64,
        pages_untyped_reserved: snap.pages_untyped_reserved as u64,
        pages_mo_data: snap.pages_mo_data as u64,
        pages_mo_meta: snap.pages_mo_meta as u64,
        pages_page_cache: snap.pages_page_cache as u64,
        pages_anon_private: snap.pages_anon_private as u64,
        pages_anon_shared: snap.pages_anon_shared as u64,
        pages_file: snap.pages_file as u64,
        pages_kernel_pagetable: snap.kmeta_pagetable as u64,
        pages_kernel_stack: snap.kmeta_kernel_stack as u64,
        pages_kernel_slab: slab as u64,
        pages_emergency_reserve: snap.pages_emergency_reserve as u64,
        pages_dirty_file: snap.pages_dirty_file as u64,
        pages_writeback_file: snap.pages_writeback_file as u64,
        pages_active: snap.pages_active as u64,
        pages_inactive: snap.pages_inactive as u64,
        page_size: crate::mm::PAGE_SIZE as u64,
        snapshot_ns: crate::arch::now_ns(),
        reserved: [0u64; 1],
    };

    unsafe {
        if !crate::arch::uaccess::copy_to_user(out_ptr, &out) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
    }

    SyscallResult::ok(0)
}
