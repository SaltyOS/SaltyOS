// SPDX-License-Identifier: GPL-2.0-only
//! Kernel-authority capability handlers — RNG, shutdown, clocks,
//! system info, debug.

const CLOCK_MONOTONIC: u64 = uapi::KERNITE_CLOCK_ID_MONOTONIC as u64;
const CLOCK_REALTIME: u64 = uapi::KERNITE_CLOCK_ID_REALTIME as u64;

use super::{
    CapRights, Capability, ObjectType, SyscallError, SyscallResult, copy_to_current_ipc_words,
    syscall_error_from_cap_error, validate_capability,
};
use crate::cap::{CapRef, KernelObject};
use crate::event::irq::{IrqHandler, MAX_IRQS};
use crate::mm::PAGE_SIZE;

pub(super) fn syscall_rng_read(cap: &Capability, user_buf: u64, user_len: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::KernelRng, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if user_buf == 0 || user_len == 0 {
        return SyscallResult::ok(0);
    }
    let mut staging = [0u8; 64];
    let mut written: u64 = 0;
    while written < user_len {
        let want = ((user_len - written) as usize).min(staging.len());
        let mut filled = 0usize;
        while filled < want {
            let chunk = match crate::kernel::random::rdrand64() {
                Some(v) => v,
                None => return SyscallResult::err(SyscallError::InvalidOperation),
            };
            let take = (want - filled).min(8);
            for i in 0..take {
                staging[filled + i] = ((chunk >> (i * 8)) & 0xFF) as u8;
            }
            filled += take;
        }
        unsafe {
            if !crate::arch::uaccess::copy_to_user_bytes(user_buf + written, staging.as_ptr(), want)
            {
                return SyscallResult::err(SyscallError::BadAddress);
            }
        }
        written += want as u64;
    }
    SyscallResult::ok(written)
}

pub(super) fn syscall_system_shutdown(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SystemControl, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    crate::arch::shutdown();
}

pub(super) fn syscall_system_reboot(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SystemControl, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    crate::arch::reboot();
}

pub(super) fn syscall_clock_read(cap: &Capability, clock_id: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Clock, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let now = match clock_id {
        CLOCK_MONOTONIC => crate::arch::now_ns(),
        CLOCK_REALTIME => crate::arch::now_ns().saturating_add(
            crate::kernel::time::BOOT_TIME_NS.load(core::sync::atomic::Ordering::Relaxed),
        ),
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    };
    SyscallResult::ok(now)
}

/// `SYSINFO_GET_INFO` — system-wide CPU/time snapshot.
///
/// Writes a `Header` to `header_ptr` and, when `cpu_array_ptr` is
/// non-zero, up to `capacity` `CpuEntry` records to `cpu_array_ptr`
/// (packed). `Header.cpus_written` and the returned value both report
/// the per-CPU record count actually copied. The two structs mirror
/// `TronaSysInfo` / `TronaSysInfoCpu` in `lib/trona/protocol/src/init.rs`
/// byte-for-byte; the trailing `_reserved` word leaves room for
/// irq/steal counters.
///
/// The scheduler already owns the per-CPU accumulators, so this reads
/// kernel state directly — no init brokering. A `SystemInfo` invoke
/// never blocks on a userland peer.
pub(super) fn syscall_system_get_info(
    cap: &Capability,
    header_ptr: u64,
    cpu_array_ptr: u64,
    capacity: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SystemInfo, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if header_ptr == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

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

    let scheduler = crate::sched::scheduler::scheduler();
    let online = scheduler.online_cpus as u32;
    let effective = online.min(crate::arch::MAX_CPUS as u32);
    let to_write = if cpu_array_ptr == 0 {
        0u32
    } else {
        capacity.min(effective as u64) as u32
    };

    let mut ctxsw_total: u64 = 0;
    for cpu in 0..(effective as usize) {
        ctxsw_total = ctxsw_total.saturating_add(
            scheduler.context_switches[cpu].load(core::sync::atomic::Ordering::Acquire),
        );
    }

    let header = Header {
        uptime_ns: crate::arch::now_ns(),
        boot_time_ns: crate::kernel::time::BOOT_TIME_NS.load(core::sync::atomic::Ordering::Relaxed),
        cpu_count: effective,
        cpus_written: to_write,
        context_switches_total: ctxsw_total,
    };

    unsafe {
        if !crate::arch::uaccess::copy_to_user(header_ptr, &header) {
            return SyscallResult::err(SyscallError::BadAddress);
        }
    }

    let mut addr = cpu_array_ptr;
    for cpu in 0..(to_write as usize) {
        let entry = CpuEntry {
            idle_time_ns: scheduler.idle_runtime_ns[cpu]
                .load(core::sync::atomic::Ordering::Acquire),
            user_time_ns: scheduler.per_cpu_user_runtime_ns[cpu]
                .load(core::sync::atomic::Ordering::Acquire),
            system_time_ns: scheduler.per_cpu_system_runtime_ns[cpu]
                .load(core::sync::atomic::Ordering::Acquire),
            reserved: 0,
        };
        unsafe {
            if !crate::arch::uaccess::copy_to_user(addr, &entry) {
                return SyscallResult::err(SyscallError::BadAddress);
            }
        }
        addr = addr.saturating_add(core::mem::size_of::<CpuEntry>() as u64);
    }

    SyscallResult::ok(to_write as u64)
}

pub(super) fn syscall_system_get_meminfo(cap: &Capability, out_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SystemInfo, CapRights::READ) {
        return SyscallResult::err(e);
    }
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

    // Use the cached (≤1 s) activity snapshot: procfs reads /proc/meminfo
    // frequently, and an uncached `force_global_activity_snapshot` runs an
    // IRQ-disabled page-table sweep over every live VSpace on every read.
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
        page_size: PAGE_SIZE as u64,
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

pub(super) fn syscall_kdebug_putchar(cap: &Capability, ch: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::KernelDebug, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    crate::kernel::printk::serial_putc_hw(ch as u8);
    SyscallResult::ok(0)
}

pub(super) fn syscall_kdebug_putstr(
    cap: &Capability,
    user_buf: u64,
    user_len: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::KernelDebug, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let len = user_len.min(4096) as usize;
    let mut staging = [0u8; 4096];
    unsafe {
        if !crate::arch::uaccess::copy_from_user_bytes(user_buf, staging.as_mut_ptr(), len) {
            return SyscallResult::err(SyscallError::BadAddress);
        }
    }
    crate::kernel::printk::serial_write_hw(&staging[..len]);
    SyscallResult::ok(len as u64)
}

pub(super) fn syscall_kdebug_putbuf(
    cap: &Capability,
    user_buf: u64,
    user_len: u64,
) -> SyscallResult {
    syscall_kdebug_putstr(cap, user_buf, user_len)
}

pub(super) fn syscall_kdebug_dump_state(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::KernelDebug, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    crate::kernel::panic::dump_system_state("KDEBUG_DUMP_STATE");
    SyscallResult::ok(0)
}

pub(super) fn syscall_kdebug_console_control(cap: &Capability, enable: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::KernelDebug, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    if enable == 0 {
        crate::console::disable();
    } else {
        crate::console::enable();
    }
    SyscallResult::ok(0)
}

fn consume_dest_depth() -> Result<u8, SyscallError> {
    let current = crate::sched::scheduler::scheduler().current();
    if current.is_null() {
        return Err(SyscallError::InvalidOperation);
    }
    let (dest_depth, _) = unsafe { super::cspace::read_invoke_depths(current) };
    Ok(dest_depth)
}

unsafe fn create_device_cap_locked(
    dest_cspace: u64,
    dest_slot: u64,
    dest_depth: u8,
    obj_type: ObjectType,
    make_object: impl FnOnce() -> Option<*mut KernelObject>,
) -> SyscallResult {
    unsafe {
        super::cspace::with_cap_lock(|| {
            let dest_root = match super::cspace::lookup_cnode_root(dest_cspace, CapRights::WRITE) {
                Ok(root) => root,
                Err(err) => return SyscallResult::err(err),
            };
            let (leaf, index) = match super::cspace::resolve_invoke_write_slot(
                &*dest_root,
                dest_slot,
                dest_depth,
            ) {
                Ok(slot) => slot,
                Err(err) => return SyscallResult::err(err),
            };
            if !(*leaf).is_slot_empty(index) {
                return SyscallResult::err(SyscallError::SlotOccupied);
            }
            let Some(cap_slot) = crate::cap::alloc_slot() else {
                return SyscallResult::err(SyscallError::OutOfMemory);
            };
            let Some(object) = make_object() else {
                crate::cap::write_capability(cap_slot, Capability::null());
                crate::cap::free_slot(cap_slot);
                return SyscallResult::err(SyscallError::InsufficientResources);
            };
            crate::cap::write_capability(
                cap_slot,
                Capability {
                    object,
                    badge: 0,
                    // Device caps never confer EXECUTE (W^X egress invariant).
                    rights: CapRights::ALL.without(CapRights::EXECUTE),
                    obj_type,
                    depth: 0,
                    _reserved: 0,
                    _pad: 0,
                },
            );
            match (&mut *leaf).insert_ref(index, CapRef::new(cap_slot)) {
                Ok(()) => SyscallResult::ok(0),
                Err(err) => {
                    crate::cap::write_capability(cap_slot, Capability::null());
                    crate::cap::free_slot(cap_slot);
                    SyscallResult::err(syscall_error_from_cap_error(err))
                }
            }
        })
    }
}

pub(super) fn syscall_device_control_create_ioport(
    cap: &Capability,
    base_port: u64,
    num_ports: u64,
    dest_cspace: u64,
    dest_slot: u64,
) -> SyscallResult {
    if let Err(err) = validate_capability(cap, ObjectType::DeviceControl, CapRights::CONFIGURE) {
        return SyscallResult::err(err);
    }
    if num_ports == 0 || base_port >= 0x1_0000 || num_ports > u16::MAX as u64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let Some(end) = base_port.checked_add(num_ports) else {
        return SyscallResult::err(SyscallError::InvalidArgument);
    };
    if end > 0x1_0000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let dest_depth = match consume_dest_depth() {
        Ok(depth) => depth,
        Err(err) => return SyscallResult::err(err),
    };
    unsafe {
        create_device_cap_locked(
            dest_cspace,
            dest_slot,
            dest_depth,
            ObjectType::IoPort,
            || {
                crate::init::main::alloc_dynamic_ioport(base_port as u16, num_ports as u16)
                    .map(|obj| obj as *mut KernelObject)
            },
        )
    }
}

pub(super) fn syscall_device_control_create_device_untyped(
    cap: &Capability,
    phys_addr: u64,
    size_bits: u64,
    dest_cspace: u64,
    dest_slot: u64,
) -> SyscallResult {
    if let Err(err) = validate_capability(cap, ObjectType::DeviceControl, CapRights::CONFIGURE) {
        return SyscallResult::err(err);
    }
    if !(12..=52).contains(&size_bits) || phys_addr & (PAGE_SIZE as u64 - 1) != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let size = 1u64 << size_bits;
    if phys_addr.checked_add(size).is_none() {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let dest_depth = match consume_dest_depth() {
        Ok(depth) => depth,
        Err(err) => return SyscallResult::err(err),
    };
    unsafe {
        create_device_cap_locked(
            dest_cspace,
            dest_slot,
            dest_depth,
            ObjectType::Untyped,
            || {
                crate::init::main::alloc_device_untyped(phys_addr, size_bits as u8)
                    .map(|obj| obj as *mut KernelObject)
            },
        )
    }
}

pub(super) fn syscall_device_control_create_irq_handler(
    cap: &Capability,
    irq: u64,
    dest_cspace: u64,
    dest_slot: u64,
    flags: u64,
) -> SyscallResult {
    if let Err(err) = validate_capability(cap, ObjectType::DeviceControl, CapRights::CONFIGURE) {
        return SyscallResult::err(err);
    }
    if irq as usize >= MAX_IRQS {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let dest_depth = match consume_dest_depth() {
        Ok(depth) => depth,
        Err(err) => return SyscallResult::err(err),
    };
    let mut handler_ptr: *mut IrqHandler = core::ptr::null_mut();
    let result = unsafe {
        create_device_cap_locked(
            dest_cspace,
            dest_slot,
            dest_depth,
            ObjectType::IrqHandler,
            || {
                crate::init::main::alloc_dynamic_irq_handler(irq as u32).map(|obj| {
                    handler_ptr = obj;
                    obj as *mut KernelObject
                })
            },
        )
    };
    if result.error == 0 && !handler_ptr.is_null() {
        unsafe {
            (*handler_ptr).level_triggered = (flags & 1) != 0;
        }
        let _ = crate::event::irq::register_handler(irq as usize, handler_ptr);
    }
    result
}

// Untyped statistics
pub(super) fn syscall_untyped_get_stats(cap: &Capability, out_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Untyped, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if out_ptr == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    unsafe {
        let ut = &*(cap.object as *const crate::cap::UntypedMemory);
        if let Err(err) =
            copy_to_current_ipc_words(0, &[ut.size_bytes() as u64, ut.available() as u64])
        {
            return SyscallResult::err(err);
        }
    }
    SyscallResult::ok(0)
}
