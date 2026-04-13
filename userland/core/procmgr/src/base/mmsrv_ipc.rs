// SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

const TRONA_OK: u64 = trona::TRONA_OK;
const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;

/// Map initrd pages into a child's VSpace for exec.
///
/// Tries device-mapping first. Falls back to mmsrv initrd copy transactions.
///
/// # Safety
/// `initrd` must point to the initrd data, `initrd_size` must be valid.
pub(crate) unsafe fn exec_map_initrd_mmsrv(
    proc_vs: Cap,
    initrd: *const u8,
    initrd_size: usize,
    pid: u32,
    initrd_base: u64,
) -> i32 {
    let initrd_pages = (initrd_size + 4095) / 4096;
    let mut mapped_device = true;

    for pg in 0..initrd_pages {
        let err = trona::invoke::vspace_map_device(
            proc_vs,
            trona::caps::initrd_untyped(),
            (pg as u64) * 4096,
            initrd_base + pg as u64 * 4096,
            VSPACE_FLAG_USER,
        );
        if err != 0 {
            for mapped_pg in 0..pg {
                trona::invoke::vspace_unmap(proc_vs, initrd_base + mapped_pg as u64 * 4096);
            }
            mapped_device = false;
            break;
        }
    }

    if mapped_device {
        return 0;
    }

    let _ = initrd;
    if alloc_initrd_copy_from_mmsrv(
        pid,
        initrd_base,
        initrd_pages as u64,
        initrd_size as u64,
        VSPACE_FLAG_USER,
    )
    .is_err()
    {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] exec: initrd MM_ALLOC_INITRD_COPY failed\n");
        });
        return -1;
    }

    0
}

/// Map boot info page into child VSpace for exec via mmsrv.
///
/// Returns 0 on success.
pub(crate) unsafe fn exec_map_bootinfo_mmsrv(pid: u32) -> i32 {
    if alloc_bootinfo_copy_from_mmsrv(pid, crate::BOOTINFO_VADDR, VSPACE_FLAG_USER).is_err() {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] exec: bootinfo MM_ALLOC_BOOTINFO_COPY failed\n");
        });
        return -1;
    }
    0
}

/// Map IPC buffer page into child VSpace for exec via mmsrv.
///
/// Returns 0 on success.
pub(crate) unsafe fn exec_map_ipc_buf_mmsrv(pid: u32, ipc_buf_vaddr: u64) -> i32 {
    unsafe {
        let mut mm_msg = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        mm_msg.label = trona::protocol::MM_MAP_BATCH;
        mm_msg.length = 4;
        mm_msg.regs[0] = pid as u64;
        mm_msg.regs[1] = ipc_buf_vaddr;
        mm_msg.regs[2] = 1;
        mm_msg.regs[3] = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const mm_msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK || mm_reply.regs[0] != 1 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] exec: IPC buf MM_MAP_BATCH failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(mm_reply.label);
                _lb.str(b" mapped=");
                _lb.hex(mm_reply.regs[0]);
                _lb.str(b" pid=");
                _lb.hex(pid as u64);
                _lb.str(b"\n");
            });
            return -1;
        }
        0
    }
}

/// Register a process with mmsrv.
///
/// `heap_base` is the page-aligned end of the ELF load span (brk).
/// `mmap_base` is derived from the process layout.
pub(crate) fn register_mmsrv_client(
    client_badge: u64,
    pid: u32,
    vspace_cap: Cap,
    heap_base: u64,
    mmap_base: u64,
) -> bool {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_REGISTER;
    msg.length = 4;
    msg.regs[0] = client_badge;
    msg.regs[1] = heap_base;
    msg.regs[2] = mmap_base;
    msg.regs[3] = pid as u64;
    unsafe {
        trona::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, vspace_cap);
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_with_mmsrv failed badge=");
                _lb.hex(client_badge);
                _lb.str(b" pid=");
                _lb.hex(pid as u64);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return false;
        }

        true
    }
}

pub(crate) fn register_with_mmsrv(
    pid: u32,
    vspace_cap: Cap,
    heap_base: u64,
    mmap_base: u64,
) -> bool {
    register_mmsrv_client(pid as u64, pid, vspace_cap, heap_base, mmap_base)
}

pub(crate) fn clear_fault_handler(tcb_cap: Cap, pid: u32) {
    if tcb_cap == 0 {
        return;
    }

    let err = trona::invoke::tcb_set_fault_handler(tcb_cap, 0);
    if err != 0 {
        trona::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] WARN: clear fault handler failed pid=");
            _lb.hex(pid as u64);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }
}

pub(crate) fn deregister_mmsrv_client(client_badge: u64) -> bool {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_DEREGISTER;
    msg.length = 1;
    msg.regs[0] = client_badge;
    let err = unsafe {
        trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        )
    };

    if err != 0 || mm_reply.label != trona::TRONA_OK {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] deregister_from_mmsrv failed badge=");
            _lb.hex(client_badge);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b" label=");
            _lb.hex(mm_reply.label);
            _lb.str(b"\n");
        });
        return false;
    }

    true
}

/// Deregister a process from mmsrv on spawn failure.
pub(crate) fn deregister_from_mmsrv(pid: u32) -> bool {
    deregister_mmsrv_client(pid as u64)
}

pub(crate) unsafe fn prefault_range_in_mmsrv(
    client_badge: u64,
    start_vaddr: u64,
    page_count: u64,
    prot: u64,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona::protocol::MM_PREFAULT_RANGE;
        msg.length = 4;
        msg.regs[0] = client_badge;
        msg.regs[1] = start_vaddr;
        msg.regs[2] = page_count;
        msg.regs[3] = prot;
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] MM_PREFAULT_RANGE failed badge=");
                _lb.hex(client_badge);
                _lb.str(b" addr=");
                _lb.hex(start_vaddr);
                _lb.str(b" pages=");
                _lb.hex(page_count);
                _lb.str(b" prot=");
                _lb.hex(prot);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return -1;
        }
        0
    }
}

pub(crate) unsafe fn mprotect_target_range_in_mmsrv(
    client_badge: u64,
    start_vaddr: u64,
    length: u64,
    prot: u64,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona::protocol::MM_MPROTECT_TARGET;
        msg.length = 4;
        msg.regs[0] = client_badge;
        msg.regs[1] = start_vaddr;
        msg.regs[2] = length;
        msg.regs[3] = prot;
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] MM_MPROTECT_TARGET failed badge=");
                _lb.hex(client_badge);
                _lb.str(b" addr=");
                _lb.hex(start_vaddr);
                _lb.str(b" len=");
                _lb.hex(length);
                _lb.str(b" prot=");
                _lb.hex(prot);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return -1;
        }
        0
    }
}

pub(crate) fn quiesce_and_deregister_mmsrv_client(
    tcb_cap: Cap,
    pid: u32,
    client_badge: u64,
) -> bool {
    clear_fault_handler(tcb_cap, pid);
    deregister_mmsrv_client(client_badge)
}

pub(crate) fn alloc_initrd_copy_from_mmsrv(
    pid: u32,
    region_base: u64,
    region_pages: u64,
    copy_len: u64,
    flags: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_INITRD_COPY;
    msg.length = 5;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = region_pages;
    msg.regs[3] = copy_len;
    msg.regs[4] = flags;
    unsafe {
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn alloc_bootinfo_copy_from_mmsrv(
    pid: u32,
    region_base: u64,
    flags: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_BOOTINFO_COPY;
    msg.length = 3;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = flags;
    unsafe {
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn copy_from_client_region_to_mmsrv(
    pid: u32,
    target_vaddr: u64,
    source_vaddr: u64,
    page_count: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_COPY_FROM_CLIENT_REGION;
    msg.length = 4;
    msg.regs[0] = pid as u64;
    msg.regs[1] = target_vaddr;
    msg.regs[2] = source_vaddr;
    msg.regs[3] = page_count;
    unsafe {
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn alloc_private_copy_from_client_region_to_mmsrv(
    pid: u32,
    region_base: u64,
    region_pages: u64,
    target_vaddr: u64,
    source_vaddr: u64,
    page_count: u64,
    flags: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION;
    msg.length = 7;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = region_pages;
    msg.regs[3] = target_vaddr;
    msg.regs[4] = source_vaddr;
    msg.regs[5] = page_count;
    msg.regs[6] = flags;
    unsafe {
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn alloc_typed_copy_from_client_region_to_mmsrv(
    pid: u32,
    region_base: u64,
    region_pages: u64,
    target_vaddr: u64,
    source_vaddr: u64,
    page_count: u64,
    flags: u64,
    region_type: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_TYPED_COPY_FROM_CLIENT_REGION;
    msg.length = 8;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = region_pages;
    msg.regs[3] = target_vaddr;
    msg.regs[4] = source_vaddr;
    msg.regs[5] = page_count;
    msg.regs[6] = flags;
    msg.regs[7] = region_type;
    unsafe {
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

/// # Safety
/// `_initrd` must point to valid initrd data, `initrd_size` must be valid.
pub(crate) unsafe fn map_initrd_to_child_tx(
    child_vs: Cap,
    _initrd: *const u8,
    initrd_size: usize,
    pid: u32,
    lib_window_pages: usize,
    initrd_base_vaddr: u64,
) -> i32 {
    let map_pages = if lib_window_pages > 0 {
            lib_window_pages
        } else {
            (initrd_size + 4095) / 4096
        };

        let mut mapped_with_device = true;

        for pg in 0..map_pages {
            let err = trona::invoke::vspace_map_device(
                child_vs,
                trona::caps::initrd_untyped(),
                (pg as u64) * 4096,
                initrd_base_vaddr + pg as u64 * 4096,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] initrd device map failed pg=");
                    _lb.hex(pg as u64);
                    _lb.str(b" err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                for mapped_pg in 0..pg {
                    trona::invoke::vspace_unmap(
                        child_vs,
                        initrd_base_vaddr + mapped_pg as u64 * 4096,
                    );
                }
                mapped_with_device = false;
                break;
            }
        }

        if mapped_with_device {
            return 0;
        }

        let _ = _initrd;
        let copy_size = map_pages * 4096;
        if alloc_initrd_copy_from_mmsrv(
            pid,
            initrd_base_vaddr,
            map_pages as u64,
            copy_size as u64,
            VSPACE_FLAG_USER,
        )
        .is_err()
        {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] initrd MM_ALLOC_INITRD_COPY failed\n");
            });
            return -1;
        }
    0
}

/// Map boot info page into child VSpace via mmsrv.
///
/// The child must already be registered with mmsrv (MM_REGISTER done).
pub(crate) unsafe fn map_boot_info_to_child_tx(child_vs: Cap, pid: u32) -> i32 {
    let _ = child_vs;
    if alloc_bootinfo_copy_from_mmsrv(pid, crate::BOOTINFO_VADDR, VSPACE_FLAG_USER).is_err() {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] bootinfo MM_ALLOC_BOOTINFO_COPY failed\n");
        });
        return -1;
    }
    0
}
