//! SaltyOS Win32 CSRSS — Win32 Subsystem Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Minimal Win32 subsystem server providing:
//! - Import resolution for PE binaries (kernel32.dll functions)
//!
//! Registers as "win32/csrss" with namesrv so PE processes can receive the
//! subsystem endpoint through the startup cap table.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::common::{TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_OK};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::win32::W32_RESOLVE_IMPORT;

// All system roles flow through the substrate `trona_runtime::client::caps::*` getters
// populated from the supervisor-built startup cap table.
const KERNEL32_PATH: &[u8] = b"/Windows/System32/kernel32.dll";
const MAX_IMPORT_NAME: usize = 144;
const MAX_EXPORT_NAME: usize = 128;
const MAX_PE_SECTIONS: usize = 64;

const PE_DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const PE_OPT_MAGIC_PE32PLUS: u16 = 0x020B;
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct DosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    ordinal_base: u32,
    address_table_entries: u32,
    number_of_name_pointers: u32,
    export_address_table_rva: u32,
    name_pointer_rva: u32,
    ordinal_table_rva: u32,
}

// ======================================================================
// Helpers
// ======================================================================

fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

fn max_u32(a: u32, b: u32) -> u32 {
    if a >= b { a } else { b }
}

unsafe fn vfs_open_readonly(path: &[u8]) -> i32 {
    match unsafe {
        trona_runtime::client::vfs::nt_open_existing_readonly(path.as_ptr(), path.len())
    } {
        Ok(fd) => fd,
        Err(_) => -1,
    }
}

unsafe fn vfs_close(fd: i32) {
    let _ = unsafe { trona_runtime::client::vfs::nt_close(fd) };
}

unsafe fn vfs_pread_exact(fd: i32, offset: u64, buf: &mut [u8]) -> bool {
    unsafe {
        trona_runtime::client::vfs::nt_read_exact_at(fd, offset, buf.as_mut_ptr(), buf.len() as u64)
            .is_ok()
    }
}

unsafe fn read_pod<T: Copy>(fd: i32, offset: u64) -> Option<T> {
    unsafe {
        let mut value: T = core::mem::zeroed();
        let bytes = core::slice::from_raw_parts_mut(
            (&raw mut value).cast::<u8>(),
            core::mem::size_of::<T>(),
        );
        if vfs_pread_exact(fd, offset, bytes) {
            Some(value)
        } else {
            None
        }
    }
}

unsafe fn read_c_string(fd: i32, offset: u64, out: &mut [u8]) -> Option<usize> {
    unsafe {
        if out.is_empty() {
            return None;
        }
        for i in 0..out.len() {
            let mut byte = [0u8; 1];
            if !vfs_pread_exact(fd, offset + i as u64, &mut byte) {
                return None;
            }
            if byte[0] == 0 {
                return Some(i);
            }
            out[i] = byte[0];
        }
        None
    }
}

fn rva_to_file_offset(rva: u32, size_of_headers: u32, sections: &[SectionHeader]) -> Option<u64> {
    if rva < size_of_headers {
        return Some(rva as u64);
    }
    let rva64 = rva as u64;
    for section in sections {
        let start = section.virtual_address as u64;
        let span = max_u32(section.virtual_size, section.size_of_raw_data) as u64;
        let end = start.checked_add(span)?;
        if rva64 >= start && rva64 < end {
            return Some(section.pointer_to_raw_data as u64 + (rva64 - start));
        }
    }
    None
}

fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

unsafe fn resolve_export_rva_by_ordinal(
    fd: i32,
    export_dir: &ExportDirectory,
    sections: &[SectionHeader],
    size_of_headers: u32,
    ordinal: u16,
) -> Option<u32> {
    unsafe {
        if ordinal == 0 || export_dir.address_table_entries == 0 {
            return None;
        }
        let ordinal_base = export_dir.ordinal_base;
        if (ordinal as u32) < ordinal_base {
            return None;
        }
        let index = (ordinal as u32) - ordinal_base;
        if index >= export_dir.address_table_entries {
            return None;
        }
        let func_rva_off = rva_to_file_offset(
            export_dir
                .export_address_table_rva
                .checked_add(index.checked_mul(4)?)?,
            size_of_headers,
            sections,
        )?;
        read_pod::<u32>(fd, func_rva_off)
    }
}

unsafe fn resolve_kernel32_export_rva(name: &[u8], ordinal: u16) -> Option<u32> {
    unsafe {
        let fd = vfs_open_readonly(KERNEL32_PATH);
        if fd < 0 {
            return None;
        }

        let mut resolved = None;

        let dos = match read_pod::<DosHeader>(fd, 0) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };
        if dos.e_magic != PE_DOS_MAGIC {
            vfs_close(fd);
            return None;
        }

        let pe_off = dos.e_lfanew as u64;
        let sig = match read_pod::<u32>(fd, pe_off) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };
        if sig != PE_SIGNATURE {
            vfs_close(fd);
            return None;
        }

        let coff_off = pe_off + 4;
        let coff = match read_pod::<CoffHeader>(fd, coff_off) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };

        let opt_off = coff_off + core::mem::size_of::<CoffHeader>() as u64;
        let opt = match read_pod::<OptionalHeader64>(fd, opt_off) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };
        if opt.magic != PE_OPT_MAGIC_PE32PLUS {
            vfs_close(fd);
            return None;
        }
        if coff.number_of_sections as usize > MAX_PE_SECTIONS {
            vfs_close(fd);
            return None;
        }
        if opt.number_of_rva_and_sizes as usize <= IMAGE_DIRECTORY_ENTRY_EXPORT {
            vfs_close(fd);
            return None;
        }

        let export_dirent_off = opt_off
            + core::mem::size_of::<OptionalHeader64>() as u64
            + (IMAGE_DIRECTORY_ENTRY_EXPORT * core::mem::size_of::<DataDirectory>()) as u64;
        let export_dirent = match read_pod::<DataDirectory>(fd, export_dirent_off) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };
        if export_dirent.virtual_address == 0 {
            vfs_close(fd);
            return None;
        }

        let sections_off = opt_off + coff.size_of_optional_header as u64;
        let mut sections: [SectionHeader; MAX_PE_SECTIONS] = core::mem::zeroed();
        for i in 0..coff.number_of_sections as usize {
            let sec_off = sections_off + (i * core::mem::size_of::<SectionHeader>()) as u64;
            match read_pod::<SectionHeader>(fd, sec_off) {
                Some(sec) => sections[i] = sec,
                None => {
                    vfs_close(fd);
                    return None;
                }
            }
        }
        let sections = &sections[..coff.number_of_sections as usize];

        let export_off = match rva_to_file_offset(
            export_dirent.virtual_address,
            opt.size_of_headers,
            sections,
        ) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };
        let export_dir = match read_pod::<ExportDirectory>(fd, export_off) {
            Some(v) => v,
            None => {
                vfs_close(fd);
                return None;
            }
        };

        if !name.is_empty() {
            for i in 0..export_dir.number_of_name_pointers {
                let name_rva_slot = export_dir.name_pointer_rva.checked_add(i.checked_mul(4)?)?;
                let name_rva_off =
                    match rva_to_file_offset(name_rva_slot, opt.size_of_headers, sections) {
                        Some(v) => v,
                        None => continue,
                    };
                let export_name_rva = match read_pod::<u32>(fd, name_rva_off) {
                    Some(v) => v,
                    None => continue,
                };
                let export_name_off =
                    match rva_to_file_offset(export_name_rva, opt.size_of_headers, sections) {
                        Some(v) => v,
                        None => continue,
                    };
                let mut export_name = [0u8; MAX_EXPORT_NAME];
                let export_name_len = match read_c_string(fd, export_name_off, &mut export_name) {
                    Some(v) => v,
                    None => continue,
                };
                if !bytes_equal(name, &export_name[..export_name_len]) {
                    continue;
                }

                let ordinal_slot = export_dir
                    .ordinal_table_rva
                    .checked_add(i.checked_mul(2)?)?;
                let ordinal_off =
                    match rva_to_file_offset(ordinal_slot, opt.size_of_headers, sections) {
                        Some(v) => v,
                        None => continue,
                    };
                let ordinal_index = match read_pod::<u16>(fd, ordinal_off) {
                    Some(v) => v as u32,
                    None => continue,
                };
                if ordinal_index >= export_dir.address_table_entries {
                    continue;
                }
                let func_rva_slot = export_dir
                    .export_address_table_rva
                    .checked_add(ordinal_index.checked_mul(4)?)?;
                let func_rva_off =
                    match rva_to_file_offset(func_rva_slot, opt.size_of_headers, sections) {
                        Some(v) => v,
                        None => continue,
                    };
                resolved = read_pod::<u32>(fd, func_rva_off);
                if resolved.is_some() {
                    break;
                }
            }
        } else {
            resolved = resolve_export_rva_by_ordinal(
                fd,
                &export_dir,
                sections,
                opt.size_of_headers,
                ordinal,
            );
        }

        vfs_close(fd);
        resolved
    }
}

/// Handle import resolution: look up a Win32 API function name and return
/// the exported RVA within kernel32.dll. The PE rtld adds the client's
/// mapped kernel32 base locally.
unsafe fn handle_resolve_import(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let name_len = (*msg).regs[0] as usize;
        let ordinal = (*msg).regs[1] as u16;
        let available = ((*msg).length.saturating_sub(2) as usize) * 8;
        if name_len > MAX_IMPORT_NAME || name_len > available {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let name = if name_len == 0 {
            &[][..]
        } else {
            core::slice::from_raw_parts((&raw const (*msg).regs[2]).cast::<u8>(), name_len)
        };

        let resolved_rva = resolve_kernel32_export_rva(name, ordinal).unwrap_or(0);
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = resolved_rva as u64;
        (*reply).length = 1;
    }
}

// ======================================================================
// Entry point
// ======================================================================

/// Cookie for the single service-pipe `STATE_READABLE` Watch (kind 0, slot 0,
/// generation 1). win32_csrss has one event source, so the cookie is constant.
const WIN32_CSRSS_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Single-source reactor dispatcher: the only armed event is `STATE_READABLE`
/// on the service pipe; routes by label and replies on the same pipe
/// (txid-correlated).
struct Win32CsrssDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    scratch: Cap,
}

impl trona_server::event_loop::EqDispatcher for Win32CsrssDispatcher {
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
            W32_RESOLVE_IMPORT => unsafe {
                handle_resolve_import(msg as *const TronaMsg, &raw mut reply)
            },
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
            WIN32_CSRSS_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[WIN32_CSRSS] Win32 subsystem server starting\n");
    });

    // Register with namesrv as "win32/csrss"
    if !register_with_namesrv() {
        return 1;
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[WIN32_CSRSS] ready, entering dispatch loop\n");
    });

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
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[WIN32_CSRSS] reactor EventQueue/Watch alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let scratch = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"win32_csrss recv scratch");
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        WIN32_CSRSS_SERVICE_COOKIE,
    );
    core::mem::forget(eq);
    core::mem::forget(watch);
    let mut reactor = trona_server::event_loop::EventLoop::new(
        eq_cap,
        Win32CsrssDispatcher {
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
fn register_with_namesrv() -> bool {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let mut reg_msg = TronaMsg::zeroed();
    let mut reg_reply = TronaMsg::zeroed();
    let svc_name = b"win32_csrss";
    reg_msg.label = NAMESRV_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
    unsafe {
        for i in 0..svc_name.len() {
            *ns_dst.add(i) = svc_name[i];
        }
    }
    reg_msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    reg_msg.length = (REGISTER_FLAGS_REG + 1) as u64;

    let publish_tc = trona_runtime::client::caps::service_client_ep_for_transfer();
    unsafe {
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.as_ref().map_or(0, |t| t.slot()));
        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const reg_msg,
            &raw mut reg_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        drop(publish_tc);
        if err == 0 && reg_reply.label == TRONA_OK {
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[WIN32_CSRSS] registered with namesrv\n");
            });
            true
        } else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[WIN32_CSRSS] namesrv registration failed\n");
            });
            false
        }
    }
}

fn idle() -> ! {
    loop {
        trona_kernel::syscall::yield_now();
    }
}
