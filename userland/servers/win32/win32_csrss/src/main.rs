//! SaltyOS Win32 CSRSS — Win32 Subsystem Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Minimal Win32 subsystem server providing:
//! - Import resolution for PE binaries (kernel32.dll functions)
//! - Console I/O delegation to the console server
//! - Per-client console mode tracking
//!
//! Registers as "win32/csrss" with namesrv so procmgr can look up
//! the endpoint and pass it to PE processes via AT_SALTYOS_WIN32SRV.

#![no_std]
#![no_main]

extern crate trona;

use trona::consts::kernel::*;
use trona::consts::posix::O_RDONLY;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::namesrv::*;
use trona::protocol::server::*;
use trona::protocol::vfs::*;
use trona::protocol::win32::*;
use trona::types::core::*;
use trona::types::pe::*;

// ======================================================================
// Capability slot layout (set by .service file)
// ======================================================================

const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NAMESRV_EP: u64 = 64;   // NeedEP namesrv:64
const CAP_CONSOLE_EP: u64 = 65;   // NeedEP console:65
const CAP_VFS_EP: u64 = 66;       // NeedEP vfs:66
const KERNEL32_PATH: &[u8] = b"/initrd/kernel32.dll";
const MAX_IMPORT_NAME: usize = 144;
const MAX_EXPORT_NAME: usize = 128;
const MAX_PE_SECTIONS: usize = 64;

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

// ======================================================================
// Per-client state
// ======================================================================

const MAX_CLIENTS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct ClientState {
    badge: u64,
    active: bool,
    input_mode: u32,
    output_mode: u32,
}

impl ClientState {
    const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            active: false,
            input_mode: DEFAULT_INPUT_MODE,
            output_mode: DEFAULT_OUTPUT_MODE,
        }
    }
}

static mut CLIENTS: [ClientState; MAX_CLIENTS] = [ClientState::zeroed(); MAX_CLIENTS];

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
    trona::current_ipc_ctx()
}

fn max_u32(a: u32, b: u32) -> u32 {
    if a >= b { a } else { b }
}

unsafe fn pack_path(msg: *mut TronaMsg, offset: usize, path: &[u8]) -> u8 {
    unsafe {
        let avail = (20usize.saturating_sub(offset + 1)) * 8;
        let limit = if path.len() < avail { path.len() } else { avail };
        let path_len = limit as u8;
        (*msg).regs[offset] = path_len as u64;
        for i in (offset + 1)..20 {
            (*msg).regs[i] = 0;
        }
        let dst = &raw mut (*msg).regs[offset + 1] as *mut u8;
        for (i, byte) in path[..limit].iter().enumerate() {
            *dst.add(i) = *byte;
        }
        path_len
    }
}

unsafe fn vfs_open_readonly(path: &[u8]) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_OPEN;
        msg.regs[0] = 0;
        msg.regs[1] = O_RDONLY as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

unsafe fn vfs_close(fd: i32) {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;
        let _ = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const msg, &raw mut reply);
    }
}

unsafe fn vfs_pread_exact(fd: i32, offset: u64, buf: &mut [u8]) -> bool {
    unsafe {
        let mut done = 0usize;
        while done < buf.len() {
            let remaining = buf.len() - done;
            let chunk = if remaining > 152 { 152 } else { remaining };
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_PREAD;
            msg.length = 3;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk as u64;
            msg.regs[2] = offset + done as u64;

            let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const msg, &raw mut reply);
            if err != 0 || reply.label != TRONA_OK {
                return false;
            }

            let actual = reply.regs[0] as usize;
            if actual == 0 || actual > chunk {
                return false;
            }

            let src = &reply.regs[1] as *const u64 as *const u8;
            for i in 0..actual {
                buf[done + i] = *src.add(i);
            }
            done += actual;
        }
        true
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
            export_dir.export_address_table_rva.checked_add(index.checked_mul(4)?)?,
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

        let export_off = match rva_to_file_offset(export_dirent.virtual_address, opt.size_of_headers, sections) {
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
                let name_rva_off = match rva_to_file_offset(name_rva_slot, opt.size_of_headers, sections) {
                    Some(v) => v,
                    None => continue,
                };
                let export_name_rva = match read_pod::<u32>(fd, name_rva_off) {
                    Some(v) => v,
                    None => continue,
                };
                let export_name_off = match rva_to_file_offset(export_name_rva, opt.size_of_headers, sections) {
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

                let ordinal_slot = export_dir.ordinal_table_rva.checked_add(i.checked_mul(2)?)?;
                let ordinal_off = match rva_to_file_offset(ordinal_slot, opt.size_of_headers, sections) {
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
                let func_rva_slot = export_dir.export_address_table_rva.checked_add(ordinal_index.checked_mul(4)?)?;
                let func_rva_off = match rva_to_file_offset(func_rva_slot, opt.size_of_headers, sections) {
                    Some(v) => v,
                    None => continue,
                };
                resolved = read_pod::<u32>(fd, func_rva_off);
                if resolved.is_some() {
                    break;
                }
            }
        } else {
            resolved = resolve_export_rva_by_ordinal(fd, &export_dir, sections, opt.size_of_headers, ordinal);
        }

        vfs_close(fd);
        resolved
    }
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

unsafe fn find_or_create_client(badge: u64) -> *mut ClientState {
    unsafe {
        let clients = &raw mut CLIENTS;
        // Find existing
        for i in 0..MAX_CLIENTS {
            if (*clients)[i].active && (*clients)[i].badge == badge {
                return &raw mut (*clients)[i];
            }
        }
        // Allocate new
        for i in 0..MAX_CLIENTS {
            if !(*clients)[i].active {
                (*clients)[i].badge = badge;
                (*clients)[i].active = true;
                (*clients)[i].input_mode = DEFAULT_INPUT_MODE;
                (*clients)[i].output_mode = DEFAULT_OUTPUT_MODE;
                return &raw mut (*clients)[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn remove_client(badge: u64) {
    unsafe {
        let clients = &raw mut CLIENTS;
        for i in 0..MAX_CLIENTS {
            if (*clients)[i].active && (*clients)[i].badge == badge {
                (*clients)[i].active = false;
                return;
            }
        }
    }
}

// ======================================================================
// Console I/O delegation
// ======================================================================

/// Forward a console write to the console server via CONSOLE_WRITE IPC.
unsafe fn handle_console_write(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let byte_count = (*msg).regs[0];
        if byte_count == 0 || byte_count > 144 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Build CONSOLE_WRITE message for the console server
        let mut con_msg = TronaMsg::zeroed();
        let mut con_reply = TronaMsg::zeroed();
        con_msg.label = CONSOLE_WRITE;
        con_msg.regs[0] = byte_count;
        con_msg.length = 1 + ((byte_count + 7) / 8);

        // Copy data bytes from incoming message
        let src = &(*msg).regs[1] as *const u64 as *const u8;
        let dst = &raw mut con_msg.regs[1] as *mut u8;
        for i in 0..byte_count as usize {
            *dst.add(i) = *src.add(i);
        }

        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_CONSOLE_EP,
            &raw const con_msg,
            &raw mut con_reply,
        );
        if err == 0 && con_reply.label == TRONA_OK {
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = byte_count;
            (*reply).length = 1;
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

/// Forward a console read to the console server.
/// For the minimal implementation, we delegate to VFS stdin reads.
unsafe fn handle_console_read(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let max_bytes = (*msg).regs[0];
        if max_bytes == 0 || max_bytes > 152 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Read from VFS fd 0 (stdin) for the calling process.
        // In the minimal implementation, we send a VFS_READ for fd 0.
        let mut vfs_msg = TronaMsg::zeroed();
        let mut vfs_reply = TronaMsg::zeroed();
        vfs_msg.label = VFS_READ;
        vfs_msg.length = 2;
        vfs_msg.regs[0] = 0; // fd 0 = stdin
        vfs_msg.regs[1] = max_bytes;

        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_VFS_EP,
            &raw const vfs_msg,
            &raw mut vfs_reply,
        );
        if err == 0 && vfs_reply.label == TRONA_OK {
            let actual = vfs_reply.regs[0];
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = actual;
            (*reply).length = 1 + ((actual + 7) / 8);
            // Copy data from VFS reply
            let src = &vfs_reply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..actual as usize {
                *dst.add(i) = *src.add(i);
            }
        } else {
            (*reply).label = if err != 0 { TRONA_INVALID_OPERATION } else { vfs_reply.label };
        }
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

/// Handle GetConsoleMode request.
unsafe fn handle_get_console_mode(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let cli = find_or_create_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        let handle_type = (*msg).regs[0]; // 0=input, 1=output
        let mode = if handle_type == 0 {
            (*cli).input_mode
        } else {
            (*cli).output_mode
        };
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = mode as u64;
        (*reply).length = 1;
    }
}

/// Handle SetConsoleMode request.
unsafe fn handle_set_console_mode(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let cli = find_or_create_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        let handle_type = (*msg).regs[0];
        let new_mode = (*msg).regs[1] as u32;
        if handle_type == 0 {
            (*cli).input_mode = new_mode;
        } else {
            (*cli).output_mode = new_mode;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[WIN32_CSRSS] Win32 subsystem server starting\n");
    });

    // Register with namesrv as "win32/csrss"
    register_with_namesrv();

    signal_ready();

    trona::uinfo!(|_lb| {
        _lb.str(b"[WIN32_CSRSS] ready, entering dispatch loop\n");
    });

    // Main IPC dispatch loop
    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;

    // Initial recv
    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[WIN32_CSRSS] initial recv failed\n");
        });
        idle();
    }

    loop {
        let mut reply = TronaMsg::zeroed();

        match msg.label {
            W32_RESOLVE_IMPORT => {
                unsafe { handle_resolve_import(&raw const msg, &raw mut reply) };
            }
            W32_CONSOLE_WRITE => {
                unsafe { handle_console_write(&raw const msg, &raw mut reply) };
            }
            W32_CONSOLE_READ => {
                unsafe { handle_console_read(&raw const msg, &raw mut reply, badge) };
            }
            W32_GET_CONSOLE_MODE => {
                unsafe { handle_get_console_mode(&raw const msg, &raw mut reply, badge) };
            }
            W32_SET_CONSOLE_MODE => {
                unsafe { handle_set_console_mode(&raw const msg, &raw mut reply, badge) };
            }
            W32_CLIENT_REGISTER => {
                unsafe {
                    let _ = find_or_create_client(badge);
                }
                reply.label = TRONA_OK;
            }
            W32_CLIENT_EXIT => {
                unsafe { remove_client(badge) };
                reply.label = TRONA_OK;
            }
            _ => {
                reply.label = TRONA_INVALID_OPERATION;
            }
        }

        let err = unsafe {
            ipc::reply_recv_ctx(
                ipc_ctx(),
                CAP_SERVER_EP,
                &raw const reply,
                &raw mut msg,
                &raw mut badge,
            )
        };
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[WIN32_CSRSS] reply_recv failed\n");
            });
            break;
        }
    }

    idle();
}

fn register_with_namesrv() {
    let mut reg_msg = TronaMsg::zeroed();
    let mut reg_reply = TronaMsg::zeroed();
    let svc_name = b"win32/csrss";
    reg_msg.label = NS_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
    let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
    unsafe {
        for i in 0..svc_name.len() {
            *ns_dst.add(i) = svc_name[i];
        }
    }

    unsafe {
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_NAMESRV_EP,
            &raw const reg_msg,
            &raw mut reg_reply,
        );
        if err == 0 && reg_reply.label == TRONA_OK {
            trona::uinfo!(|_lb| {
                _lb.str(b"[WIN32_CSRSS] registered with namesrv\n");
            });
        } else {
            trona::uerror!(|_lb| {
                _lb.str(b"[WIN32_CSRSS] namesrv registration failed\n");
            });
        }
    }
}

fn idle() -> ! {
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
