// SPDX-License-Identifier: GPL-2.0-only
//
//! `execve` request parsing and exec-image header reads.
//!
//! `posix_execve` (lib/trona/posix/proc.rs) sends a Unix-style request —
//! a path, argv, and envp — and forwards a non-exec backing MemoryObject for
//! the resolved binary as `caps[0]`. init resolves it through ldsrv before this
//! module copies the argv/envp strings out of the IPC buffer (which is reused on
//! the next IPC) and reads the ELF/PE headers from the exec MemoryObject via
//! `MO_READ`, so the loader can stage the image directly from the MemoryObject.
//!
//! `MO_READ` drives the VFS pager and surfaces a pager failure as a
//! recoverable error, so reading the headers never faults init (PID 1) —
//! unlike mapping the MemoryObject into init's own address space and
//! touching it, which would take a fatal fault on pager failure.

use trona_kernel::core_types::{CapRef, TronaMsg};
use trona_kernel::invoke;

/// Maximum exec path length. Matches `posix_execve`'s 64-byte cap.
pub const MAX_EXEC_PATH: usize = 64;
/// Maximum argv (and, separately, envp) entries init will marshal.
pub const MAX_EXEC_ARGS: usize = 64;
/// Backing store for the copied argv/envp string blob. Sized to the IPC
/// buffer reserved area `posix_execve` packs the strings into.
pub const EXEC_STR_BUF: usize = 4096;
/// Upper bound on the header bytes init reads from the exec MO. The ELF
/// header, program-header table, and `PT_INTERP` path of a page-aligned
/// target all live within the first page; bounded by the IPC buffer that
/// `MO_READ` lands bytes in.
pub const EXEC_HEADER_MAX: usize = uapi::KERNITE_IPC_BUFFER_SIZE as usize;

/// The parsed shape of an exec request. The `(start, len)` pairs index
/// into the caller-provided string buffer; the caller materialises the
/// `&[&[u8]]` argv/envp from them so the borrow of the string buffer is
/// separate from the mutable fill performed here.
pub struct ExecLayout {
    pub path_len: usize,
    pub exec_size: u64,
    pub exec_offset: u64,
    pub argc: usize,
    pub envc: usize,
    pub arg_off: [(u16, u16); MAX_EXEC_ARGS],
    pub env_off: [(u16, u16); MAX_EXEC_ARGS],
}

/// Parse the `posix_execve` wire format out of `request` (header) and the
/// current IPC buffer reserved area (argv/envp strings). `path_buf`
/// receives the NUL-terminated path; `str_buf` receives the packed
/// argv/envp blob. Returns the layout describing where each argument
/// lives inside `str_buf`.
///
/// Wire format (see `posix_execve`):
///   regs[0]            = path_len
///   regs[1..]          = path bytes (8 per word)
///   regs[path_regs]    = (argc << 32) | envc        where path_regs = 1 + ceil(path_len/8)
///   regs[path_regs+1]  = total argv/envp blob bytes (in ipc_buffer.reserved)
///   regs[path_regs+2]  = exact executable byte size from VFS_OPEN_FOR_EXEC
///   regs[path_regs+3]  = executable byte offset within the backing MO
///   ipc_buffer.reserved = argc NUL-terminated argv strings, then envc envp strings
pub fn parse_exec_request(
    request: &TronaMsg,
    path_buf: &mut [u8; MAX_EXEC_PATH + 1],
    str_buf: &mut [u8; EXEC_STR_BUF],
) -> Result<ExecLayout, i32> {
    let path_len = request.regs[0] as usize;
    if path_len == 0 || path_len > MAX_EXEC_PATH {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    // Copy the path bytes (packed 8 per word starting at regs[1]).
    let path_src = unsafe { request.regs.as_ptr().add(1) as *const u8 };
    for i in 0..path_len {
        path_buf[i] = unsafe { *path_src.add(i) };
    }
    path_buf[path_len] = 0;

    let path_regs = 1 + path_len.div_ceil(8);
    if path_regs + 3 >= request.regs.len() {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    let packed = request.regs[path_regs];
    let argc = (packed >> 32) as usize;
    let envc = (packed & 0xFFFF_FFFF) as usize;
    let total_str_len = request.regs[path_regs + 1] as usize;
    let exec_size = request.regs[path_regs + 2];
    let exec_offset = request.regs[path_regs + 3];
    if argc > MAX_EXEC_ARGS || envc > MAX_EXEC_ARGS || total_str_len > EXEC_STR_BUF {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    if exec_size == 0 {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }

    // Copy the argv/envp blob out of the IPC buffer reserved area before
    // the next IPC reuses it.
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() || unsafe { (*ctx).ipc_buffer.is_null() } {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    let reserved = unsafe { (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8 };
    for i in 0..total_str_len {
        str_buf[i] = unsafe { *reserved.add(i) };
    }

    // Walk the blob: `argc` NUL-terminated argv strings, then `envc` envp
    // strings. Record each entry's (start, len) inside `str_buf`.
    let mut layout = ExecLayout {
        path_len,
        exec_size,
        exec_offset,
        argc,
        envc,
        arg_off: [(0, 0); MAX_EXEC_ARGS],
        env_off: [(0, 0); MAX_EXEC_ARGS],
    };
    let mut pos = 0usize;
    for slot in 0..(argc + envc) {
        let start = pos;
        while pos < total_str_len && str_buf[pos] != 0 {
            pos += 1;
        }
        if pos >= total_str_len {
            // Missing NUL terminator for a declared entry.
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
        }
        let len = pos - start;
        pos += 1; // skip NUL
        let pair = (start as u16, len as u16);
        if slot < argc {
            layout.arg_off[slot] = pair;
        } else {
            layout.env_off[slot - argc] = pair;
        }
    }

    Ok(layout)
}

/// Read the leading ELF/PE headers from the exec MemoryObject into `buf`,
/// returning the number of bytes read.
///
/// Uses `MO_READ`, which drives the VFS pager and returns a recoverable
/// error on pager failure — init (PID 1) is never faulted by touching a
/// not-yet-paged exec page. Only the headers are read here; the loader
/// stages the image's segments from `exec_mo` directly.
pub fn read_exec_headers(exec_mo: CapRef, buf: &mut [u8; EXEC_HEADER_MAX]) -> Result<usize, i32> {
    let (err, size_pages) = invoke::mo_get_size(exec_mo);
    if err != 0 {
        return Err(err);
    }
    if size_pages == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    // `mo_get_size` reports the MemoryObject's size in PAGES (the file MO is
    // page- and power-of-two-rounded), not bytes — convert before clamping to
    // the one-page header window. The ELF/PE headers fit in the first page.
    let size_bytes = (size_pages as usize).saturating_mul(uapi::KERNITE_PAGE_BYTES as usize);
    let read_len = core::cmp::min(size_bytes, EXEC_HEADER_MAX);

    // MO_READ copies the bytes to the IPC buffer base; lift them out before
    // the next IPC reuses the buffer.
    let (err, got) = invoke::mo_read(exec_mo, 0, read_len as u64);
    if err != 0 {
        return Err(err);
    }
    let got = core::cmp::min(got as usize, EXEC_HEADER_MAX);
    if got == 0 {
        return Err(uapi::KERNITE_ERR_IO_ERROR as i32);
    }

    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() || unsafe { (*ctx).ipc_buffer.is_null() } {
        return Err(uapi::KERNITE_ERR_INVALID_OPERATION as i32);
    }
    let src = unsafe { (*ctx).ipc_buffer as *const u8 };
    for i in 0..got {
        buf[i] = unsafe { *src.add(i) };
    }
    Ok(got)
}
