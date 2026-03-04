//! VFS-based ELF file loading
//!
//! Provides a fallback path for loading ELF binaries from the VFS (disk-based
//! rootfs) when they are not found in the initrd CPIO.
//!
//! Supports two read strategies:
//! - **Bulk SHM** (preferred): 256KB per IPC round-trip via shared memory
//! - **Legacy inline**: 152 bytes per IPC round-trip via message registers
//!
//! The bulk path is attempted first and silently falls back to legacy if
//! SHM setup fails (e.g. mmsrv not ready, VFS doesn't support bulk).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use besalt::consts::*;
use besalt::ipc;
use besalt::serial::LineBuf;
use besalt::types::*;

const CAP_VFS_EP: Cap = super::CAP_VFS_EP;
const CAP_MMSRV_EP: Cap = super::CAP_MMSRV_EP;

// VFS protocol labels (must match besalt::consts)
const VFS_OPEN: u64 = POSIX_VFS_OPEN;
const VFS_READ: u64 = POSIX_VFS_READ;
const VFS_CLOSE: u64 = POSIX_VFS_CLOSE;
const VFS_FSTAT: u64 = POSIX_VFS_FSTAT;
const VFS_BULK_SETUP: u64 = POSIX_VFS_BULK_SETUP;
const VFS_BULK_READ: u64 = POSIX_VFS_BULK_READ;

/// Maximum file size we will attempt to load from VFS (128 MiB).
const MAX_VFS_FILE_SIZE: usize = 128 * 1024 * 1024;

/// Bytes readable per VFS READ IPC call (legacy inline path).
/// BesaltMsg has 20 regs; READ returns data in regs[1..], so max 19*8=152 bytes.
const READ_CHUNK_SIZE: u64 = 152;

/// Per-process bulk SHM state for procmgr.
static mut BULK_SHM_ADDR: u64 = 0;
static mut BULK_SHM_READY: bool = false;

/// Result of a successful VFS load.
pub struct VfsLoadResult {
    pub data: *const u8,
    pub data_len: usize,
    /// Page-aligned allocation size used for the scratch mmap.
    /// Must be passed to cleanup_vfs_load to unmap exactly the right range.
    pub alloc_size: u64,
}

/// Try to load an ELF binary from the VFS.
///
/// Builds a path by prepending `/bin/` if the name does not start with `/`.
/// Opens the file via VFS, reads it into an anonymous mmap region,
/// and returns a pointer to the data.
///
/// Returns `None` if the file cannot be found or loaded.
pub unsafe fn try_load_from_vfs(name: &[u8], name_len: usize) -> Option<VfsLoadResult> {
    unsafe {
        if CAP_VFS_EP == 0 {
            return None;
        }

        // Build path: "/bin/<name>" or use as-is if starts with '/'
        let mut path_buf = [0u8; 256];
        let path_len;
        if name_len > 0 && name[0] == b'/' {
            if name_len > 255 {
                return None;
            }
            for i in 0..name_len {
                path_buf[i] = name[i];
            }
            path_len = name_len;
        } else {
            let prefix = b"/bin/";
            if prefix.len() + name_len > 255 {
                return None;
            }
            for i in 0..prefix.len() {
                path_buf[i] = prefix[i];
            }
            for i in 0..name_len {
                path_buf[prefix.len() + i] = name[i];
            }
            path_len = prefix.len() + name_len;
        }
        // Null-terminate for pack_path
        path_buf[path_len] = 0;

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] VFS load: ");
            lb.bytes(&path_buf[..path_len]);
            lb.str(b"\n");
            lb.flush();
        }

        let fd = vfs_open(&path_buf, path_len)?;

        // 2. Get file size via fstat
        let file_size = match vfs_fstat(fd) {
            Some(sz) => sz,
            None => {
                vfs_close(fd);
                return None;
            }
        };

        if file_size == 0 || file_size > MAX_VFS_FILE_SIZE {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] VFS: bad file size ");
            lb.hex(file_size as u64);
            lb.str(b"\n");
            lb.flush();
            vfs_close(fd);
            return None;
        }

        // 3. Allocate scratch buffer via mmsrv anonymous mmap
        let alloc_size = ((file_size + 0xFFF) & !0xFFF) as u64;
        let buf = besalt::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            alloc_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY,
            -1,
            0,
        );
        if buf as usize == usize::MAX {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] VFS: scratch mmap failed\n");
            lb.flush();
            vfs_close(fd);
            return None;
        }

        // 4. Read file content — try bulk SHM path first, fall back to legacy
        let total_read = if file_size > 4096 {
            match vfs_bulk_read_all(fd, buf, file_size) {
                Some(n) => n,
                None => vfs_legacy_read_all(fd, buf, file_size, alloc_size)?,
            }
        } else {
            vfs_legacy_read_all(fd, buf, file_size, alloc_size)?
        };

        // 5. Close the file
        vfs_close(fd);

        if total_read == 0 {
            besalt::posix_mm::posix_munmap(buf, alloc_size);
            return None;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] VFS: loaded ");
            lb.hex(total_read as u64);
            lb.str(b" bytes\n");
            lb.flush();
        }

        Some(VfsLoadResult {
            data: buf as *const u8,
            data_len: total_read,
            alloc_size,
        })
    }
}

// ---------------------------------------------------------------------------
// Bulk SHM read path
// ---------------------------------------------------------------------------

/// Lazy one-time setup of procmgr's bulk SHM with VFS.
unsafe fn ensure_bulk_shm() -> bool {
    unsafe {
        if *(&raw const BULK_SHM_READY) {
            return true;
        }
        if CAP_VFS_EP == 0 || CAP_MMSRV_EP == 0 {
            return false;
        }

        let ctx = super::ipc_ctx();

        // Use a fixed SHM ID unique to procmgr
        let shm_id: u64 = 0x50_524F_434D; // "PROCM"

        // 1. Create SHM via mmsrv
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = MM_SHM_CREATE;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if reply.label != BESALT_OK && reply.label != BESALT_ALREADY_EXISTS {
            return false;
        }

        // 2. Map into our address space (auto-place)
        msg = BesaltMsg::zeroed();
        reply = BesaltMsg::zeroed();
        msg.label = MM_SHM_MAP;
        msg.regs[0] = shm_id;
        msg.regs[1] = 0; // self
        msg.regs[2] = 0; // auto-place
        msg.regs[3] = 0x3; // RW
        msg.length = 4;
        ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if reply.label != BESALT_OK {
            return false;
        }
        *(&raw mut BULK_SHM_ADDR) = reply.regs[0];

        // 3. Tell VFS to map our SHM
        msg = BesaltMsg::zeroed();
        reply = BesaltMsg::zeroed();
        msg.label = VFS_BULK_SETUP;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        ipc::call_ctx(ctx, CAP_VFS_EP, &raw const msg, &raw mut reply);
        if reply.label != BESALT_OK {
            return false;
        }

        *(&raw mut BULK_SHM_READY) = true;
        super::puts(b"[PROCMGR] VFS: SHM bulk setup OK\n");
        true
    }
}

/// Read an entire file using the bulk SHM path.
/// Returns total bytes read on success, None if bulk path unavailable.
unsafe fn vfs_bulk_read_all(fd: i32, buf: *mut u8, file_size: usize) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm() {
            return None;
        }

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = BULK_SHM_PAGES * 4096;
        let ctx = super::ipc_ctx();
        let mut total_read: usize = 0;

        while total_read < file_size {
            let remaining = (file_size - total_read) as u64;
            let chunk = remaining.min(shm_size);

            let mut msg = BesaltMsg::zeroed();
            let mut reply = BesaltMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            msg.regs[2] = 0; // shm_offset
            msg.length = 3;

            let err = ipc::call_ctx(ctx, CAP_VFS_EP, &raw const msg, &raw mut reply);
            if err != 0 || reply.label != BESALT_OK {
                if total_read > 0 {
                    return Some(total_read);
                }
                return None;
            }

            let got = reply.regs[0] as usize;
            if got == 0 {
                break; // EOF
            }

            // SAFETY: shm_addr is mapped with got <= shm_size bytes valid.
            // buf is mmap'd with at least file_size bytes allocated.
            core::ptr::copy_nonoverlapping(
                shm_addr as *const u8,
                buf.add(total_read),
                got,
            );
            total_read += got;
            if (got as u64) < chunk {
                break; // short read = EOF
            }
        }

        Some(total_read)
    }
}

// ---------------------------------------------------------------------------
// Legacy inline read path (152 bytes per IPC)
// ---------------------------------------------------------------------------

/// Read an entire file using the legacy 152-byte-per-IPC path.
/// Returns total bytes read on success, None on error (cleans up buf on error).
unsafe fn vfs_legacy_read_all(
    fd: i32,
    buf: *mut u8,
    file_size: usize,
    alloc_size: u64,
) -> Option<usize> {
    unsafe {
        let mut total_read: usize = 0;

        while total_read < file_size {
            let remaining = (file_size - total_read) as u64;
            let chunk = if remaining > READ_CHUNK_SIZE {
                READ_CHUNK_SIZE
            } else {
                remaining
            };
            let got = match vfs_read(fd, buf.add(total_read), chunk) {
                Some(n) => n,
                None => {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] VFS: read failed at offset ");
                    lb.hex(total_read as u64);
                    lb.str(b"\n");
                    lb.flush();
                    vfs_close(fd);
                    besalt::posix_mm::posix_munmap(buf, alloc_size);
                    return None;
                }
            };

            if got == 0 {
                break; // EOF
            }
            total_read += got;
        }

        Some(total_read)
    }
}

// ---------------------------------------------------------------------------
// VFS IPC helpers
// ---------------------------------------------------------------------------

/// Open a file via VFS IPC.
/// Returns the file descriptor on success, None on failure.
unsafe fn vfs_open(path: &[u8], path_len: usize) -> Option<i32> {
    // SAFETY: We are constructing an IPC message to send to VFS.
    // The ipc_ctx() pointer is valid for procmgr's lifetime.
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();

        msg.label = VFS_OPEN;
        msg.regs[0] = 0o644; // mode (ignored for O_RDONLY)
        msg.regs[1] = O_RDONLY as u64; // flags

        // Pack path: regs[2] = bytes packed, regs[3..] = path bytes as u64s
        // Reject paths longer than 128 bytes (IPC register capacity).
        let max_path = if path_len > 128 { 128 } else { path_len };
        msg.regs[2] = max_path as u64;
        // Zero regs[3..] before packing
        for i in 3..20 {
            msg.regs[i] = 0;
        }
        let dst = &raw mut msg.regs[3] as *mut u8;
        for i in 0..max_path {
            *dst.add(i) = path[i];
        }
        msg.length = 3 + ((max_path as u64 + 7) / 8);

        let err = ipc::call_ctx(
            super::ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != BESALT_OK {
            return None;
        }

        let fd = reply.regs[0] as i32;
        if fd < 0 {
            return None;
        }
        Some(fd)
    }
}

/// Get file size via VFS fstat.
unsafe fn vfs_fstat(fd: i32) -> Option<usize> {
    // SAFETY: IPC message construction is safe; ipc_ctx() is valid.
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();

        msg.label = VFS_FSTAT;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = ipc::call_ctx(
            super::ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != BESALT_OK {
            return None;
        }

        // st_size is at regs[3] in the fstat reply (matches posix_fstat layout)
        let size = reply.regs[3] as usize;
        Some(size)
    }
}

/// Read data from an open VFS file (legacy inline path).
/// Returns number of bytes read, or None on error.
unsafe fn vfs_read(fd: i32, buf: *mut u8, count: u64) -> Option<usize> {
    // SAFETY: buf must be valid for writes of up to count bytes.
    // ipc_ctx() is valid for procmgr's lifetime.
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();

        msg.label = VFS_READ;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = count;

        let err = ipc::call_ctx(
            super::ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != BESALT_OK {
            return None;
        }

        // reply.regs[0] = bytes_read, data in regs[1..]
        let bytes_read = reply.regs[0] as usize;
        if bytes_read == 0 {
            return Some(0);
        }

        // Copy data from reply registers to buffer
        let src = &reply.regs[1] as *const u64 as *const u8;
        let copy_len = if bytes_read > count as usize {
            count as usize
        } else {
            bytes_read
        };
        for i in 0..copy_len {
            *buf.add(i) = *src.add(i);
        }

        Some(copy_len)
    }
}

/// Close an open VFS file descriptor.
unsafe fn vfs_close(fd: i32) {
    // SAFETY: IPC message construction is safe; ipc_ctx() is valid.
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();

        msg.label = VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let _ = ipc::call_ctx(
            super::ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
    }
}

/// Clean up VFS-loaded data by unmapping the scratch region.
///
/// `alloc_size` must be the value from `VfsLoadResult::alloc_size` — the
/// page-aligned size of the original mmap, which may differ from `data_len`
/// if a short read occurred.
///
/// Must only be called after the ELF data has been fully processed
/// (loaded into the child's address space).
pub unsafe fn cleanup_vfs_load(data: *const u8, alloc_size: u64) {
    // SAFETY: Unmapping a region we previously mapped via posix_mmap.
    unsafe {
        besalt::posix_mm::posix_munmap(data as *mut u8, alloc_size);
    }
}
