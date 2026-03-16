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
const VFS_GETCWD: u64 = POSIX_VFS_GETCWD;
const VFS_BULK_SETUP: u64 = POSIX_VFS_BULK_SETUP;
const VFS_BULK_READ: u64 = POSIX_VFS_BULK_READ;

/// Maximum file size we will attempt to load from VFS (128 MiB).
const MAX_VFS_FILE_SIZE: usize = 128 * 1024 * 1024;
/// Above this size, avoid buffering the entire ELF in procmgr.
const STREAM_VFS_ELF_THRESHOLD: usize = 8 * 1024 * 1024;
/// Maximum bytes reserved for program headers while inspecting a streamed ELF.
const MAX_STREAM_ELF_PHDR_BYTES: usize = 4096;
/// Maximum interpreter path bytes copied from PT_INTERP.
const MAX_STREAM_INTERP_LEN: usize = 64;

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

/// Streamed VFS ELF metadata used to avoid buffering very large binaries.
pub struct VfsStreamExec {
    pub fd: i32,
    pub file_size: usize,
    pub elf_span: u64,
    pub is_dynamic: bool,
    pub needed: besalt::elf_dynamic::NeededLibs,
    pub interp_name: [u8; MAX_STREAM_INTERP_LEN],
    pub interp_name_len: usize,
    pub phdr_vaddr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub rela_data: *const u8,
    pub rela_len: usize,
    pub rela_ent: usize,
    rela_alloc_size: u64,
}

/// VFS-backed executable source.
pub enum VfsExecSource {
    None,
    Buffered(VfsLoadResult),
    Streamed(VfsStreamExec),
}

impl VfsExecSource {
    pub const fn none() -> Self {
        Self::None
    }

    pub fn buffered_data(&self) -> Option<(*const u8, usize)> {
        match self {
            Self::Buffered(buf) => Some((buf.data, buf.data_len)),
            _ => None,
        }
    }

    pub fn streamed(&self) -> Option<&VfsStreamExec> {
        match self {
            Self::Streamed(exec) => Some(exec),
            _ => None,
        }
    }
}

fn page_align_up_u64(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

unsafe fn mint_badged_vfs_cap(client_badge: u64) -> Option<Cap> {
    unsafe {
        let alloc = &mut *(&raw mut super::ALLOCATOR);
        let slot = alloc.alloc_single_slot()?;
        let err = besalt::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            CAP_VFS_EP,
            super::CAP_SELF_CSPACE,
            slot,
            client_badge,
        );
        if err != 0 {
            alloc.free_single_slot(slot);
            return None;
        }
        Some(slot)
    }
}

unsafe fn release_badged_vfs_cap(slot: Cap) {
    unsafe {
        let _ = besalt::invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
        (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(slot);
    }
}

unsafe fn get_cwd_for_badge(client_badge: u64, cwd_buf: &mut [u8; 128]) -> Option<usize> {
    unsafe {
        let vfs_cap = mint_badged_vfs_cap(client_badge)?;
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = VFS_GETCWD;
        msg.length = 1;
        msg.regs[0] = cwd_buf.len() as u64;

        let err = ipc::call_ctx(super::ipc_ctx(), vfs_cap, &raw const msg, &raw mut reply);
        release_badged_vfs_cap(vfs_cap);
        if err != 0 || reply.label != BESALT_OK {
            return None;
        }

        let cwd_len = reply.regs[0] as usize;
        if cwd_len == 0 || cwd_len > cwd_buf.len() {
            return None;
        }
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..cwd_len {
            cwd_buf[i] = *src.add(i);
        }
        Some(cwd_len)
    }
}

unsafe fn canonicalize_absolute_path(
    raw_abs: &[u8],
    raw_len: usize,
    out: &mut [u8; 256],
) -> Option<usize> {
    unsafe {
        if raw_len == 0 || raw_len > out.len() || raw_abs[0] != b'/' {
            return None;
        }

        out[0] = b'/';
        let mut out_len: usize = 1;
        let mut comp_starts = [0usize; 128];
        let mut depth: usize = 0;
        let mut pos: usize = 1;

        while pos < raw_len {
            while pos < raw_len && raw_abs[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw_abs[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }
            if seg_len == 1 && raw_abs[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw_abs[start] == b'.' && raw_abs[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        out[0] = b'/';
                    }
                }
                continue;
            }

            if depth >= comp_starts.len() {
                return None;
            }
            if out_len > 1 {
                if out_len >= out.len() {
                    return None;
                }
                out[out_len] = b'/';
                out_len += 1;
            }
            comp_starts[depth] = out_len;
            depth += 1;
            if out_len + seg_len > out.len() {
                return None;
            }
            for i in 0..seg_len {
                out[out_len + i] = raw_abs[start + i];
            }
            out_len += seg_len;
        }

        Some(out_len)
    }
}

unsafe fn build_vfs_path(
    name: &[u8],
    name_len: usize,
    client_badge: u64,
    path_buf: &mut [u8; 256],
) -> Option<usize> {
    unsafe {
        if name_len == 0 || name_len > 128 {
            return None;
        }
        if name[0] == b'/' {
            for i in 0..name_len {
                path_buf[i] = name[i];
            }
            path_buf[name_len] = 0;
            return Some(name_len);
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
            let path_len = prefix.len() + name_len;
            if path_len > 128 {
                return None;
            }
            for i in 0..prefix.len() {
                path_buf[i] = prefix[i];
            }
            for i in 0..name_len {
                path_buf[prefix.len() + i] = name[i];
            }
            path_buf[path_len] = 0;
            return Some(path_len);
        }

        let mut cwd = [0u8; 128];
        let cwd_len = get_cwd_for_badge(client_badge, &mut cwd)?;
        let cwd_is_root = cwd_len == 1 && cwd[0] == b'/';
        let raw_len = if cwd_is_root {
            1 + name_len
        } else {
            cwd_len + 1 + name_len
        };
        if raw_len > 128 || raw_len > path_buf.len() {
            return None;
        }

        let mut raw_abs = [0u8; 256];
        if cwd_is_root {
            raw_abs[0] = b'/';
            for i in 0..name_len {
                raw_abs[1 + i] = name[i];
            }
        } else {
            for i in 0..cwd_len {
                raw_abs[i] = cwd[i];
            }
            raw_abs[cwd_len] = b'/';
            for i in 0..name_len {
                raw_abs[cwd_len + 1 + i] = name[i];
            }
        }

        let path_len = canonicalize_absolute_path(&raw_abs[..raw_len], raw_len, path_buf)?;
        if path_len > 128 {
            return None;
        }
        path_buf[path_len] = 0;
        Some(path_len)
    }
}

fn elf_page_align_down(v: u64) -> u64 {
    v & !0xFFFu64
}

fn elf_page_align_up(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFFu64
}

unsafe fn stream_phdr_from_bytes(phdr_bytes: &[u8], idx: usize, phentsz: usize) -> Option<Elf64Phdr> {
    unsafe {
        let off = idx.checked_mul(phentsz)?;
        if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes.len() {
            return None;
        }
        Some(core::ptr::read_unaligned(
            phdr_bytes.as_ptr().add(off) as *const Elf64Phdr,
        ))
    }
}

unsafe fn stream_va_to_file_offset(
    phdr_bytes: &[u8],
    phnum: usize,
    phentsz: usize,
    va: u64,
) -> Option<usize> {
    unsafe {
        for i in 0..phnum {
            let phdr = stream_phdr_from_bytes(phdr_bytes, i, phentsz)?;
            if phdr.p_type != PT_LOAD {
                continue;
            }
            if va >= phdr.p_vaddr && va < phdr.p_vaddr + phdr.p_filesz {
                return Some((va - phdr.p_vaddr + phdr.p_offset) as usize);
            }
        }
        None
    }
}

unsafe fn read_open_vfs_file_to_buffer(fd: i32, file_size: usize) -> Option<VfsLoadResult> {
    unsafe {
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
            return None;
        }

        let total_read = if file_size > 4096 {
            match vfs_bulk_read_all(fd, buf, file_size) {
                Some(n) => n,
                None => vfs_legacy_read_all(fd, buf, file_size, alloc_size)?,
            }
        } else {
            vfs_legacy_read_all(fd, buf, file_size, alloc_size)?
        };

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

/// Try to load an ELF binary from the VFS.
///
/// Builds a path by prepending `/bin/` if the name does not start with `/`.
/// Opens the file via VFS, reads it into an anonymous mmap region,
/// and returns a pointer to the data.
///
/// Returns `None` if the file cannot be found or loaded.
pub unsafe fn try_load_from_vfs_for_badge(
    name: &[u8],
    name_len: usize,
    client_badge: u64,
) -> Option<VfsLoadResult> {
    unsafe {
        if CAP_VFS_EP == 0 {
            return None;
        }

        let mut path_buf = [0u8; 256];
        let path_len = build_vfs_path(name, name_len, client_badge, &mut path_buf)?;

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

        let result = read_open_vfs_file_to_buffer(fd, file_size);
        vfs_close(fd);
        result
    }
}

pub unsafe fn try_load_from_vfs(name: &[u8], name_len: usize) -> Option<VfsLoadResult> {
    unsafe { try_load_from_vfs_for_badge(name, name_len, 0) }
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

unsafe fn vfs_bulk_read_exact_at(fd: i32, buf: *mut u8, count: usize, offset: usize) -> Option<()> {
    unsafe {
        if !ensure_bulk_shm() {
            return None;
        }
        if vfs_lseek(fd, offset as i64, SEEK_SET as i32)? != offset as i64 {
            return None;
        }

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = (BULK_SHM_PAGES * 4096) as usize;
        let ctx = super::ipc_ctx();
        let mut total_read = 0usize;

        while total_read < count {
            let chunk = core::cmp::min(count - total_read, shm_size);
            let mut msg = BesaltMsg::zeroed();
            let mut reply = BesaltMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk as u64;
            msg.regs[2] = 0;
            msg.length = 3;

            let err = ipc::call_ctx(ctx, CAP_VFS_EP, &raw const msg, &raw mut reply);
            if err != 0 || reply.label != BESALT_OK {
                return None;
            }

            let got = reply.regs[0] as usize;
            if got != chunk {
                return None;
            }

            core::ptr::copy_nonoverlapping(
                shm_addr as *const u8,
                buf.add(total_read),
                got,
            );
            total_read += got;
        }

        Some(())
    }
}

unsafe fn vfs_seek_read_exact(fd: i32, buf: *mut u8, count: usize, offset: usize) -> Option<()> {
    unsafe {
        if vfs_lseek(fd, offset as i64, SEEK_SET as i32)? != offset as i64 {
            return None;
        }

        let mut total = 0usize;
        while total < count {
            let chunk = core::cmp::min(count - total, READ_CHUNK_SIZE as usize);
            let got = vfs_read(fd, buf.add(total), chunk as u64)?;
            if got == 0 {
                return None;
            }
            total += got;
        }
        Some(())
    }
}

pub unsafe fn vfs_read_exact_at(fd: i32, buf: *mut u8, count: usize, offset: usize) -> bool {
    unsafe {
        if count == 0 {
            return true;
        }
        if count > READ_CHUNK_SIZE as usize && vfs_bulk_read_exact_at(fd, buf, count, offset).is_some() {
            return true;
        }
        vfs_seek_read_exact(fd, buf, count, offset).is_some()
    }
}

unsafe fn read_c_string_at(
    fd: i32,
    file_off: usize,
    out: &mut [u8],
) -> Option<usize> {
    unsafe {
        if out.is_empty() {
            return None;
        }
        for i in 0..out.len() {
            let mut byte = 0u8;
            vfs_seek_read_exact(fd, &raw mut byte, 1, file_off + i)?;
            if byte == 0 {
                return Some(i);
            }
            out[i] = byte;
        }
        Some(out.len())
    }
}

unsafe fn inspect_streamed_vfs_elf(fd: i32, file_size: usize) -> Option<VfsStreamExec> {
    unsafe {
        let mut ehdr = core::mem::MaybeUninit::<Elf64Ehdr>::uninit();
        if !vfs_read_exact_at(
            fd,
            ehdr.as_mut_ptr() as *mut u8,
            core::mem::size_of::<Elf64Ehdr>(),
            0,
        ) {
            return None;
        }
        let ehdr = ehdr.assume_init();

        if ehdr.e_ident[0] != 0x7F
            || ehdr.e_ident[1] != b'E'
            || ehdr.e_ident[2] != b'L'
            || ehdr.e_ident[3] != b'F'
            || ehdr.e_ident[4] != ELFCLASS64
            || ehdr.e_ident[5] != ELFDATA2LSB
        {
            return None;
        }
        if ehdr.e_machine != EM_X86_64 {
            return None;
        }

        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;
        let phdr_bytes_len = phnum.checked_mul(phentsz)?;
        if phnum == 0 || phdr_bytes_len == 0 || phdr_bytes_len > MAX_STREAM_ELF_PHDR_BYTES {
            return None;
        }

        let mut phdr_bytes = [0u8; MAX_STREAM_ELF_PHDR_BYTES];
        if !vfs_read_exact_at(fd, phdr_bytes.as_mut_ptr(), phdr_bytes_len, ehdr.e_phoff as usize) {
            return None;
        }
        let phdr_bytes = &phdr_bytes[..phdr_bytes_len];

        let mut min_vaddr = u64::MAX;
        let mut max_vaddr_end = 0u64;
        let mut is_dynamic = false;
        let mut interp_name = [0u8; MAX_STREAM_INTERP_LEN];
        let mut interp_name_len = 12usize;
        let default_interp = b"ld-besalt.so";
        for i in 0..default_interp.len() {
            interp_name[i] = default_interp[i];
        }
        let mut dyn_file_off = 0usize;
        let mut dyn_size = 0usize;

        for i in 0..phnum {
            let phdr = stream_phdr_from_bytes(phdr_bytes, i, phentsz)?;
            if phdr.p_type == PT_LOAD {
                if phdr.p_vaddr < min_vaddr {
                    min_vaddr = phdr.p_vaddr;
                }
                let end = phdr.p_vaddr + phdr.p_memsz;
                if end > max_vaddr_end {
                    max_vaddr_end = end;
                }
            } else if phdr.p_type == PT_INTERP {
                is_dynamic = true;
                let mut interp_buf = [0u8; MAX_STREAM_INTERP_LEN];
                let interp_copy = core::cmp::min(phdr.p_filesz as usize, interp_buf.len());
                if interp_copy > 0
                    && vfs_read_exact_at(fd, interp_buf.as_mut_ptr(), interp_copy, phdr.p_offset as usize)
                {
                    let mut start = 0usize;
                    let mut end = 0usize;
                    while end < interp_copy && interp_buf[end] != 0 {
                        if interp_buf[end] == b'/' {
                            start = end + 1;
                        }
                        end += 1;
                    }
                    if end > start {
                        interp_name_len = core::cmp::min(end - start, interp_name.len());
                        for j in 0..interp_name_len {
                            interp_name[j] = interp_buf[start + j];
                        }
                    }
                }
            } else if phdr.p_type == PT_DYNAMIC {
                dyn_file_off = phdr.p_offset as usize;
                dyn_size = phdr.p_filesz as usize;
            }
        }

        if min_vaddr == u64::MAX || max_vaddr_end == 0 {
            return None;
        }

        let mut needed = besalt::elf_dynamic::NeededLibs::new();
        let mut rela_data: *const u8 = core::ptr::null();
        let mut rela_len = 0usize;
        let mut rela_ent = 0usize;
        let mut rela_alloc_size = 0u64;

        if dyn_size != 0 {
            let dyn_count = dyn_size / core::mem::size_of::<Elf64Dyn>();
            let mut strtab_va = 0u64;
            let mut needed_offsets = [0u64; besalt::elf_dynamic::MAX_NEEDED_LIBS];
            let mut needed_count = 0usize;
            let mut rela_va = 0u64;
            let mut rela_size = 0usize;
            let mut rela_ent_size = 0usize;

            for i in 0..dyn_count {
                let entry_off = dyn_file_off + i * core::mem::size_of::<Elf64Dyn>();
                let mut dyn_entry = core::mem::MaybeUninit::<Elf64Dyn>::uninit();
                if !vfs_read_exact_at(
                    fd,
                    dyn_entry.as_mut_ptr() as *mut u8,
                    core::mem::size_of::<Elf64Dyn>(),
                    entry_off,
                ) {
                    return None;
                }
                let dyn_entry = dyn_entry.assume_init();
                if dyn_entry.d_tag == DT_NULL {
                    break;
                }
                if dyn_entry.d_tag == DT_STRTAB {
                    strtab_va = dyn_entry.d_val;
                } else if dyn_entry.d_tag == DT_NEEDED {
                    if needed_count < needed_offsets.len() {
                        needed_offsets[needed_count] = dyn_entry.d_val;
                        needed_count += 1;
                    }
                } else if dyn_entry.d_tag == DT_RELA {
                    rela_va = dyn_entry.d_val;
                } else if dyn_entry.d_tag == DT_RELASZ {
                    rela_size = dyn_entry.d_val as usize;
                } else if dyn_entry.d_tag == DT_RELAENT {
                    rela_ent_size = dyn_entry.d_val as usize;
                }
            }

            if strtab_va != 0 {
                let strtab_file_off = stream_va_to_file_offset(phdr_bytes, phnum, phentsz, strtab_va)?;
                for i in 0..needed_count {
                    let mut name_buf = [0u8; besalt::elf_dynamic::MAX_NEEDED_NAME];
                    let name_len = read_c_string_at(
                        fd,
                        strtab_file_off + needed_offsets[i] as usize,
                        &mut name_buf,
                    )?;
                    if name_len == 0 {
                        continue;
                    }
                    let copy_len = core::cmp::min(name_len, besalt::elf_dynamic::MAX_NEEDED_NAME);
                    if needed.count < besalt::elf_dynamic::MAX_NEEDED_LIBS {
                        for j in 0..copy_len {
                            needed.names[needed.count][j] = name_buf[j];
                        }
                        needed.name_lens[needed.count] = copy_len;
                        needed.count += 1;
                    }
                }
            }

            if ehdr.e_type == ET_DYN && rela_va != 0 && rela_size != 0 && rela_ent_size >= core::mem::size_of::<Elf64Rela>() {
                let rela_file_off = stream_va_to_file_offset(phdr_bytes, phnum, phentsz, rela_va)?;
                rela_alloc_size = page_align_up_u64(rela_size as u64);
                let rela_buf = besalt::posix_mm::posix_mmap(
                    core::ptr::null_mut(),
                    rela_alloc_size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY,
                    -1,
                    0,
                );
                if rela_buf as usize == usize::MAX {
                    return None;
                }
                if !vfs_read_exact_at(fd, rela_buf, rela_size, rela_file_off) {
                    besalt::posix_mm::posix_munmap(rela_buf, rela_alloc_size);
                    return None;
                }
                rela_data = rela_buf as *const u8;
                rela_len = rela_size;
                rela_ent = rela_ent_size;
            }
        }

        Some(VfsStreamExec {
            fd,
            file_size,
            elf_span: elf_page_align_up(max_vaddr_end) - elf_page_align_down(min_vaddr),
            is_dynamic,
            needed,
            interp_name,
            interp_name_len,
            phdr_vaddr: ehdr.e_phoff,
            phent: ehdr.e_phentsize as u64,
            phnum: ehdr.e_phnum as u64,
            rela_data,
            rela_len,
            rela_ent,
            rela_alloc_size,
        })
    }
}

pub unsafe fn try_open_exec_source_from_vfs_for_badge(
    name: &[u8],
    name_len: usize,
    client_badge: u64,
) -> Option<VfsExecSource> {
    unsafe {
        if CAP_VFS_EP == 0 {
            return None;
        }

        let mut path_buf = [0u8; 256];
        let path_len = build_vfs_path(name, name_len, client_badge, &mut path_buf)?;

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] VFS load: ");
            lb.bytes(&path_buf[..path_len]);
            lb.str(b"\n");
            lb.flush();
        }

        let fd = vfs_open(&path_buf, path_len)?;
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

        if file_size <= STREAM_VFS_ELF_THRESHOLD {
            let result = read_open_vfs_file_to_buffer(fd, file_size)?;
            vfs_close(fd);
            return Some(VfsExecSource::Buffered(result));
        }

        match inspect_streamed_vfs_elf(fd, file_size) {
            Some(exec) => Some(VfsExecSource::Streamed(exec)),
            None => {
                vfs_close(fd);
                None
            }
        }
    }
}

pub unsafe fn try_open_exec_source_from_vfs(name: &[u8], name_len: usize) -> Option<VfsExecSource> {
    unsafe { try_open_exec_source_from_vfs_for_badge(name, name_len, 0) }
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

unsafe fn vfs_lseek(fd: i32, offset: i64, whence: i32) -> Option<i64> {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();

        msg.label = POSIX_VFS_LSEEK;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = whence as u64;

        let err = ipc::call_ctx(
            super::ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != BESALT_OK {
            return None;
        }
        Some(reply.regs[0] as i64)
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

/// Clean up any VFS-backed exec source.
pub unsafe fn cleanup_exec_source(source: &mut VfsExecSource) {
    unsafe {
        match source {
            VfsExecSource::None => {}
            VfsExecSource::Buffered(buf) => {
                cleanup_vfs_load(buf.data, buf.alloc_size);
            }
            VfsExecSource::Streamed(exec) => {
                if exec.fd >= 0 {
                    vfs_close(exec.fd);
                }
                if !exec.rela_data.is_null() && exec.rela_alloc_size != 0 {
                    besalt::posix_mm::posix_munmap(exec.rela_data as *mut u8, exec.rela_alloc_size);
                }
            }
        }
        *source = VfsExecSource::None;
    }
}
