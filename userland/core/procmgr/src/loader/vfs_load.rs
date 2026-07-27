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

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use trona_protocol::posix_abi::file::*;
use trona_protocol::posix_abi::mm::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

/// Iterate program headers (from raw bytes) to find PT_PHDR and return its p_vaddr.
/// Falls back to `e_phoff` if no PT_PHDR exists.
unsafe fn elf_get_phdr_load_offset_inline(
    phdrs_ptr: *const u8,
    phnum: usize,
    phentsz: usize,
    buf_len: usize,
    e_phoff: u64,
) -> Option<u64> {
    unsafe {
        for i in 0..phnum {
            let off = i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > buf_len {
                break;
            }
            let ph = &*(phdrs_ptr.add(off) as *const Elf64Phdr);
            if ph.p_type == PT_PHDR {
                return Some(ph.p_vaddr);
            }
        }
        Some(e_phoff)
    }
}

/// Maximum file size we will attempt to load from VFS (128 MiB).
const MAX_VFS_FILE_SIZE: usize = 128 * 1024 * 1024;
/// Above this size, avoid buffering the entire ELF in procmgr.
const STREAM_VFS_ELF_THRESHOLD: usize = 8 * 1024 * 1024;
/// Maximum bytes reserved for program headers while inspecting a streamed ELF.
const MAX_STREAM_ELF_PHDR_BYTES: usize = 4096;
/// Maximum interpreter path bytes copied from PT_INTERP.
const MAX_STREAM_INTERP_LEN: usize = 64;

/// Bytes readable per VFS READ IPC call (legacy inline path).
/// TronaMsg has 20 regs; READ returns data in regs[1..], so max 19*8=152 bytes.
const READ_CHUNK_SIZE: u64 = 152;

/// Per-process bulk SHM state for procmgr.
static mut BULK_SHM_ADDR: u64 = 0;
static mut BULK_SHM_READY: bool = false;

#[inline]
fn vfs_self_ep() -> Cap {
    crate::base::cap_helpers::vfs_self_client_ep()
}

#[inline]
fn vfs_provider_ep() -> Cap {
    crate::base::cap_helpers::vfs_provider_ep()
}

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
    pub needed: super::NeededLibs,
    pub interp_name: [u8; MAX_STREAM_INTERP_LEN],
    pub interp_name_len: usize,
    /// PHDR address relative to the chosen image load base.
    pub phdr_vaddr: u64,
    pub phent: u64,
    pub phnum: u64,
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

pub(crate) unsafe fn mint_badged_vfs_cap(client_badge: u64) -> Option<Cap> {
    unsafe {
        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        let slot = alloc.alloc_single_slot()?;
        let err = trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            vfs_provider_ep(),
            crate::CAP_SELF_CSPACE,
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

pub(crate) unsafe fn release_badged_vfs_cap(slot: Cap) {
    unsafe {
        let _ = trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, slot);
        (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(slot);
    }
}

fn elf_page_align_down(v: u64) -> u64 {
    v & !0xFFFu64
}

fn elf_page_align_up(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFFu64
}

unsafe fn stream_phdr_from_bytes(
    phdr_bytes: &[u8],
    idx: usize,
    phentsz: usize,
) -> Option<Elf64Phdr> {
    unsafe {
        let off = idx.checked_mul(phentsz)?;
        if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes.len() {
            return None;
        }
        Some(core::ptr::read_unaligned(
            phdr_bytes.as_ptr().add(off) as *const Elf64Phdr
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
        let buf = trona_runtime::client::mm::mmap(
            core::ptr::null_mut(),
            alloc_size,
            PROT_READ | PROT_WRITE,
            // These scratch buffers are populated immediately after mmap.
            // Avoid demand-paged mappings here so the first store into the
            // ELF header lands deterministically before validation.
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap_or(usize::MAX as *mut u8);
        if buf as usize == usize::MAX {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS: scratch mmap failed\n");
            });
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

        if total_read == 0 || total_read != file_size {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS: short read got=");
                _lb.hex(total_read as u64);
                _lb.str(b" expect=");
                _lb.hex(file_size as u64);
                _lb.str(b"\n");
            });
            vfs_close(fd);
            let _ = trona_runtime::client::mm::munmap(buf, alloc_size);
            return None;
        }

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] VFS: loaded ");
            _lb.hex(total_read as u64);
            _lb.str(b" bytes\n");
        });

        Some(VfsLoadResult {
            data: buf as *const u8,
            data_len: total_read,
            alloc_size,
        })
    }
}

/// Try to load an ELF binary from the VFS.
///
/// All callers pass absolute paths (starting with `/`).
/// Opens the file via VFS, reads it into an anonymous mmap region,
/// and returns a pointer to the data.
///
/// Returns `None` if the file cannot be found or loaded.
pub unsafe fn try_load_from_vfs(name: &[u8], name_len: usize) -> Option<VfsLoadResult> {
    unsafe {
        if vfs_self_ep() == 0 {
            return None;
        }

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] VFS load: ");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"\n");
        });

        let fd = vfs_open(name, name_len)?;

        let file_size = match vfs_fstat(fd) {
            Some(sz) => sz,
            None => {
                vfs_close(fd);
                return None;
            }
        };

        if file_size == 0 || file_size > MAX_VFS_FILE_SIZE {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS: bad file size ");
                _lb.hex(file_size as u64);
                _lb.str(b"\n");
            });
            vfs_close(fd);
            return None;
        }

        let result = read_open_vfs_file_to_buffer(fd, file_size);
        vfs_close(fd);
        result
    }
}

// ---------------------------------------------------------------------------
// Bulk SHM read path
// ---------------------------------------------------------------------------

/// Lazy one-time setup of procmgr's bulk SHM with VFS.
unsafe fn ensure_bulk_shm_local() -> bool {
    unsafe {
        if *(&raw const BULK_SHM_ADDR) != 0 {
            return true;
        }
        if trona_runtime::client::caps::mmsrv_ep() == 0 {
            return false;
        }

        let ctx = crate::ipc_ctx();

        // Use a fixed SHM ID unique to procmgr
        let shm_id: u64 = 0x50_524F_434D; // "PROCM"

        // 1. Create SHM via mmsrv
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SHM_CREATE;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if reply.label != TRONA_OK && reply.label != TRONA_ALREADY_EXISTS {
            return false;
        }

        // 2. Map into our address space (auto-place)
        msg = TronaMsg::zeroed();
        reply = TronaMsg::zeroed();
        msg.label = MM_SHM_MAP;
        msg.regs[0] = shm_id;
        msg.regs[1] = 0; // self
        msg.regs[2] = 0; // auto-place
        msg.regs[3] = 0x3; // RW
        msg.length = 4;
        ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if reply.label != TRONA_OK {
            return false;
        }
        *(&raw mut BULK_SHM_ADDR) = reply.regs[0];

        true
    }
}

unsafe fn register_bulk_shm_with_vfs(ep: Cap) -> bool {
    unsafe {
        if ep == 0 || !ensure_bulk_shm_local() {
            return false;
        }

        let ctx = crate::ipc_ctx();
        let shm_id: u64 = 0x50_524F_434D; // "PROCM"
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_BULK_SETUP;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        ipc::call_ctx(ctx, ep, &raw const msg, &raw mut reply);
        reply.label == TRONA_OK
    }
}

unsafe fn ensure_bulk_shm() -> bool {
    unsafe {
        if *(&raw const BULK_SHM_READY) {
            return true;
        }
        if vfs_self_ep() == 0 {
            return false;
        }
        if !register_bulk_shm_with_vfs(vfs_self_ep()) {
            return false;
        }
        *(&raw mut BULK_SHM_READY) = true;
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] VFS: SHM bulk setup OK\n");
        });
        true
    }
}

unsafe fn ensure_bulk_shm_on(ep: Cap) -> bool {
    unsafe {
        if ep == vfs_self_ep() {
            return ensure_bulk_shm();
        }
        register_bulk_shm_with_vfs(ep)
    }
}

/// Read an entire file using the bulk SHM path.
/// Returns total bytes read on success, None on short read or IPC failure.
unsafe fn vfs_bulk_read_all(fd: i32, buf: *mut u8, file_size: usize) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm() {
            return None;
        }

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = BULK_SHM_PAGES * 4096;
        let ctx = crate::ipc_ctx();
        let mut total_read: usize = 0;

        while total_read < file_size {
            let remaining = (file_size - total_read) as u64;
            let chunk = remaining.min(shm_size);

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            msg.regs[2] = 0; // shm_offset
            msg.length = 3;

            let err = ipc::call_ctx(ctx, vfs_self_ep(), &raw const msg, &raw mut reply);
            if err != 0 || reply.label != TRONA_OK {
                return None;
            }

            let got = reply.regs[0] as usize;
            if got == 0 {
                break; // EOF
            }

            // SAFETY: shm_addr is mapped with got <= shm_size bytes valid.
            // buf is mmap'd with at least file_size bytes allocated.
            core::ptr::copy_nonoverlapping(shm_addr as *const u8, buf.add(total_read), got);
            total_read += got;
            if (got as u64) < chunk {
                break; // short read = EOF
            }
        }

        if total_read == file_size {
            Some(total_read)
        } else {
            None
        }
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
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] VFS: read failed at offset ");
                        _lb.hex(total_read as u64);
                        _lb.str(b"\n");
                    });
                    vfs_close(fd);
                    let _ = trona_runtime::client::mm::munmap(buf, alloc_size);
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
        let ctx = crate::ipc_ctx();
        let mut total_read = 0usize;

        while total_read < count {
            let chunk = core::cmp::min(count - total_read, shm_size);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk as u64;
            msg.regs[2] = 0;
            msg.length = 3;

            let err = ipc::call_ctx(ctx, vfs_self_ep(), &raw const msg, &raw mut reply);
            if err != 0 || reply.label != TRONA_OK {
                return None;
            }

            let got = reply.regs[0] as usize;
            if got != chunk {
                return None;
            }

            core::ptr::copy_nonoverlapping(shm_addr as *const u8, buf.add(total_read), got);
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
        if count > READ_CHUNK_SIZE as usize
            && vfs_bulk_read_exact_at(fd, buf, count, offset).is_some()
        {
            return true;
        }
        vfs_seek_read_exact(fd, buf, count, offset).is_some()
    }
}

unsafe fn read_c_string_at(fd: i32, file_off: usize, out: &mut [u8]) -> Option<usize> {
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
        #[cfg(target_arch = "x86_64")]
        if ehdr.e_machine != EM_X86_64 {
            return None;
        }
        #[cfg(target_arch = "aarch64")]
        if ehdr.e_machine != EM_AARCH64 {
            return None;
        }

        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;
        let phdr_bytes_len = phnum.checked_mul(phentsz)?;
        if phnum == 0 || phdr_bytes_len == 0 || phdr_bytes_len > MAX_STREAM_ELF_PHDR_BYTES {
            return None;
        }

        let mut phdr_bytes = [0u8; MAX_STREAM_ELF_PHDR_BYTES];
        if !vfs_read_exact_at(
            fd,
            phdr_bytes.as_mut_ptr(),
            phdr_bytes_len,
            ehdr.e_phoff as usize,
        ) {
            return None;
        }
        let phdr_bytes = &phdr_bytes[..phdr_bytes_len];

        let mut min_vaddr = u64::MAX;
        let mut max_vaddr_end = 0u64;
        let mut is_dynamic = false;
        let mut interp_name = [0u8; MAX_STREAM_INTERP_LEN];
        let mut interp_name_len = super::resolve_interp_to_cpio_path(&[], &mut interp_name);
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
                    && vfs_read_exact_at(
                        fd,
                        interp_buf.as_mut_ptr(),
                        interp_copy,
                        phdr.p_offset as usize,
                    )
                {
                    // Find null terminator
                    let mut len = 0usize;
                    while len < interp_copy && interp_buf[len] != 0 {
                        len += 1;
                    }
                    if len > 0 {
                        let resolved = super::resolve_interp_to_cpio_path(
                            &interp_buf[..len],
                            &mut interp_name,
                        );
                        if resolved > 0 {
                            interp_name_len = resolved;
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

        let phdr_runtime_vaddr = elf_get_phdr_load_offset_inline(
            phdr_bytes.as_ptr(),
            phnum,
            phentsz,
            phdr_bytes_len,
            ehdr.e_phoff,
        )?;

        let mut needed = super::NeededLibs::new();

        if dyn_size != 0 {
            let dyn_count = dyn_size / core::mem::size_of::<Elf64Dyn>();
            let mut strtab_va = 0u64;
            let mut needed_offsets = [0u64; super::MAX_NEEDED_LIBS];
            let mut needed_count = 0usize;

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
                }
            }

            if strtab_va != 0 {
                let strtab_file_off =
                    stream_va_to_file_offset(phdr_bytes, phnum, phentsz, strtab_va)?;
                for i in 0..needed_count {
                    let mut name_buf = [0u8; super::MAX_NEEDED_NAME];
                    let name_len = read_c_string_at(
                        fd,
                        strtab_file_off + needed_offsets[i] as usize,
                        &mut name_buf,
                    )?;
                    if name_len == 0 {
                        continue;
                    }
                    let copy_len = core::cmp::min(name_len, super::MAX_NEEDED_NAME);
                    if needed.count < super::MAX_NEEDED_LIBS {
                        for j in 0..copy_len {
                            needed.names[needed.count][j] = name_buf[j];
                        }
                        needed.name_lens[needed.count] = copy_len;
                        needed.count += 1;
                    }
                }
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
            phdr_vaddr: phdr_runtime_vaddr,
            phent: ehdr.e_phentsize as u64,
            phnum: ehdr.e_phnum as u64,
        })
    }
}

/// Result of a VFS_POSIX_STAT_FOR_EXEC call: file mode, owner uid/gid, and size.
pub struct VfsExecStatResult {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}

/// Try to open an executable source from the VFS.
///
/// All callers pass absolute paths (starting with `/`).
/// Opens the file, stats it, and returns either a buffered or streamed
/// exec source depending on file size.
///
/// Returns `None` if the file cannot be found or loaded.
pub unsafe fn try_open_exec_source_from_vfs(name: &[u8], name_len: usize) -> Option<VfsExecSource> {
    unsafe {
        if vfs_self_ep() == 0 {
            return None;
        }

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] VFS load: ");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"\n");
        });

        let fd = vfs_open(name, name_len)?;
        let file_size = match vfs_fstat(fd) {
            Some(sz) => sz,
            None => {
                vfs_close(fd);
                return None;
            }
        };

        if file_size == 0 || file_size > MAX_VFS_FILE_SIZE {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS: bad file size ");
                _lb.hex(file_size as u64);
                _lb.str(b"\n");
            });
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

// ---------------------------------------------------------------------------
// VFS IPC helpers
// ---------------------------------------------------------------------------

/// Open a file via VFS IPC.
/// Returns the file descriptor on success, None on failure.
unsafe fn vfs_open(path: &[u8], path_len: usize) -> Option<i32> {
    // SAFETY: We are constructing an IPC message to send to VFS.
    // The ipc_ctx() pointer is valid for procmgr's lifetime.
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_POSIX_OPEN;
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
            crate::ipc_ctx(),
            vfs_self_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
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
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_POSIX_FSTAT;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            vfs_self_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        // st_size is at regs[3] in the fstat reply (matches posix_fstat layout)
        let size = reply.regs[3] as usize;
        Some(size)
    }
}

unsafe fn vfs_lseek(fd: i32, offset: i64, whence: i32) -> Option<i64> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_LSEEK;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = whence as u64;

        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            vfs_self_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
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
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_READ;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = count;

        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            vfs_self_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
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
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let _ = ipc::call_ctx(
            crate::ipc_ctx(),
            vfs_self_ep(),
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
    // SAFETY: Unmapping a region we previously mapped via mmap.
    unsafe {
        let _ = trona_runtime::client::mm::munmap(data as *mut u8, alloc_size);
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
            }
        }
        *source = VfsExecSource::None;
    }
}

/// Inspect a shared object available through the default VFS endpoint.
///
/// Returns the page-aligned PT_LOAD span and DT_NEEDED list without keeping the
/// underlying file open or buffered past the call.
pub unsafe fn inspect_shared_object_from_vfs(
    path: &[u8],
    path_len: usize,
) -> Option<(u64, super::NeededLibs)> {
    unsafe {
        let mut source = try_open_exec_source_from_vfs(path, path_len)?;
        let result = match &source {
            VfsExecSource::None => None,
            VfsExecSource::Buffered(buf) => Some((
                super::elf_compute_load_span(buf.data, buf.data_len),
                super::elf_get_needed(buf.data, buf.data_len),
            )),
            VfsExecSource::Streamed(exec) => Some((exec.elf_span, exec.needed)),
        };
        cleanup_exec_source(&mut source);
        result
    }
}

// ---------------------------------------------------------------------------
// Badged-endpoint VFS IPC helpers (_on variants)
//
// These mirror the default VFS-endpoint helpers above but take an explicit
// endpoint cap, allowing procmgr to issue VFS calls as a specific client
// (identified by the badge baked into the endpoint).
//
// Bulk SHM is not used — only legacy inline reads.  Exec binary loading
// is a one-shot operation so the per-IPC overhead is acceptable.
// ---------------------------------------------------------------------------

pub(crate) unsafe fn vfs_canon_path_on(
    ep: Cap,
    path: &[u8],
    path_len: usize,
    out: &mut [u8; 256],
) -> Option<usize> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_POSIX_CANON_PATH;
        let max_path = if path_len > 128 { 128 } else { path_len };
        msg.regs[0] = max_path as u64;
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..max_path {
            *dst.add(i) = path[i];
        }
        msg.length = 1 + ((max_path as u64 + 7) / 8);

        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        let canon_len = reply.regs[0] as usize;
        if canon_len == 0 || canon_len > out.len() {
            return None;
        }
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..canon_len {
            out[i] = *src.add(i);
        }
        Some(canon_len)
    }
}

pub(crate) unsafe fn vfs_stat_for_exec_on(
    ep: Cap,
    path: &[u8],
    path_len: usize,
) -> Option<VfsExecStatResult> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_POSIX_STAT_FOR_EXEC;
        let max_path = if path_len > 128 { 128 } else { path_len };
        msg.regs[0] = max_path as u64;
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..max_path {
            *dst.add(i) = path[i];
        }
        msg.length = 1 + ((max_path as u64 + 7) / 8);

        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        Some(VfsExecStatResult {
            mode: reply.regs[0] as u32,
            uid: reply.regs[1] as u32,
            gid: reply.regs[2] as u32,
            size: reply.regs[3],
        })
    }
}

pub(crate) unsafe fn vfs_open_on(ep: Cap, path: &[u8], path_len: usize) -> Option<i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_POSIX_OPEN;
        msg.regs[0] = 0o644;
        msg.regs[1] = O_RDONLY as u64;

        let max_path = if path_len > 128 { 128 } else { path_len };
        msg.regs[2] = max_path as u64;
        for i in 3..20 {
            msg.regs[i] = 0;
        }
        let dst = &raw mut msg.regs[3] as *mut u8;
        for i in 0..max_path {
            *dst.add(i) = path[i];
        }
        msg.length = 3 + ((max_path as u64 + 7) / 8);

        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        let fd = reply.regs[0] as i32;
        if fd < 0 {
            return None;
        }
        Some(fd)
    }
}

pub(crate) unsafe fn vfs_fstat_on(ep: Cap, fd: i32) -> Option<usize> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_POSIX_FSTAT;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        Some(reply.regs[3] as usize)
    }
}

pub(crate) unsafe fn vfs_close_on(ep: Cap, fd: i32) {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let _ = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
    }
}

pub(crate) unsafe fn vfs_read_on(ep: Cap, fd: i32, buf: *mut u8, count: u64) -> Option<usize> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_READ;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = count;

        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        let bytes_read = reply.regs[0] as usize;
        if bytes_read == 0 {
            return Some(0);
        }

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

pub(crate) unsafe fn vfs_lseek_on(ep: Cap, fd: i32, offset: i64, whence: i32) -> Option<i64> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = VFS_LSEEK;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = whence as u64;

        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }
        Some(reply.regs[0] as i64)
    }
}

// ---------------------------------------------------------------------------
// Composite _on helpers for exec source loading
// ---------------------------------------------------------------------------

unsafe fn vfs_read_exact_at_on(
    ep: Cap,
    fd: i32,
    buf: *mut u8,
    count: usize,
    offset: usize,
) -> bool {
    unsafe {
        if count == 0 {
            return true;
        }
        vfs_bulk_read_exact_at_on(ep, fd, buf, count, offset).is_some()
    }
}

unsafe fn read_c_string_at_on(ep: Cap, fd: i32, file_off: usize, out: &mut [u8]) -> Option<usize> {
    unsafe {
        if out.is_empty() {
            return None;
        }
        for i in 0..out.len() {
            let mut byte = 0u8;
            vfs_bulk_read_exact_at_on(ep, fd, &raw mut byte, 1, file_off + i)?;
            if byte == 0 {
                return Some(i);
            }
            out[i] = byte;
        }
        Some(out.len())
    }
}

unsafe fn vfs_bulk_read_all_on(ep: Cap, fd: i32, buf: *mut u8, file_size: usize) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm_on(ep) {
            return None;
        }

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = BULK_SHM_PAGES * 4096;
        let ctx = crate::ipc_ctx();
        let mut total_read: usize = 0;

        while total_read < file_size {
            let remaining = (file_size - total_read) as u64;
            let chunk = remaining.min(shm_size);

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            msg.regs[2] = 0;
            msg.length = 3;

            let err = ipc::call_ctx(ctx, ep, &raw const msg, &raw mut reply);
            if err != 0 || reply.label != TRONA_OK {
                return None;
            }

            let got = reply.regs[0] as usize;
            if got == 0 {
                break;
            }

            core::ptr::copy_nonoverlapping(shm_addr as *const u8, buf.add(total_read), got);
            total_read += got;
            if (got as u64) < chunk {
                break;
            }
        }

        if total_read == file_size {
            Some(total_read)
        } else {
            None
        }
    }
}

unsafe fn vfs_bulk_read_exact_at_on(
    ep: Cap,
    fd: i32,
    buf: *mut u8,
    count: usize,
    offset: usize,
) -> Option<()> {
    unsafe {
        if !ensure_bulk_shm_on(ep) {
            return None;
        }
        if vfs_lseek_on(ep, fd, offset as i64, SEEK_SET as i32)? != offset as i64 {
            return None;
        }

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = (BULK_SHM_PAGES * 4096) as usize;
        let ctx = crate::ipc_ctx();
        let mut total_read = 0usize;

        while total_read < count {
            let chunk = core::cmp::min(count - total_read, shm_size);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk as u64;
            msg.regs[2] = 0;
            msg.length = 3;

            let err = ipc::call_ctx(ctx, ep, &raw const msg, &raw mut reply);
            if err != 0 || reply.label != TRONA_OK {
                return None;
            }

            let got = reply.regs[0] as usize;
            if got != chunk {
                return None;
            }

            core::ptr::copy_nonoverlapping(shm_addr as *const u8, buf.add(total_read), got);
            total_read += got;
        }

        Some(())
    }
}

unsafe fn read_open_vfs_file_to_buffer_on(
    ep: Cap,
    fd: i32,
    file_size: usize,
) -> Option<VfsLoadResult> {
    unsafe {
        let alloc_size = ((file_size + 0xFFF) & !0xFFF) as u64;
        let buf = trona_runtime::client::mm::mmap(
            core::ptr::null_mut(),
            alloc_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap_or(usize::MAX as *mut u8);
        if buf as usize == usize::MAX {
            return None;
        }

        let total_read = match vfs_bulk_read_all_on(ep, fd, buf, file_size) {
            Some(n) => n,
            None => {
                vfs_close_on(ep, fd);
                let _ = trona_runtime::client::mm::munmap(buf, alloc_size);
                return None;
            }
        };
        if total_read != file_size {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS(on): short read got=");
                _lb.hex(total_read as u64);
                _lb.str(b" expect=");
                _lb.hex(file_size as u64);
                _lb.str(b"\n");
            });
            vfs_close_on(ep, fd);
            let _ = trona_runtime::client::mm::munmap(buf, alloc_size);
            return None;
        }

        Some(VfsLoadResult {
            data: buf as *const u8,
            data_len: total_read,
            alloc_size,
        })
    }
}

unsafe fn inspect_streamed_vfs_elf_on(ep: Cap, fd: i32, file_size: usize) -> Option<VfsStreamExec> {
    unsafe {
        let mut ehdr = core::mem::MaybeUninit::<Elf64Ehdr>::uninit();
        if !vfs_read_exact_at_on(
            ep,
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
        #[cfg(target_arch = "x86_64")]
        if ehdr.e_machine != EM_X86_64 {
            return None;
        }
        #[cfg(target_arch = "aarch64")]
        if ehdr.e_machine != EM_AARCH64 {
            return None;
        }

        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;
        let phdr_bytes_len = phnum.checked_mul(phentsz)?;
        if phnum == 0 || phdr_bytes_len == 0 || phdr_bytes_len > MAX_STREAM_ELF_PHDR_BYTES {
            return None;
        }

        let mut phdr_bytes = [0u8; MAX_STREAM_ELF_PHDR_BYTES];
        if !vfs_read_exact_at_on(
            ep,
            fd,
            phdr_bytes.as_mut_ptr(),
            phdr_bytes_len,
            ehdr.e_phoff as usize,
        ) {
            return None;
        }
        let phdr_bytes = &phdr_bytes[..phdr_bytes_len];

        let mut min_vaddr = u64::MAX;
        let mut max_vaddr_end = 0u64;
        let mut is_dynamic = false;
        let mut interp_name = [0u8; MAX_STREAM_INTERP_LEN];
        let mut interp_name_len = super::resolve_interp_to_cpio_path(&[], &mut interp_name);
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
                    && vfs_read_exact_at_on(
                        ep,
                        fd,
                        interp_buf.as_mut_ptr(),
                        interp_copy,
                        phdr.p_offset as usize,
                    )
                {
                    let mut len = 0usize;
                    while len < interp_copy && interp_buf[len] != 0 {
                        len += 1;
                    }
                    if len > 0 {
                        let resolved = super::resolve_interp_to_cpio_path(
                            &interp_buf[..len],
                            &mut interp_name,
                        );
                        if resolved > 0 {
                            interp_name_len = resolved;
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

        let phdr_runtime_vaddr = elf_get_phdr_load_offset_inline(
            phdr_bytes.as_ptr(),
            phnum,
            phentsz,
            phdr_bytes_len,
            ehdr.e_phoff,
        )?;

        let mut needed = super::NeededLibs::new();

        if dyn_size != 0 {
            let dyn_count = dyn_size / core::mem::size_of::<Elf64Dyn>();
            let mut strtab_va = 0u64;
            let mut needed_offsets = [0u64; super::MAX_NEEDED_LIBS];
            let mut needed_count = 0usize;

            for i in 0..dyn_count {
                let entry_off = dyn_file_off + i * core::mem::size_of::<Elf64Dyn>();
                let mut dyn_entry = core::mem::MaybeUninit::<Elf64Dyn>::uninit();
                if !vfs_read_exact_at_on(
                    ep,
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
                }
            }

            if strtab_va != 0 {
                let strtab_file_off =
                    stream_va_to_file_offset(phdr_bytes, phnum, phentsz, strtab_va)?;
                for i in 0..needed_count {
                    let mut name_buf = [0u8; super::MAX_NEEDED_NAME];
                    let name_len = read_c_string_at_on(
                        ep,
                        fd,
                        strtab_file_off + needed_offsets[i] as usize,
                        &mut name_buf,
                    )?;
                    if name_len == 0 {
                        continue;
                    }
                    let copy_len = core::cmp::min(name_len, super::MAX_NEEDED_NAME);
                    if needed.count < super::MAX_NEEDED_LIBS {
                        for j in 0..copy_len {
                            needed.names[needed.count][j] = name_buf[j];
                        }
                        needed.name_lens[needed.count] = copy_len;
                        needed.count += 1;
                    }
                }
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
            phdr_vaddr: phdr_runtime_vaddr,
            phent: ehdr.e_phentsize as u64,
            phnum: ehdr.e_phnum as u64,
        })
    }
}

/// Open an exec source from VFS using a badged endpoint.
///
/// When `stat_out` is non-null, VFS_POSIX_STAT_FOR_EXEC is called first (new wire:
/// badge-based, no caller_badge in regs) to retrieve mode/uid/gid/size and
/// check X_OK. If the stat fails, the open is aborted.
pub(crate) unsafe fn try_open_exec_source_on(
    ep: Cap,
    path: &[u8],
    path_len: usize,
    stat_out: *mut VfsExecStatResult,
) -> Option<VfsExecSource> {
    unsafe {
        if !stat_out.is_null() {
            if let Some(stat) = vfs_stat_for_exec_on(ep, path, path_len) {
                *stat_out = stat;
            } else {
                return None;
            }
        }

        let fd = vfs_open_on(ep, path, path_len)?;
        let file_size = match vfs_fstat_on(ep, fd) {
            Some(sz) => sz,
            None => {
                vfs_close_on(ep, fd);
                return None;
            }
        };

        if file_size == 0 || file_size > MAX_VFS_FILE_SIZE {
            vfs_close_on(ep, fd);
            return None;
        }

        if file_size <= STREAM_VFS_ELF_THRESHOLD {
            let result = read_open_vfs_file_to_buffer_on(ep, fd, file_size)?;
            vfs_close_on(ep, fd);
            return Some(VfsExecSource::Buffered(result));
        }

        match inspect_streamed_vfs_elf_on(ep, fd, file_size) {
            Some(exec) => Some(VfsExecSource::Streamed(exec)),
            None => {
                vfs_close_on(ep, fd);
                None
            }
        }
    }
}

/// Clean up a VFS-backed exec source opened via badged endpoint.
///
/// Uses `vfs_close_on` for the streamed fd since the fd belongs to
/// the subject process's VFS client state, not procmgr's.
pub unsafe fn cleanup_exec_source_on(ep: Cap, source: &mut VfsExecSource) {
    unsafe {
        match source {
            VfsExecSource::None => {}
            VfsExecSource::Buffered(buf) => {
                cleanup_vfs_load(buf.data, buf.alloc_size);
            }
            VfsExecSource::Streamed(exec) => {
                if exec.fd >= 0 {
                    vfs_close_on(ep, exec.fd);
                }
            }
        }
        *source = VfsExecSource::None;
    }
}
