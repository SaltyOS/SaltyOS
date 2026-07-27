// SPDX-License-Identifier: GPL-2.0-only
//
//! Resolution mechanics: content-digest hashing, conferring `EXECUTE`, and the
//! VFS disk path for an object that is neither adopted nor already cached.
//!
//! `ldsrv` hashes an object by streaming the requested image window of its
//! **read-only backing** through `MO_READ` — which pages a file-backed MO in
//! through its pager transparently — never by mapping an `R-X` view (the digest
//! is computed before `EXECUTE` exists). The digest is a de-duplication
//! identity, so an object already in the cache returns the one shared code MO
//! (R5) rather than a second copy.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_protocol::ldsrv::{ContentDigest, LDSRV_FORMAT_ELF, LDSRV_FORMAT_PE};
use trona_runtime::core::slot_alloc::{
    dup_for_transfer, resolved_cap_ref, slot_alloc, slot_invoke_depth,
};

use crate::cache::{Cache, CodeObject, Identity};

const SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;

/// Largest `MO_READ` chunk. The kernel copies into this thread's IPC buffer, so
/// it must stay well under the buffer size; ldsrv has already copied the
/// in-flight request onto the stack, so clobbering the buffer here is benign.
const HASH_CHUNK: u64 = 2048;

fn ipc_buffer_bytes() -> *const u8 {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return core::ptr::null();
    }
    unsafe { (*ctx).ipc_buffer as *const u8 }
}

/// Stream `image_size` bytes at `image_offset` of `mo_slot` through `MO_READ`,
/// returning the 128-bit content identity and the detected image format (from
/// the leading magic).
///
/// # Safety
/// `mo_slot` must name a readable MemoryObject this process owns.
pub unsafe fn hash_mo(mo_slot: u64, image_offset: u64, image_size: u64) -> Option<(Identity, u64)> {
    let buf = ipc_buffer_bytes();
    if image_size == 0 || buf.is_null() {
        return None;
    }
    let mut digest = ContentDigest::new();
    let mut format = LDSRV_FORMAT_ELF;
    let mut off = 0u64;
    let mut first = true;
    while off < image_size {
        let want = (image_size - off).min(HASH_CHUNK);
        let read_off = image_offset.checked_add(off)?;
        let (err, got) = invoke::mo_read(resolved_cap_ref(mo_slot), read_off, want);
        if err != 0 || got != want {
            return None;
        }
        let bytes = unsafe { core::slice::from_raw_parts(buf, want as usize) };
        if first {
            format = format_of(bytes);
            first = false;
        }
        digest.update(bytes);
        off += want;
    }
    let (lo, hi) = digest.finish();
    Some((Identity { lo, hi }, format))
}

/// Classify an image by its leading bytes: ELF (`\x7fELF`) vs PE (`MZ`).
/// Defaults to ELF — the format tag is an advisory hint and the consumer reads
/// the real headers from the code MO.
fn format_of(bytes: &[u8]) -> u64 {
    if bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z' {
        LDSRV_FORMAT_PE
    } else {
        LDSRV_FORMAT_ELF
    }
}

/// Hash the image window in `backing_slot`, and either return the index of an
/// already-cached object with the same content identity (R5 — release
/// `backing_slot` upstream) or confer `READ|EXECUTE` on a code MO with
/// `exec_authority` and cache it. Returns the cache index, or `None` on
/// failure.
///
/// # Safety
/// `backing_slot` is a non-exec backing MO this process owns; the
/// `(image_offset, image_size)` window names the executable image bytes within
/// it; `exec_authority` names the moved `ExecAuthority` cap (`0` if the handoff
/// has not delivered it, in which case conferral fails).
pub unsafe fn confer_and_cache(
    backing_slot: u64,
    image_offset: u64,
    image_size: u64,
    exec_authority: u64,
    cache: &mut Cache,
) -> Option<usize> {
    if exec_authority == 0 || image_size == 0 {
        return None;
    }
    let _image_end = image_offset.checked_add(image_size)?;
    let (identity, format) = unsafe { hash_mo(backing_slot, image_offset, image_size) }?;
    if let Some(idx) = cache.find_object(identity) {
        return Some(idx);
    }

    // PE file layout (file offsets) differs from memory layout (RVAs), so PE
    // always relays into a fresh memory-image MO before EXECUTE conferral. ELF
    // can confer directly only when the image starts at backing offset 0; a
    // non-zero-offset ELF is relayed so byte 0 of the code MO is the ELF header
    // the existing init/rtld loaders expect. Writable relay caps are dropped
    // before the R-X child is cached, so no writable view of the code object
    // coexists with the executable one (W^X).
    let (confer_src, image_size, entry, relaid) = if format == LDSRV_FORMAT_PE {
        match unsafe { relayout_pe(backing_slot, image_offset, image_size) } {
            Some((memimage, sz, e)) => (memimage, sz, e, Some(memimage)),
            None => return None,
        }
    } else if image_offset == 0 {
        (backing_slot, image_size, 0u64, None)
    } else {
        match unsafe { relay_file_window(backing_slot, image_offset, image_size) } {
            Some(memimage) => (memimage, image_size, 0u64, Some(memimage)),
            None => return None,
        }
    };

    let Some(dest) = slot_alloc() else {
        if let Some(m) = relaid {
            free_slot(m);
        }
        return None;
    };
    // ldsrv installs code MOs into flat root-CNode slots (its object count stays
    // well within the root CNode), addressed as `(self-cspace, dest)`.
    let err = invoke::mo_mark_executable_ref(
        resolved_cap_ref(exec_authority),
        resolved_cap_ref(confer_src),
        CapRef::flat(SELF_CSPACE),
        CapRef::at_depth(dest, slot_invoke_depth(dest)),
    );
    // Drop the writable relayout cap: the R-X child holds its own ref on the MO,
    // so the object survives with no writable view.
    if let Some(m) = relaid {
        free_slot(m);
    }
    if err != 0 {
        free_slot(dest);
        return None;
    }
    // For PE, `entry` carries the parsed entry-point RVA; for ELF the consumer
    // reads it from the code MO (advisory-zero here).
    cache.insert_object(CodeObject::new(
        identity, dest, image_size, format, entry, 0, 0,
    ))
}

/// Delete a cap from ldsrv's root CNode and recycle its slot.
fn free_slot(slot: u64) {
    let depth = slot_invoke_depth(slot);
    let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), slot, depth);
}

/// Relay a contiguous file window into a fresh zero-based MemoryObject. This is
/// used for non-zero-offset ELF images: the loader contract is that byte 0 of the
/// code MO is the image header, even when the VFS backing covers a larger file
/// or filesystem object.
///
/// # Safety
/// `file_slot` names a readable file MemoryObject this process owns.
unsafe fn relay_file_window(file_slot: u64, file_offset: u64, file_size: u64) -> Option<u64> {
    use trona_loader::common::image::{PROT_READ, PROT_WRITE};

    if file_size == 0 {
        return None;
    }
    let _file_end = file_offset.checked_add(file_size)?;
    let map_len = checked_page_align_up(file_size)?;
    let copy_len = usize::try_from(file_size).ok()?;
    let memimage = trona_runtime::client::mm::mo_create(map_len).ok()?;
    let map_copy = dup_for_transfer(resolved_cap_ref(memimage.as_raw()))?;
    let mapped = unsafe {
        trona_runtime::client::mm::mmap_mo(0, map_len, (PROT_READ | PROT_WRITE) as u64, 0, map_copy)
    }
    .ok()?;
    let copied = unsafe { read_chunked(file_slot, file_offset, mapped, copy_len) };
    let unmapped = unsafe { trona_runtime::client::mm::munmap(mapped, map_len) }.is_ok();
    if copied != copy_len || !unmapped {
        return None;
    }
    Some(memimage.into_raw())
}

/// Relay a PE *file* MO out into a fresh *memory-image* MO: a new anonymous MO
/// of `size_of_image` bytes with the PE headers and each section copied from its
/// file offset to its RVA (the remainder left zero). Returns the memory-image MO
/// slot, its byte size, and the entry-point RVA; the caller confers `EXECUTE` on
/// it and then drops the writable slot. `None` on any failure.
///
/// # Safety
/// `file_slot` names a readable PE file MemoryObject this process owns.
unsafe fn relayout_pe(file_slot: u64, file_offset: u64, file_size: u64) -> Option<(u64, u64, u64)> {
    use trona_loader::common::pe::memory_image::{MAX_COPIES, PeCopy, plan_memory_image};

    if file_size == 0 {
        return None;
    }
    let _file_end = file_offset.checked_add(file_size)?;

    // 1) Bounded header read exposes enough bytes for `validate` +
    //    section-table walk. The planner is bounded by 8 KiB because
    //    every standard PE keeps DOS + PE + COFF + opt + data dirs in
    //    the first page; section headers begin within the second page.
    let mut hdr = [0u8; 8192];
    let cap = if file_size < hdr.len() as u64 {
        file_size as usize
    } else {
        hdr.len()
    };
    let hlen = unsafe { read_chunked(file_slot, file_offset, hdr.as_mut_ptr(), cap) };
    if hlen != cap {
        return None;
    }

    // 2) Plan the (file_off → RVA) copy list from the shared helper.
    //    The planner enforces the same header + bounds invariants as
    //    init's `adopt_object_pe`, so the two paths cannot drift.
    let mut copies = [PeCopy {
        src_file_offset: 0,
        dst_rva: 0,
        bytes: 0,
    }; MAX_COPIES];
    let (image_size, _size_of_headers, entry, copy_count) =
        unsafe { plan_memory_image(&hdr[..hlen], &mut copies) }.ok()?;

    // 3) Allocate memory-image MO + R/W mapping.
    let map_len = checked_page_align_up(image_size)?;
    let memimage = trona_runtime::client::mm::mo_create(map_len).ok()?;
    let map_copy = dup_for_transfer(resolved_cap_ref(memimage.as_raw()))?;
    let mapped = unsafe {
        trona_runtime::client::mm::mmap_mo(
            0,
            map_len,
            (uapi::KERNITE_RIGHT_READ | uapi::KERNITE_RIGHT_WRITE) as u64,
            0,
            map_copy,
        )
    }
    .ok()?;
    let dst = mapped as usize;

    // 4) Execute each copy. The planner validated bounds, so a
    //    `read_chunked` short read is the only way this loop can fail.
    let mut ok = true;
    for c in &copies[..copy_count] {
        if !ok {
            break;
        }
        let len = usize::try_from(c.bytes).ok()?;
        let src_off = file_offset.checked_add(c.src_file_offset)?;
        let dst_off = c.dst_rva as usize;
        let copied = unsafe { read_chunked(file_slot, src_off, (dst + dst_off) as *mut u8, len) };
        ok = copied == len;
    }
    let unmapped = unsafe { trona_runtime::client::mm::munmap(mapped, map_len) }.is_ok();
    if !ok || !unmapped {
        return None;
    }
    Some((memimage.into_raw(), image_size, entry))
}

/// Stream `len` bytes of `mo_slot` at `off` through `MO_READ` into `dst`,
/// copying out of the IPC buffer chunk by chunk. Returns the byte count written.
///
/// # Safety
/// `mo_slot` is readable; `dst` is writable for at least `len` bytes.
unsafe fn read_chunked(mo_slot: u64, off: u64, dst: *mut u8, len: usize) -> usize {
    let buf = ipc_buffer_bytes();
    if buf.is_null() {
        return 0;
    }
    let mut done = 0usize;
    while done < len {
        let want = (len - done).min(HASH_CHUNK as usize) as u64;
        let Some(read_off) = off.checked_add(done as u64) else {
            break;
        };
        let (err, got) = unsafe { invoke::mo_read(resolved_cap_ref(mo_slot), read_off, want) };
        if err != 0 || got == 0 {
            break;
        }
        let got = (got as usize).min(want as usize);
        unsafe { core::ptr::copy_nonoverlapping(buf, dst.add(done), got) };
        done += got;
    }
    done
}

#[inline]
fn checked_page_align_up(v: u64) -> Option<u64> {
    Some(v.checked_add(4095)? & !4095)
}

/// Resolve a `DT_NEEDED` soname that missed the cache by opening it through the
/// VFS under ldsrv's own authority (the library namespace is ldsrv's; the
/// `X_OK` / `MNT_NOEXEC` exec policy applies only to main images, which take
/// the caller-authority path instead). Confers `EXECUTE`, caches by identity,
/// binds the soname, and returns the cache index.
///
/// # Safety
/// `cache` is the live cache; `exec_authority` is the moved authority slot.
pub unsafe fn from_vfs(soname: &[u8], exec_authority: u64, cache: &mut Cache) -> Option<usize> {
    // ldsrv owns the library namespace; search the directories the in-linker
    // search used to cover (`/usr/lib` first, then `/lib`) so resolution does
    // not regress now that the linker hands over a bare soname.
    const PREFIXES: [&[u8]; 2] = [b"/usr/lib/", b"/lib/"];
    for prefix in PREFIXES {
        let mut path = [0u8; 96];
        if prefix.len() + soname.len() + 1 > path.len() {
            continue;
        }
        path[..prefix.len()].copy_from_slice(prefix);
        path[prefix.len()..prefix.len() + soname.len()].copy_from_slice(soname);
        // NUL terminator already zero.

        let fd = match unsafe { trona_runtime::client::vfs::open_readonly(path.as_ptr()) } {
            Ok(fd) => fd,
            Err(_) => continue,
        };

        let result = unsafe { resolve_open_fd(fd, soname, exec_authority, cache) };
        let _ = unsafe { trona_runtime::client::vfs::close(fd) };
        if result.is_some() {
            return result;
        }
    }
    None
}

/// With `fd` open: size it, fetch its non-exec backing MO, confer + cache, and
/// bind the soname. Split out so the caller always closes `fd`.
unsafe fn resolve_open_fd(
    fd: i32,
    soname: &[u8],
    exec_authority: u64,
    cache: &mut Cache,
) -> Option<usize> {
    const SEEK_SET: i32 = 0;
    const SEEK_END: i32 = 2;
    let size = match unsafe { trona_runtime::client::vfs::lseek(fd, 0, SEEK_END) } {
        Ok(s) if s > 0 => s as u64,
        _ => return None,
    };
    let _ = unsafe { trona_runtime::client::vfs::lseek(fd, 0, SEEK_SET) };

    let (backing, image_offset) = unsafe { vfs_get_backing_mo(fd, size)? };
    let idx = unsafe { confer_and_cache(backing, image_offset, size, exec_authority, cache) };
    // Release the non-exec backing: on a hit it is redundant, and on a miss
    // `mo_mark_executable` minted an independent CDT-child cap for the code MO,
    // so the backing slot is no longer needed.
    let depth = slot_invoke_depth(backing);
    let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), backing, depth);
    let idx = idx?;
    if let Some(id) = cache.object(idx).map(|o| o.identity) {
        if !cache.bind_soname(soname, id) {
            return None;
        }
    }
    Some(idx)
}

/// Fetch the non-exec backing MO for `fd` via `VFS_GET_BACKING_MO`, receiving
/// the transferred cap into a freshly allocated slot and returning the image's
/// backing offset. The server's sticky receive-slot configuration is saved and
/// restored around the one-off cap-receiving call so the serve loop's arena is
/// left untouched.
unsafe fn vfs_get_backing_mo(fd: i32, size: u64) -> Option<(u64, u64)> {
    use trona_protocol::vfs::public::{
        VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH, VFS_BACKING_MO_REPLY_REG_COUNT,
        VFS_BACKING_MO_REPLY_REG_OFFSET, VFS_BACKING_MO_REPLY_REG_SIZE,
        VFS_BACKING_MO_REPLY_REQUIRED_REGS, VFS_GET_BACKING_MO,
    };

    let ctx = trona_runtime::current_ipc_ctx();
    let vfs = trona_runtime::client::caps::vfs_ep();
    if ctx.is_null() || vfs.is_null() {
        return None;
    }

    let recv = slot_alloc()?;
    let recv_depth = slot_invoke_depth(recv);

    let saved = unsafe { trona_kernel::ipc::get_receive_slot_path_ctx(ctx) };
    unsafe {
        trona_kernel::ipc::set_receive_slot_path_ctx(ctx, SELF_CSPACE, recv, 0, recv_depth as u64);
    }

    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = VFS_GET_BACKING_MO;
    msg.regs[0] = fd as u64;
    msg.regs[1] = 0;
    msg.regs[2] = size;
    msg.length = 3;
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };

    unsafe {
        trona_kernel::ipc::set_receive_slot_path_ctx(ctx, saved.0, saved.1, saved.2, saved.3);
    }

    if err != 0
        || reply.label != trona_protocol::common::TRONA_OK
        || reply.length < VFS_BACKING_MO_REPLY_REQUIRED_REGS
        || reply.regs[VFS_BACKING_MO_REPLY_REG_SIZE] == 0
    {
        let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), recv, recv_depth);
        return None;
    }
    let offset = reply.regs[VFS_BACKING_MO_REPLY_REG_OFFSET];
    if reply.length >= VFS_BACKING_MO_REPLY_REG_COUNT {
        let backing_length = reply.regs[VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH];
        if offset
            .checked_add(size)
            .is_none_or(|end| end > backing_length)
        {
            let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), recv, recv_depth);
            return None;
        }
    }
    Some((recv, offset))
}
