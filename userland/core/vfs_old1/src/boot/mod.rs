// SPDX-License-Identifier: GPL-2.0-only
//! Bootstrap initrd import.

pub(crate) mod fstab;
pub(crate) mod rootfs;

use trona_loader::common::cpio::{CpioEntryExt, CpioIter};
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::vfs_core::vnode::{VT_LNK, VT_REG};

const INITRD_PATH_MAX: usize = 256;

fn read_boot_info_initrd_size() -> usize {
    unsafe {
        match trona_kernel::bootinfo::read_typed::<uapi::kernite_bootinfo_initrd>(
            uapi::KERNITE_BOOTINFO_TAG_INITRD as u16,
        ) {
            Some(r) => r.length as usize,
            None => 0,
        }
    }
}

fn reserved_mountpoint_path(path: &[u8]) -> bool {
    matches!(
        path,
        b"/dev" | b"/proc" | b"/sys" | b"/tmp" | b"/pipe" | b"/newroot" | b"/initramfs"
    ) || path.starts_with(b"/dev/")
        || path.starts_with(b"/proc/")
        || path.starts_with(b"/sys/")
        || path.starts_with(b"/tmp/")
        || path.starts_with(b"/pipe/")
        || path.starts_with(b"/newroot/")
        || path.starts_with(b"/initramfs/")
}

unsafe fn normalize_cpio_path(
    entry: &CpioEntryExt,
    out: &mut [u8; INITRD_PATH_MAX],
) -> Option<usize> {
    unsafe {
        if entry.name.is_null() || entry.name_len == 0 {
            return None;
        }

        let mut start = 0usize;
        let mut end = entry.name_len;
        while start < end && *entry.name.add(start) == b'/' {
            start += 1;
        }
        while start + 1 < end
            && *entry.name.add(start) == b'.'
            && *entry.name.add(start + 1) == b'/'
        {
            start += 2;
        }
        while end > start && *entry.name.add(end - 1) == b'/' {
            end -= 1;
        }
        if start >= end {
            return None;
        }

        let mut len = 1usize;
        out[0] = b'/';
        let mut prev_slash = true;
        let mut pos = start;
        while pos < end {
            let c = *entry.name.add(pos);
            if c == b'/' {
                if !prev_slash {
                    if len >= out.len() {
                        return None;
                    }
                    out[len] = b'/';
                    len += 1;
                }
                prev_slash = true;
                pos += 1;
                continue;
            }
            if len >= out.len() {
                return None;
            }
            out[len] = c;
            len += 1;
            prev_slash = false;
            pos += 1;
        }

        if len > 1 && out[len - 1] == b'/' {
            len -= 1;
        }
        if len <= 1 {
            return None;
        }
        Some(len)
    }
}

fn ensure_parent_dirs(state: &mut VfsState, path: &[u8]) -> bool {
    if path.len() <= 1 {
        return true;
    }

    let mut current = [0u8; INITRD_PATH_MAX];
    current[0] = b'/';
    let mut current_len = 1usize;
    let mut pos = 1usize;
    while pos < path.len() {
        let start = pos;
        while pos < path.len() && path[pos] != b'/' {
            pos += 1;
        }
        if pos >= path.len() {
            break;
        }

        if current_len > 1 {
            current[current_len] = b'/';
            current_len += 1;
        }
        let comp_len = pos - start;
        current[current_len..current_len + comp_len].copy_from_slice(&path[start..pos]);
        current_len += comp_len;

        match state.bootstrap_mkdir_path(&current[..current_len], (S_IFDIR as u32) | 0o755) {
            Ok(_) | Err(TRONA_ALREADY_EXISTS) => {}
            Err(_) => return false,
        }

        pos += 1;
    }
    true
}

fn apply_entry(state: &mut VfsState, path: &[u8], entry: &CpioEntryExt) -> bool {
    if reserved_mountpoint_path(path) {
        return true;
    }
    if !ensure_parent_dirs(state, path) {
        return false;
    }

    let mode = if entry.mode != 0 {
        entry.mode
    } else {
        (S_IFREG as u32) | 0o444
    };
    let kind = (mode as u64) & S_IFMT;

    if kind == S_IFDIR {
        let vh = match state.bootstrap_mkdir_path(path, mode) {
            Ok(vh) => vh,
            Err(TRONA_ALREADY_EXISTS) => match state.bootstrap_lookup_path(path) {
                Some(vh) => vh,
                None => return false,
            },
            Err(_) => return false,
        };
        if let Some(vn) = state.vnodes.get_mut(vh) {
            vn.mode = mode;
            vn.uid = entry.uid;
            vn.gid = entry.gid;
            vn.nlink = if entry.nlink == 0 { 1 } else { entry.nlink };
            vn.atime_ns = (entry.mtime as u64) * 1_000_000_000;
            vn.mtime_ns = (entry.mtime as u64) * 1_000_000_000;
        }
        return true;
    }

    if kind == S_IFLNK {
        let vh = match state.bootstrap_lookup_path(path) {
            Some(vh) => vh,
            None => match state.bootstrap_create_symlink_path(path, mode, unsafe {
                core::slice::from_raw_parts(entry.data, entry.data_len)
            }) {
                Ok(vh) => vh,
                Err(_) => return false,
            },
        };
        let Some(vn) = state.vnodes.get(vh) else {
            return false;
        };
        if vn.vtype != VT_LNK {
            return false;
        }
        if let Some(vn) = state.vnodes.get_mut(vh) {
            vn.mode = mode;
            vn.uid = entry.uid;
            vn.gid = entry.gid;
            vn.nlink = if entry.nlink == 0 { 1 } else { entry.nlink };
            vn.atime_ns = (entry.mtime as u64) * 1_000_000_000;
            vn.mtime_ns = (entry.mtime as u64) * 1_000_000_000;
        }
        return true;
    }

    if kind == S_IFREG {
        let vh = match state.bootstrap_lookup_path(path) {
            Some(vh) => vh,
            None => match state.bootstrap_create_regular_file_path(path, mode) {
                Ok(vh) => vh,
                Err(_) => return false,
            },
        };
        let Some(vn) = state.vnodes.get(vh) else {
            return false;
        };
        if vn.vtype != VT_REG {
            return false;
        }
        if !state.bootstrap_resize_file(vh, 0) {
            return false;
        }
        if entry.data_len != 0
            && state
                .bootstrap_write_file(vh, 0, entry.data, entry.data_len)
                .is_none()
        {
            return false;
        }
        if let Some(vn) = state.vnodes.get_mut(vh) {
            vn.mode = mode;
            vn.uid = entry.uid;
            vn.gid = entry.gid;
            vn.nlink = if entry.nlink == 0 { 1 } else { entry.nlink };
            vn.atime_ns = (entry.mtime as u64) * 1_000_000_000;
            vn.mtime_ns = (entry.mtime as u64) * 1_000_000_000;
        }
        return true;
    }

    true
}

pub(crate) fn extract_initrd(state: &mut VfsState) -> bool {
    unsafe {
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = read_boot_info_initrd_size();
        if initrd_size == 0 {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] WARN: initrd not present\n");
            });
            return true;
        }

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] Initrd size: ");
            _lb.hex(initrd_size as u64);
            _lb.str(b" bytes\n");
        });

        let mut iter = CpioIter::new(initrd, initrd_size);
        let mut imported = 0u32;
        let mut skipped = 0u32;
        let mut path = [0u8; INITRD_PATH_MAX];

        while let Some(entry) = iter.next_entry_ext() {
            let Some(path_len) = normalize_cpio_path(&entry, &mut path) else {
                continue;
            };
            if apply_entry(state, &path[..path_len], &entry) {
                imported = imported.saturating_add(1);
            } else {
                skipped = skipped.saturating_add(1);
            }
        }

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] Imported ");
            _lb.dec(imported as u64);
            _lb.str(b" initrd entries");
            if skipped != 0 {
                _lb.str(b" skipped_symlinks=");
                _lb.dec(skipped as u64);
            }
            _lb.str(b"\n");
        });
        true
    }
}
