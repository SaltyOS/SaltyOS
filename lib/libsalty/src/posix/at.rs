// SPDX-License-Identifier: GPL-2.0-only
//! POSIX *at() operations (openat, fstatat, unlinkat, renameat, symlinkat).

use crate::consts::*;
use crate::types::*;
use super::{pack_path, CAP_VFS_EP};

/// openat(dirfd, path, flags, mode)
/// IPC: reg[0]=dirfd, reg[1]=open_flags, reg[2]=mode, reg[3..]=path(len+data)
pub unsafe fn posix_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_OPENAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = flags as u32 as u64;
        msg.regs[2] = mode as u64;
        let path_len = pack_path(&raw mut msg, 3, path);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// fstatat(dirfd, path, statbuf, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub unsafe fn posix_fstatat(dirfd: i32, path: *const u8, st: *mut SaltyStat, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FSTATAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// unlinkat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub unsafe fn posix_unlinkat(dirfd: i32, path: *const u8, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_UNLINKAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// renameat(old_dirfd, old_path, new_dirfd, new_path)
/// IPC: reg[0]=old_dirfd, reg[1]=new_dirfd, reg[2]=old_len, reg[3]=new_len, reg[4..]=paths
pub unsafe fn posix_renameat(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_RENAMEAT;

        let mut old_len: u8 = 0;
        while *old_path.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }
        let mut new_len: u8 = 0;
        while *new_path.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        msg.regs[0] = old_dirfd as u32 as u64;
        msg.regs[1] = new_dirfd as u32 as u64;
        msg.regs[2] = old_len as u64;
        msg.regs[3] = new_len as u64;
        for i in 4..20 {
            msg.regs[i] = 0;
        }
        let dst = &mut msg.regs[4] as *mut u64 as *mut u8;
        for i in 0..old_len as usize {
            *dst.add(i) = *old_path.add(i);
        }
        let dst2 = (&mut msg.regs[4 + ((old_len as usize + 7) / 8)]) as *mut u64 as *mut u8;
        for i in 0..new_len as usize {
            *dst2.add(i) = *new_path.add(i);
        }
        msg.length = 4 + ((old_len as u64 + 7) / 8) + ((new_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// mkdirat(dirfd, path, mode)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2..]=path(len+data)
pub unsafe fn posix_mkdirat(dirfd: i32, path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MKDIRAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// faccessat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub unsafe fn posix_faccessat(dirfd: i32, path: *const u8, mode: i32, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FACCESSAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 3, path);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// fchmodat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub unsafe fn posix_fchmodat(dirfd: i32, path: *const u8, mode: u32, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHMODAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 3, path);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
/// IPC: reg[0]=dirfd, reg[1]=uid, reg[2]=gid, reg[3]=at_flags, reg[4..]=path(len+data)
pub unsafe fn posix_fchownat(
    dirfd: i32,
    path: *const u8,
    uid: u32,
    gid: u32,
    at_flags: i32,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHOWNAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = uid as u64;
        msg.regs[2] = gid as u64;
        msg.regs[3] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 4, path);
        msg.length = 5 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// utimensat(dirfd, path, times, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..5]=times, reg[6..]=path(len+data)
pub unsafe fn posix_utimensat(
    dirfd: i32,
    path: *const u8,
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    at_flags: i32,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_UTIMENSAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        msg.regs[2] = atime_sec as u64;
        msg.regs[3] = atime_nsec as u64;
        msg.regs[4] = mtime_sec as u64;
        msg.regs[5] = mtime_nsec as u64;
        let path_len = pack_path(&raw mut msg, 6, path);
        msg.length = 7 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Create a symbolic link at `linkpath` (relative to `newdirfd`) pointing to `target`.
/// IPC layout: regs[0]=newdirfd, regs[1]=target_len, regs[2..10]=target(64B), regs[10]=link_len, regs[11..19]=link(64B)
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SYMLINKAT;

        // newdirfd in regs[0]
        msg.regs[0] = newdirfd as u32 as u64;

        // Measure target length
        let mut target_len: u8 = 0;
        while *target.add(target_len as usize) != 0 && target_len < 64 {
            target_len += 1;
        }

        // Measure link path length
        let mut link_len: u8 = 0;
        while *linkpath.add(link_len as usize) != 0 && link_len < 64 {
            link_len += 1;
        }

        // Pack target into regs[1..10]: regs[1]=target_len, regs[2..10]=target bytes
        msg.regs[1] = target_len as u64;
        let dst = &mut msg.regs[2] as *mut u64 as *mut u8;
        for i in 0..target_len as usize {
            *dst.add(i) = *target.add(i);
        }

        // Pack link path into regs[10..19]: regs[10]=link_len, regs[11..19]=link bytes
        msg.regs[10] = link_len as u64;
        let dst2 = &mut msg.regs[11] as *mut u64 as *mut u8;
        for i in 0..link_len as usize {
            *dst2.add(i) = *linkpath.add(i);
        }

        msg.length = 19;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Read the target of a symbolic link at `path` (relative to `dirfd`).
/// IPC layout: regs[0]=path_len, regs[1..]=path bytes
/// Reply: regs[0]=target_len, regs[1..]=target bytes
/// Returns the number of bytes placed in `buf`, or -1 on error.
pub unsafe fn posix_readlinkat(_dirfd: i32, path: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_READLINKAT;
        let path_len = pack_path(&raw mut msg, 0, path);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        let target_len = reply.regs[0] as usize;
        let copy_len = if target_len < bufsiz { target_len } else { bufsiz };
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..copy_len {
            *buf.add(i) = *src.add(i);
        }
        copy_len as i64
    }
}

/// Create a hard link: `newpath` (relative to `newdirfd`) becomes an additional
/// name for the file at `oldpath` (relative to `olddirfd`).
/// IPC layout: regs[0]=old_len, regs[1..9]=oldpath(64B), regs[9]=new_len, regs[10..18]=newpath(64B)
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_linkat(
    _olddirfd: i32, oldpath: *const u8,
    _newdirfd: i32, newpath: *const u8,
    _flags: i32,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_LINKAT;

        // Measure old path length
        let mut old_len: u8 = 0;
        while *oldpath.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }

        // Measure new path length
        let mut new_len: u8 = 0;
        while *newpath.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        // Pack old path into regs[0..9]
        msg.regs[0] = old_len as u64;
        let dst = &mut msg.regs[1] as *mut u64 as *mut u8;
        for i in 0..old_len as usize {
            *dst.add(i) = *oldpath.add(i);
        }

        // Pack new path into regs[9..18]
        msg.regs[9] = new_len as u64;
        let dst2 = &mut msg.regs[10] as *mut u64 as *mut u8;
        for i in 0..new_len as usize {
            *dst2.add(i) = *newpath.add(i);
        }

        msg.length = 18;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}
