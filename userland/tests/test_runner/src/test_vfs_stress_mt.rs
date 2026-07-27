//! Multi-threaded VFS stress tests.
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use trona_posix::consts::*;
use trona_posix::pthread;
use trona_runtime::debug::serial;

const OPEN_THREADS: usize = 6;
const OPEN_ITERS: usize = 96;
const NS_THREADS: usize = 4;
const NS_ITERS: usize = 48;
const OPEN_READ_BYTES: usize = 32 * 1024;
const CROSS_CHILDREN: usize = 4;
const CROSS_OPEN_THREADS: usize = 4;
const CROSS_OPEN_ITERS: usize = 128;

static OPEN_FAILS: AtomicU32 = AtomicU32::new(0);
static NS_FAILS: AtomicU32 = AtomicU32::new(0);
static OPEN_OPEN_FAILS: AtomicU32 = AtomicU32::new(0);
static OPEN_READ_FAILS: AtomicU32 = AtomicU32::new(0);
static OPEN_CLOSE_FAILS: AtomicU32 = AtomicU32::new(0);
static OPEN_FIRST_OPEN_RET: AtomicI32 = AtomicI32::new(0);
static OPEN_FIRST_READ_RET: AtomicI32 = AtomicI32::new(0);
static OPEN_FIRST_CLOSE_RET: AtomicI32 = AtomicI32::new(0);

// Use a file that is guaranteed to be present in the post-pivot rootfs.
const OPEN_STRESS_PATH: &[u8] = b"/bin/vfs_stress_elf\0";
const PE_STRESS_PATH: &[u8] = b"/bin/vfs_stress_pe\0";

#[derive(Clone, Copy)]
struct OpenReadCloseResult {
    open_ret: i32,
    read_ret: i64,
    close_ret: i32,
}

const EINTR: i32 = -4;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn append_bytes(buf: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        if *pos + 1 >= buf.len() {
            break;
        }
        buf[*pos] = b;
        *pos += 1;
    }
}

fn append_dec(buf: &mut [u8], pos: &mut usize, mut value: usize) {
    let mut tmp = [0u8; 20];
    let mut len = 0usize;

    if value == 0 {
        append_bytes(buf, pos, b"0");
        return;
    }

    while value != 0 && len < tmp.len() {
        tmp[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }

    while len != 0 {
        len -= 1;
        append_bytes(buf, pos, &tmp[len..len + 1]);
    }
}

fn append_i32(buf: &mut [u8], pos: &mut usize, value: i32) {
    if value < 0 {
        append_bytes(buf, pos, b"-");
    }
    append_dec(buf, pos, value.unsigned_abs() as usize);
}

fn report_open_read_close_failures(prefix: &[u8]) {
    let mut buf = [0u8; 192];
    let mut pos = 0usize;

    append_bytes(&mut buf, &mut pos, prefix);
    append_bytes(&mut buf, &mut pos, b" open=");
    append_dec(
        &mut buf,
        &mut pos,
        OPEN_OPEN_FAILS.load(Ordering::Relaxed) as usize,
    );
    append_bytes(&mut buf, &mut pos, b" first=");
    append_i32(
        &mut buf,
        &mut pos,
        OPEN_FIRST_OPEN_RET.load(Ordering::Relaxed),
    );
    append_bytes(&mut buf, &mut pos, b" read=");
    append_dec(
        &mut buf,
        &mut pos,
        OPEN_READ_FAILS.load(Ordering::Relaxed) as usize,
    );
    append_bytes(&mut buf, &mut pos, b" first=");
    append_i32(
        &mut buf,
        &mut pos,
        OPEN_FIRST_READ_RET.load(Ordering::Relaxed),
    );
    append_bytes(&mut buf, &mut pos, b" close=");
    append_dec(
        &mut buf,
        &mut pos,
        OPEN_CLOSE_FAILS.load(Ordering::Relaxed) as usize,
    );
    append_bytes(&mut buf, &mut pos, b" first=");
    append_i32(
        &mut buf,
        &mut pos,
        OPEN_FIRST_CLOSE_RET.load(Ordering::Relaxed),
    );
    append_bytes(&mut buf, &mut pos, b"\n");
    puts(&buf[..pos]);
}

fn reset_open_read_close_counters() {
    OPEN_FAILS.store(0, Ordering::Relaxed);
    OPEN_OPEN_FAILS.store(0, Ordering::Relaxed);
    OPEN_READ_FAILS.store(0, Ordering::Relaxed);
    OPEN_CLOSE_FAILS.store(0, Ordering::Relaxed);
    OPEN_FIRST_OPEN_RET.store(0, Ordering::Relaxed);
    OPEN_FIRST_READ_RET.store(0, Ordering::Relaxed);
    OPEN_FIRST_CLOSE_RET.store(0, Ordering::Relaxed);
}

fn record_open_read_close_failure(result: OpenReadCloseResult) {
    if result.open_ret < 0 {
        OPEN_FAILS.fetch_add(1, Ordering::Relaxed);
        OPEN_OPEN_FAILS.fetch_add(1, Ordering::Relaxed);
        let _ = OPEN_FIRST_OPEN_RET.compare_exchange(
            0,
            result.open_ret,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        return;
    }

    if result.read_ret != OPEN_READ_BYTES as i64 {
        OPEN_FAILS.fetch_add(1, Ordering::Relaxed);
        OPEN_READ_FAILS.fetch_add(1, Ordering::Relaxed);
        let read_ret = if result.read_ret < i32::MIN as i64 {
            i32::MIN
        } else if result.read_ret > i32::MAX as i64 {
            i32::MAX
        } else {
            result.read_ret as i32
        };
        let _ =
            OPEN_FIRST_READ_RET.compare_exchange(0, read_ret, Ordering::Relaxed, Ordering::Relaxed);
        return;
    }

    if result.close_ret != 0 {
        OPEN_FAILS.fetch_add(1, Ordering::Relaxed);
        OPEN_CLOSE_FAILS.fetch_add(1, Ordering::Relaxed);
        let _ = OPEN_FIRST_CLOSE_RET.compare_exchange(
            0,
            result.close_ret,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

fn make_ns_path(buf: &mut [u8], tid: usize, iter: usize, suffix: &[u8]) -> *const u8 {
    let mut pos = 0usize;
    append_bytes(buf, &mut pos, b"/tmp/vfs_stress_mt/t");
    append_dec(buf, &mut pos, tid);
    append_bytes(buf, &mut pos, b"_");
    append_dec(buf, &mut pos, iter);
    append_bytes(buf, &mut pos, suffix);
    buf[pos] = 0;
    buf.as_ptr()
}

unsafe fn open_read_close_stress_path() -> OpenReadCloseResult {
    unsafe {
        let fd = trona_posix::posix_open(OPEN_STRESS_PATH.as_ptr(), O_RDONLY as i32, 0);
        if fd < 0 {
            return OpenReadCloseResult {
                open_ret: fd,
                read_ret: 0,
                close_ret: 0,
            };
        }

        // posix_read may legitimately return a short count even for
        // regular files under load. Loop until the buffer is full, EOF is
        // hit, or an error is returned. The aggregate byte count is
        // reported as read_ret so existing "too few bytes" detection still
        // flags real failures; errno-style negative returns are propagated
        // unchanged so the outer EINTR retry path stays intact.
        let mut buf = [0u8; OPEN_READ_BYTES];
        let mut total: i64 = 0;
        let read_ret: i64 = loop {
            let remaining = (OPEN_READ_BYTES as i64) - total;
            if remaining <= 0 {
                break total;
            }
            let n =
                trona_posix::posix_read(fd, buf.as_mut_ptr().add(total as usize), remaining as u64);
            if n < 0 {
                break n;
            }
            if n == 0 {
                break total;
            }
            total += n;
        };

        let close_ret = trona_posix::posix_close(fd);
        OpenReadCloseResult {
            open_ret: fd,
            read_ret,
            close_ret,
        }
    }
}

unsafe fn open_read_close_stress_path_retry_eintr() -> OpenReadCloseResult {
    unsafe {
        loop {
            let result = open_read_close_stress_path();
            if result.open_ret == EINTR
                || result.read_ret == EINTR as i64
                || result.close_ret == EINTR
            {
                continue;
            }
            return result;
        }
    }
}

unsafe fn waitpid_retry_eintr(pid: i32, status: *mut i32) -> i32 {
    unsafe {
        loop {
            let waited = trona_posix::posix_waitpid(pid, status);
            if waited == -4 {
                continue;
            }
            return waited;
        }
    }
}

unsafe fn run_open_read_close_iters(iters: usize) {
    unsafe {
        for _ in 0..iters {
            let result = open_read_close_stress_path_retry_eintr();
            if result.open_ret < 0
                || result.read_ret != OPEN_READ_BYTES as i64
                || result.close_ret != 0
            {
                record_open_read_close_failure(result);
            }
            trona_kernel::syscall::yield_now();
        }
    }
}

fn wait_cross_children(pids: &[i32]) -> bool {
    for &pid in pids {
        if pid <= 0 {
            continue;
        }

        let mut status = 0i32;
        let waited = unsafe { waitpid_retry_eintr(pid, &raw mut status) };
        if waited != pid {
            puts(b"  waitpid returned wrong pid for vfs_stress_pe child\n");
            return false;
        }
        if status != 0 {
            puts(b"  vfs_stress_pe child exited with failure\n");
            return false;
        }
    }

    true
}

unsafe extern "C" fn thread_open_read_close(_arg: *mut u8) -> *mut u8 {
    unsafe {
        run_open_read_close_iters(OPEN_ITERS);
        core::ptr::null_mut()
    }
}

unsafe extern "C" fn thread_cross_open_read_close(_arg: *mut u8) -> *mut u8 {
    unsafe {
        run_open_read_close_iters(CROSS_OPEN_ITERS);
        core::ptr::null_mut()
    }
}

fn test_open_read_close_stress() -> bool {
    puts(b"  vfs_mt_open_read_close: start\n");
    reset_open_read_close_counters();

    let mut handles: [pthread::PthreadT; OPEN_THREADS] = [0; OPEN_THREADS];
    for handle in &mut handles {
        let ret = unsafe {
            pthread::pthread_create(
                handle as *mut _,
                core::ptr::null(),
                thread_open_read_close,
                core::ptr::null_mut(),
            )
        };
        if ret != 0 {
            puts(b"  pthread_create failed in open/read/close stress\n");
            return false;
        }
    }

    for &handle in &handles {
        let ret = unsafe { pthread::pthread_join(handle, core::ptr::null_mut()) };
        if ret != 0 {
            puts(b"  pthread_join failed in open/read/close stress\n");
            return false;
        }
    }

    if OPEN_FAILS.load(Ordering::Relaxed) != 0 {
        puts(b"  open/read/close stress saw failures\n");
        report_open_read_close_failures(b"  open/read/close details:");
        return false;
    }

    puts(b"  vfs_mt_open_read_close: ok\n");
    true
}

unsafe extern "C" fn thread_namespace_mutation(arg: *mut u8) -> *mut u8 {
    let tid = arg as usize;

    unsafe {
        let mut path_a = [0u8; 96];
        let mut path_b = [0u8; 96];

        for iter in 0..NS_ITERS {
            let a = make_ns_path(&mut path_a, tid, iter, b"_a");
            let b = make_ns_path(&mut path_b, tid, iter, b"_b");

            let fd = trona_posix::posix_open(a, (O_CREAT | O_TRUNC | O_RDWR) as i32, 0o644);
            if fd < 0 {
                NS_FAILS.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let byte = [b'X'];
            if trona_posix::posix_write(fd, byte.as_ptr(), 1) != 1 {
                NS_FAILS.fetch_add(1, Ordering::Relaxed);
            }
            trona_posix::posix_close(fd);

            if trona_posix::posix_rename(a, b) != 0 {
                NS_FAILS.fetch_add(1, Ordering::Relaxed);
                let _ = trona_posix::posix_unlink(a);
                let _ = trona_posix::posix_unlink(b);
                continue;
            }

            let verify_fd = trona_posix::posix_open(b, O_RDONLY as i32, 0);
            if verify_fd < 0 {
                NS_FAILS.fetch_add(1, Ordering::Relaxed);
                let _ = trona_posix::posix_unlink(b);
                continue;
            }

            let mut buf = [0u8; 1];
            if trona_posix::posix_read(verify_fd, buf.as_mut_ptr(), 1) != 1 || buf[0] != b'X' {
                NS_FAILS.fetch_add(1, Ordering::Relaxed);
            }
            trona_posix::posix_close(verify_fd);

            if trona_posix::posix_unlink(b) != 0 {
                NS_FAILS.fetch_add(1, Ordering::Relaxed);
            }
        }

        core::ptr::null_mut()
    }
}

fn test_namespace_mutation_stress() -> bool {
    puts(b"  vfs_mt_namespace: start\n");
    NS_FAILS.store(0, Ordering::Relaxed);

    let _ = unsafe { trona_posix::posix_mkdir(b"/tmp/vfs_stress_mt\0".as_ptr(), 0o755) };

    // Drop any leftovers from a prior aborted run. The naming convention
    // is deterministic (t{tid}_{iter}_{a,b}) so we can sweep the full
    // coordinate space without needing a directory-listing API.
    {
        let mut path_a = [0u8; 96];
        let mut path_b = [0u8; 96];
        for tid in 0..NS_THREADS {
            for iter in 0..NS_ITERS {
                let a = make_ns_path(&mut path_a, tid, iter, b"_a");
                let b = make_ns_path(&mut path_b, tid, iter, b"_b");
                unsafe {
                    let _ = trona_posix::posix_unlink(a);
                    let _ = trona_posix::posix_unlink(b);
                }
            }
        }
    }

    let mut handles: [pthread::PthreadT; NS_THREADS] = [0; NS_THREADS];
    for (idx, handle) in handles.iter_mut().enumerate() {
        let ret = unsafe {
            pthread::pthread_create(
                handle as *mut _,
                core::ptr::null(),
                thread_namespace_mutation,
                idx as *mut u8,
            )
        };
        if ret != 0 {
            puts(b"  pthread_create failed in namespace stress\n");
            return false;
        }
    }

    for &handle in &handles {
        let ret = unsafe { pthread::pthread_join(handle, core::ptr::null_mut()) };
        if ret != 0 {
            puts(b"  pthread_join failed in namespace stress\n");
            return false;
        }
    }

    let _ = unsafe { trona_posix::posix_rmdir(b"/tmp/vfs_stress_mt\0".as_ptr()) };

    if NS_FAILS.load(Ordering::Relaxed) != 0 {
        puts(b"  namespace mutation stress saw failures\n");
        return false;
    }

    puts(b"  vfs_mt_namespace: ok\n");
    true
}

fn test_cross_personality_exec_open() -> bool {
    puts(b"  vfs_mt_cross_personality: start\n");

    reset_open_read_close_counters();

    let mut pids = [0i32; CROSS_CHILDREN];
    for pid_slot in &mut pids {
        let pid = trona_posix::posix_fork();
        if pid < 0 {
            puts(b"  fork for vfs_stress_pe failed\n");
            let _ = wait_cross_children(&pids);
            return false;
        }

        if pid == 0 {
            unsafe {
                let argv = [PE_STRESS_PATH.as_ptr(), core::ptr::null()];
                trona_posix::proc::posix_execve(
                    PE_STRESS_PATH.as_ptr(),
                    argv.as_ptr(),
                    core::ptr::null(),
                );
                trona_posix::posix_exit(127);
            }
        }

        *pid_slot = pid;
    }

    let mut handles: [pthread::PthreadT; CROSS_OPEN_THREADS] = [0; CROSS_OPEN_THREADS];
    let mut created = 0usize;
    for handle in &mut handles {
        let ret = unsafe {
            pthread::pthread_create(
                handle as *mut _,
                core::ptr::null(),
                thread_cross_open_read_close,
                core::ptr::null_mut(),
            )
        };
        if ret != 0 {
            puts(b"  pthread_create failed in cross-personality stress\n");
            for &created_handle in &handles[..created] {
                let _ = unsafe { pthread::pthread_join(created_handle, core::ptr::null_mut()) };
            }
            let _ = wait_cross_children(&pids);
            return false;
        }
        created += 1;
    }

    for &handle in &handles[..created] {
        let ret = unsafe { pthread::pthread_join(handle, core::ptr::null_mut()) };
        if ret != 0 {
            puts(b"  pthread_join failed in cross-personality stress\n");
            let _ = wait_cross_children(&pids);
            return false;
        }
    }

    if OPEN_FAILS.load(Ordering::Relaxed) != 0 {
        let _ = wait_cross_children(&pids);
        puts(b"  parent open/read on /bin/vfs_stress_elf failed during vfs_stress_pe exec swarm\n");
        report_open_read_close_failures(b"  cross-personality details:");
        return false;
    }

    if !wait_cross_children(&pids) {
        return false;
    }

    puts(b"  vfs_mt_cross_personality: ok\n");
    true
}

pub fn run() -> bool {
    puts(b"[TEST_VFS_STRESS_MT] Starting multi-threaded VFS stress tests\n");

    let mut ok = true;
    if !test_open_read_close_stress() {
        ok = false;
    }
    if !test_cross_personality_exec_open() {
        ok = false;
    }
    if !test_namespace_mutation_stress() {
        ok = false;
    }

    if ok {
        puts(b"[TEST_VFS_STRESS_MT] All VFS stress tests passed\n");
    }
    ok
}
