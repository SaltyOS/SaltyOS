//! SaltyOS login — PAM-based user authentication and session setup
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Authenticates a user via the PAM "login" service chain, then transitions
//! to the user's shell with appropriate UID/GID/groups and home directory.
//!
//! Flow:
//!   1. Get username (from argv[1] or PAM prompt)
//!   2. PAM authenticate (prompts for password via openpam_ttyconv)
//!   3. PAM account management (check expiry)
//!   4. getpwnam → resolve uid, gid, home, shell
//!   5. setgid → setgroups → setuid (drop privileges)
//!   6. chdir(home)
//!   7. exec(shell)
//!
//! `libpam` is resolved at runtime via `dlopen(3)` so the core userland build
//! does not need a hard link-time dependency on the `openpam` port.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

use trona_posix::*;

// ---------------------------------------------------------------------------
// C ABI imports — PAM and pwd functions from basaltc (linked via libc.so)
// ---------------------------------------------------------------------------

// Opaque PAM handle
#[repr(C)]
struct PamHandle {
    _opaque: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: i32,
    msg: *const u8,
}

#[repr(C)]
struct PamResponse {
    resp: *mut u8,
    resp_retcode: i32,
}

type PamConvFn =
    unsafe extern "C" fn(i32, *const *const PamMessage, *mut *mut PamResponse, *mut u8) -> i32;

#[repr(C)]
struct PamConv {
    conv: PamConvFn,
    appdata_ptr: *mut u8,
}

/// Mirror of basaltc's `struct passwd` — must match FreeBSD 11-field layout
/// exactly (see lib/basalt/c/include/pwd.h). Total size = 80 bytes on x86_64.
#[repr(C)]
struct Passwd {
    pw_name: *const u8,
    pw_passwd: *const u8,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: i64,
    pw_class: *const u8,
    pw_gecos: *const u8,
    pw_dir: *const u8,
    pw_shell: *const u8,
    pw_expire: i64,
    pw_fields: i32,
}

#[repr(C)]
struct Group {
    gr_name: *const u8,
    gr_passwd: *const u8,
    gr_gid: u32,
    gr_mem: *const *const u8,
}

unsafe extern "C" {
    safe fn dlopen(filename: *const u8, flags: i32) -> *mut u8;
    safe fn dlsym(handle: *mut u8, symbol: *const u8) -> *mut u8;
    safe fn dlclose(handle: *mut u8) -> i32;
    safe fn dlerror() -> *mut u8;
    safe fn getpwnam(name: *const u8) -> *mut Passwd;
    safe fn getgrent() -> *mut Group;
    safe fn setgrent();
    safe fn endgrent();
}

const PAM_SUCCESS: i32 = 0;
const PAM_TTY: i32 = 3;
const MAX_ATTEMPTS: i32 = 3;
const RTLD_NOW: i32 = 0x0002;

type OpenpamTtyconvFn =
    unsafe extern "C" fn(i32, *const *const PamMessage, *mut *mut PamResponse, *mut u8) -> i32;
type PamStartFn =
    unsafe extern "C" fn(*const u8, *const u8, *const PamConv, *mut *mut PamHandle) -> i32;
type PamEndFn = unsafe extern "C" fn(*mut PamHandle, i32) -> i32;
type PamAuthFn = unsafe extern "C" fn(*mut PamHandle, i32) -> i32;
type PamGetUserFn = unsafe extern "C" fn(*mut PamHandle, *mut *const u8, *const u8) -> i32;
type PamSetItemFn = unsafe extern "C" fn(*mut PamHandle, i32, *const u8) -> i32;
type PamStrerrorFn = unsafe extern "C" fn(*mut PamHandle, i32) -> *const u8;

struct PamApi {
    handle: *mut u8,
    openpam_ttyconv: OpenpamTtyconvFn,
    pam_start: PamStartFn,
    pam_end: PamEndFn,
    pam_authenticate: PamAuthFn,
    pam_acct_mgmt: PamAuthFn,
    pam_setcred: PamAuthFn,
    pam_open_session: PamAuthFn,
    pam_get_user: PamGetUserFn,
    pam_set_item: PamSetItemFn,
    pam_strerror: PamStrerrorFn,
}

impl PamApi {
    unsafe fn load() -> Option<Self> {
        unsafe {
            let mut first_error = [0u8; 128];
            let mut handle = dlopen(b"/usr/lib/libpam.so\0".as_ptr(), RTLD_NOW);
            if handle.is_null() {
                let err = dlerror();
                if !err.is_null() {
                    let mut i = 0usize;
                    while i < first_error.len() - 1 && *err.add(i) != 0 {
                        first_error[i] = *err.add(i);
                        i += 1;
                    }
                    first_error[i] = 0;
                }
                handle = dlopen(b"libpam.so\0".as_ptr(), RTLD_NOW);
            }
            if handle.is_null() {
                if first_error[0] != 0 {
                    write_str(2, b"login: first dlopen error: ");
                    write_cstr(2, first_error.as_ptr());
                    write_str(2, b"\n");
                }
                return None;
            }

            macro_rules! sym {
                ($name:literal, $ty:ty) => {{
                    let ptr = dlsym(handle, concat!($name, "\0").as_ptr());
                    if ptr.is_null() {
                        let err = dlerror();
                        write_str(2, b"login: PAM symbol lookup failed: ");
                        write_str(2, concat!($name, "\n").as_bytes());
                        if !err.is_null() {
                            write_cstr(2, err);
                            write_str(2, b"\n");
                        }
                        dlclose(handle);
                        return None;
                    }
                    core::mem::transmute::<*mut u8, $ty>(ptr)
                }};
            }

            Some(Self {
                handle,
                openpam_ttyconv: sym!("openpam_ttyconv", OpenpamTtyconvFn),
                pam_start: sym!("pam_start", PamStartFn),
                pam_end: sym!("pam_end", PamEndFn),
                pam_authenticate: sym!("pam_authenticate", PamAuthFn),
                pam_acct_mgmt: sym!("pam_acct_mgmt", PamAuthFn),
                pam_setcred: sym!("pam_setcred", PamAuthFn),
                pam_open_session: sym!("pam_open_session", PamAuthFn),
                pam_get_user: sym!("pam_get_user", PamGetUserFn),
                pam_set_item: sym!("pam_set_item", PamSetItemFn),
                pam_strerror: sym!("pam_strerror", PamStrerrorFn),
            })
        }
    }
}

impl Drop for PamApi {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            dlclose(self.handle);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::debug::serial::serial_puts(b"[LOGIN] main entered\n");
    unsafe {
        trona_runtime::debug::serial::serial_puts(b"[LOGIN] calling PamApi::load\n");
        let Some(pam) = PamApi::load() else {
            trona_runtime::debug::serial::serial_puts(
                b"[LOGIN] PamApi::load returned None, exiting(1)\n",
            );
            write_str(2, b"login: failed to load /usr/lib/libpam.so\n");
            let err = dlerror();
            if !err.is_null() {
                write_cstr(2, err);
                write_str(2, b"\n");
            }
            posix_exit(1);
        };
        trona_runtime::debug::serial::serial_puts(b"[LOGIN] PamApi::load OK\n");

        preflight_login_pam_modules();

        // PAM conversations may toggle echo/canonical mode. Restore the tty
        // before handing control to the interactive shell.
        let mut saved_termios = Termios::zeroed();
        let have_saved_termios = posix_tcgetattr(0, &raw mut saved_termios) == 0;

        let tty_dev = posix_get_session_tty_dev();
        let mut tty_env_buf = [0u8; 40];
        let mut pam_tty_buf = [0u8; 32];
        if tty_dev <= 0
            || !build_current_tty_strings(tty_dev as u64, &mut tty_env_buf, &mut pam_tty_buf)
        {
            write_str(2, b"login: failed to resolve controlling tty\n");
            posix_exit(1);
        }

        // Extract username from argv[1] if provided (getty may pass it)
        let mut preset_user: *const u8 = core::ptr::null();
        if argc >= 2 && !argv.is_null() {
            // SAFETY: argv is valid for argc elements
            let arg1 = *argv.add(1);
            if !arg1.is_null() && *arg1 != 0 {
                preset_user = arg1;
            }
        }

        // PAM conversation function: openpam_ttyconv (handles echo toggle)
        let conv = PamConv {
            conv: pam.openpam_ttyconv,
            appdata_ptr: core::ptr::null_mut(),
        };

        let mut attempts = 0i32;

        loop {
            if attempts >= MAX_ATTEMPTS {
                if have_saved_termios {
                    let _ = posix_tcsetattr(0, 0, &raw const saved_termios);
                }
                write_str(2, b"Login failed after maximum attempts\n");
                posix_exit(1);
            }
            attempts += 1;

            // Start PAM session
            let mut pamh: *mut PamHandle = core::ptr::null_mut();
            let ret = (pam.pam_start)(b"login\0".as_ptr(), preset_user, &conv, &mut pamh);
            if ret != PAM_SUCCESS {
                report_pam_error(&pam, pamh, b"login: pam_start failed: ", ret);
                posix_exit(1);
            }

            // PAM_TTY should be the tty name ("console" or "pts/N"), not the
            // device path.
            // pam_securetty looks up this value in /etc/ttys.
            let tty_ret = (pam.pam_set_item)(pamh, PAM_TTY, pam_tty_buf.as_ptr());
            if tty_ret != PAM_SUCCESS {
                report_pam_error(
                    &pam,
                    pamh,
                    b"login: pam_set_item(PAM_TTY) failed: ",
                    tty_ret,
                );
                (pam.pam_end)(pamh, tty_ret);
                posix_exit(1);
            }

            // If no preset user, prompt via PAM
            let mut user_ptr: *const u8 = core::ptr::null();
            if preset_user.is_null() {
                let pret = (pam.pam_get_user)(pamh, &mut user_ptr, b"login: \0".as_ptr());
                if pret != PAM_SUCCESS || user_ptr.is_null() || *user_ptr == 0 {
                    if have_saved_termios {
                        let _ = posix_tcsetattr(0, 0, &raw const saved_termios);
                    }
                    (pam.pam_end)(pamh, pret);
                    write_str(2, b"\n");
                    preset_user = core::ptr::null();
                    continue;
                }
            } else {
                user_ptr = preset_user;
            }

            // Authenticate
            let auth_ret = (pam.pam_authenticate)(pamh, 0);
            if auth_ret != PAM_SUCCESS {
                if have_saved_termios {
                    let _ = posix_tcsetattr(0, 0, &raw const saved_termios);
                }
                write_str(2, b"Login incorrect\n");
                (pam.pam_end)(pamh, auth_ret);
                preset_user = core::ptr::null();
                // Brief delay to deter brute force
                let req = Timespec {
                    tv_sec: 2,
                    tv_nsec: 0,
                };
                let _ = posix_nanosleep(&raw const req, core::ptr::null_mut());
                continue;
            }

            // Account management (check expiry etc.)
            let acct_ret = (pam.pam_acct_mgmt)(pamh, 0);
            if acct_ret != PAM_SUCCESS {
                if have_saved_termios {
                    let _ = posix_tcsetattr(0, 0, &raw const saved_termios);
                }
                write_str(2, b"Account unavailable\n");
                (pam.pam_end)(pamh, acct_ret);
                posix_exit(1);
            }

            // Look up user in passwd database
            let pw = getpwnam(user_ptr);
            if pw.is_null() {
                if have_saved_termios {
                    let _ = posix_tcsetattr(0, 0, &raw const saved_termios);
                }
                write_str(2, b"login: unknown user\n");
                (pam.pam_end)(pamh, 0);
                posix_exit(1);
            }

            let uid = (*pw).pw_uid;
            let gid = (*pw).pw_gid;
            let home = (*pw).pw_dir;
            let shell = (*pw).pw_shell;

            // Open PAM session
            (pam.pam_open_session)(pamh, 0);
            (pam.pam_setcred)(pamh, 0);

            // Set credentials: gid → supplementary groups → uid
            // Order matters: must set gid/groups before dropping to non-root uid
            posix_setgid(gid);

            // Collect supplementary groups from /etc/group
            let mut sup_groups = [0u32; 32];
            sup_groups[0] = gid;
            let mut nsup = 1usize;

            setgrent();
            loop {
                let gr = getgrent();
                if gr.is_null() {
                    break;
                }
                let gr_gid = (*gr).gr_gid;
                if gr_gid == gid {
                    continue; // already have primary
                }
                let mem = (*gr).gr_mem;
                if mem.is_null() {
                    continue;
                }
                // SAFETY: gr_mem is null-terminated array of C strings
                let mut j = 0;
                while !(*mem.add(j)).is_null() {
                    if cstr_eq(user_ptr, *mem.add(j)) {
                        if nsup < 32 {
                            sup_groups[nsup] = gr_gid;
                            nsup += 1;
                        }
                        break;
                    }
                    j += 1;
                }
            }
            endgrent();

            posix_setgroups(nsup, sup_groups.as_ptr());
            posix_setuid(uid);

            // Change to home directory
            if !home.is_null() && *home != 0 {
                let ret = posix_chdir(home);
                if ret < 0 {
                    posix_chdir(b"/\0".as_ptr());
                }
            } else {
                posix_chdir(b"/\0".as_ptr());
            }

            // Build environment for the shell
            let mut path_buf = [0u8; 48];
            build_env_var(&mut path_buf, b"PATH=", trona_posix::consts::DEFAULT_PATH);

            let mut home_buf = [0u8; 80];
            build_env_var_cstr(&mut home_buf, b"HOME=", home);

            let mut shell_buf = [0u8; 80];
            build_env_var_cstr(&mut shell_buf, b"SHELL=", shell);

            let mut user_buf = [0u8; 80];
            build_env_var_cstr(&mut user_buf, b"USER=", user_ptr);

            let mut logname_buf = [0u8; 80];
            build_env_var_cstr(&mut logname_buf, b"LOGNAME=", user_ptr);

            // Determine shell to exec
            let shell_path = if !shell.is_null() && *shell != 0 {
                shell
            } else {
                b"/usr/bin/bash\0".as_ptr()
            };

            // Extract shell basename for argv[0] (prefixed with '-' for login shell)
            let mut shell_name = [0u8; 64];
            shell_name[0] = b'-';
            let base = basename(shell_path);
            let mut k = 0usize;
            while k < 62 && *base.add(k) != 0 {
                shell_name[k + 1] = *base.add(k);
                k += 1;
            }
            shell_name[k + 1] = 0;

            let new_argv: [*const u8; 2] = [shell_name.as_ptr(), core::ptr::null()];

            let new_envp: [*const u8; 8] = [
                path_buf.as_ptr(),
                home_buf.as_ptr(),
                shell_buf.as_ptr(),
                user_buf.as_ptr(),
                logname_buf.as_ptr(),
                b"TERM=vt100\0".as_ptr(),
                tty_env_buf.as_ptr(),
                core::ptr::null(),
            ];

            if have_saved_termios {
                let _ = posix_tcsetattr(0, 0, &raw const saved_termios);
            }

            // End PAM before exec
            (pam.pam_end)(pamh, 0);

            // Exec the shell
            posix_execve(shell_path, new_argv.as_ptr(), new_envp.as_ptr());

            // If execve failed, try /usr/bin/bash as fallback
            write_str(2, b"login: exec shell failed, trying /usr/bin/bash\n");
            let fallback_argv: [*const u8; 2] = [b"-bash\0".as_ptr(), core::ptr::null()];
            posix_execve(
                b"/usr/bin/bash\0".as_ptr(),
                fallback_argv.as_ptr(),
                new_envp.as_ptr(),
            );

            write_str(2, b"login: exec /usr/bin/bash failed\n");
            posix_exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_decimal(buf: &mut [u8], pos: &mut usize, mut value: u64) -> bool {
    if value == 0 {
        if *pos >= buf.len() {
            return false;
        }
        buf[*pos] = b'0';
        *pos += 1;
        return true;
    }

    let mut digits = [0u8; 20];
    let mut count = 0usize;
    while value != 0 {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
    }
    if *pos + count > buf.len() {
        return false;
    }
    while count != 0 {
        count -= 1;
        buf[*pos] = digits[count];
        *pos += 1;
    }
    true
}

fn build_current_tty_strings(tty_dev: u64, tty_env: &mut [u8], pam_tty: &mut [u8]) -> bool {
    let mut tty_env_pos = 0usize;
    let tty_prefix = b"TTY=";
    if tty_prefix.len() >= tty_env.len() {
        return false;
    }
    while tty_env_pos < tty_prefix.len() {
        tty_env[tty_env_pos] = tty_prefix[tty_env_pos];
        tty_env_pos += 1;
    }

    let mut pam_pos = 0usize;
    if tty_dev == trona_posix::consts::TTY_DEV_CONSOLE {
        let tty_suffix = b"/dev/console";
        let pam_suffix = b"console";
        if tty_env_pos + tty_suffix.len() + 1 > tty_env.len()
            || pam_suffix.len() + 1 > pam_tty.len()
        {
            return false;
        }
        for &b in tty_suffix {
            tty_env[tty_env_pos] = b;
            tty_env_pos += 1;
        }
        for &b in pam_suffix {
            pam_tty[pam_pos] = b;
            pam_pos += 1;
        }
    } else if tty_dev >= trona_posix::consts::TTY_DEV_PTS_BASE {
        let pty_id = tty_dev - trona_posix::consts::TTY_DEV_PTS_BASE;
        let tty_suffix = b"/dev/pts/";
        let pam_prefix = b"pts/";
        if tty_env_pos + tty_suffix.len() + 1 > tty_env.len()
            || pam_prefix.len() + 1 > pam_tty.len()
        {
            return false;
        }
        for &b in tty_suffix {
            tty_env[tty_env_pos] = b;
            tty_env_pos += 1;
        }
        for &b in pam_prefix {
            pam_tty[pam_pos] = b;
            pam_pos += 1;
        }
        if !append_decimal(tty_env, &mut tty_env_pos, pty_id)
            || !append_decimal(pam_tty, &mut pam_pos, pty_id)
        {
            return false;
        }
    } else {
        return false;
    }

    if tty_env_pos >= tty_env.len() || pam_pos >= pam_tty.len() {
        return false;
    }
    tty_env[tty_env_pos] = 0;
    pam_tty[pam_pos] = 0;
    true
}

unsafe fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let len = s.len();
        let wlen = if len > 0 && s[len - 1] == 0 {
            len - 1
        } else {
            len
        };
        posix_write(fd, s.as_ptr(), wlen as u64);
    }
}

unsafe fn write_cstr(fd: i32, s: *const u8) {
    unsafe {
        if s.is_null() {
            return;
        }
        let mut len = 0usize;
        while *s.add(len) != 0 {
            len += 1;
        }
        posix_write(fd, s, len as u64);
    }
}

unsafe fn write_i32(fd: i32, value: i32) {
    unsafe {
        let mut buf = [0u8; 16];
        let mut index = buf.len();
        let negative = value < 0;
        let mut n = if negative {
            value.wrapping_neg() as u32
        } else {
            value as u32
        };

        if n == 0 {
            index -= 1;
            buf[index] = b'0';
        } else {
            while n != 0 {
                index -= 1;
                buf[index] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }

        if negative {
            index -= 1;
            buf[index] = b'-';
        }

        posix_write(fd, buf[index..].as_ptr(), (buf.len() - index) as u64);
    }
}

unsafe fn report_pam_error(pam: &PamApi, pamh: *mut PamHandle, prefix: &[u8], code: i32) {
    unsafe {
        write_str(2, prefix);
        write_str(2, b"code=");
        write_i32(2, code);
        write_str(2, b" error=");
        let msg = (pam.pam_strerror)(pamh, code);
        if msg.is_null() {
            write_str(2, b"<null>");
        } else {
            write_cstr(2, msg);
        }
        write_str(2, b"\n");
    }
}

unsafe fn preflight_login_pam_modules() {
    unsafe {
        let modules: [&[u8]; 6] = [
            b"/usr/lib/pam/pam_securetty.so\0",
            b"/usr/lib/pam/pam_unix.so\0",
            b"/usr/lib/pam/pam_nologin.so\0",
            b"/usr/lib/pam/pam_login_access.so\0",
            b"/usr/lib/pam/pam_xdg.so\0",
            b"/usr/lib/pam/pam_permit.so\0",
        ];

        for module in modules {
            let handle = dlopen(module.as_ptr(), RTLD_NOW);
            if handle.is_null() {
                write_str(2, b"login: preflight dlopen failed: ");
                write_str(2, module);
                write_str(2, b": ");
                let err = dlerror();
                if err.is_null() {
                    write_str(2, b"<null>");
                } else {
                    write_cstr(2, err);
                }
                write_str(2, b"\n");
            } else {
                dlclose(handle);
            }
        }
    }
}

unsafe fn cstr_eq(a: *const u8, b: *const u8) -> bool {
    unsafe {
        let mut i = 0;
        loop {
            let ca = *a.add(i);
            let cb = *b.add(i);
            if ca != cb {
                return false;
            }
            if ca == 0 {
                return true;
            }
            i += 1;
        }
    }
}

fn build_env_var(dst: &mut [u8], key: &[u8], val: &[u8]) {
    let mut i = 0;
    for &b in key {
        if i < dst.len() - 1 {
            dst[i] = b;
            i += 1;
        }
    }
    for &b in val {
        if i < dst.len() - 1 {
            dst[i] = b;
            i += 1;
        }
    }
    dst[i] = 0;
}

unsafe fn build_env_var_cstr(dst: &mut [u8], key: &[u8], val: *const u8) {
    let mut i = 0;
    for &b in key {
        if i < dst.len() - 1 {
            dst[i] = b;
            i += 1;
        }
    }
    if !val.is_null() {
        unsafe {
            let mut j = 0;
            while *val.add(j) != 0 && i < dst.len() - 1 {
                dst[i] = *val.add(j);
                i += 1;
                j += 1;
            }
        }
    }
    dst[i] = 0;
}

unsafe fn basename(path: *const u8) -> *const u8 {
    unsafe {
        let mut last_slash = path;
        let mut p = path;
        while *p != 0 {
            if *p == b'/' {
                last_slash = p.add(1);
            }
            p = p.add(1);
        }
        last_slash
    }
}
