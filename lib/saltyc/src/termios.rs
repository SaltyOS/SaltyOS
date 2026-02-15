//! Terminal I/O (termios)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides the `termios` struct and `tcgetattr`/`tcsetattr`/`cfmakeraw`/
//! `cfgetospeed`/`cfsetospeed`/`cfgetispeed`/`cfsetispeed`. Attribute
//! get/set are stored locally (not sent to a kernel terminal driver).
//! Speed constants use Linux numbering (`B9600 = 13`, `B115200 = 0x1002`).

pub const NCCS: usize = 32;

// Input flags (c_iflag)
pub const IGNBRK: u32 = 0o000001;
pub const BRKINT: u32 = 0o000002;
pub const IGNPAR: u32 = 0o000004;
pub const PARMRK: u32 = 0o000010;
pub const INPCK: u32 = 0o000020;
pub const ISTRIP: u32 = 0o000040;
pub const INLCR: u32 = 0o000100;
pub const IGNCR: u32 = 0o000200;
pub const ICRNL: u32 = 0o000400;
pub const IXON: u32 = 0o002000;
pub const IXOFF: u32 = 0o010000;
pub const IXANY: u32 = 0o020000;
pub const IMAXBEL: u32 = 0o020000;

// Output flags (c_oflag)
pub const OPOST: u32 = 0o000001;
pub const ONLCR: u32 = 0o000004;

// Control flags (c_cflag)
pub const CSIZE: u32 = 0o000060;
pub const CS5: u32 = 0o000000;
pub const CS6: u32 = 0o000020;
pub const CS7: u32 = 0o000040;
pub const CS8: u32 = 0o000060;
pub const CSTOPB: u32 = 0o000100;
pub const CREAD: u32 = 0o000200;
pub const PARENB: u32 = 0o000400;
pub const HUPCL: u32 = 0o002000;
pub const CLOCAL: u32 = 0o004000;

// Local flags (c_lflag)
pub const ISIG: u32 = 0o000001;
pub const ICANON: u32 = 0o000002;
pub const ECHO: u32 = 0o000010;
pub const ECHOE: u32 = 0o000020;
pub const ECHOK: u32 = 0o000040;
pub const ECHONL: u32 = 0o000100;
pub const NOFLSH: u32 = 0o000200;
pub const TOSTOP: u32 = 0o000400;
pub const IEXTEN: u32 = 0o100000;
pub const ECHOCTL: u32 = 0o001000;
pub const ECHOKE: u32 = 0o004000;

// cc indices
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;

// tcsetattr actions
pub const TCSANOW: i32 = 0;
pub const TCSADRAIN: i32 = 1;
pub const TCSAFLUSH: i32 = 2;

// Baud rates
pub const B0: u32 = 0;
pub const B9600: u32 = 9600;
pub const B19200: u32 = 19200;
pub const B38400: u32 = 38400;
pub const B57600: u32 = 57600;
pub const B115200: u32 = 115200;

// tcflush queue selectors
pub const TCIFLUSH: i32 = 0;
pub const TCOFLUSH: i32 = 1;
pub const TCIOFLUSH: i32 = 2;

// tcflow actions
pub const TCOOFF: i32 = 0;
pub const TCOON: i32 = 1;
pub const TCIOFF: i32 = 2;
pub const TCION: i32 = 3;

#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

static mut DEFAULT_TERMIOS: Termios = Termios {
    c_iflag: ICRNL | IXON,
    c_oflag: OPOST | ONLCR,
    c_cflag: CS8 | CREAD | CLOCAL,
    c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN | ECHOCTL | ECHOKE,
    c_line: 0,
    c_cc: [0; NCCS],
    c_ispeed: B38400,
    c_ospeed: B38400,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcgetattr(fd: i32, termios_p: *mut Termios) -> i32 {
    unsafe {
        // Route through VFS → console server IPC
        let mut salty_t = salty::types::Termios::zeroed();
        let ret = salty::posix::posix_tcgetattr(fd, &raw mut salty_t);
        if ret != 0 {
            // Fallback to local defaults
            let src = &raw const DEFAULT_TERMIOS;
            core::ptr::copy_nonoverlapping(src as *const u8, termios_p as *mut u8, core::mem::size_of::<Termios>());
            (*termios_p).c_cc[VINTR] = 3;
            (*termios_p).c_cc[VQUIT] = 28;
            (*termios_p).c_cc[VERASE] = 127;
            (*termios_p).c_cc[VKILL] = 21;
            (*termios_p).c_cc[VEOF] = 4;
            (*termios_p).c_cc[VMIN] = 1;
            (*termios_p).c_cc[VSTART] = 17;
            (*termios_p).c_cc[VSTOP] = 19;
            (*termios_p).c_cc[VSUSP] = 26;
            return 0;
        }
        // Copy from salty Termios to saltyc Termios
        (*termios_p).c_iflag = salty_t.c_iflag;
        (*termios_p).c_oflag = salty_t.c_oflag;
        (*termios_p).c_cflag = salty_t.c_cflag;
        (*termios_p).c_lflag = salty_t.c_lflag;
        (*termios_p).c_line = salty_t.c_line;
        (*termios_p).c_ispeed = salty_t.c_ispeed;
        (*termios_p).c_ospeed = salty_t.c_ospeed;
        for i in 0..NCCS {
            (*termios_p).c_cc[i] = salty_t.c_cc[i];
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsetattr(fd: i32, action: i32, termios_p: *const Termios) -> i32 {
    unsafe {
        // Route through VFS → console server IPC
        let mut salty_t = salty::types::Termios::zeroed();
        salty_t.c_iflag = (*termios_p).c_iflag;
        salty_t.c_oflag = (*termios_p).c_oflag;
        salty_t.c_cflag = (*termios_p).c_cflag;
        salty_t.c_lflag = (*termios_p).c_lflag;
        salty_t.c_line = (*termios_p).c_line;
        salty_t.c_ispeed = (*termios_p).c_ispeed;
        salty_t.c_ospeed = (*termios_p).c_ospeed;
        for i in 0..NCCS {
            salty_t.c_cc[i] = (*termios_p).c_cc[i];
        }
        let ret = salty::posix::posix_tcsetattr(fd, action, &raw const salty_t);
        if ret != 0 {
            // Fallback: update local static
            let dst = &raw mut DEFAULT_TERMIOS;
            core::ptr::copy_nonoverlapping(termios_p as *const u8, dst as *mut u8, core::mem::size_of::<Termios>());
            return 0;
        }
        // Also update local cached copy
        let dst = &raw mut DEFAULT_TERMIOS;
        core::ptr::copy_nonoverlapping(termios_p as *const u8, dst as *mut u8, core::mem::size_of::<Termios>());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cfgetospeed(termios_p: *const Termios) -> u32 {
    unsafe { (*termios_p).c_ospeed }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cfgetispeed(termios_p: *const Termios) -> u32 {
    unsafe { (*termios_p).c_ispeed }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cfsetospeed(termios_p: *mut Termios, speed: u32) -> i32 {
    unsafe {
        (*termios_p).c_ospeed = speed;
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cfsetispeed(termios_p: *mut Termios, speed: u32) -> i32 {
    unsafe {
        (*termios_p).c_ispeed = speed;
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cfmakeraw(termios_p: *mut Termios) {
    unsafe {
        (*termios_p).c_iflag &= !(ICRNL | IXON);
        (*termios_p).c_oflag &= !OPOST;
        (*termios_p).c_lflag &= !(ECHO | ICANON | ISIG | IEXTEN);
        (*termios_p).c_cflag |= CS8;
        (*termios_p).c_cc[VMIN] = 1;
        (*termios_p).c_cc[VTIME] = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcdrain(_fd: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcflush(_fd: i32, _queue: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsendbreak(_fd: i32, _duration: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcflow(_fd: i32, _action: i32) -> i32 {
    0
}
