//! saltyc — SaltyOS C Standard Library
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Rust implementation of a C standard library for SaltyOS. Provides POSIX
//! and BSD-compatible C functions for ported userland programs (FreeBSD ls,
//! cat, etc.). All public functions use `#[unsafe(no_mangle)] pub extern "C"`
//! for C ABI compatibility and are linked into executables via `libsalty.so`.
//!
//! System operations (file I/O, memory management, process control) are
//! delegated to `libsalty`, which communicates with kernel services via IPC.
//! The library assumes single-threaded execution — `static mut` globals are
//! used without synchronization.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(c_variadic)]
#![feature(linkage)]

extern crate salty;

pub mod crt;
pub mod ctype;
pub mod env;
pub mod errno;
pub mod malloc;
pub mod mem;
pub mod string;
pub mod stdio;
pub mod unistd;
pub mod process;
pub mod signal_impl;
pub mod dirent_impl;
pub mod jobctl;
pub mod ioctl;
pub mod termios;
pub mod termcap;
pub mod regex;
pub mod time_impl;
pub mod stdlib_impl;
pub mod wchar;
pub mod sysinfo;
pub mod pwd_impl;
pub mod locale;
pub mod glob_impl;
pub mod select_impl;
pub mod math_impl;
pub mod misc_impl;
pub mod compat;
pub mod err_impl;

// Panic handler is provided by libsalty (our dependency)
