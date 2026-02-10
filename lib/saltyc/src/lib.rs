//! saltyc — SaltyOS C Standard Library
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Rust implementation of a C standard library for SaltyOS.
//! All public functions are `#[unsafe(no_mangle)] pub extern "C"` for
//! C ABI compatibility. Calls into libsalty for system operations.

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

// Phase 2+
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

// Panic handler is provided by libsalty (our dependency)
