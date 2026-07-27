// SPDX-License-Identifier: GPL-2.0-only
//! Kernite - SaltyOS microkernel crate root.
//!
//! The crate root owns only top-level module wiring. Kernel infrastructure
//! lives under `kernel/`, boot/init code under `init/`, and firmware table
//! plumbing under `firmware/`.

#![no_std]
#![no_main]
#![allow(dead_code)]

mod arch;
mod cap;
mod console;
mod event;
mod firmware;
mod init;
mod ipc;
mod kernel;
mod mm;
mod object;
mod sched;
mod syscall;
mod task;

extern crate uapi;
