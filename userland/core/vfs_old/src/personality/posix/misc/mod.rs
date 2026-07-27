// SPDX-License-Identifier: GPL-2.0-only
//! POSIX miscellaneous operations — split into focused submodules.

pub(crate) mod cwd;
pub(crate) mod device;
pub(crate) mod fcntl;
pub(crate) mod ftrunc;
pub(crate) mod ioctl;
pub(crate) mod shm;

pub(crate) use cwd::*;
pub(crate) use device::*;
pub(crate) use fcntl::*;
pub(crate) use ftrunc::*;
pub(crate) use ioctl::*;
pub(crate) use shm::*;
