// SPDX-License-Identifier: GPL-2.0-only
//! Kernel-authority capability tokens.
//!
//! These objects are not memory-bearing; they grant the holder the
//! authority to perform a kernel operation that has no per-instance
//! state. Each capability is a single `KernelObject` header. The
//! semantics of the operation live in the corresponding invoke handler.
//!
//! - `KernelRng`        — read kernel CSPRNG bytes
//! - `SystemControl`    — system-wide shutdown / reboot / halt
//! - `Clock`            — read realtime / monotonic clocks
//! - `SystemInfo`       — read system accounting (uptime, memory, cpu)
//! - `KernelDebug`      — privileged debug putc / putstr / dump / console-control
//! - `DeviceControl`    — mint device authority caps for trusted drivers
//! - `ExecAuthority`    — confer EXECUTE on a code MemoryObject (`mo_mark_executable`)

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;

#[repr(C)]
pub struct KernelRng {
    pub header: KernelObject,
}

#[repr(C)]
pub struct SystemControl {
    pub header: KernelObject,
}

#[repr(C)]
pub struct Clock {
    pub header: KernelObject,
}

#[repr(C)]
pub struct SystemInfo {
    pub header: KernelObject,
}

#[repr(C)]
pub struct KernelDebug {
    pub header: KernelObject,
}

#[repr(C)]
pub struct DeviceControl {
    pub header: KernelObject,
}

#[repr(C)]
pub struct ExecAuthority {
    pub header: KernelObject,
}

impl KernelRng {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::KernelRng, 0),
        }
    }
}

impl SystemControl {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::SystemControl, 0),
        }
    }
}

impl Clock {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Clock, 0),
        }
    }
}

impl SystemInfo {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::SystemInfo, 0),
        }
    }
}

impl KernelDebug {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::KernelDebug, 0),
        }
    }
}

impl DeviceControl {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::DeviceControl, 0),
        }
    }
}

impl ExecAuthority {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::ExecAuthority, 0),
        }
    }
}
