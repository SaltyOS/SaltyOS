// SPDX-License-Identifier: GPL-2.0-only
//
//! [`RetypeClass`] abstracts `KERNITE_OBJ_*` kinds across spawn
//! backends. Direct untyped retype lives in `spawn::alloc` and
//! `boot_core`; post-rsrcsrv allocation routes through
//! [`crate::supervisor::rsrc_ipc::rsrc_alloc`].

use uapi::{
    KERNITE_OBJ_CNODE, KERNITE_OBJ_EVENT_QUEUE, KERNITE_OBJ_FRAME, KERNITE_OBJ_MESSAGE_PIPE_CORE,
    KERNITE_OBJ_SCHED_CONTEXT, KERNITE_OBJ_TCB, KERNITE_OBJ_TIMER, KERNITE_OBJ_VSPACE,
    KERNITE_OBJ_WATCH,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetypeClass {
    Tcb,
    CNode,
    VSpace,
    SchedContext,
    EventQueue,
    Watch,
    MpPair,
    Timer,
    Frame,
}

impl RetypeClass {
    /// Map to the `KERNITE_OBJ_*` value the kernel expects.
    pub fn obj_type(self) -> u64 {
        match self {
            RetypeClass::Tcb => KERNITE_OBJ_TCB as u64,
            RetypeClass::CNode => KERNITE_OBJ_CNODE as u64,
            RetypeClass::VSpace => KERNITE_OBJ_VSPACE as u64,
            RetypeClass::SchedContext => KERNITE_OBJ_SCHED_CONTEXT as u64,
            RetypeClass::EventQueue => KERNITE_OBJ_EVENT_QUEUE as u64,
            RetypeClass::Watch => KERNITE_OBJ_WATCH as u64,
            RetypeClass::MpPair => KERNITE_OBJ_MESSAGE_PIPE_CORE as u64,
            RetypeClass::Timer => KERNITE_OBJ_TIMER as u64,
            RetypeClass::Frame => KERNITE_OBJ_FRAME as u64,
        }
    }
}
