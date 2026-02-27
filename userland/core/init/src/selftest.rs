//! Optional self-test: IPC and fault handling tests
//! Extracted from original init phases 1 & 2.
//! SPDX-License-Identifier: GPL-2.0-only

use besalt::consts::*;
use besalt::invoke;
use besalt::ipc;
use besalt::serial;
use besalt::serial::LineBuf;
use besalt::syscall::syscall;
use besalt::types::*;

use super::{CAP_SELF_TCB, CAP_SELF_VSPACE, CAP_SELF_CSPACE};

const CAP_TEST_EP: u64 = 128;
const CAP_TEST_TCB: u64 = 129;
const CAP_TEST_SC: u64 = 130;
const CAP_IPC_BUF2_FRAME: u64 = 132;

const CAP_FAULT_EP: u64 = 133;
const CAP_FAULT_TCB: u64 = 134;
const CAP_FAULT_SC: u64 = 135;
const CAP_FAULT_FRAME: u64 = 136;

const IPC_BUF2_VADDR: u64 = 0x0000_0000_0020_1000;
const FAULT_TEST_ADDR: u64 = 0x4000_0000;
const TEST_IPC_LABEL: u64 = 0x42;

#[repr(C, align(4096))]
struct AlignedPage([u8; 4096]);

static mut THREAD2_STACK: AlignedPage = AlignedPage([0; 4096]);
static mut FAULT_HANDLER_STACK: AlignedPage = AlignedPage([0; 4096]);

static mut THREAD2_IPC_CTX: IpcContext = IpcContext::new();
static mut FAULT_IPC_CTX: IpcContext = IpcContext::new();

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}


unsafe extern "C" fn thread2_entry() {
    unsafe {
        ipc::ipc_context_init(&raw mut THREAD2_IPC_CTX, IPC_BUF2_VADDR as *mut IpcBuffer);
        puts(b"[THREAD2] started, waiting on endpoint\n");

        let mut msg = BesaltMsg::zeroed();
        let mut badge: u64 = 0;

        let err = ipc::recv_ctx(&raw mut THREAD2_IPC_CTX, CAP_TEST_EP, &raw mut msg, &raw mut badge);
        if err == 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[THREAD2] received message! label="); lb.hex(msg.label); lb.str(b" reg0="); lb.hex(msg.regs[0]); lb.str(b"\n"); lb.flush(); }
        } else {
            { let mut lb = LineBuf::new(); lb.str(b"[THREAD2] recv failed, error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
        }

        loop {
            syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }
}

unsafe extern "C" fn fault_handler_entry() {
    unsafe {
        ipc::ipc_context_init(&raw mut FAULT_IPC_CTX, super::IPC_BUF_VADDR as *mut IpcBuffer);
        puts(b"[FAULT_HANDLER] started, waiting for fault\n");

        let mut msg = BesaltMsg::zeroed();
        let mut badge: u64 = 0;

        let err = ipc::recv_ctx(&raw mut FAULT_IPC_CTX, CAP_FAULT_EP, &raw mut msg, &raw mut badge);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[FAULT_HANDLER] recv failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
        } else {
            puts(b"[FAULT_HANDLER] received fault! mapping page...\n");

            let merr = invoke::vspace_map(
                CAP_SELF_VSPACE,
                CAP_FAULT_FRAME,
                FAULT_TEST_ADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if merr != 0 {
                { let mut lb = LineBuf::new(); lb.str(b"[FAULT_HANDLER] vspace_map failed err="); lb.hex(merr as u64); lb.str(b"\n"); lb.flush(); }
            } else {
                puts(b"[FAULT_HANDLER] page mapped OK\n");
            }

            let reply = BesaltMsg::zeroed();
            ipc::reply_recv_ctx(
                &raw mut FAULT_IPC_CTX,
                CAP_FAULT_EP,
                &raw const reply,
                &raw mut msg,
                &raw mut badge,
            );
        }

        loop {
            syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }
}

pub unsafe fn phase1_ipc_test(ut: Cap) -> i32 {
    puts(b"[INIT] Phase 1: IPC test\n");

    macro_rules! retype {
        ($obj:expr, $slot:expr, $name:expr) => {
            let err = invoke::untyped_retype(ut, $obj, 0, $slot);
            if err != 0 {
                { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: "); lb.str($name); lb.str(b" retype error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
                return -1;
            }
        };
    }

    unsafe {
        retype!(OBJ_ENDPOINT, CAP_TEST_EP, b"Endpoint");
        puts(b"[INIT] Endpoint created\n");

        retype!(OBJ_TCB, CAP_TEST_TCB, b"TCB");
        retype!(OBJ_SCHED_CONTEXT, CAP_TEST_SC, b"SchedContext");

        let err = invoke::tcb_set_space(CAP_TEST_TCB, CAP_SELF_CSPACE, CAP_SELF_VSPACE);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: TCB_SET_SPACE error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        let t2_rip = thread2_entry as *const () as u64;
        let t2_rsp = (&raw const THREAD2_STACK) as *const u8 as u64 + 4096;
        let err = invoke::tcb_configure(CAP_TEST_TCB, t2_rip, t2_rsp, 0);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: TCB_CONFIGURE error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        // IPC buffer for thread2
        let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, CAP_IPC_BUF2_FRAME);
        if err != 0 {
            puts(b"[INIT] WARN: thread2 IPC buf frame retype err\n");
        } else {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                CAP_IPC_BUF2_FRAME,
                IPC_BUF2_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err == 0 {
                invoke::tcb_set_ipc_buffer(CAP_TEST_TCB, IPC_BUF2_VADDR);
            }
        }

        let err = invoke::sc_configure(CAP_TEST_SC, 10000, 100000);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: SC_CONFIGURE error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        let err = invoke::sc_bind(CAP_TEST_SC, CAP_TEST_TCB);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: SC_BIND error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        let err = invoke::tcb_resume(CAP_TEST_TCB);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: TCB_RESUME error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);

        puts(b"[INIT] Sending test message to endpoint\n");
        let mut msg = BesaltMsg::zeroed();
        msg.label = TEST_IPC_LABEL;
        msg.length = 1;
        msg.regs[0] = 0xDEAD_BEEF;

        let err = ipc::send_ctx(super::ipc_ctx(), CAP_TEST_EP, &raw const msg);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: send error="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }
        puts(b"[INIT] Message sent successfully!\n");
        puts(b"[INIT] Phase 1 IPC test PASSED\n");

        // Clean up
        invoke::tcb_suspend(CAP_TEST_TCB);

        0
    }
}

pub unsafe fn phase2_fault_test(ut: Cap) -> i32 {
    puts(b"\n[INIT] Phase 2: Fault test\n");

    macro_rules! retype {
        ($obj:expr, $slot:expr, $name:expr) => {
            let err = invoke::untyped_retype(ut, $obj, 0, $slot);
            if err != 0 {
                { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: "); lb.str($name); lb.str(b" retype err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
                return -1;
            }
        };
    }

    unsafe {
        retype!(OBJ_ENDPOINT, CAP_FAULT_EP, b"fault EP");
        retype!(OBJ_TCB, CAP_FAULT_TCB, b"fault TCB");
        retype!(OBJ_SCHED_CONTEXT, CAP_FAULT_SC, b"fault SC");
        retype!(OBJ_FRAME, CAP_FAULT_FRAME, b"fault Frame");

        let err = invoke::tcb_set_space(CAP_FAULT_TCB, CAP_SELF_CSPACE, CAP_SELF_VSPACE);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: fault TCB set_space err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        let fh_rip = fault_handler_entry as *const () as u64;
        let fh_rsp = (&raw const FAULT_HANDLER_STACK) as *const u8 as u64 + 4096;
        let err = invoke::tcb_configure(CAP_FAULT_TCB, fh_rip, fh_rsp, 0);
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] FAIL: fault TCB configure err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }

        let err = invoke::sc_configure(CAP_FAULT_SC, 10000, 100000);
        if err != 0 { return -1; }

        let err = invoke::sc_bind(CAP_FAULT_SC, CAP_FAULT_TCB);
        if err != 0 { return -1; }

        let err = invoke::tcb_set_fault_handler(CAP_SELF_TCB, CAP_FAULT_EP);
        if err != 0 { return -1; }

        let err = invoke::tcb_resume(CAP_FAULT_TCB);
        if err != 0 { return -1; }

        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);

        { let mut lb = LineBuf::new(); lb.str(b"[INIT] Triggering page fault at "); lb.hex(FAULT_TEST_ADDR); lb.str(b"\n"); lb.flush(); }

        let fault_ptr = FAULT_TEST_ADDR as *const u64;
        let val = core::ptr::read_volatile(fault_ptr);

        { let mut lb = LineBuf::new(); lb.str(b"[INIT] Resumed after fault! val="); lb.hex(val); lb.str(b"\n"); lb.flush(); }
        puts(b"[INIT] Phase 2 Fault test PASSED\n");
        0
    }
}
