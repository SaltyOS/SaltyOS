//! SaltyOS Name Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Service registry: servers register name->endpoint mappings,
//! clients look up services by name.
//!
//! IPC protocol:
//!   Label 1 = REGISTER: name packed in MRs, EP cap via cap transfer
//!   Label 2 = LOOKUP:   name packed in MRs -> returns EP cap via cap transfer
//!
//! Cap layout (set by init/procmgr):
//!   0 = self TCB
//!   1 = self VSpace
//!   2 = self CSpace
//!   3 = server endpoint

#![no_std]
#![no_main]

extern crate besalt;

use besalt::consts::*;
use besalt::ipc;
use besalt::types::*;

const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 3;
const CAP_READINESS_NTFN: u64 = 14;

const CAP_SERVICE_BASE: u64 = 32;
const MAX_SERVICES: usize = 32;
const MAX_NAME_LEN: usize = 32;

#[derive(Clone, Copy)]
struct ServiceEntry {
    name: [u8; MAX_NAME_LEN],
    name_len: u8,
    ep_slot: u64,
    active: u8,
}

impl ServiceEntry {
    const fn zeroed() -> Self {
        ServiceEntry {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            ep_slot: 0,
            active: 0,
        }
    }
}

static mut SERVICES: [ServiceEntry; MAX_SERVICES] = [ServiceEntry::zeroed(); MAX_SERVICES];
static mut SERVICE_COUNT: usize = 0;

fn ipc_ctx() -> *mut IpcContext {
    besalt::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = besalt::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

fn name_equal(a: &[u8], alen: u8, b: &[u8], blen: u8) -> bool {
    if alen != blen {
        return false;
    }
    for i in 0..alen as usize {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

unsafe fn extract_name(msg: *const BesaltMsg, out: &mut [u8; MAX_NAME_LEN]) -> u8 {
    unsafe {
        let mut len = (*msg).regs[0] as u8;
        if (len as usize) > MAX_NAME_LEN {
            len = MAX_NAME_LEN as u8;
        }
        let raw = &(*msg).regs[1] as *const u64 as *const u8;
        for i in 0..len as usize {
            out[i] = *raw.add(i);
        }
        len
    }
}

unsafe fn handle_register(msg: *const BesaltMsg, reply: *mut BesaltMsg) {
    unsafe {
        let mut name = [0u8; MAX_NAME_LEN];
        let name_len = extract_name(msg, &mut name);

        if name_len == 0 {
            besalt::uwarn!(|_lb| {
                _lb.str(b"[NAMESERV] REGISTER: empty name\n");
            });
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        for i in 0..SERVICE_COUNT {
            if SERVICES[i].active != 0
                && name_equal(&SERVICES[i].name, SERVICES[i].name_len, &name, name_len)
            {
                besalt::uwarn!(|_lb| {
                    _lb.str(b"[NAMESERV] REGISTER: duplicate name '");
                    _lb.bytes(&name[..name_len as usize]);
                    _lb.str(b"'\n");
                });
                (*reply).label = BESALT_ALREADY_EXISTS;
                return;
            }
        }

        if SERVICE_COUNT >= MAX_SERVICES {
            besalt::uerror!(|_lb| {
                _lb.str(b"[NAMESERV] REGISTER: table full\n");
            });
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        let ep_slot = CAP_SERVICE_BASE + SERVICE_COUNT as u64;

        let entry = &mut SERVICES[SERVICE_COUNT];
        for i in 0..name_len as usize {
            entry.name[i] = name[i];
        }
        entry.name_len = name_len;
        entry.ep_slot = ep_slot;
        entry.active = 1;
        SERVICE_COUNT += 1;

        besalt::uinfo!(|_lb| {
            _lb.str(b"[NAMESERV] registered '");
            _lb.bytes(&name[..name_len as usize]);
            _lb.str(b"' at slot ");
            _lb.hex(ep_slot);
            _lb.str(b"\n");
        });

        (*reply).label = BESALT_OK;
    }
}

unsafe fn handle_lookup(msg: *const BesaltMsg, reply: *mut BesaltMsg) {
    unsafe {
        let mut name = [0u8; MAX_NAME_LEN];
        let name_len = extract_name(msg, &mut name);

        if name_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        for i in 0..SERVICE_COUNT {
            if SERVICES[i].active != 0
                && name_equal(&SERVICES[i].name, SERVICES[i].name_len, &name, name_len)
            {
                ipc::set_send_cap_ctx(ipc_ctx(), 0, SERVICES[i].ep_slot);
                (*reply).label = BESALT_OK;
                (*reply).length = 0;
                return;
            }
        }

        besalt::udebug!(|_lb| {
            _lb.str(b"[NAMESERV] LOOKUP: not found '");
            _lb.bytes(&name[..name_len as usize]);
            _lb.str(b"'\n");
        });
        (*reply).label = BESALT_NOT_FOUND;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    besalt::uinfo!(|_lb| {
        _lb.str(b"[NAMESERV] SaltyOS name server starting\n");
    });

    // Set up receive slot for cap transfers
    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_SERVICE_BASE, 0);
    }
    signal_ready();

    // Initial recv
    let mut msg = BesaltMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        besalt::uerror!(|_lb| {
            _lb.str(b"[NAMESERV] initial recv failed\n");
        });
        idle();
    }

    // Server loop
    loop {
        let mut reply = BesaltMsg::zeroed();

        unsafe {
            match msg.label {
                POSIX_NS_REGISTER => handle_register(&raw const msg, &raw mut reply),
                POSIX_NS_LOOKUP => handle_lookup(&raw const msg, &raw mut reply),
                _ => {
                    besalt::uerror!(|_lb| {
                        _lb.str(b"[NAMESERV] unknown label=");
                        _lb.hex(msg.label);
                        _lb.str(b"\n");
                    });
                    reply.label = BESALT_INVALID_OPERATION;
                }
            }
        }

        // Update receive slot for next incoming cap transfer
        unsafe {
            ipc::set_receive_slot_ctx(
                ipc_ctx(),
                CAP_SELF_CSPACE,
                CAP_SERVICE_BASE + SERVICE_COUNT as u64,
                0,
            );
        }

        let err = unsafe {
            ipc::reply_recv_ctx(
                ipc_ctx(),
                CAP_SERVER_EP,
                &raw const reply,
                &raw mut msg,
                &raw mut badge,
            )
        };
        if err != 0 {
            besalt::uerror!(|_lb| {
                _lb.str(b"[NAMESERV] reply_recv failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            break;
        }
    }

    idle();
}

fn idle() -> ! {
    loop {
        besalt::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
