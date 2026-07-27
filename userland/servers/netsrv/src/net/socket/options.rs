// SPDX-License-Identifier: GPL-2.0-only
//! Shared per-socket option storage and translation.

use trona_protocol::common::{TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_OK};
use trona_protocol::posix_abi::socket::{
    AF_INET, IP_TTL, IPPROTO_IP, SO_BROADCAST, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_RCVBUF,
    SO_REUSEADDR, SO_SNDBUF, SO_TIMESTAMP, SO_TS_CLOCK, SO_TS_MONOTONIC, SO_TYPE, SOCK_DGRAM,
    SOCK_RAW, SOCK_STREAM, SOL_SOCKET,
};
use trona_protocol::posix_abi::time::{CLOCK_MONOTONIC, CLOCK_REALTIME};

pub(crate) const DEFAULT_IP_TTL: u8 = 64;
pub(crate) const TIMESTAMP_NONE_NS: u64 = u64::MAX;
const BSD_SOL_SOCKET: i32 = 0xFFFF;

#[inline]
fn is_sol_socket(level: i32) -> bool {
    level == SOL_SOCKET || level == BSD_SOL_SOCKET
}

#[derive(Clone, Copy)]
pub(crate) struct SocketOptions {
    pub(crate) last_error: u64,
    pub(crate) reuseaddr: bool,
    pub(crate) broadcast: bool,
    pub(crate) sndbuf: u32,
    pub(crate) rcvbuf: u32,
    pub(crate) ip_ttl: u8,
    pub(crate) timestamp_enabled: bool,
    pub(crate) timestamp_clock: i32,
}

impl SocketOptions {
    pub(crate) const fn new(sndbuf: u32, rcvbuf: u32) -> Self {
        Self {
            last_error: 0,
            reuseaddr: false,
            broadcast: false,
            sndbuf,
            rcvbuf,
            ip_ttl: DEFAULT_IP_TTL,
            timestamp_enabled: false,
            timestamp_clock: SO_TS_MONOTONIC,
        }
    }
}

fn timestamp_clock_id(ts_clock: i32) -> Option<i32> {
    match ts_clock {
        SO_TS_MONOTONIC => Some(CLOCK_MONOTONIC),
        2 => Some(CLOCK_REALTIME),
        _ => None,
    }
}

pub(crate) fn sample_timestamp_ns(opts: &SocketOptions) -> u64 {
    if !opts.timestamp_enabled {
        return TIMESTAMP_NONE_NS;
    }

    let Some(clock_id) = timestamp_clock_id(opts.timestamp_clock) else {
        return TIMESTAMP_NONE_NS;
    };

    let clock_cap = trona_runtime::client::caps::clock_cap().addr();
    match clock_id {
        CLOCK_MONOTONIC => trona_kernel::syscall::clock_read_monotonic(clock_cap),
        CLOCK_REALTIME => trona_kernel::syscall::clock_read_realtime(clock_cap),
        _ => TIMESTAMP_NONE_NS,
    }
}

fn socket_type_value(sock_type: i32) -> Option<u32> {
    match sock_type {
        SOCK_STREAM => Some(SOCK_STREAM as u32),
        SOCK_DGRAM => Some(SOCK_DGRAM as u32),
        SOCK_RAW => Some(SOCK_RAW as u32),
        _ => None,
    }
}

fn decode_opt_value(optval: u64, optlen: u32) -> Option<u64> {
    match optlen {
        1 => Some(optval & 0xFF),
        2 => Some(optval & 0xFFFF),
        4 => Some(optval & 0xFFFF_FFFF),
        8 => Some(optval),
        _ => None,
    }
}

pub(crate) fn set_option(
    opts: &mut SocketOptions,
    sock_type: i32,
    level: i32,
    optname: i32,
    optval: u64,
    optlen: u32,
) -> u64 {
    let Some(value) = decode_opt_value(optval, optlen) else {
        return TRONA_INVALID_ARGUMENT;
    };

    match optname {
        SO_REUSEADDR if is_sol_socket(level) => {
            opts.reuseaddr = value != 0;
            TRONA_OK
        }
        SO_BROADCAST if is_sol_socket(level) => {
            opts.broadcast = value != 0;
            TRONA_OK
        }
        SO_SNDBUF if is_sol_socket(level) => {
            if value == 0 || value > u32::MAX as u64 {
                return TRONA_INVALID_ARGUMENT;
            }
            opts.sndbuf = value as u32;
            TRONA_OK
        }
        SO_RCVBUF if is_sol_socket(level) => {
            if value == 0 || value > u32::MAX as u64 {
                return TRONA_INVALID_ARGUMENT;
            }
            opts.rcvbuf = value as u32;
            TRONA_OK
        }
        SO_TIMESTAMP if is_sol_socket(level) => {
            opts.timestamp_enabled = value != 0;
            TRONA_OK
        }
        SO_TS_CLOCK if is_sol_socket(level) => {
            if value > i32::MAX as u64 {
                return TRONA_INVALID_ARGUMENT;
            }
            let ts_clock = value as i32;
            if timestamp_clock_id(ts_clock).is_none() {
                return TRONA_INVALID_ARGUMENT;
            }
            opts.timestamp_clock = ts_clock;
            TRONA_OK
        }
        IP_TTL if level == IPPROTO_IP => {
            if value == 0 || value > u8::MAX as u64 {
                return TRONA_INVALID_ARGUMENT;
            }
            opts.ip_ttl = value as u8;
            TRONA_OK
        }
        SO_TYPE | SO_ERROR | SO_PROTOCOL | SO_DOMAIN if is_sol_socket(level) => {
            TRONA_INVALID_OPERATION
        }
        _ => {
            let _ = sock_type;
            TRONA_INVALID_ARGUMENT
        }
    }
}

pub(crate) fn get_option(
    opts: &mut SocketOptions,
    sock_type: i32,
    protocol: i32,
    level: i32,
    optname: i32,
) -> Result<(u64, u32), u64> {
    match optname {
        SO_TYPE if is_sol_socket(level) => {
            let Some(kind) = socket_type_value(sock_type) else {
                return Err(TRONA_INVALID_ARGUMENT);
            };
            Ok((kind as u64, 4))
        }
        SO_ERROR if is_sol_socket(level) => {
            let value = opts.last_error;
            opts.last_error = 0;
            Ok((value, 4))
        }
        SO_PROTOCOL if is_sol_socket(level) => Ok((protocol as u64, 4)),
        SO_DOMAIN if is_sol_socket(level) => Ok((AF_INET as u64, 4)),
        SO_REUSEADDR if is_sol_socket(level) => Ok((opts.reuseaddr as u64, 4)),
        SO_BROADCAST if is_sol_socket(level) => Ok((opts.broadcast as u64, 4)),
        SO_SNDBUF if is_sol_socket(level) => Ok((opts.sndbuf as u64, 4)),
        SO_RCVBUF if is_sol_socket(level) => Ok((opts.rcvbuf as u64, 4)),
        SO_TIMESTAMP if is_sol_socket(level) => Ok((opts.timestamp_enabled as u64, 4)),
        SO_TS_CLOCK if is_sol_socket(level) => Ok((opts.timestamp_clock as u64, 4)),
        IP_TTL if level == IPPROTO_IP => Ok((opts.ip_ttl as u64, 4)),
        _ => Err(TRONA_INVALID_ARGUMENT),
    }
}
