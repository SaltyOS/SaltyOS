//! Socket, poll, and shared memory tests
//! Exercises AF_UNIX socketpair, data exchange, poll, SCM_RIGHTS, and POSIX shm
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU32, Ordering};
use trona_posix::consts::*;
use trona_posix::mm as posix_mm;
use trona_posix::*;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

const SOCK_SEQPACKET: i32 = 5;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub fn run() -> bool {
    puts(b"[TEST_SOCKET] Starting socket tests\n");

    if !test_socketpair() {
        return false;
    }
    if !test_socketpair_dgram() {
        return false;
    }
    if !test_socketpair_seqpacket() {
        return false;
    }
    if !test_unix_dgram_path() {
        return false;
    }
    if !test_unix_dgram_abstract() {
        return false;
    }
    if !test_unix_stream_abstract() {
        return false;
    }
    if !test_poll() {
        return false;
    }
    if !test_scm_rights() {
        return false;
    }
    if !test_shm() {
        return false;
    }
    if !test_shm_snapshot_committed() {
        return false;
    }
    if !test_shm_snapshot_chain() {
        return false;
    }
    if !test_shm_snapshot_f3_race() {
        return false;
    }

    puts(b"[TEST_SOCKET] All socket tests PASSED\n");
    true
}

// ---- Test 1: socketpair + bidirectional data exchange ----
fn test_socketpair() -> bool {
    puts(b"[TEST_SOCKET] Test 1: socketpair + data exchange\n");

    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe {
        trona_posix::posix_socketpair(AF_UNIX as i32, SOCK_STREAM as i32, 0, fds.as_mut_ptr())
    };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: socketpair returned error\n");
        return false;
    }
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_SOCKET] socketpair fds: ");
        lb.dec(fds[0] as u64);
        lb.str(b", ");
        lb.dec(fds[1] as u64);
        lb.str(b"\n");
        lb.flush();
    }

    if fds[0] < 0 || fds[1] < 0 {
        puts(b"[TEST_SOCKET] FAIL: invalid fds\n");
        return false;
    }

    // Write "hello" on fds[0], read on fds[1]
    let data = b"hello";
    let written = unsafe { trona_posix::posix_write(fds[0], data.as_ptr(), data.len() as u64) };
    if written != data.len() as i64 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: write returned ");
            lb.hex(written as u64);
            lb.str(b"\n");
            lb.flush();
        }
        return false;
    }

    let mut buf = [0u8; 32];
    let nread = unsafe { trona_posix::posix_read(fds[1], buf.as_mut_ptr(), buf.len() as u64) };
    if nread != data.len() as i64 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: read returned ");
            lb.hex(nread as u64);
            lb.str(b"\n");
            lb.flush();
        }
        return false;
    }

    if &buf[..5] != b"hello" {
        puts(b"[TEST_SOCKET] FAIL: data mismatch\n");
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: socketpair data exchange OK\n");

    // Write in reverse direction
    let data2 = b"world";
    let w2 = unsafe { trona_posix::posix_write(fds[1], data2.as_ptr(), data2.len() as u64) };
    if w2 != data2.len() as i64 {
        puts(b"[TEST_SOCKET] FAIL: reverse write error\n");
        return false;
    }

    let mut buf2 = [0u8; 32];
    let r2 = unsafe { trona_posix::posix_read(fds[0], buf2.as_mut_ptr(), buf2.len() as u64) };
    if r2 != data2.len() as i64 || &buf2[..5] != b"world" {
        puts(b"[TEST_SOCKET] FAIL: reverse read mismatch\n");
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: bidirectional exchange OK\n");

    // Close both ends
    unsafe {
        trona_posix::posix_close(fds[0]);
        trona_posix::posix_close(fds[1]);
    }

    true
}

fn test_socketpair_dgram() -> bool {
    puts(b"[TEST_SOCKET] Test 1b: dgram socketpair + packet exchange\n");

    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe {
        trona_posix::posix_socketpair(AF_UNIX as i32, SOCK_DGRAM as i32, 0, fds.as_mut_ptr())
    };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: dgram socketpair returned error\n");
        return false;
    }

    let data = b"alpha";
    let written = unsafe { trona_posix::posix_write(fds[0], data.as_ptr(), data.len() as u64) };
    if written != data.len() as i64 {
        puts(b"[TEST_SOCKET] FAIL: dgram write returned wrong length\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    let mut buf = [0u8; 32];
    let nread = unsafe { trona_posix::posix_read(fds[1], buf.as_mut_ptr(), buf.len() as u64) };
    if nread != data.len() as i64 || &buf[..data.len()] != data {
        puts(b"[TEST_SOCKET] FAIL: dgram read mismatch\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    unsafe {
        trona_posix::posix_close(fds[0]);
        trona_posix::posix_close(fds[1]);
    }
    puts(b"[TEST_SOCKET] PASS: dgram socketpair OK\n");
    true
}

fn test_socketpair_seqpacket() -> bool {
    puts(b"[TEST_SOCKET] Test 1c: seqpacket socketpair + record exchange\n");

    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe {
        trona_posix::posix_socketpair(AF_UNIX as i32, SOCK_SEQPACKET as i32, 0, fds.as_mut_ptr())
    };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: seqpacket socketpair returned error\n");
        return false;
    }

    let data = b"record";
    let written = unsafe { trona_posix::posix_write(fds[0], data.as_ptr(), data.len() as u64) };
    if written != data.len() as i64 {
        puts(b"[TEST_SOCKET] FAIL: seqpacket write returned wrong length\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    let mut buf = [0u8; 32];
    let nread = unsafe { trona_posix::posix_read(fds[1], buf.as_mut_ptr(), buf.len() as u64) };
    if nread != data.len() as i64 || &buf[..data.len()] != data {
        puts(b"[TEST_SOCKET] FAIL: seqpacket read mismatch\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    unsafe {
        trona_posix::posix_close(fds[0]);
        trona_posix::posix_close(fds[1]);
    }
    puts(b"[TEST_SOCKET] PASS: seqpacket socketpair OK\n");
    true
}

fn make_sockaddr_un(path: &[u8]) -> SockAddrUn {
    let mut sa = SockAddrUn::zeroed();
    sa.sun_family = AF_UNIX as u16;
    let copy_len = core::cmp::min(path.len(), sa.sun_path.len().saturating_sub(1));
    sa.sun_path[..copy_len].copy_from_slice(&path[..copy_len]);
    sa
}

fn make_sockaddr_un_abstract(name: &[u8]) -> SockAddrUn {
    let mut sa = SockAddrUn::zeroed();
    sa.sun_family = AF_UNIX as u16;
    let copy_len = core::cmp::min(name.len(), sa.sun_path.len().saturating_sub(1));
    sa.sun_path[0] = 0;
    sa.sun_path[1..1 + copy_len].copy_from_slice(&name[..copy_len]);
    sa
}

fn test_unix_dgram_path() -> bool {
    puts(b"[TEST_SOCKET] Test 1c: pathname dgram sendto/recvfrom\n");

    let send_path = b"/tmp/af_unix_dgram_send\0";
    let recv_path = b"/tmp/af_unix_dgram_recv\0";
    unsafe {
        let _ = trona_posix::posix_unlink(send_path.as_ptr());
        let _ = trona_posix::posix_unlink(recv_path.as_ptr());
    }

    let sender = unsafe { trona_posix::posix_socket(AF_UNIX as i32, SOCK_DGRAM as i32, 0) };
    let receiver = unsafe { trona_posix::posix_socket(AF_UNIX as i32, SOCK_DGRAM as i32, 0) };
    if sender < 0 || receiver < 0 {
        puts(b"[TEST_SOCKET] FAIL: pathname dgram socket create failed\n");
        unsafe {
            if sender >= 0 {
                trona_posix::posix_close(sender);
            }
            if receiver >= 0 {
                trona_posix::posix_close(receiver);
            }
        }
        return false;
    }

    let send_sa = make_sockaddr_un(send_path);
    let recv_sa = make_sockaddr_un(recv_path);
    let send_len = 2 + send_path.len() as u32;
    let recv_len = 2 + recv_path.len() as u32;
    if unsafe {
        trona_posix::posix_bind(
            sender,
            &raw const send_sa as *const SockAddrUn as *const u8,
            send_len,
        )
    } != 0
        || unsafe {
            trona_posix::posix_bind(
                receiver,
                &raw const recv_sa as *const SockAddrUn as *const u8,
                recv_len,
            )
        } != 0
    {
        puts(b"[TEST_SOCKET] FAIL: pathname dgram bind failed\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
            let _ = trona_posix::posix_unlink(send_path.as_ptr());
            let _ = trona_posix::posix_unlink(recv_path.as_ptr());
        }
        return false;
    }

    let payload = b"pkt";
    let sent = unsafe {
        trona_posix::posix_sendto(
            sender,
            payload.as_ptr(),
            payload.len(),
            0,
            &raw const recv_sa as *const SockAddrUn as *const u8,
            recv_len,
        )
    };
    if sent != payload.len() as i64 {
        puts(b"[TEST_SOCKET] FAIL: pathname dgram sendto failed\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
            let _ = trona_posix::posix_unlink(send_path.as_ptr());
            let _ = trona_posix::posix_unlink(recv_path.as_ptr());
        }
        return false;
    }

    let mut buf = [0u8; 32];
    let mut peer = SockAddrUn::zeroed();
    let mut peer_len = core::mem::size_of::<SockAddrUn>() as u32;
    let got = unsafe {
        trona_posix::posix_recvfrom_local(
            receiver,
            buf.as_mut_ptr(),
            buf.len(),
            0,
            &raw mut peer as *mut SockAddrUn as *mut u8,
            &raw mut peer_len,
        )
    };
    if got != payload.len() as i64 || &buf[..payload.len()] != payload {
        puts(b"[TEST_SOCKET] FAIL: pathname dgram recvfrom data mismatch\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
            let _ = trona_posix::posix_unlink(send_path.as_ptr());
            let _ = trona_posix::posix_unlink(recv_path.as_ptr());
        }
        return false;
    }
    if peer.sun_family != AF_UNIX as u16 || peer.sun_path[0] != b'/' {
        puts(b"[TEST_SOCKET] FAIL: pathname dgram recvfrom address missing\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
            let _ = trona_posix::posix_unlink(send_path.as_ptr());
            let _ = trona_posix::posix_unlink(recv_path.as_ptr());
        }
        return false;
    }

    unsafe {
        trona_posix::posix_close(sender);
        trona_posix::posix_close(receiver);
        let _ = trona_posix::posix_unlink(send_path.as_ptr());
        let _ = trona_posix::posix_unlink(recv_path.as_ptr());
    }
    puts(b"[TEST_SOCKET] PASS: pathname dgram sendto/recvfrom OK\n");
    true
}

fn test_unix_dgram_abstract() -> bool {
    puts(b"[TEST_SOCKET] Test 1d: abstract dgram sendto/recvfrom\n");

    let send_name = b"af_unix_abs_send";
    let recv_name = b"af_unix_abs_recv";
    let sender = unsafe { trona_posix::posix_socket(AF_UNIX as i32, SOCK_DGRAM as i32, 0) };
    let receiver = unsafe { trona_posix::posix_socket(AF_UNIX as i32, SOCK_DGRAM as i32, 0) };
    if sender < 0 || receiver < 0 {
        puts(b"[TEST_SOCKET] FAIL: abstract dgram socket create failed\n");
        return false;
    }

    let sender_addr = make_sockaddr_un_abstract(send_name);
    let receiver_addr = make_sockaddr_un_abstract(recv_name);
    let sender_len = (2 + 1 + send_name.len()) as u32;
    let receiver_len = (2 + 1 + recv_name.len()) as u32;
    if unsafe {
        trona_posix::posix_bind(
            sender,
            &sender_addr as *const SockAddrUn as *const u8,
            sender_len,
        )
    } != 0
        || unsafe {
            trona_posix::posix_bind(
                receiver,
                &receiver_addr as *const SockAddrUn as *const u8,
                receiver_len,
            )
        } != 0
    {
        puts(b"[TEST_SOCKET] FAIL: abstract dgram bind failed\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
        }
        return false;
    }

    let payload = b"absgram";
    let sent = unsafe {
        trona_posix::posix_sendto(
            sender,
            payload.as_ptr(),
            payload.len(),
            0,
            &receiver_addr as *const SockAddrUn as *const u8,
            receiver_len,
        )
    };
    if sent != payload.len() as i64 {
        puts(b"[TEST_SOCKET] FAIL: abstract dgram sendto failed\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
        }
        return false;
    }

    let mut buf = [0u8; 32];
    let mut src = SockAddrUn::zeroed();
    let mut src_len = core::mem::size_of::<SockAddrUn>() as u32;
    let got = unsafe {
        trona_posix::posix_recvfrom_local(
            receiver,
            buf.as_mut_ptr(),
            buf.len(),
            0,
            &mut src as *mut SockAddrUn as *mut u8,
            &mut src_len,
        )
    };
    if got != payload.len() as i64 || &buf[..payload.len()] != payload {
        puts(b"[TEST_SOCKET] FAIL: abstract dgram recvfrom data mismatch\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
        }
        return false;
    }
    if src.sun_family != AF_UNIX as u16
        || src.sun_path[0] != 0
        || &src.sun_path[1..1 + send_name.len()] != send_name
        || src_len != (2 + 1 + send_name.len()) as u32
    {
        puts(b"[TEST_SOCKET] FAIL: abstract dgram recvfrom name mismatch\n");
        unsafe {
            trona_posix::posix_close(sender);
            trona_posix::posix_close(receiver);
        }
        return false;
    }

    unsafe {
        trona_posix::posix_close(sender);
        trona_posix::posix_close(receiver);
    }
    puts(b"[TEST_SOCKET] PASS: abstract dgram sendto/recvfrom OK\n");
    true
}

fn test_unix_stream_abstract() -> bool {
    puts(b"[TEST_SOCKET] Test 1e: abstract stream bind/connect/getpeername\n");

    let listen_name = b"af_unix_abs_stream";
    let listen_addr = make_sockaddr_un_abstract(listen_name);
    let listen_len = (2 + 1 + listen_name.len()) as u32;

    let listener = unsafe { trona_posix::posix_socket(AF_UNIX as i32, SOCK_STREAM as i32, 0) };
    let client = unsafe { trona_posix::posix_socket(AF_UNIX as i32, SOCK_STREAM as i32, 0) };
    if listener < 0 || client < 0 {
        puts(b"[TEST_SOCKET] FAIL: abstract stream socket create failed\n");
        return false;
    }

    if unsafe {
        trona_posix::posix_bind(
            listener,
            &listen_addr as *const SockAddrUn as *const u8,
            listen_len,
        )
    } != 0
        || unsafe { trona_posix::posix_listen(listener, 4) } != 0
        || unsafe {
            trona_posix::posix_connect(
                client,
                &listen_addr as *const SockAddrUn as *const u8,
                listen_len,
            )
        } != 0
    {
        puts(b"[TEST_SOCKET] FAIL: abstract stream setup failed\n");
        unsafe {
            trona_posix::posix_close(listener);
            trona_posix::posix_close(client);
        }
        return false;
    }

    let accepted = unsafe { trona_posix::posix_accept(listener) };
    if accepted < 0 {
        puts(b"[TEST_SOCKET] FAIL: abstract stream accept failed\n");
        unsafe {
            trona_posix::posix_close(listener);
            trona_posix::posix_close(client);
        }
        return false;
    }

    let mut peer = SockAddrUn::zeroed();
    let mut peer_len = core::mem::size_of::<SockAddrUn>() as u32;
    let mut local = SockAddrUn::zeroed();
    let mut local_len = core::mem::size_of::<SockAddrUn>() as u32;
    let peer_ret = unsafe {
        trona_posix::posix_getpeername(
            client,
            &mut peer as *mut SockAddrUn as *mut u8,
            &mut peer_len,
        )
    };
    let local_ret = unsafe {
        trona_posix::posix_getsockname(
            accepted,
            &mut local as *mut SockAddrUn as *mut u8,
            &mut local_len,
        )
    };
    if peer_ret != 0
        || local_ret != 0
        || peer.sun_path[0] != 0
        || &peer.sun_path[1..1 + listen_name.len()] != listen_name
        || local.sun_path[0] != 0
        || &local.sun_path[1..1 + listen_name.len()] != listen_name
    {
        puts(b"[TEST_SOCKET] FAIL: abstract stream socket names mismatch\n");
        unsafe {
            trona_posix::posix_close(listener);
            trona_posix::posix_close(client);
            trona_posix::posix_close(accepted);
        }
        return false;
    }

    let payload = b"absstream";
    if unsafe { trona_posix::posix_write(client, payload.as_ptr(), payload.len() as u64) }
        != payload.len() as i64
    {
        puts(b"[TEST_SOCKET] FAIL: abstract stream write failed\n");
        unsafe {
            trona_posix::posix_close(listener);
            trona_posix::posix_close(client);
            trona_posix::posix_close(accepted);
        }
        return false;
    }
    let mut buf = [0u8; 32];
    if unsafe { trona_posix::posix_read(accepted, buf.as_mut_ptr(), buf.len() as u64) }
        != payload.len() as i64
        || &buf[..payload.len()] != payload
    {
        puts(b"[TEST_SOCKET] FAIL: abstract stream read failed\n");
        unsafe {
            trona_posix::posix_close(listener);
            trona_posix::posix_close(client);
            trona_posix::posix_close(accepted);
        }
        return false;
    }

    unsafe {
        trona_posix::posix_close(listener);
        trona_posix::posix_close(client);
        trona_posix::posix_close(accepted);
    }
    puts(b"[TEST_SOCKET] PASS: abstract stream bind/connect/getpeername OK\n");
    true
}

// ---- Test 2: poll on socket fds ----
fn test_poll() -> bool {
    puts(b"[TEST_SOCKET] Test 2: poll on sockets\n");

    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe {
        trona_posix::posix_socketpair(AF_UNIX as i32, SOCK_STREAM as i32, 0, fds.as_mut_ptr())
    };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: socketpair for poll failed\n");
        return false;
    }

    // Poll fds[1] for POLLIN — should have nothing yet (timeout=0, non-blocking)
    let mut pfd = [PollFd {
        fd: fds[1],
        events: POLLIN,
        revents: 0,
    }];
    let n = unsafe { trona_posix::posix_poll(pfd.as_mut_ptr(), 1, 0) };
    if n < 0 {
        puts(b"[TEST_SOCKET] FAIL: poll returned error\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }
    if pfd[0].revents & POLLIN != 0 {
        puts(b"[TEST_SOCKET] FAIL: POLLIN set on empty socket\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: poll empty socket has no POLLIN\n");

    // Write data, then poll again
    let data = b"test";
    unsafe { trona_posix::posix_write(fds[0], data.as_ptr(), data.len() as u64) };

    pfd[0].revents = 0;
    let n2 = unsafe { trona_posix::posix_poll(pfd.as_mut_ptr(), 1, 0) };
    if n2 < 0 {
        puts(b"[TEST_SOCKET] FAIL: poll after write returned error\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }
    if pfd[0].revents & POLLIN == 0 {
        puts(b"[TEST_SOCKET] FAIL: POLLIN not set after write\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: poll detects POLLIN after write\n");

    // Drain data
    let mut buf = [0u8; 32];
    unsafe { trona_posix::posix_read(fds[1], buf.as_mut_ptr(), buf.len() as u64) };

    unsafe {
        trona_posix::posix_close(fds[0]);
        trona_posix::posix_close(fds[1]);
    }
    true
}

// ---- Test 3: SCM_RIGHTS (fd passing via sendmsg/recvmsg) ----
fn test_scm_rights() -> bool {
    puts(b"[TEST_SOCKET] Test 3: SCM_RIGHTS fd passing\n");

    // Create socketpair for passing fds
    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe {
        trona_posix::posix_socketpair(AF_UNIX as i32, SOCK_STREAM as i32, 0, fds.as_mut_ptr())
    };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: socketpair for SCM_RIGHTS failed\n");
        return false;
    }

    // Open a file to pass
    let file_fd = unsafe { trona_posix::posix_open(b"/dev/null\0".as_ptr(), O_RDWR as i32, 0) };
    if file_fd < 0 {
        puts(b"[TEST_SOCKET] FAIL: open /dev/null failed\n");
        unsafe {
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    // sendmsg: send data + file_fd over fds[0]
    let msg_data = b"fd";
    let fd_to_send: [i32; 1] = [file_fd];
    let sent = unsafe {
        trona_posix::posix_sendmsg(
            fds[0],
            msg_data.as_ptr(),
            msg_data.len() as u64,
            fd_to_send.as_ptr(),
            1,
        )
    };
    if sent < 0 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: sendmsg returned ");
            lb.hex(sent as u64);
            lb.str(b"\n");
            lb.flush();
        }
        unsafe {
            trona_posix::posix_close(file_fd);
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_SOCKET] sendmsg sent ");
        lb.dec(sent as u64);
        lb.str(b" bytes + 1 fd\n");
        lb.flush();
    }

    // recvmsg: receive data + fd on fds[1]
    let mut recv_buf = [0u8; 32];
    let mut recv_fds: [i32; 4] = [-1; 4];
    let mut recv_fd_count: u32 = 4;
    let rcvd = unsafe {
        trona_posix::posix_recvmsg(
            fds[1],
            recv_buf.as_mut_ptr(),
            recv_buf.len() as u64,
            recv_fds.as_mut_ptr(),
            &mut recv_fd_count,
            0,
        )
    };
    if rcvd < 0 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: recvmsg returned ");
            lb.hex(rcvd as u64);
            lb.str(b"\n");
            lb.flush();
        }
        unsafe {
            trona_posix::posix_close(file_fd);
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    if rcvd != 2 || &recv_buf[..2] != b"fd" {
        puts(b"[TEST_SOCKET] FAIL: recvmsg data mismatch\n");
        unsafe {
            trona_posix::posix_close(file_fd);
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    if recv_fd_count != 1 || recv_fds[0] < 0 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: expected 1 fd, got ");
            lb.dec(recv_fd_count as u64);
            lb.str(b"\n");
            lb.flush();
        }
        unsafe {
            trona_posix::posix_close(file_fd);
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_SOCKET] received fd=");
        lb.dec(recv_fds[0] as u64);
        lb.str(b"\n");
        lb.flush();
    }

    // Verify the received fd works (write to /dev/null should succeed)
    let wr = unsafe { trona_posix::posix_write(recv_fds[0], b"x".as_ptr(), 1) };
    if wr < 0 {
        puts(b"[TEST_SOCKET] FAIL: write via passed fd failed\n");
        unsafe {
            trona_posix::posix_close(recv_fds[0]);
            trona_posix::posix_close(file_fd);
            trona_posix::posix_close(fds[0]);
            trona_posix::posix_close(fds[1]);
        }
        return false;
    }

    puts(b"[TEST_SOCKET] PASS: SCM_RIGHTS fd passing OK\n");

    unsafe {
        trona_posix::posix_close(recv_fds[0]);
        trona_posix::posix_close(file_fd);
        trona_posix::posix_close(fds[0]);
        trona_posix::posix_close(fds[1]);
    }
    true
}

// ---- Test 4: POSIX shared memory ----
fn test_shm() -> bool {
    puts(b"[TEST_SOCKET] Test 4: POSIX shared memory\n");

    // posix_mm reads mmsrv via trona_runtime::client::caps::mmsrv_ep() now — no explicit
    // init call needed here.

    // shm_open
    let fd = unsafe {
        trona_posix::posix_shm_open(b"/test_shm\0".as_ptr(), (O_CREAT | O_RDWR) as i32, 0o600)
    };
    if fd < 0 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: shm_open returned ");
            lb.hex(fd as u64);
            lb.str(b"\n");
            lb.flush();
        }
        return false;
    }
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_SOCKET] shm_open fd=");
        lb.dec(fd as u64);
        lb.str(b"\n");
        lb.flush();
    }

    // ftruncate to 4096
    let ret = unsafe { trona_posix::posix_ftruncate(fd, 4096) };
    if ret != 0 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: ftruncate returned ");
            lb.hex(ret as u64);
            lb.str(b"\n");
            lb.flush();
        }
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: ftruncate OK\n");

    let shared = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if shared as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: MAP_SHARED shm mmap failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    let fd2 = unsafe { trona_posix::posix_shm_open(b"/test_shm\0".as_ptr(), O_RDWR as i32, 0) };
    if fd2 < 0 {
        puts(b"[TEST_SOCKET] FAIL: second shm_open failed\n");
        unsafe {
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        };
        return false;
    }

    let shared_alias = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd2,
            0,
        )
    };
    if shared_alias as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: second MAP_SHARED shm mmap failed\n");
        unsafe {
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        };
        return false;
    }

    let private_snapshot = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE,
            fd2,
            0,
        )
    };
    if private_snapshot as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: MAP_PRIVATE shm mmap failed\n");
        unsafe {
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        };
        return false;
    }

    unsafe {
        core::ptr::write_volatile(shared, 0x4A);
        core::ptr::write_volatile(shared.add(4095), 0x7C);
        if core::ptr::read_volatile(shared_alias) != 0x4A
            || core::ptr::read_volatile(shared_alias.add(4095)) != 0x7C
        {
            puts(b"[TEST_SOCKET] FAIL: shared SHM alias did not observe writes\n");
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
            return false;
        }

        if core::ptr::read_volatile(private_snapshot) != 0
            || core::ptr::read_volatile(private_snapshot.add(4095)) != 0
        {
            puts(b"[TEST_SOCKET] FAIL: private SHM mapping was not snapshot-isolated\n");
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
            return false;
        }

        core::ptr::write_volatile(private_snapshot, 0x11);
        if core::ptr::read_volatile(shared) != 0x4A {
            puts(b"[TEST_SOCKET] FAIL: private SHM write leaked into shared mapping\n");
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
            return false;
        }
    }

    puts(b"[TEST_SOCKET] PASS: SHM shared/private mmap semantics OK\n");

    let grow_ret = unsafe { trona_posix::posix_ftruncate(fd, 8192) };
    if grow_ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: SHM grow ftruncate failed\n");
        unsafe {
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    let second_page = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            4096,
        )
    };
    if second_page as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: SHM second-page mmap after grow failed\n");
        unsafe {
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    unsafe {
        if core::ptr::read_volatile(second_page) != 0 {
            puts(b"[TEST_SOCKET] FAIL: grown SHM page was not zero-filled\n");
            posix_mm::posix_munmap(second_page, 4096);
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
            return false;
        }
    }

    let shrink_busy = unsafe { trona_posix::posix_ftruncate(fd, 4096) };
    if shrink_busy == 0 {
        puts(b"[TEST_SOCKET] FAIL: SHM shrink succeeded while tail mapping was live\n");
        unsafe {
            posix_mm::posix_munmap(second_page, 4096);
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    unsafe {
        posix_mm::posix_munmap(second_page, 4096);
    }

    let shrink_ok = unsafe { trona_posix::posix_ftruncate(fd, 4096) };
    if shrink_ok != 0 {
        puts(b"[TEST_SOCKET] FAIL: SHM shrink failed after tail unmap\n");
        unsafe {
            posix_mm::posix_munmap(private_snapshot, 4096);
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    puts(b"[TEST_SOCKET] PASS: SHM resize semantics OK\n");

    unsafe {
        posix_mm::posix_munmap(private_snapshot, 4096);
        posix_mm::posix_munmap(shared_alias, 4096);
        trona_posix::posix_close(fd2);
        posix_mm::posix_munmap(shared, 4096);
    }

    // Close and cleanup
    unsafe { trona_posix::posix_close(fd) };

    // Unlink
    let ret = unsafe { trona_posix::posix_shm_unlink(b"/test_shm\0".as_ptr()) };
    if ret != 0 {
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SOCKET] FAIL: shm_unlink returned ");
            lb.hex(ret as u64);
            lb.str(b"\n");
            lb.flush();
        }
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: shm_open/ftruncate/unlink OK\n");

    true
}

/// General-case SHM snapshot. Unlike `test_shm`, which snapshots an all-zero
/// object and so only exercises the empty-hidden-parent / zero-fill path, this
/// commits real content *before* the MAP_PRIVATE. The kernel must then
/// (a) freeze the committed pages into the hidden parent and serve them to the
/// private child by COW (not zero-fill), (b) keep the private child frozen
/// against later writes to the shared object, and (c) keep a concurrent shared
/// alias coherent once a shared writer breaks COW against the hidden parent
/// (sibling reconverge).
fn test_shm_snapshot_committed() -> bool {
    puts(b"[TEST_SOCKET] Test 4b: SHM committed-content snapshot\n");

    let fd = unsafe {
        trona_posix::posix_shm_open(
            b"/test_shm_snap\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o600,
        )
    };
    if fd < 0 {
        puts(b"[TEST_SOCKET] FAIL: snapshot shm_open failed\n");
        return false;
    }
    if unsafe { trona_posix::posix_ftruncate(fd, 4096) } != 0 {
        puts(b"[TEST_SOCKET] FAIL: snapshot ftruncate failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    let shared = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if shared as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: snapshot MAP_SHARED failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    // Commit distinct content before the snapshot — the step `test_shm` omits.
    unsafe {
        core::ptr::write_volatile(shared, 0xAB);
        core::ptr::write_volatile(shared.add(100), 0xCD);
        core::ptr::write_volatile(shared.add(4095), 0xEF);
    }

    let fd2 =
        unsafe { trona_posix::posix_shm_open(b"/test_shm_snap\0".as_ptr(), O_RDWR as i32, 0) };
    if fd2 < 0 {
        puts(b"[TEST_SOCKET] FAIL: snapshot second shm_open failed\n");
        unsafe {
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }
    let shared_alias = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd2,
            0,
        )
    };
    if shared_alias as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: snapshot second MAP_SHARED failed\n");
        unsafe {
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    // Fault the alias in as a *present* writable mapping before the snapshot so
    // the later COW break has a sibling to reconverge (exercises
    // sibling-invalidate, not just demand re-resolution).
    let alias_coherent = unsafe {
        core::ptr::read_volatile(shared_alias) == 0xAB
            && core::ptr::read_volatile(shared_alias.add(100)) == 0xCD
            && core::ptr::read_volatile(shared_alias.add(4095)) == 0xEF
    };
    if !alias_coherent {
        puts(b"[TEST_SOCKET] FAIL: pre-snapshot shared alias incoherent\n");
        unsafe {
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    let private = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE,
            fd2,
            0,
        )
    };
    if private as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: snapshot MAP_PRIVATE failed\n");
        unsafe {
            posix_mm::posix_munmap(shared_alias, 4096);
            trona_posix::posix_close(fd2);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    let mut ok = true;
    unsafe {
        // (a) The private child observes the COMMITTED snapshot-time content,
        // proving it reads the frozen hidden parent rather than a zero page.
        if core::ptr::read_volatile(private) != 0xAB
            || core::ptr::read_volatile(private.add(100)) != 0xCD
            || core::ptr::read_volatile(private.add(4095)) != 0xEF
        {
            puts(b"[TEST_SOCKET] FAIL: private snapshot lost committed content\n");
            ok = false;
        }

        if ok {
            // Mutate the shared object after the snapshot; each write breaks COW
            // against the hidden parent.
            core::ptr::write_volatile(shared, 0x11);
            core::ptr::write_volatile(shared.add(100), 0x22);

            // (b) The private child stays frozen at snapshot-time content.
            if core::ptr::read_volatile(private) != 0xAB
                || core::ptr::read_volatile(private.add(100)) != 0xCD
                || core::ptr::read_volatile(private.add(4095)) != 0xEF
            {
                puts(b"[TEST_SOCKET] FAIL: private snapshot saw post-snapshot writes\n");
                ok = false;
            }
        }

        // (c) The shared alias reconverges with the writer after the COW break.
        if ok
            && (core::ptr::read_volatile(shared_alias) != 0x11
                || core::ptr::read_volatile(shared_alias.add(100)) != 0x22
                || core::ptr::read_volatile(shared_alias.add(4095)) != 0xEF)
        {
            puts(b"[TEST_SOCKET] FAIL: shared alias diverged after snapshot break\n");
            ok = false;
        }

        // Private writes stay isolated from the shared object.
        if ok {
            core::ptr::write_volatile(private, 0x99);
            if core::ptr::read_volatile(shared) != 0x11 {
                puts(b"[TEST_SOCKET] FAIL: private write leaked into shared\n");
                ok = false;
            }
        }
    }

    unsafe {
        posix_mm::posix_munmap(private, 4096);
        posix_mm::posix_munmap(shared_alias, 4096);
        trona_posix::posix_close(fd2);
        posix_mm::posix_munmap(shared, 4096);
        trona_posix::posix_close(fd);
        trona_posix::posix_shm_unlink(b"/test_shm_snap\0".as_ptr());
    }

    if ok {
        puts(b"[TEST_SOCKET] PASS: SHM committed-content snapshot OK\n");
    }
    ok
}

/// Repeated MAP_PRIVATE on the same shm — exercises the kernel's chained
/// hidden-parent insert. The first private mapping snapshots the (root) shm;
/// the second snapshots the shm *after* it has itself become a CoW child, which
/// must splice a second hidden parent into the chain rather than fail. Each
/// private mapping stays frozen at its own snapshot instant, independent of the
/// other and of later shared writes. Teardown also drives the lazy-collapse of
/// the resulting chain.
fn test_shm_snapshot_chain() -> bool {
    puts(b"[TEST_SOCKET] Test 4c: SHM chained snapshot (repeated MAP_PRIVATE)\n");

    let fd = unsafe {
        trona_posix::posix_shm_open(
            b"/test_shm_chain\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o600,
        )
    };
    if fd < 0 {
        puts(b"[TEST_SOCKET] FAIL: chain shm_open failed\n");
        return false;
    }
    if unsafe { trona_posix::posix_ftruncate(fd, 4096) } != 0 {
        puts(b"[TEST_SOCKET] FAIL: chain ftruncate failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    let shared = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if shared as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: chain MAP_SHARED failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    // Snapshot 1 captures 0xA1 (the shm is a CoW root at this point).
    unsafe { core::ptr::write_volatile(shared, 0xA1) };
    let priv1 = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE,
            fd,
            0,
        )
    };
    if priv1 as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: chain first MAP_PRIVATE failed\n");
        unsafe {
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    // Break the shm (now a CoW child of the first hidden parent), then snapshot
    // again: the source is no longer a root, so this drives the chained insert.
    unsafe { core::ptr::write_volatile(shared, 0xB2) };
    let priv2 = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE,
            fd,
            0,
        )
    };
    if priv2 as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: chain second MAP_PRIVATE failed (chained snapshot)\n");
        unsafe {
            posix_mm::posix_munmap(priv1, 4096);
            posix_mm::posix_munmap(shared, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    let mut ok = true;
    unsafe {
        // Each private child is frozen at its own snapshot instant.
        if core::ptr::read_volatile(priv1) != 0xA1 {
            puts(b"[TEST_SOCKET] FAIL: priv1 not frozen at snapshot 1\n");
            ok = false;
        }
        if ok && core::ptr::read_volatile(priv2) != 0xB2 {
            puts(b"[TEST_SOCKET] FAIL: priv2 not frozen at snapshot 2 (chain)\n");
            ok = false;
        }
        // A later shared write reaches neither frozen child.
        if ok {
            core::ptr::write_volatile(shared, 0xC3);
            if core::ptr::read_volatile(priv1) != 0xA1 || core::ptr::read_volatile(priv2) != 0xB2 {
                puts(b"[TEST_SOCKET] FAIL: chained private snapshot saw a later write\n");
                ok = false;
            }
        }
        // Private writes stay isolated from the shared object and from each
        // other.
        if ok {
            core::ptr::write_volatile(priv1, 0x11);
            core::ptr::write_volatile(priv2, 0x22);
            if core::ptr::read_volatile(shared) != 0xC3
                || core::ptr::read_volatile(priv1) != 0x11
                || core::ptr::read_volatile(priv2) != 0x22
            {
                puts(b"[TEST_SOCKET] FAIL: chained private write isolation broken\n");
                ok = false;
            }
        }
    }

    unsafe {
        posix_mm::posix_munmap(priv2, 4096);
        posix_mm::posix_munmap(priv1, 4096);
        posix_mm::posix_munmap(shared, 4096);
        trona_posix::posix_close(fd);
        trona_posix::posix_shm_unlink(b"/test_shm_chain\0".as_ptr());
    }

    if ok {
        puts(b"[TEST_SOCKET] PASS: SHM chained snapshot OK\n");
    }
    ok
}

// =========================================================================
// Test 4d: F3 freeze-window race — concurrent writer vs repeated snapshot
// =========================================================================

static F3_STOP: AtomicU32 = AtomicU32::new(0);
static F3_PROGRESS: AtomicU32 = AtomicU32::new(0);

/// Hammer the shared object `P` (the mapped word handed in via `arg`) with
/// monotonically increasing values until signalled to stop, bumping a progress
/// counter on each write so the main thread can confirm real writes landed
/// between its two snapshot reads.
unsafe extern "C" fn f3_writer(arg: *mut u8) -> *mut u8 {
    // SAFETY: `arg` is a live, u32-aligned word inside the caller's MAP_SHARED
    // mapping; it stays mapped until the main thread stops and joins this writer.
    let word = unsafe { AtomicU32::from_ptr(arg as *mut u32) };
    let mut v: u32 = 0xF300_0000;
    while F3_STOP.load(Ordering::Acquire) == 0 {
        v = v.wrapping_add(1);
        word.store(v, Ordering::Relaxed);
        F3_PROGRESS.fetch_add(1, Ordering::Release);
    }
    core::ptr::null_mut()
}

/// Test 4d — F3 freeze-window race guard. A writer thread mutates the shared
/// object `P` while the main thread repeatedly snapshots it (`MAP_PRIVATE`).
/// Once a private snapshot `C` exists its value is fixed: later `P` writes must
/// never change it. The pre-fix attach-before-downgrade ordering let a snapshot
/// taken inside the freeze window share `P`'s still-writable frame, so its value
/// mutated on the next `P` write — caught here as `a != b`. The race only
/// surfaces under `--smp >= 2`; on a single CPU the snapshot syscall always
/// completes before the next write, so this passes trivially. The sequential
/// "write P after snapshot" case is already covered by
/// `test_shm_snapshot_committed`; this adds the concurrent dimension a
/// sequential test cannot reach.
fn test_shm_snapshot_f3_race() -> bool {
    puts(b"[TEST_SOCKET] Test 4d: SHM snapshot F3 freeze-window race\n");

    const PAGES: usize = 4;
    const SZ: u64 = (PAGES * 4096) as u64;
    // The downgrade walk write-protects P's pages in order, so the last page has
    // the widest freeze window — hammer its first word.
    const HOT: usize = (PAGES - 1) * 4096;
    const ITERS: u32 = 64;

    let fd = unsafe {
        trona_posix::posix_shm_open(b"/test_shm_f3\0".as_ptr(), (O_CREAT | O_RDWR) as i32, 0o600)
    };
    if fd < 0 {
        puts(b"[TEST_SOCKET] FAIL: f3 shm_open failed\n");
        return false;
    }
    if unsafe { trona_posix::posix_ftruncate(fd, SZ) } != 0 {
        puts(b"[TEST_SOCKET] FAIL: f3 ftruncate failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    let shared = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            SZ,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if shared as usize == usize::MAX {
        puts(b"[TEST_SOCKET] FAIL: f3 MAP_SHARED failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    // Commit every page so the snapshot downgrade walk has work on each.
    unsafe {
        for p in 0..PAGES {
            core::ptr::write_volatile(shared.add(p * 4096), 0xF0);
        }
    }

    F3_STOP.store(0, Ordering::Relaxed);
    F3_PROGRESS.store(0, Ordering::Relaxed);

    let mut writer: trona_posix::pthread::PthreadT = 0;
    let cr = unsafe {
        trona_posix::pthread::pthread_create(
            &raw mut writer,
            core::ptr::null(),
            f3_writer,
            shared.add(HOT),
        )
    };
    if cr != 0 {
        puts(b"[TEST_SOCKET] FAIL: f3 writer pthread_create failed\n");
        unsafe {
            posix_mm::posix_munmap(shared, SZ);
            trona_posix::posix_close(fd);
            trona_posix::posix_shm_unlink(b"/test_shm_f3\0".as_ptr());
        }
        return false;
    }

    let fd2 = unsafe { trona_posix::posix_shm_open(b"/test_shm_f3\0".as_ptr(), O_RDWR as i32, 0) };
    if fd2 < 0 {
        puts(b"[TEST_SOCKET] FAIL: f3 second shm_open failed\n");
        F3_STOP.store(1, Ordering::Release);
        unsafe {
            trona_posix::pthread::pthread_join(writer, core::ptr::null_mut());
            posix_mm::posix_munmap(shared, SZ);
            trona_posix::posix_close(fd);
            trona_posix::posix_shm_unlink(b"/test_shm_f3\0".as_ptr());
        }
        return false;
    }

    let mut ok = true;
    for _ in 0..ITERS {
        let private = unsafe {
            posix_mm::posix_mmap(
                core::ptr::null_mut(),
                SZ,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE,
                fd2,
                0,
            )
        };
        if private as usize == usize::MAX {
            puts(b"[TEST_SOCKET] FAIL: f3 MAP_PRIVATE failed\n");
            ok = false;
            break;
        }

        // SAFETY: `private.add(HOT)` is a u32-aligned word in this snapshot's own
        // COW mapping, valid until the munmap below.
        let snap = unsafe { AtomicU32::from_ptr(private.add(HOT) as *mut u32) };
        let a = snap.load(Ordering::Relaxed);
        // Wait until the writer makes observable progress against P between the
        // two reads (observed-event sync, not a timed guess) so a leaked
        // window-shared frame would visibly change under us.
        let base = F3_PROGRESS.load(Ordering::Acquire);
        while F3_PROGRESS.load(Ordering::Acquire).wrapping_sub(base) < 256 {
            trona_kernel::syscall::yield_now();
        }
        let b = snap.load(Ordering::Relaxed);

        unsafe { posix_mm::posix_munmap(private, SZ) };

        if a != b {
            puts(b"[TEST_SOCKET] FAIL: F3 snapshot mutated after P writes (freeze-window leak)\n");
            ok = false;
            break;
        }
    }

    F3_STOP.store(1, Ordering::Release);
    unsafe {
        trona_posix::pthread::pthread_join(writer, core::ptr::null_mut());
        posix_mm::posix_munmap(shared, SZ);
        trona_posix::posix_close(fd2);
        trona_posix::posix_close(fd);
        trona_posix::posix_shm_unlink(b"/test_shm_f3\0".as_ptr());
    }

    if ok {
        puts(b"[TEST_SOCKET] PASS: SHM snapshot F3 freeze-window race OK\n");
    }
    ok
}
