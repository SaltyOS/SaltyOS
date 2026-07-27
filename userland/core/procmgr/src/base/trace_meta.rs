//! Trace metadata emission for correlating kernel trace ids with processes.
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::Cap;

#[inline]
fn trim_nul(bytes: &[u8]) -> &[u8] {
    let mut len = 0usize;
    while len < bytes.len() && bytes[len] != 0 {
        len += 1;
    }
    &bytes[..len]
}

pub(crate) fn emit_process_mapping(
    event: &[u8],
    pid: u32,
    ppid: u32,
    tcb_cap: Cap,
    vspace_cap: Cap,
    name: &[u8],
    exe_path: &[u8],
) {
    let tid = if tcb_cap != 0 {
        trona_kernel::invoke::tcb_get_trace_id(tcb_cap).unwrap_or(0)
    } else {
        0
    };
    let vsid = if vspace_cap != 0 {
        trona_kernel::invoke::vspace_get_trace_id(vspace_cap).unwrap_or(0)
    } else {
        0
    };
    let name = trim_nul(name);
    let exe_path = trim_nul(exe_path);

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[TRACE_META] event=");
        _lb.bytes(event);
        _lb.str(b" pid=");
        _lb.hex(pid as u64);
        _lb.str(b" ppid=");
        _lb.hex(ppid as u64);
        _lb.str(b" tid=");
        _lb.hex(tid);
        _lb.str(b" vsid=");
        _lb.hex(vsid);
        if !name.is_empty() {
            _lb.str(b" name=");
            _lb.bytes(name);
        }
        if !exe_path.is_empty() {
            _lb.str(b" exe=");
            _lb.bytes(exe_path);
        }
        _lb.str(b"\n");
    });
}
