// SPDX-License-Identifier: GPL-2.0-only
//! `DataPipe` — bulk byte stream channel.
//!
//! Storage layout mirrors `MessagePipe`: a shared `DataPipeCore` owns
//! the two ring buffers (one per direction) plus locks and waiter
//! queues, while two lightweight `DataPipe` handles each tag
//! themselves "side A" or "side B" and reference the same core.
//!
//! Transport API is **non-blocking only** at the object level —
//! `try_produce_chunk` / `try_consume_chunk` perform a single
//! lock-protected attempt and report the outcome via
//! `TryProduceErr` / `TryConsumeErr`. The blocking + retry policy
//! (deadline-armed park, byte-level partial-progress accounting) is
//! the syscall layer's responsibility, exactly as on `MessagePipe`.
//! `enqueue_dp_writer_waiter` / `enqueue_dp_reader_waiter` park the
//! current thread on the matching waiter queue and stamp a fresh
//! `wait_seq` so the caller can arm an `IpcTimeout` deadline-queue
//! entry consistently with the wake plan.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const STATE_CLOSED: u64 = uapi::KERNITE_STATE_CLOSED as u64;
const STATE_PEER_CLOSED: u64 = uapi::KERNITE_STATE_PEER_CLOSED as u64;
const STATE_READABLE: u64 = uapi::KERNITE_STATE_READABLE as u64;
const STATE_WRITABLE: u64 = uapi::KERNITE_STATE_WRITABLE as u64;
const STATE_READ_THRESHOLD: u64 = uapi::KERNITE_STATE_READ_THRESHOLD as u64;
const STATE_WRITE_THRESHOLD: u64 = uapi::KERNITE_STATE_WRITE_THRESHOLD as u64;

/// Datagram frame header — a little-endian `u32` payload length precedes
/// each record when the pipe is in datagram mode.
const DGRAM_HDR: usize = 4;
/// Largest datagram payload. One framed record (`DGRAM_HDR + payload`) must
/// fit a single ring; this also bounds the syscall layer's staging buffer.
pub const DATA_PIPE_MAX_DATAGRAM: usize = 2048;

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::event::watcher_list::WatcherList;
use crate::mm::SpinLock;
use crate::sched::thread::Tcb;

/// Ring capacity per direction.
pub const DATA_PIPE_RING_BYTES: usize = 4096;

/// Side identity stored on each `DataPipe` handle.
pub const SIDE_A: u8 = 0;
pub const SIDE_B: u8 = 1;

/// Outcome of a single non-blocking `try_produce_chunk`. The byte
/// ring is partial-friendly: a successful attempt may have written
/// fewer bytes than the caller offered (when the ring's free space
/// was smaller than the source slice). The caller drives the retry
/// loop and decides when to park on `enqueue_dp_writer_waiter`.
pub enum TryProduceErr {
    /// Either side is closed or the peer side has been reaped — no
    /// further bytes can be produced through this handle.
    PeerClosed,
    /// Ring is full at this instant; no bytes were written.
    WouldBlock,
}

/// Outcome of a single non-blocking `try_consume_chunk`. Mirrors
/// `TryProduceErr` for the reader side.
pub enum TryConsumeErr {
    /// Side closed or peer-closed AND the inbound ring is empty —
    /// no further bytes will arrive.
    PeerClosed,
    /// Ring is empty at this instant; no bytes were read.
    WouldBlock,
}

/// Single-direction byte ring.
#[repr(C)]
struct ByteRing {
    head: u32,
    tail: u32,
    used: u32,
    /// Single-reader peek-then-commit reservation. When non-zero,
    /// `try_consume_chunk` has peeked `pending_peek_bytes` from
    /// `head` without yet calling `commit_consume`. A second
    /// concurrent reader (a sibling thread holding a copied
    /// DataPipe-side cap) is refused with `WouldBlock` so the two
    /// readers never observe overlapping byte ranges. Lock-protected
    /// by the owning `DataPipeCore.lock`.
    reader_busy: u32,
    /// Byte count snapshot from the most recent `peek`, kept around
    /// so `abort_peek` and an over-eager `commit_consume(n > peeked)`
    /// can be sanity-checked against the actual reservation. Lock-
    /// protected by the owning `DataPipeCore.lock`.
    pending_peek_bytes: u32,
    _pad: u32,
    bytes: [u8; DATA_PIPE_RING_BYTES],
}

impl ByteRing {
    const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            used: 0,
            reader_busy: 0,
            pending_peek_bytes: 0,
            _pad: 0,
            bytes: [0; DATA_PIPE_RING_BYTES],
        }
    }

    fn free_bytes(&self) -> usize {
        DATA_PIPE_RING_BYTES - self.used as usize
    }

    fn push(&mut self, data: &[u8]) -> usize {
        let chunk = data.len().min(self.free_bytes());
        let mut i = 0;
        while i < chunk {
            let pos = (self.tail as usize + i) % DATA_PIPE_RING_BYTES;
            self.bytes[pos] = data[i];
            i += 1;
        }
        self.tail = ((self.tail as usize + chunk) % DATA_PIPE_RING_BYTES) as u32;
        self.used += chunk as u32;
        chunk
    }

    /// Copy up to `out.len()` bytes from the head WITHOUT advancing
    /// it. Returns the byte count copied. Used by
    /// `try_consume_chunk`'s peek-then-commit protocol so a failed
    /// user-space copy does not lose ring data — the caller commits
    /// via `advance_head` only after the user copy has succeeded.
    fn peek(&self, out: &mut [u8]) -> usize {
        let chunk = out.len().min(self.used as usize);
        let mut i = 0;
        while i < chunk {
            let pos = (self.head as usize + i) % DATA_PIPE_RING_BYTES;
            out[i] = self.bytes[pos];
            i += 1;
        }
        chunk
    }

    /// Advance head by `n` bytes (clamped to `self.used`). Pairs
    /// with `peek` to commit a peek-then-copy transaction.
    fn advance_head(&mut self, n: usize) {
        let n = n.min(self.used as usize);
        self.head = ((self.head as usize + n) % DATA_PIPE_RING_BYTES) as u32;
        self.used -= n as u32;
    }

    /// Read a little-endian `u32` at byte offset `off` from `head`,
    /// honoring ring wrap. Caller guarantees `used >= off + 4`.
    fn read_u32_at(&self, off: usize) -> u32 {
        let mut b = [0u8; 4];
        let mut i = 0;
        while i < 4 {
            let pos = (self.head as usize + off + i) % DATA_PIPE_RING_BYTES;
            b[i] = self.bytes[pos];
            i += 1;
        }
        u32::from_le_bytes(b)
    }

    /// Datagram producer: append one framed record `[u32 len][payload]`
    /// atomically. Returns `false` (writing nothing) when the whole frame
    /// does not fit the ring's free space — a datagram is never split.
    fn push_frame(&mut self, data: &[u8]) -> bool {
        if self.free_bytes() < DGRAM_HDR + data.len() {
            return false;
        }
        let hdr = (data.len() as u32).to_le_bytes();
        // Both pushes are guaranteed full by the free-space check above.
        self.push(&hdr);
        self.push(data);
        true
    }

    /// Datagram consumer peek: read the head frame's header, copy up to
    /// `out.len()` payload bytes (datagram truncation when `out` is
    /// smaller), and report `(copied, frame_total)` WITHOUT advancing.
    /// `frame_total` (`DGRAM_HDR + len`) is what `commit_consume` must
    /// drain so the whole record is dropped even on a truncated read.
    /// Returns `None` only if no complete frame is present.
    fn peek_frame(&self, out: &mut [u8]) -> Option<(usize, usize)> {
        if (self.used as usize) < DGRAM_HDR {
            return None;
        }
        let len = self.read_u32_at(0) as usize;
        if (self.used as usize) < DGRAM_HDR + len {
            return None;
        }
        let copy = len.min(out.len());
        let mut i = 0;
        while i < copy {
            let pos = (self.head as usize + DGRAM_HDR + i) % DATA_PIPE_RING_BYTES;
            out[i] = self.bytes[pos];
            i += 1;
        }
        Some((copy, DGRAM_HDR + len))
    }
}

/// Singly-linked waiter queue (intrusive on `Tcb.eq_wait_next`).
#[repr(C)]
struct WaiterQueue {
    head: *mut Tcb,
    tail: *mut Tcb,
}

impl WaiterQueue {
    const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }

    /// Append `tcb` to the queue. Caller must hold the owning core's
    /// lock. Bumps `sched_ref` for the waiter slot — paired with a
    /// `sched_ref_release_may_destroy` after the wake.
    fn push(&mut self, tcb: *mut Tcb) {
        unsafe { (*tcb).eq_wait_next = core::ptr::null_mut() };
        unsafe { (*tcb).sched_ref_inc() };
        if self.tail.is_null() {
            self.head = tcb;
        } else {
            unsafe { (*self.tail).eq_wait_next = tcb };
        }
        self.tail = tcb;
    }

    fn pop(&mut self) -> *mut Tcb {
        let head = self.head;
        if head.is_null() {
            return core::ptr::null_mut();
        }
        let next = unsafe { (*head).eq_wait_next };
        self.head = next;
        if next.is_null() {
            self.tail = core::ptr::null_mut();
        }
        unsafe { (*head).eq_wait_next = core::ptr::null_mut() };
        head
    }

    /// Remove a specific TCB from the queue. Caller must hold the
    /// owning core's lock.
    fn remove(&mut self, tcb: *mut Tcb) -> bool {
        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let next = unsafe { (*cur).eq_wait_next };
            if cur == tcb {
                if prev.is_null() {
                    self.head = next;
                } else {
                    unsafe { (*prev).eq_wait_next = next };
                }
                if self.tail == cur {
                    self.tail = prev;
                }
                unsafe { (*cur).eq_wait_next = core::ptr::null_mut() };
                return true;
            }
            prev = cur;
            cur = next;
        }
        false
    }
}

/// Shared DataPipe core.
#[repr(C)]
pub struct DataPipeCore {
    pub header: KernelObject,
    pub lock: SpinLock,
    pub state_a: AtomicU64,
    pub state_b: AtomicU64,
    pub watchers_a: WatcherList,
    pub watchers_b: WatcherList,
    /// Bytes produced by side A, consumed by side B.
    a_to_b: ByteRing,
    /// Bytes produced by side B, consumed by side A.
    b_to_a: ByteRing,
    waiters_a_read: WaiterQueue,
    waiters_a_write: WaiterQueue,
    waiters_b_read: WaiterQueue,
    waiters_b_write: WaiterQueue,
    side_a_alive: AtomicBool,
    side_b_alive: AtomicBool,
    paired: AtomicBool,
    /// Datagram (record-boundary) mode, fixed at `pair` time before any
    /// produce/consume runs — lock-protected reads thereafter.
    datagram: bool,
    /// RX/TX byte thresholds per side (`0` = disabled), lock-protected.
    /// `STATE_READ_THRESHOLD` on `side` asserts when the side's inbound
    /// ring `used >= rx_threshold[side]`; `STATE_WRITE_THRESHOLD` when its
    /// outbound ring `free >= tx_threshold[side]`.
    rx_threshold: [u32; 2],
    tx_threshold: [u32; 2],
    /// Per-writer-side half-close: once set, that direction accepts no
    /// further bytes and the peer reader sees EOF after draining the ring.
    /// Lock-protected; indexed by writer side.
    write_shut: [bool; 2],
}

unsafe impl Sync for DataPipeCore {}

impl DataPipeCore {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::DataPipeCore, 0),
            lock: SpinLock::new(),
            state_a: AtomicU64::new(STATE_WRITABLE),
            state_b: AtomicU64::new(STATE_WRITABLE),
            watchers_a: WatcherList::new(),
            watchers_b: WatcherList::new(),
            a_to_b: ByteRing::new(),
            b_to_a: ByteRing::new(),
            waiters_a_read: WaiterQueue::new(),
            waiters_a_write: WaiterQueue::new(),
            waiters_b_read: WaiterQueue::new(),
            waiters_b_write: WaiterQueue::new(),
            side_a_alive: AtomicBool::new(false),
            side_b_alive: AtomicBool::new(false),
            paired: AtomicBool::new(false),
            datagram: false,
            rx_threshold: [0; 2],
            tx_threshold: [0; 2],
            write_shut: [false; 2],
        }
    }

    fn ring_for_writer(&mut self, writer_side: u8) -> &mut ByteRing {
        if writer_side == SIDE_A {
            &mut self.a_to_b
        } else {
            &mut self.b_to_a
        }
    }

    fn ring_for_reader(&mut self, reader_side: u8) -> &mut ByteRing {
        if reader_side == SIDE_A {
            &mut self.b_to_a
        } else {
            &mut self.a_to_b
        }
    }

    fn state_for(&self, side: u8) -> &AtomicU64 {
        if side == SIDE_A {
            &self.state_a
        } else {
            &self.state_b
        }
    }

    fn watchers_for(&mut self, side: u8) -> &mut WatcherList {
        if side == SIDE_A {
            &mut self.watchers_a
        } else {
            &mut self.watchers_b
        }
    }

    fn waiters_read(&mut self, side: u8) -> &mut WaiterQueue {
        if side == SIDE_A {
            &mut self.waiters_a_read
        } else {
            &mut self.waiters_b_read
        }
    }

    fn waiters_write(&mut self, side: u8) -> &mut WaiterQueue {
        if side == SIDE_A {
            &mut self.waiters_a_write
        } else {
            &mut self.waiters_b_write
        }
    }

    fn side_alive(&self, side: u8) -> &AtomicBool {
        if side == SIDE_A {
            &self.side_a_alive
        } else {
            &self.side_b_alive
        }
    }

    fn other_side(side: u8) -> u8 {
        if side == SIDE_A { SIDE_B } else { SIDE_A }
    }

    /// Recompute the RX/TX threshold state bits for `side` under the core
    /// lock; returns the bits that newly asserted (0→1) so the caller can
    /// `publish` them to watchers after the lock is dropped. Cleared bits
    /// are applied immediately (level-triggered watchers re-read state).
    fn recompute_thresholds_locked(&mut self, side: u8) -> u64 {
        let rx_t = self.rx_threshold[side as usize];
        let tx_t = self.tx_threshold[side as usize];
        let rx_used = self.ring_for_reader(side).used;
        let tx_free = self.ring_for_writer(side).free_bytes() as u32;
        let st = self.state_for(side);
        let prev = st.load(Ordering::Acquire);
        let mut publish = 0u64;

        let rx_on = rx_t != 0 && rx_used >= rx_t;
        if rx_on && (prev & STATE_READ_THRESHOLD) == 0 {
            st.fetch_or(STATE_READ_THRESHOLD, Ordering::Release);
            publish |= STATE_READ_THRESHOLD;
        } else if !rx_on && (prev & STATE_READ_THRESHOLD) != 0 {
            st.fetch_and(!STATE_READ_THRESHOLD, Ordering::Release);
        }

        let tx_on = tx_t != 0 && tx_free >= tx_t;
        if tx_on && (prev & STATE_WRITE_THRESHOLD) == 0 {
            st.fetch_or(STATE_WRITE_THRESHOLD, Ordering::Release);
            publish |= STATE_WRITE_THRESHOLD;
        } else if !tx_on && (prev & STATE_WRITE_THRESHOLD) != 0 {
            st.fetch_and(!STATE_WRITE_THRESHOLD, Ordering::Release);
        }
        publish
    }

    /// Detach `tcb` from the read- or write-side waiter queue
    /// matching `reason` and release its waiter-slot `sched_ref`.
    /// Mirror of `MessagePipeCore::detach_waiter` for byte streams.
    ///
    /// # Safety
    /// `core` must be a live `DataPipeCore` and `tcb` the thread
    /// whose `wait_object` points at this core.
    pub unsafe fn detach_waiter(
        core: *mut DataPipeCore,
        tcb: *mut Tcb,
        side: u8,
        reason: crate::sched::thread::BlockedReason,
    ) {
        if core.is_null() || tcb.is_null() {
            return;
        }
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core).lock.lock() };
        let removed = match reason {
            crate::sched::thread::BlockedReason::DataPipeWrite => unsafe {
                (*core).waiters_write(side).remove(tcb)
            },
            crate::sched::thread::BlockedReason::DataPipeRead => unsafe {
                (*core).waiters_read(side).remove(tcb)
            },
            _ => false,
        };
        unsafe { (*core).lock.unlock() };
        unsafe { crate::mm::restore_irq(irq) };

        if removed {
            unsafe {
                crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
            }
        }
    }
}

/// Lightweight side handle into a `DataPipeCore`. All watcher state
/// lives on the shared core; the side keeps only a strong pointer
/// plus its own side identity.
#[repr(C)]
pub struct DataPipe {
    pub header: KernelObject,
    pub core: *mut DataPipeCore,
    pub which_side: u8,
    pub _pad: [u8; 7],
}

unsafe impl Sync for DataPipe {}

impl DataPipe {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::DataPipe, 0),
            core: core::ptr::null_mut(),
            which_side: 0xFF,
            _pad: [0; 7],
        }
    }

    /// Bind two newly retyped sides + a core into a paired channel.
    ///
    /// # Safety
    /// `core`, `a`, and `b` must be live, kernel-allocated objects
    /// the caller currently holds caps for.
    pub unsafe fn pair(
        core: *mut DataPipeCore,
        a: *mut DataPipe,
        b: *mut DataPipe,
        datagram: bool,
    ) -> Result<(), ()> {
        if core.is_null() || a.is_null() || b.is_null() || a == b {
            return Err(());
        }
        unsafe {
            if (*core).paired.swap(true, Ordering::AcqRel) {
                return Err(());
            }
            if !(*a).core.is_null() || !(*b).core.is_null() {
                (*core).paired.store(false, Ordering::Release);
                return Err(());
            }
            // Fixed before either side becomes alive — the alive-store
            // Release publishes this write to any later producer/consumer.
            (*core).datagram = datagram;
            (*a).core = core;
            (*a).which_side = SIDE_A;
            (*b).core = core;
            (*b).which_side = SIDE_B;
            (*core).side_a_alive.store(true, Ordering::Release);
            (*core).side_b_alive.store(true, Ordering::Release);
            crate::cap::increment_refcount(core as *mut KernelObject);
            crate::cap::increment_refcount(core as *mut KernelObject);
        }
        Ok(())
    }

    /// Single-attempt non-blocking byte-ring append.
    ///
    /// Returns `Ok(n)` after pushing `n` bytes (`0 < n <=
    /// bytes.len()`), `Err(WouldBlock)` when the ring is full at
    /// this instant, `Err(PeerClosed)` when this side or the peer
    /// has been closed.
    ///
    /// `n` may be smaller than `bytes.len()` because the byte ring
    /// fills partially — the syscall layer treats partial progress
    /// as success and re-enters `try_produce_chunk` for the
    /// remainder.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle with a non-null core.
    pub unsafe fn try_produce_chunk(&self, bytes: &[u8]) -> Result<usize, TryProduceErr> {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return Err(TryProduceErr::PeerClosed);
        }
        let me = self.which_side;
        let other = DataPipeCore::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };

        if (core.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0
            || core.write_shut[me as usize]
            || !core.side_alive(other).load(Ordering::Acquire)
        {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryProduceErr::PeerClosed);
        }

        if core.ring_for_writer(me).free_bytes() == 0 {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryProduceErr::WouldBlock);
        }

        let chunk = core.ring_for_writer(me).push(bytes);
        // `push` only returns 0 when `free_bytes() == 0`, which we
        // checked above — defensively fall through but the compiler
        // can prove `chunk > 0` here.
        if chunk == 0 {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryProduceErr::WouldBlock);
        }

        let prev_other = core
            .state_for(other)
            .fetch_or(STATE_READABLE, Ordering::Release);
        let mut publish_to_other = if (prev_other & STATE_READABLE) == 0 {
            STATE_READABLE
        } else {
            0
        };
        if core.ring_for_writer(me).free_bytes() == 0 {
            core.state_for(me)
                .fetch_and(!STATE_WRITABLE, Ordering::Release);
        }
        // Producing raised the peer's inbound fill (its RX threshold) and
        // lowered our own outbound free (our TX threshold).
        publish_to_other |= core.recompute_thresholds_locked(other);
        let publish_to_me = core.recompute_thresholds_locked(me);

        let waiter = core.waiters_read(other).pop();
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_to_other != 0 {
            let watchers = core.watchers_for(other) as *mut WatcherList;
            unsafe { (*watchers).publish(publish_to_other) };
        }
        if publish_to_me != 0 {
            let watchers = core.watchers_for(me) as *mut WatcherList;
            unsafe { (*watchers).publish(publish_to_me) };
        }
        if !waiter.is_null() {
            unsafe { wake_thread(waiter) };
        }
        Ok(chunk)
    }

    /// Datagram producer: append `bytes` as one atomic framed record.
    /// Unlike `try_produce_chunk` this is all-or-nothing — a datagram is
    /// never partially written. `WouldBlock` means the framed record
    /// (`DGRAM_HDR + bytes.len()`) does not currently fit; the caller
    /// retries after a `WRITABLE` watch. `bytes.len()` must be
    /// `<= DATA_PIPE_MAX_DATAGRAM` (caller-enforced at the syscall layer).
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle with a non-null core.
    pub unsafe fn try_produce_datagram(&self, bytes: &[u8]) -> Result<(), TryProduceErr> {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return Err(TryProduceErr::PeerClosed);
        }
        let me = self.which_side;
        let other = DataPipeCore::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };

        if (core.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0
            || core.write_shut[me as usize]
            || !core.side_alive(other).load(Ordering::Acquire)
        {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryProduceErr::PeerClosed);
        }

        if !core.ring_for_writer(me).push_frame(bytes) {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryProduceErr::WouldBlock);
        }

        let prev_other = core
            .state_for(other)
            .fetch_or(STATE_READABLE, Ordering::Release);
        let mut publish_to_other = if (prev_other & STATE_READABLE) == 0 {
            STATE_READABLE
        } else {
            0
        };
        if core.ring_for_writer(me).free_bytes() == 0 {
            core.state_for(me)
                .fetch_and(!STATE_WRITABLE, Ordering::Release);
        }
        publish_to_other |= core.recompute_thresholds_locked(other);
        let publish_to_me = core.recompute_thresholds_locked(me);

        let waiter = core.waiters_read(other).pop();
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_to_other != 0 {
            let watchers = core.watchers_for(other) as *mut WatcherList;
            unsafe { (*watchers).publish(publish_to_other) };
        }
        if publish_to_me != 0 {
            let watchers = core.watchers_for(me) as *mut WatcherList;
            unsafe { (*watchers).publish(publish_to_me) };
        }
        if !waiter.is_null() {
            unsafe { wake_thread(waiter) };
        }
        Ok(())
    }

    /// Single-attempt non-blocking byte-ring **peek** with a single-
    /// reader reservation.
    ///
    /// Returns `Ok(n)` after copying `n` bytes from the head into
    /// `out` WITHOUT advancing the head — the caller is expected to
    /// finish copying those bytes to userspace and then call
    /// `commit_consume(n)` to advance the head. If userspace copy
    /// fails the caller calls `abort_peek` to release the
    /// reservation; the data stays in the ring for the next read
    /// attempt (no data loss across `EFAULT`-style failures, in
    /// contrast to the older pop-then-copy design).
    ///
    /// **Single-reader enforcement**: the side cap is freely copyable
    /// across CSpaces, so a sibling thread holding a duplicate cap
    /// could otherwise race a peek between the snapshot and the
    /// commit and observe the same bytes twice. The ring carries a
    /// lock-protected `reader_busy` flag — when an outstanding peek
    /// is unresolved, a second `try_consume_chunk` on the same ring
    /// returns `WouldBlock` (matching the byte-empty case so the
    /// caller's blocking policy applies uniformly).
    ///
    /// `Err(WouldBlock)` when the ring is empty AND the side is
    /// still open, when another reader has an outstanding peek, or
    /// when `peek` returned 0. `Err(PeerClosed)` when the ring is
    /// empty AND this side is closed or peer-closed.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle with a non-null core.
    /// Each successful `Ok(n > 0)` MUST be paired with a subsequent
    /// `commit_consume(n)` (success path) or `abort_peek()` (e.g.
    /// user-copy fault) to clear the single-reader reservation.
    pub unsafe fn try_consume_chunk(&self, out: &mut [u8]) -> Result<usize, TryConsumeErr> {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return Err(TryConsumeErr::PeerClosed);
        }
        let me = self.which_side;
        let other = DataPipeCore::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };

        if core.ring_for_reader(me).reader_busy != 0 {
            // Another reader has an outstanding peek-then-commit
            // window open. Refuse the second peek so the two readers
            // never observe overlapping byte ranges. WouldBlock
            // funnels into the caller's existing block-or-short-read
            // policy.
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryConsumeErr::WouldBlock);
        }

        if core.ring_for_reader(me).used > 0 {
            // Datagram mode reserves the whole framed record for commit
            // (`pending_peek_bytes = DGRAM_HDR + len`) but returns only the
            // copied payload count; stream mode reserves exactly the bytes
            // peeked.
            let (chunk, reserve) = if core.datagram {
                match core.ring_for_reader(me).peek_frame(out) {
                    Some(pair) => pair,
                    None => {
                        // Frames are produced atomically, so a partial frame
                        // here is unexpected — surface WouldBlock defensively.
                        core.lock.unlock();
                        unsafe { crate::mm::restore_irq(irq) };
                        return Err(TryConsumeErr::WouldBlock);
                    }
                }
            } else {
                let c = core.ring_for_reader(me).peek(out);
                (c, c)
            };
            if reserve > 0 {
                core.ring_for_reader(me).reader_busy = 1;
                core.ring_for_reader(me).pending_peek_bytes = reserve as u32;
            }
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Ok(chunk);
        }

        // Ring empty: EOF when this side is closed/peer-closed, or when the
        // peer half-closed its write direction (`write_shut[other]`).
        let my_state = core.state_for(me).load(Ordering::Acquire);
        let closed =
            (my_state & (STATE_CLOSED | STATE_PEER_CLOSED)) != 0 || core.write_shut[other as usize];
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if closed {
            Err(TryConsumeErr::PeerClosed)
        } else {
            Err(TryConsumeErr::WouldBlock)
        }
    }

    /// Commit a `try_consume_chunk` peek by advancing the head by
    /// `n` bytes and clearing the single-reader reservation.
    /// Republishes `STATE_WRITABLE` to the peer, clears
    /// `STATE_READABLE` if the inbound ring drained empty, and
    /// wakes one writer waiter if the peer's outbound ring just
    /// transitioned from full to non-full.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle with a non-null core.
    /// `n` must be `<= pending_peek_bytes` (the byte count
    /// `try_consume_chunk` returned for the peek being committed).
    /// MUST NOT be called without a preceding `Ok(n > 0)` from
    /// `try_consume_chunk` on the same handle.
    pub unsafe fn commit_consume(&self, n: usize) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let other = DataPipeCore::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };

        // No outstanding peek reservation → nothing to commit (a stream
        // zero-byte commit lands here too and is a benign no-op).
        if core.ring_for_reader(me).reader_busy == 0 {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return;
        }

        // Datagram drops the whole reserved frame the peek measured
        // (`pending_peek_bytes`), even for a truncated or zero-length
        // record; stream advances by exactly the committed byte count `n`.
        let advance = if core.datagram {
            core.ring_for_reader(me).pending_peek_bytes as usize
        } else {
            n
        };
        core.ring_for_reader(me).advance_head(advance);
        core.ring_for_reader(me).pending_peek_bytes = 0;
        core.ring_for_reader(me).reader_busy = 0;

        if core.ring_for_reader(me).used == 0 {
            core.state_for(me)
                .fetch_and(!STATE_READABLE, Ordering::Release);
        }
        let prev_other = core
            .state_for(other)
            .fetch_or(STATE_WRITABLE, Ordering::Release);
        let mut publish_to_other = if (prev_other & STATE_WRITABLE) == 0 {
            STATE_WRITABLE
        } else {
            0
        };
        // Draining lowered our inbound fill (our RX threshold) and raised
        // the peer's outbound free (its TX threshold).
        let publish_to_me = core.recompute_thresholds_locked(me);
        publish_to_other |= core.recompute_thresholds_locked(other);

        let writer_waiter = core.waiters_write(other).pop();
        // If the inbound ring still has bytes after the commit, wake
        // a parked reader on this side. A second reader (sibling
        // thread holding a copied side cap) may have parked on the
        // reader queue after the prior `try_consume_chunk` returned
        // `WouldBlock` because of `reader_busy != 0`. Now that
        // `reader_busy` has been cleared, that parked reader can
        // peek the surviving bytes.
        let reader_waiter = if core.ring_for_reader(me).used > 0 {
            core.waiters_read(me).pop()
        } else {
            core::ptr::null_mut()
        };
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_to_other != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(other) as *mut WatcherList };
            unsafe { (*watchers).publish(publish_to_other) };
        }
        if publish_to_me != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(me) as *mut WatcherList };
            unsafe { (*watchers).publish(publish_to_me) };
        }
        if !writer_waiter.is_null() {
            unsafe { wake_thread(writer_waiter) };
        }
        if !reader_waiter.is_null() {
            unsafe { wake_thread(reader_waiter) };
        }
    }

    /// Abort an outstanding `try_consume_chunk` peek without
    /// advancing the head. Clears the single-reader reservation so
    /// the next reader can proceed; data peeked into the staging
    /// buffer stays in the ring (the next reader will re-peek the
    /// same bytes). Used by the syscall layer when a user-mode
    /// copy of the peeked bytes faulted (`copy_to_user_bytes`
    /// returning `false`) — without this hook the failed copy
    /// would leave `reader_busy = 1` permanently and lock the ring.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle with a non-null core.
    /// Should be called at most once per outstanding peek; calling
    /// it without a peek outstanding is a benign no-op (the lock-
    /// protected fields are simply re-zeroed).
    pub unsafe fn abort_peek(&self) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        core.ring_for_reader(me).reader_busy = 0;
        core.ring_for_reader(me).pending_peek_bytes = 0;
        // Bytes are still in the ring (peek didn't advance head). A
        // sibling reader may have parked because of `reader_busy != 0`
        // — wake one so it can re-peek the same bytes now that the
        // reservation is released.
        let reader_waiter = if core.ring_for_reader(me).used > 0 {
            core.waiters_read(me).pop()
        } else {
            core::ptr::null_mut()
        };
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        if !reader_waiter.is_null() {
            unsafe { wake_thread(reader_waiter) };
        }
    }

    /// Park `tcb` on this side's writer-wait queue. Caller has
    /// already validated that `try_produce_chunk` returned
    /// `WouldBlock`. Caller must `reschedule()` after this returns.
    /// Returns the new `wait_seq` for deadline-arm coordination.
    ///
    /// # Safety
    /// `tcb` must be the current TCB.
    pub unsafe fn enqueue_dp_writer_waiter(&self, tcb: *mut Tcb) -> u64 {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return 0;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        unsafe {
            core.waiters_write(me).push(tcb);
            let t = &mut *tcb;
            t.wait_object = core_ptr as *mut core::ffi::c_void;
            t.wait_side = me;
            t.wait_seq = t.wait_seq.wrapping_add(1);
            let new_seq = t.wait_seq;
            t.tcb_lock();
            crate::task::wait::prepare_blocked_reason_locked(
                t,
                crate::sched::thread::BlockedReason::DataPipeWrite,
            );
            t.tcb_unlock();
            core.lock.unlock();
            crate::mm::restore_irq(irq);
            new_seq
        }
    }

    /// Park `tcb` on this side's reader-wait queue. Mirror of
    /// `enqueue_dp_writer_waiter`.
    ///
    /// # Safety
    /// `tcb` must be the current TCB.
    pub unsafe fn enqueue_dp_reader_waiter(&self, tcb: *mut Tcb) -> u64 {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return 0;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        unsafe {
            core.waiters_read(me).push(tcb);
            let t = &mut *tcb;
            t.wait_object = core_ptr as *mut core::ffi::c_void;
            t.wait_side = me;
            t.wait_seq = t.wait_seq.wrapping_add(1);
            let new_seq = t.wait_seq;
            t.tcb_lock();
            crate::task::wait::prepare_blocked_reason_locked(
                t,
                crate::sched::thread::BlockedReason::DataPipeRead,
            );
            t.tcb_unlock();
            core.lock.unlock();
            crate::mm::restore_irq(irq);
            new_seq
        }
    }

    /// Query this side's pending byte count and current state bits.
    ///
    /// Returns `None` if the side has not been paired with a core yet.
    /// Otherwise returns `(bytes_pending_on_this_side, state_flags)`
    /// taken atomically under the core lock; the byte count reflects
    /// the inbound ring (what `try_consume_chunk` would drain), the
    /// state bits match this side's `state_for(side)` view.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle.
    pub unsafe fn query(&self) -> Option<(u64, u64)> {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return None;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        let used = core.ring_for_reader(me).used as u64;
        let state = core.state_for(me).load(Ordering::Acquire);
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        Some((used, state))
    }

    /// Whether this pipe carries record-boundary datagrams (vs a byte
    /// stream). Fixed at `pair` time; `false` for an unpaired side.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle.
    pub unsafe fn is_datagram(&self) -> bool {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return false;
        }
        // `datagram` is fixed before either side is published (its write in
        // `pair` happens-before the alive-store Release), so an
        // unsynchronized read after a successful pair is sound.
        unsafe { (*core_ptr).datagram }
    }

    /// Set this side's RX byte threshold: `STATE_READ_THRESHOLD` asserts
    /// while inbound `used >= rx`. `0` disables. Recomputed immediately.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle.
    pub unsafe fn set_rx_threshold(&self, rx: u32) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        core.rx_threshold[me as usize] = rx;
        let publish = core.recompute_thresholds_locked(me);
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        if publish != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(me) as *mut WatcherList };
            unsafe { (*watchers).publish(publish) };
        }
    }

    /// Set this side's TX free-space threshold: `STATE_WRITE_THRESHOLD`
    /// asserts while outbound `free >= tx`. `0` disables.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle.
    pub unsafe fn set_tx_threshold(&self, tx: u32) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        core.tx_threshold[me as usize] = tx;
        let publish = core.recompute_thresholds_locked(me);
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        if publish != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(me) as *mut WatcherList };
            unsafe { (*watchers).publish(publish) };
        }
    }

    /// Half-close: disable this side's write direction. Further produce on
    /// this side returns `PeerClosed`; the peer reader drains the ring then
    /// sees EOF. Wakes this side's parked writers and the peer's parked
    /// reader so both re-evaluate. Idempotent.
    ///
    /// # Safety
    /// `self` must be a live `DataPipe` handle.
    pub unsafe fn shutdown_write(&self) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let other = DataPipeCore::other_side(me);
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        if core.write_shut[me as usize] {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return;
        }
        core.write_shut[me as usize] = true;
        // The peer's inbound stream now has a definite end — flag it readable
        // so a parked reader wakes, drains, and observes EOF.
        let prev_other = core
            .state_for(other)
            .fetch_or(STATE_READABLE, Ordering::Release);
        let publish_other = if (prev_other & STATE_READABLE) == 0 {
            STATE_READABLE
        } else {
            0
        };
        let mut writers = core::ptr::null_mut();
        collect_queue(core.waiters_write(me), &mut writers);
        let reader_waiter = core.waiters_read(other).pop();
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_other != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(other) as *mut WatcherList };
            unsafe { (*watchers).publish(publish_other) };
        }
        unsafe { wake_chain(writers) };
        if !reader_waiter.is_null() {
            unsafe { wake_thread(reader_waiter) };
        }
    }

    /// Close this side. Drains both sides' waiters, propagates
    /// `STATE_PEER_CLOSED` to the peer.
    pub fn close(&mut self) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let other = DataPipeCore::other_side(me);

        unsafe {
            let irq = crate::mm::save_irq_disable();
            (*core_ptr).lock.lock();
            let core = &mut *core_ptr;

            let already_closed = (core.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0;
            if already_closed {
                core.lock.unlock();
                crate::mm::restore_irq(irq);
                return;
            }

            core.state_for(me).fetch_or(STATE_CLOSED, Ordering::Release);
            core.state_for(other)
                .fetch_or(STATE_PEER_CLOSED, Ordering::Release);
            core.side_alive(me).store(false, Ordering::Release);

            let mut readers_a = core::ptr::null_mut();
            let mut writers_a = core::ptr::null_mut();
            let mut readers_b = core::ptr::null_mut();
            let mut writers_b = core::ptr::null_mut();
            collect_queue(&mut core.waiters_a_read, &mut readers_a);
            collect_queue(&mut core.waiters_a_write, &mut writers_a);
            collect_queue(&mut core.waiters_b_read, &mut readers_b);
            collect_queue(&mut core.waiters_b_write, &mut writers_b);

            core.lock.unlock();
            crate::mm::restore_irq(irq);

            wake_chain(readers_a);
            wake_chain(writers_a);
            wake_chain(readers_b);
            wake_chain(writers_b);

            let other_watchers = core.watchers_for(other) as *mut WatcherList;
            (*other_watchers).publish(STATE_PEER_CLOSED);
            let me_watchers = core.watchers_for(me) as *mut WatcherList;
            (*me_watchers).publish(STATE_CLOSED);
        }
    }

    /// Drop the core's refcount contributed by this side. Drains the
    /// per-side watcher list inside the core so any `Watch` pointing
    /// at this side handle has its `watched_object` cleared before
    /// the side is reaped.
    ///
    /// # Safety
    /// Must be called exactly once per side, after `close()`.
    pub unsafe fn cleanup(&mut self) {
        let core_ptr = self.core;
        let me = self.which_side;
        self.close();
        self.core = core::ptr::null_mut();
        unsafe {
            if !core_ptr.is_null() {
                let watchers = (*core_ptr).watchers_for(me) as *mut WatcherList;
                (*watchers).drain_closed();
                crate::cap::release_object(core_ptr as *mut KernelObject, ObjectType::DataPipeCore);
            }
        }
    }
}

unsafe fn wake_thread(tcb: *mut Tcb) {
    unsafe {
        let _ = crate::sched::control::execute_wake_plan(
            crate::sched::control::pipe_wait_wake_plan(tcb),
        );
        crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
    }
}

#[inline]
fn collect_queue(q: &mut WaiterQueue, out: &mut *mut Tcb) {
    *out = q.head;
    q.head = core::ptr::null_mut();
    q.tail = core::ptr::null_mut();
}

#[inline]
unsafe fn wake_chain(mut head: *mut Tcb) {
    while !head.is_null() {
        unsafe {
            let next = (*head).eq_wait_next;
            (*head).eq_wait_next = core::ptr::null_mut();
            wake_thread(head);
            head = next;
        }
    }
}
