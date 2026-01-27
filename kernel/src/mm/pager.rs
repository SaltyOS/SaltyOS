//! External Pager Interface
//!
//! Foundation for Phase 3: Handles page faults with pager registration
//! and zero-fill fallback for unhandled faults.

#![no_std]

use spin::Mutex;
use saltyos_ska::BootInfo;

use super::VirtAddr;
use crate::mm::PAGE_SIZE;
use crate::mm::{allocate_frame};
use crate::mm::vm::{map_page, frame_to_virt, PageFlags};
use crate::mm::heap::KernelError;

/// Page fault error code flags
#[derive(Clone, Copy, Debug)]
pub struct PageFaultError(u64);

impl PageFaultError {
    /// Create from error code
    pub fn new(code: u64) -> Self {
        Self(code)
    }

    /// Present bit: 0 = page not present, 1 = protection violation
    pub fn is_not_present(&self) -> bool {
        self.0 & 0x1 == 0
    }

    /// Present bit: 0 = page not present, 1 = protection violation
    pub fn is_protection_violation(&self) -> bool {
        self.0 & 0x1 != 0
    }

    /// Write access: 1 = caused by write, 0 = caused by read
    pub fn is_write(&self) -> bool {
        self.0 & 0x2 != 0
    }

    /// Read access: 1 = caused by read, 0 = caused by write
    pub fn is_read(&self) -> bool {
        self.0 & 0x2 == 0
    }

    /// User mode: 1 = caused by user mode, 0 = caused by supervisor mode
    pub fn is_user_mode(&self) -> bool {
        self.0 & 0x4 != 0
    }

    /// Supervisor mode: 1 = caused by supervisor mode, 0 = caused by user mode
    pub fn is_supervisor_mode(&self) -> bool {
        self.0 & 0x4 == 0
    }

    /// Instruction fetch: 1 = caused by instruction fetch, 0 = caused by data access
    pub fn is_instruction_fetch(&self) -> bool {
        self.0 & 0x10 != 0
    }

    /// Data access: 1 = caused by data access, 0 = caused by instruction fetch
    pub fn is_data_access(&self) -> bool {
        self.0 & 0x10 == 0
    }

    /// Get raw error code
    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// Pager function type
///
/// Takes a virtual address and returns a physical frame to map,
/// or None if the page should not be mapped.
pub type PagerFn = unsafe fn(VirtAddr) -> Option<super::Frame>;

/// Registered pager
static PAGER: Mutex<Option<PagerFn>> = Mutex::new(None);

/// Pager initialization state
static PAGER_READY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Initialize the pager interface
///
/// # Safety
/// Must be called once during kernel initialization.
pub unsafe fn init(_bootinfo: &BootInfo) {
    // Mark pager as ready
    PAGER_READY.store(1, core::sync::atomic::Ordering::Release);
}

/// Register a pager function
///
/// The pager will be called for page faults to provide backing frames.
pub fn register_pager(pager: PagerFn) {
    *PAGER.lock() = Some(pager);
}

/// Handle a page fault
///
/// Only handles non-present faults (P=0). Protection violations cause a panic.
///
/// # Safety
/// Must be called from the page fault interrupt handler.
pub unsafe fn handle_page_fault(
    fault_addr: VirtAddr,
    error_code: u64,
) -> Result<(), KernelError> {
    let error = PageFaultError::new(error_code);

    // Only handle non-present faults (P=0)
    if error.is_protection_violation() {
        // Present bit set = protection violation
        serial_print_str("\r\n*** PROTECTION VIOLATION ***\r\n");
        serial_print_str("Fault address: ");
        serial_print_hex(fault_addr.as_u64());
        serial_print_str("\r\n");

        // Print detailed error information
        serial_print_str("Access: ");
        if error.is_write() {
            serial_print_str("Write");
        } else {
            serial_print_str("Read");
        }
        serial_print_str("\r\n");

        serial_print_str("Mode: ");
        if error.is_user_mode() {
            serial_print_str("User");
        } else {
            serial_print_str("Supervisor");
        }
        serial_print_str("\r\n");

        serial_print_str("Type: ");
        if error.is_instruction_fetch() {
            serial_print_str("Instruction fetch");
        } else {
            serial_print_str("Data access");
        }
        serial_print_str("\r\n");

        serial_print_str("Error code: ");
        serial_print_number(error_code);
        serial_print_str("\r\n");

        loop { core::arch::asm!("hlt"); }
    }

    // Try registered pager first
    // Note: Acquire pager lock, get frame, release lock BEFORE calling map_page()
    // to avoid deadlock (map_page acquires KERNEL_AS lock)
    let pager_frame = {
        let pager_guard = PAGER.lock();
        if let Some(pager) = *pager_guard {
            pager(fault_addr)
        } else {
            None
        }
    };

    if let Some(frame) = pager_frame {
        // Map the frame provided by the pager
        match map_page(
            fault_addr.align_down(PAGE_SIZE),
            frame,
            PageFlags::PRESENT | PageFlags::WRITABLE,
        ) {
            Ok(_) => return Ok(()),
            Err(_) => return Err(KernelError::OutOfMemory),
        }
    }

    // Fallback: Zero-fill a new frame
    let frame = allocate_frame().ok_or(KernelError::OutOfMemory)?;

    // Zero the frame
    let virt = frame_to_virt(frame);
    core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, PAGE_SIZE as usize);

    // Map into faulting address
    match map_page(
        fault_addr.align_down(PAGE_SIZE),
        frame,
        PageFlags::PRESENT | PageFlags::WRITABLE,
    ) {
        Ok(_) => Ok(()),
        Err(_) => Err(KernelError::OutOfMemory),
    }
}

// Serial helper functions (copied from main.rs for pager use)
const COM1_PORT: u16 = 0x3f8;

fn serial_print_str(s: &str) {
    for byte in s.bytes() {
        serial_write(byte);
    }
}

fn serial_print_hex(mut n: u64) {
    serial_print_str("0x");

    let mut buffer = [0u8; 16];
    let mut i = 0;

    if n == 0 {
        serial_write(b'0');
        return;
    }

    while n > 0 {
        let digit = (n & 0xf) as u8;
        buffer[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
        i += 1;
    }

    while i > 0 {
        serial_write(buffer[i - 1]);
        i -= 1;
    }
}

fn serial_print_number(mut n: u64) {
    if n == 0 {
        serial_write(b'0');
        return;
    }

    let mut buffer = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        buffer[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    while i > 0 {
        serial_write(buffer[i - 1]);
        i -= 1;
    }
}

fn serial_write(byte: u8) {
    unsafe {
        while (inb(COM1_PORT + 5) & 0x20) == 0 {}
        outb(COM1_PORT, byte);
    }
}

unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack));
    val
}

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}
