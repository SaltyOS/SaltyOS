//! Task State Segment (TSS) for x86_64

#![no_std]

#[repr(C, packed)]
pub struct Tss {
    _reserved0: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    _reserved1: u64,
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    pub iomap_base: u16,
}

impl Tss {
    pub const fn new() -> Self {
        Self {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: 0,
        }
    }
}

const STACK_SIZE: usize = 4096 * 4;

static mut RSP0_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
static mut IST1_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

pub unsafe fn init_tss(tss: &mut Tss) {
    let rsp0 = (&raw const RSP0_STACK as *const u8) as u64 + STACK_SIZE as u64;
    let ist1 = (&raw const IST1_STACK as *const u8) as u64 + STACK_SIZE as u64;
    tss.rsp0 = rsp0;
    tss.ist[0] = ist1;
    tss.iomap_base = core::mem::size_of::<Tss>() as u16;
}
