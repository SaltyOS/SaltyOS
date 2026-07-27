// SPDX-License-Identifier: GPL-2.0-only
//! Bounded DWARF CFI unwinding for panic tracebacks.

#[derive(Clone, Copy)]
pub(crate) struct Cursor {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct StackBounds {
    pub bottom: u64,
    pub top: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum StopReason {
    NoEhFrame,
    NoFde,
    EndOfStack,
    Unsupported,
    InvalidStack,
}

unsafe extern "C" {
    static __eh_frame_start: u8;
    static __eh_frame_end: u8;
}

const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SLEB128: u8 = 0x09;
const DW_EH_PE_SDATA2: u8 = 0x0a;
const DW_EH_PE_SDATA4: u8 = 0x0b;
const DW_EH_PE_SDATA8: u8 = 0x0c;
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_INDIRECT: u8 = 0x80;

const DW_CFA_NOP: u8 = 0x00;
const DW_CFA_SET_LOC: u8 = 0x01;
const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
const DW_CFA_UNDEFINED: u8 = 0x07;
const DW_CFA_SAME_VALUE: u8 = 0x08;
const DW_CFA_REGISTER: u8 = 0x09;
const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
const DW_CFA_RESTORE_STATE: u8 = 0x0b;
const DW_CFA_DEF_CFA: u8 = 0x0c;
const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
const DW_CFA_DEF_CFA_SF: u8 = 0x12;
const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
const DW_CFA_VAL_OFFSET: u8 = 0x14;
const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;

#[cfg(target_arch = "x86_64")]
const REG_FP: u64 = 6;
#[cfg(target_arch = "x86_64")]
const REG_SP: u64 = 7;
#[cfg(target_arch = "x86_64")]
const REG_RA: u64 = 16;

#[cfg(target_arch = "aarch64")]
const REG_FP: u64 = 29;
#[cfg(target_arch = "aarch64")]
const REG_RA: u64 = 30;
#[cfg(target_arch = "aarch64")]
const REG_SP: u64 = 31;

#[derive(Clone, Copy)]
struct Cie {
    start: usize,
    end: usize,
    instructions: usize,
    code_align: u64,
    data_align: i64,
    return_reg: u64,
    fde_encoding: u8,
    augmentation_z: bool,
}

#[derive(Clone, Copy)]
struct Fde {
    start_pc: u64,
    end_pc: u64,
    instructions: usize,
    end: usize,
    cie: Cie,
}

#[derive(Clone, Copy)]
enum RegisterRule {
    Unset,
    Undefined,
    SameValue,
    Offset(i64),
}

#[derive(Clone, Copy)]
struct Rules {
    cfa_reg: u64,
    cfa_offset: i64,
    ra_rule: RegisterRule,
    fp_rule: RegisterRule,
}

impl Rules {
    const fn new() -> Self {
        Self {
            cfa_reg: REG_SP,
            cfa_offset: 0,
            ra_rule: RegisterRule::Unset,
            fp_rule: RegisterRule::Unset,
        }
    }
}

pub(crate) fn unwind_next(cursor: Cursor, bounds: StackBounds) -> Result<Cursor, StopReason> {
    if eh_frame().is_empty() {
        return Err(StopReason::NoEhFrame);
    }
    let fde = find_fde(cursor.pc).ok_or(StopReason::NoFde)?;
    let rules = evaluate_rules(&fde, cursor.pc).ok_or(StopReason::Unsupported)?;
    apply_rules(cursor, rules, bounds)
}

fn eh_frame() -> &'static [u8] {
    let start = core::ptr::addr_of!(__eh_frame_start) as usize;
    let end = core::ptr::addr_of!(__eh_frame_end) as usize;
    if end <= start {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(start as *const u8, end - start) }
}

fn eh_base() -> usize {
    core::ptr::addr_of!(__eh_frame_start) as usize
}

fn find_fde(pc: u64) -> Option<Fde> {
    let data = eh_frame();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let entry_start = off;
        let len = read_u32(data, off)? as usize;
        off += 4;
        if len == 0 {
            break;
        }
        let entry_end = off.checked_add(len)?;
        if entry_end > data.len() {
            break;
        }
        let id_field = off;
        let id = read_u32(data, off)?;
        off += 4;
        if id != 0 {
            let cie_start_addr = (eh_base() + id_field).checked_sub(id as usize)?;
            let cie_start = cie_start_addr.checked_sub(eh_base())?;
            if let Some(cie) = parse_cie(cie_start) {
                let mut c = Reader::new(data, off, entry_end);
                let start_pc = c.read_encoded(cie.fde_encoding)?;
                let range_enc = cie.fde_encoding & 0x0f;
                let range = c.read_encoded(range_enc)?;
                if cie.augmentation_z {
                    let aug_len = c.uleb()? as usize;
                    c.skip(aug_len)?;
                }
                let end_pc = start_pc.saturating_add(range);
                if pc >= start_pc && pc < end_pc {
                    return Some(Fde {
                        start_pc,
                        end_pc,
                        instructions: c.off,
                        end: entry_end,
                        cie,
                    });
                }
            }
        }
        off = entry_end;
        if off <= entry_start {
            break;
        }
    }
    None
}

fn parse_cie(start: usize) -> Option<Cie> {
    let data = eh_frame();
    if start + 8 > data.len() {
        return None;
    }
    let len = read_u32(data, start)? as usize;
    let id = read_u32(data, start + 4)?;
    if id != 0 {
        return None;
    }
    let end = start.checked_add(4)?.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let mut c = Reader::new(data, start + 8, end);
    let _version = c.u8()?;
    let aug_start = c.off;
    while c.u8()? != 0 {}
    let aug_end = c.off - 1;
    let code_align = c.uleb()?;
    let data_align = c.sleb()?;
    let return_reg = c.uleb()?;
    let mut fde_encoding = DW_EH_PE_ABSPTR;
    let augmentation_z = data.get(aug_start) == Some(&b'z');
    if augmentation_z {
        let aug_len = c.uleb()? as usize;
        let aug_data_end = c.off.checked_add(aug_len)?;
        let mut p = aug_start + 1;
        while p < aug_end {
            match data[p] {
                b'R' => {
                    fde_encoding = *data.get(c.off)?;
                    c.off += 1;
                }
                b'L' => {
                    c.off += 1;
                }
                b'P' => {
                    let enc = *data.get(c.off)?;
                    c.off += 1;
                    let _ = c.read_encoded(enc)?;
                }
                _ => {}
            }
            p += 1;
        }
        c.off = aug_data_end;
    }
    Some(Cie {
        start,
        end,
        instructions: c.off,
        code_align,
        data_align,
        return_reg,
        fde_encoding,
        augmentation_z,
    })
}

fn evaluate_rules(fde: &Fde, target_pc: u64) -> Option<Rules> {
    let mut cie_rules = Rules::new();
    eval_instructions(
        fde.cie.instructions,
        fde.cie.end,
        0,
        None,
        &fde.cie,
        Rules::new(),
        &mut cie_rules,
    )?;
    let mut rules = cie_rules;
    eval_instructions(
        fde.instructions,
        fde.end,
        fde.start_pc,
        Some(target_pc),
        &fde.cie,
        cie_rules,
        &mut rules,
    )
}

fn eval_instructions(
    start: usize,
    end: usize,
    initial_loc: u64,
    target_pc: Option<u64>,
    cie: &Cie,
    initial_rules: Rules,
    rules: &mut Rules,
) -> Option<Rules> {
    let data = eh_frame();
    let mut c = Reader::new(data, start, end);
    let mut loc = initial_loc;
    let mut saved = [Rules::new(); 8];
    let mut saved_count = 0usize;
    while c.off < end {
        let op = c.u8()?;
        let high = op & 0xc0;
        if high == 0x40 {
            let next = loc.saturating_add(((op & 0x3f) as u64).saturating_mul(cie.code_align));
            if target_pc.is_some_and(|target| next > target) {
                return Some(*rules);
            }
            loc = next;
            let _ = loc;
            continue;
        }
        if high == 0x80 {
            let reg = (op & 0x3f) as u64;
            let off = (c.uleb()? as i64).saturating_mul(cie.data_align);
            set_offset_rule(rules, cie.return_reg, reg, off);
            continue;
        }
        if high == 0xc0 {
            let reg = (op & 0x3f) as u64;
            restore_register_rule(rules, initial_rules, cie.return_reg, reg);
            continue;
        }
        match op {
            DW_CFA_NOP => {}
            DW_CFA_SET_LOC => {
                loc = c.read_encoded(cie.fde_encoding)?;
                let _ = loc;
            }
            DW_CFA_ADVANCE_LOC1 => {
                let next = loc.saturating_add((c.u8()? as u64).saturating_mul(cie.code_align));
                if target_pc.is_some_and(|target| next > target) {
                    return Some(*rules);
                }
                loc = next;
                let _ = loc;
            }
            DW_CFA_ADVANCE_LOC2 => {
                let next = loc.saturating_add((c.u16()? as u64).saturating_mul(cie.code_align));
                if target_pc.is_some_and(|target| next > target) {
                    return Some(*rules);
                }
                loc = next;
                let _ = loc;
            }
            DW_CFA_ADVANCE_LOC4 => {
                let next = loc.saturating_add((c.u32()? as u64).saturating_mul(cie.code_align));
                if target_pc.is_some_and(|target| next > target) {
                    return Some(*rules);
                }
                loc = next;
                let _ = loc;
            }
            DW_CFA_OFFSET_EXTENDED => {
                let reg = c.uleb()?;
                let off = (c.uleb()? as i64).saturating_mul(cie.data_align);
                set_offset_rule(rules, cie.return_reg, reg, off);
            }
            DW_CFA_OFFSET_EXTENDED_SF => {
                let reg = c.uleb()?;
                let off = c.sleb()?.saturating_mul(cie.data_align);
                set_offset_rule(rules, cie.return_reg, reg, off);
            }
            DW_CFA_DEF_CFA => {
                rules.cfa_reg = c.uleb()?;
                rules.cfa_offset = c.uleb()? as i64;
            }
            DW_CFA_DEF_CFA_REGISTER => {
                rules.cfa_reg = c.uleb()?;
            }
            DW_CFA_DEF_CFA_OFFSET => {
                rules.cfa_offset = c.uleb()? as i64;
            }
            DW_CFA_DEF_CFA_SF => {
                rules.cfa_reg = c.uleb()?;
                rules.cfa_offset = c.sleb()?.saturating_mul(cie.data_align);
            }
            DW_CFA_DEF_CFA_OFFSET_SF => {
                rules.cfa_offset = c.sleb()?.saturating_mul(cie.data_align);
            }
            DW_CFA_RESTORE_EXTENDED => {
                let reg = c.uleb()?;
                restore_register_rule(rules, initial_rules, cie.return_reg, reg);
            }
            DW_CFA_UNDEFINED => {
                let reg = c.uleb()?;
                set_register_rule(rules, cie.return_reg, reg, RegisterRule::Undefined);
            }
            DW_CFA_SAME_VALUE => {
                let reg = c.uleb()?;
                set_register_rule(rules, cie.return_reg, reg, RegisterRule::SameValue);
            }
            DW_CFA_REGISTER => {
                let reg = c.uleb()?;
                let _ = c.uleb()?;
                if is_tracked_register(cie.return_reg, reg) {
                    return None;
                }
            }
            DW_CFA_VAL_OFFSET | DW_CFA_VAL_OFFSET_SF => {
                let reg = c.uleb()?;
                let _ = if op == DW_CFA_VAL_OFFSET {
                    c.uleb()? as i64
                } else {
                    c.sleb()?
                };
                if is_tracked_register(cie.return_reg, reg) {
                    return None;
                }
            }
            DW_CFA_REMEMBER_STATE => {
                if saved_count >= saved.len() {
                    return None;
                }
                saved[saved_count] = *rules;
                saved_count += 1;
            }
            DW_CFA_RESTORE_STATE => {
                if saved_count == 0 {
                    return None;
                }
                saved_count -= 1;
                *rules = saved[saved_count];
            }
            _ => return None,
        }
    }
    Some(*rules)
}

fn set_offset_rule(rules: &mut Rules, return_reg: u64, reg: u64, off: i64) {
    if reg == return_reg || reg == REG_RA {
        rules.ra_rule = RegisterRule::Offset(off);
    } else if reg == REG_FP {
        rules.fp_rule = RegisterRule::Offset(off);
    }
}

fn set_register_rule(rules: &mut Rules, return_reg: u64, reg: u64, rule: RegisterRule) {
    if reg == return_reg || reg == REG_RA {
        rules.ra_rule = rule;
    } else if reg == REG_FP {
        rules.fp_rule = rule;
    }
}

fn restore_register_rule(rules: &mut Rules, initial_rules: Rules, return_reg: u64, reg: u64) {
    if reg == return_reg || reg == REG_RA {
        rules.ra_rule = initial_rules.ra_rule;
    } else if reg == REG_FP {
        rules.fp_rule = initial_rules.fp_rule;
    }
}

fn is_tracked_register(return_reg: u64, reg: u64) -> bool {
    reg == return_reg || reg == REG_RA || reg == REG_FP
}

fn apply_rules(cursor: Cursor, rules: Rules, bounds: StackBounds) -> Result<Cursor, StopReason> {
    let base = match rules.cfa_reg {
        REG_SP => cursor.sp,
        REG_FP => cursor.fp,
        _ => return Err(StopReason::Unsupported),
    };
    let cfa = add_i64(base, rules.cfa_offset).ok_or(StopReason::InvalidStack)?;
    if !in_stack(cfa, bounds) {
        return Err(StopReason::InvalidStack);
    }
    let ra_off = match rules.ra_rule {
        RegisterRule::Offset(off) => off,
        RegisterRule::Undefined => return Err(StopReason::EndOfStack),
        RegisterRule::Unset | RegisterRule::SameValue => return Err(StopReason::Unsupported),
    };
    let ra_addr = add_i64(cfa, ra_off).ok_or(StopReason::InvalidStack)?;
    let ra = read_stack_u64(ra_addr, bounds).ok_or(StopReason::InvalidStack)?;
    if ra == 0 {
        return Err(StopReason::InvalidStack);
    }
    let next_fp = match rules.fp_rule {
        RegisterRule::Offset(fp_off) => {
            let fp_addr = add_i64(cfa, fp_off).ok_or(StopReason::InvalidStack)?;
            read_stack_u64(fp_addr, bounds).unwrap_or(cursor.fp)
        }
        RegisterRule::Undefined => 0,
        RegisterRule::Unset | RegisterRule::SameValue => cursor.fp,
    };
    Ok(Cursor {
        pc: ra.saturating_sub(1),
        sp: cfa,
        fp: next_fp,
    })
}

pub(crate) fn read_stack_u64(addr: u64, bounds: StackBounds) -> Option<u64> {
    if addr < bounds.bottom || addr.checked_add(8)? > bounds.top || addr & 7 != 0 {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(addr as *const u64) })
}

fn in_stack(addr: u64, bounds: StackBounds) -> bool {
    addr >= bounds.bottom && addr <= bounds.top
}

fn add_i64(base: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        base.checked_add(offset as u64)
    } else {
        base.checked_sub(offset.unsigned_abs())
    }
}

struct Reader<'a> {
    data: &'a [u8],
    off: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], off: usize, end: usize) -> Self {
        Self { data, off, end }
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.off = self.off.checked_add(n)?;
        (self.off <= self.end).then_some(())
    }

    fn u8(&mut self) -> Option<u8> {
        if self.off >= self.end {
            return None;
        }
        let v = self.data[self.off];
        self.off += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let lo = self.u8()? as u16;
        let hi = self.u8()? as u16;
        Some(lo | (hi << 8))
    }

    fn u32(&mut self) -> Option<u32> {
        read_u32(self.data, {
            let off = self.off;
            self.off = self.off.checked_add(4)?;
            off
        })
    }

    fn u64(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let mut i = 0usize;
        while i < 8 {
            v |= (self.u8()? as u64) << (i * 8);
            i += 1;
        }
        Some(v)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        let mut byte;
        loop {
            byte = self.u8()?;
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return None;
            }
        }
        if shift < 64 && byte & 0x40 != 0 {
            result |= (!0i64) << shift;
        }
        Some(result)
    }

    fn read_encoded(&mut self, enc: u8) -> Option<u64> {
        if enc == DW_EH_PE_OMIT {
            return None;
        }
        let place = eh_base().checked_add(self.off)? as u64;
        let format = enc & 0x0f;
        let mut value = match format {
            DW_EH_PE_ABSPTR => self.u64()?,
            DW_EH_PE_ULEB128 => self.uleb()?,
            DW_EH_PE_UDATA2 => self.u16()? as u64,
            DW_EH_PE_UDATA4 => self.u32()? as u64,
            DW_EH_PE_UDATA8 => self.u64()?,
            DW_EH_PE_SLEB128 => self.sleb()? as u64,
            DW_EH_PE_SDATA2 => self.u16()? as i16 as i64 as u64,
            DW_EH_PE_SDATA4 => self.u32()? as i32 as i64 as u64,
            DW_EH_PE_SDATA8 => self.u64()? as i64 as u64,
            _ => return None,
        };
        if enc & DW_EH_PE_PCREL != 0 {
            value = place.wrapping_add(value);
        }
        if enc & DW_EH_PE_INDIRECT != 0 {
            value = unsafe { core::ptr::read_unaligned(value as *const u64) };
        }
        Some(value)
    }
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off.checked_add(4)? > data.len() {
        return None;
    }
    Some(
        data[off] as u32
            | ((data[off + 1] as u32) << 8)
            | ((data[off + 2] as u32) << 16)
            | ((data[off + 3] as u32) << 24),
    )
}
