// SPDX-License-Identifier: GPL-2.0-only
//! PS/2 keyboard scancode table and state machine.

/// Scan Code Set 1 -> ASCII (unshifted, US QWERTY layout)
pub static SC1_NORMAL: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B; // Esc
    t[0x02] = b'1'; t[0x03] = b'2'; t[0x04] = b'3'; t[0x05] = b'4';
    t[0x06] = b'5'; t[0x07] = b'6'; t[0x08] = b'7'; t[0x09] = b'8';
    t[0x0A] = b'9'; t[0x0B] = b'0'; t[0x0C] = b'-'; t[0x0D] = b'=';
    t[0x0E] = 0x08; // Backspace
    t[0x0F] = b'\t';
    t[0x10] = b'q'; t[0x11] = b'w'; t[0x12] = b'e'; t[0x13] = b'r';
    t[0x14] = b't'; t[0x15] = b'y'; t[0x16] = b'u'; t[0x17] = b'i';
    t[0x18] = b'o'; t[0x19] = b'p'; t[0x1A] = b'['; t[0x1B] = b']';
    t[0x1C] = b'\n'; // Enter
    // 0x1D = Left Ctrl (modifier)
    t[0x1E] = b'a'; t[0x1F] = b's'; t[0x20] = b'd'; t[0x21] = b'f';
    t[0x22] = b'g'; t[0x23] = b'h'; t[0x24] = b'j'; t[0x25] = b'k';
    t[0x26] = b'l'; t[0x27] = b';'; t[0x28] = b'\'';
    t[0x29] = b'`';
    // 0x2A = Left Shift (modifier)
    t[0x2B] = b'\\';
    t[0x2C] = b'z'; t[0x2D] = b'x'; t[0x2E] = b'c'; t[0x2F] = b'v';
    t[0x30] = b'b'; t[0x31] = b'n'; t[0x32] = b'm'; t[0x33] = b',';
    t[0x34] = b'.'; t[0x35] = b'/';
    // 0x36 = Right Shift (modifier)
    t[0x37] = b'*'; // Keypad *
    // 0x38 = Left Alt (modifier)
    t[0x39] = b' '; // Space
    // 0x3A = Caps Lock (modifier)
    // F1-F12 = 0x3B-0x44, 0x57-0x58 (no ASCII)
    // Keypad
    t[0x47] = b'7'; t[0x48] = b'8'; t[0x49] = b'9'; t[0x4A] = b'-';
    t[0x4B] = b'4'; t[0x4C] = b'5'; t[0x4D] = b'6'; t[0x4E] = b'+';
    t[0x4F] = b'1'; t[0x50] = b'2'; t[0x51] = b'3';
    t[0x52] = b'0'; t[0x53] = b'.';
    t
};

/// Scan Code Set 1 -> ASCII (shifted, US QWERTY layout)
pub static SC1_SHIFTED: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B; // Esc
    t[0x02] = b'!'; t[0x03] = b'@'; t[0x04] = b'#'; t[0x05] = b'$';
    t[0x06] = b'%'; t[0x07] = b'^'; t[0x08] = b'&'; t[0x09] = b'*';
    t[0x0A] = b'('; t[0x0B] = b')'; t[0x0C] = b'_'; t[0x0D] = b'+';
    t[0x0E] = 0x08; // Backspace
    t[0x0F] = b'\t';
    t[0x10] = b'Q'; t[0x11] = b'W'; t[0x12] = b'E'; t[0x13] = b'R';
    t[0x14] = b'T'; t[0x15] = b'Y'; t[0x16] = b'U'; t[0x17] = b'I';
    t[0x18] = b'O'; t[0x19] = b'P'; t[0x1A] = b'{'; t[0x1B] = b'}';
    t[0x1C] = b'\n'; // Enter
    t[0x1E] = b'A'; t[0x1F] = b'S'; t[0x20] = b'D'; t[0x21] = b'F';
    t[0x22] = b'G'; t[0x23] = b'H'; t[0x24] = b'J'; t[0x25] = b'K';
    t[0x26] = b'L'; t[0x27] = b':'; t[0x28] = b'"';
    t[0x29] = b'~';
    t[0x2B] = b'|';
    t[0x2C] = b'Z'; t[0x2D] = b'X'; t[0x2E] = b'C'; t[0x2F] = b'V';
    t[0x30] = b'B'; t[0x31] = b'N'; t[0x32] = b'M'; t[0x33] = b'<';
    t[0x34] = b'>'; t[0x35] = b'?';
    t[0x37] = b'*';
    t[0x39] = b' ';
    t
};

pub struct KbdState {
    shift_left: bool,
    shift_right: bool,
    ctrl: bool,
    alt: bool,
    caps_lock: bool,
    extended: bool,
}

impl KbdState {
    pub const fn new() -> Self {
        KbdState {
            shift_left: false,
            shift_right: false,
            ctrl: false,
            alt: false,
            caps_lock: false,
            extended: false,
        }
    }

    /// Translate a PS/2 Scan Code Set 1 byte into an ASCII character.
    /// Returns 0 for modifier-only keys, non-printable, or key releases.
    pub fn translate(&mut self, scancode: u8) -> u8 {
        // Extended scancode prefix
        if scancode == 0xE0 {
            self.extended = true;
            return 0;
        }

        let is_release = (scancode & 0x80) != 0;
        let code = scancode & 0x7F;

        if self.extended {
            self.extended = false;
            match code {
                0x1D => { self.ctrl = !is_release; return 0; }  // Right Ctrl
                0x38 => { self.alt = !is_release; return 0; }   // Right Alt
                _ => return 0,
            }
        }

        // Modifier key handling
        match code {
            0x2A => { self.shift_left = !is_release; return 0; }
            0x36 => { self.shift_right = !is_release; return 0; }
            0x1D => { self.ctrl = !is_release; return 0; }
            0x38 => { self.alt = !is_release; return 0; }
            0x3A => {
                if !is_release { self.caps_lock = !self.caps_lock; }
                return 0;
            }
            _ => {}
        }

        // Only process key presses, not releases
        if is_release {
            return 0;
        }

        let shifted = self.shift_left || self.shift_right;
        let mut c = if shifted {
            SC1_SHIFTED[code as usize]
        } else {
            SC1_NORMAL[code as usize]
        };

        if c == 0 {
            return 0;
        }

        // Caps Lock: toggle case for letters only
        if self.caps_lock && c >= b'a' && c <= b'z' {
            c -= 32;
        } else if self.caps_lock && c >= b'A' && c <= b'Z' {
            c += 32;
        }

        // Ctrl modifier: convert to control character
        if self.ctrl {
            if c >= b'a' && c <= b'z' {
                return c - b'a' + 1;
            }
            if c >= b'A' && c <= b'Z' {
                return c - b'A' + 1;
            }
            match c {
                b'[' | b'{' => return 0x1B,
                b'\\' | b'|' => return 0x1C,
                b']' | b'}' => return 0x1D,
                b'^' | b'~' => return 0x1E,
                b'_' | b'/' => return 0x1F,
                _ => {}
            }
        }

        c
    }
}
