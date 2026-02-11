; SPDX-License-Identifier: GPL-2.0-only
;
; SaltyOS Bootloader - Stage 2 Entry (BIOS)
;
; This is the entry point for Stage 2, loaded at 0x8000 by Stage 1.
;
; Responsibilities:
;   1. Enable A20 line
;   2. Collect memory map (E820)
;   3. Load Stage 3 from disk
;   4. Enter protected mode (32-bit)
;   5. Initialize BTX trampoline
;   6. Jump to Stage 3 in protected mode
;
; Stage 3 then uses BTX to load manifest/kernel and eventually
; transitions to long mode before jumping to the kernel.
;

[BITS 16]
; ORG is handled by linker script - Stage 2 loads at 0x8000

; ============================================================================
; Constants
; ============================================================================

STAGE3_LOAD_ADDR    equ 0x40000         ; Stage 3 load address
MEMMAP_BUFFER       equ 0x30000         ; E820 memory map buffer
STAGE2_INFO_ADDR    equ 0x1000          ; Stage2Info structure (below V86 stack at 0x7000)

; Stack addresses
REAL_MODE_STACK     equ 0x7FF0
PROT_MODE_STACK     equ 0x9FFF0

; Disk layout
BRA_START_LBA       equ 2048            ; Boot Reserved Area start
MANIFEST_SECTORS    equ 64              ; 32 KB
STAGE2_SECTORS      equ 128             ; 64 KB
STAGE3_LBA          equ BRA_START_LBA + MANIFEST_SECTORS + STAGE2_SECTORS
STAGE3_SECTORS      equ 512             ; 256 KB
SECTORS_PER_READ    equ 128             ; Max sectors per INT 13h read (64 KB)

; ============================================================================
; 16-bit Entry Point
; ============================================================================

section .text.entry
global _start
_start:
    ; Set up segments and stack
    cli
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax
    mov     sp, REAL_MODE_STACK
    sti

    ; Save boot drive
    mov     [boot_drive], dl

    ; Print banner
    mov     si, msg_stage2
    call    print16

    ; Enable A20 line
    call    enable_a20
    test    ax, ax
    jz      .a20_failed

    mov     si, msg_a20_ok
    call    print16

    ; Get memory map via E820
    call    get_memory_map
    test    ax, ax
    jz      .e820_failed

    mov     si, msg_e820_ok
    call    print16

    ; Load Stage 3 from disk
    call    load_stage3
    test    ax, ax
    jz      .stage3_failed

    mov     si, msg_stage3_ok
    call    print16

    ; Build Stage2Info structure
    call    build_stage2_info

    ; Set up VBE framebuffer (optional — silent fallback if VBE fails)
    call    setup_vbe

    ; Now transition to protected mode (32-bit)
    mov     si, msg_prot_mode
    call    print16

    ; Disable interrupts for mode switch
    cli

    ; Load GDT
    lgdt    [gdt_ptr]

    ; Enter protected mode
    mov     eax, cr0
    or      eax, 1              ; Set PE bit
    mov     cr0, eax

    ; Far jump to 32-bit code
    jmp     0x08:protected_mode

.a20_failed:
    mov     si, msg_a20_fail
    call    print16
    jmp     halt16

.e820_failed:
    mov     si, msg_e820_fail
    call    print16
    jmp     halt16

.stage3_failed:
    mov     si, msg_stage3_fail
    call    print16
    jmp     halt16

; ============================================================================
; A20 Enable
; ============================================================================
; Returns: AX=1 on success, AX=0 on failure

enable_a20:
    ; First check if A20 is already enabled
    call    check_a20
    test    ax, ax
    jnz     .done

    ; Try BIOS method (INT 15h, AX=2401h)
    mov     ax, 0x2401
    int     0x15
    jc      .try_keyboard

    call    check_a20
    test    ax, ax
    jnz     .done

.try_keyboard:
    ; Try keyboard controller method
    call    a20_keyboard
    call    check_a20
    test    ax, ax
    jnz     .done

    ; Try Fast A20 (Port 0x92)
    in      al, 0x92
    or      al, 2
    and     al, 0xFE            ; Don't reset!
    out     0x92, al

    call    check_a20

.done:
    ret

; Check if A20 is enabled by comparing memory at 0x0000:0x0500 and 0xFFFF:0x0510
check_a20:
    push    ds
    push    es
    push    di
    push    si

    xor     ax, ax
    mov     ds, ax
    mov     si, 0x0500

    mov     ax, 0xFFFF
    mov     es, ax
    mov     di, 0x0510

    ; Save original values
    mov     al, [ds:si]
    push    ax
    mov     al, [es:di]
    push    ax

    ; Write different values
    mov     byte [ds:si], 0x00
    mov     byte [es:di], 0xFF

    ; Check if they wrap
    cmp     byte [ds:si], 0xFF

    ; Restore original values
    pop     ax
    mov     [es:di], al
    pop     ax
    mov     [ds:si], al

    ; Set return value
    mov     ax, 0
    je      .disabled
    mov     ax, 1

.disabled:
    pop     si
    pop     di
    pop     es
    pop     ds
    ret

; Enable A20 via keyboard controller
a20_keyboard:
    call    .wait_input
    mov     al, 0xAD            ; Disable keyboard
    out     0x64, al

    call    .wait_input
    mov     al, 0xD0            ; Read output port
    out     0x64, al

    call    .wait_output
    in      al, 0x60
    push    ax

    call    .wait_input
    mov     al, 0xD1            ; Write output port
    out     0x64, al

    call    .wait_input
    pop     ax
    or      al, 2               ; Set A20 bit
    out     0x60, al

    call    .wait_input
    mov     al, 0xAE            ; Enable keyboard
    out     0x64, al

    call    .wait_input
    ret

.wait_input:
    in      al, 0x64
    test    al, 2
    jnz     .wait_input
    ret

.wait_output:
    in      al, 0x64
    test    al, 1
    jz      .wait_output
    ret

; ============================================================================
; E820 Memory Map
; ============================================================================
; Returns: AX=entry count on success, AX=0 on failure

get_memory_map:
    push    es
    push    di
    push    ebx
    push    ecx
    push    edx

    ; Use segment:offset addressing for MEMMAP_BUFFER (0x30000)
    ; ES = 0x3000, so ES:DI = 0x3000:offset -> linear 0x30000+offset
    mov     ax, 0x3000
    mov     es, ax
    mov     di, 4                   ; ES:DI = 0x3000:0x0004 -> linear 0x30004
    xor     ebx, ebx                ; Continuation value
    xor     bp, bp                  ; Entry counter

.loop:
    mov     eax, 0xE820
    mov     ecx, 24                 ; Entry size
    mov     edx, 0x534D4150         ; "SMAP"
    int     0x15

    jc      .done                   ; Carry set = end or error
    cmp     eax, 0x534D4150
    jne     .error

    ; Valid entry
    inc     bp
    add     di, 24

    ; Check if we have space for more entries
    cmp     bp, 64
    jge     .done

    ; Check continuation
    test    ebx, ebx
    jnz     .loop

.done:
    ; Store entry count at start of buffer (linear 0x30000)
    ; ES is still 0x3000 from above
    mov     word [es:0], bp
    mov     word [es:2], 0

    ; Restore ES to 0 for remaining code
    xor     ax, ax
    mov     es, ax

    mov     ax, bp
    jmp     .exit

.error:
    ; Restore ES to 0
    xor     ax, ax
    mov     es, ax
    ; ax is already 0

.exit:
    pop     edx
    pop     ecx
    pop     ebx
    pop     di
    pop     es
    ret

; ============================================================================
; Load Stage 3
; ============================================================================
; Returns: AX=1 on success, AX=0 on failure

load_stage3:
    push    es
    push    bx
    push    cx

    mov     cx, STAGE3_SECTORS / SECTORS_PER_READ  ; 4 iterations

    ; Set constant DAP fields once
    mov     word [dap + 0], 16
    mov     word [dap + 2], SECTORS_PER_READ
    mov     dword [dap + 12], 0

    ; Set initial variable DAP fields
    mov     word [dap + 4], STAGE3_LOAD_ADDR & 0xF   ; offset = 0
    mov     word [dap + 6], STAGE3_LOAD_ADDR >> 4     ; segment = 0x4000
    mov     dword [dap + 8], STAGE3_LBA               ; LBA = 2240

.read_loop:
    mov     ah, 0x42
    mov     dl, [boot_drive]
    mov     si, dap
    int     0x13
    jc      .error

    ; Advance segment by 0x1000 (= +64 KB linear) and LBA by 128
    add     word [dap + 6], 0x1000
    add     dword [dap + 8], SECTORS_PER_READ

    dec     cx
    jnz     .read_loop

    mov     ax, 1
    jmp     .done

.error:
    xor     ax, ax

.done:
    pop     cx
    pop     bx
    pop     es
    ret

; ============================================================================
; VBE Framebuffer Setup
; ============================================================================
; Sets up a linear framebuffer via VESA BIOS Extensions (VBE 2.0+).
; Writes framebuffer info to Stage2Info at STAGE2_INFO_ADDR.
; If VBE fails at any step, returns silently (serial-only boot).

VBE_CTRL_INFO   equ 0x2000          ; VBE controller info buffer (512 bytes)
VBE_MODE_INFO   equ 0x2200          ; VBE mode info buffer (256 bytes)

setup_vbe:
    push    es
    push    fs
    push    di
    push    si
    push    bx
    push    cx
    push    dx

    ; --- Step 1: Get VBE controller info ---
    xor     ax, ax
    mov     es, ax
    mov     di, VBE_CTRL_INFO

    ; Write "VBE2" signature to request VBE 2.0+ info
    mov     dword [es:di], 0x32454256       ; "VBE2" in little-endian
    mov     ax, 0x4F00
    int     0x10
    cmp     ax, 0x004F
    jne     .vbe_fail

    ; --- Step 2: Get mode list pointer (far pointer at offset 0x0E) ---
    mov     si, [es:VBE_CTRL_INFO + 0x0E]  ; offset
    mov     ax, [es:VBE_CTRL_INFO + 0x10]  ; segment
    mov     fs, ax                          ; FS:SI = mode list

    ; --- Step 3: Enumerate modes ---
    mov     word [vbe_best_mode], 0xFFFF

.vbe_mode_loop:
    mov     cx, [fs:si]                     ; Read mode number
    cmp     cx, 0xFFFF                      ; End of list?
    je      .vbe_mode_done
    add     si, 2                           ; Advance to next mode

    ; Get mode info for this mode
    push    si
    push    cx
    xor     ax, ax
    mov     es, ax
    mov     ax, 0x4F01
    mov     di, VBE_MODE_INFO
    int     0x10
    pop     cx
    pop     si

    cmp     ax, 0x004F
    jne     .vbe_mode_loop                  ; Skip if query failed

    ; Check ModeAttributes: bit 0 (supported) and bit 7 (LFB available)
    xor     ax, ax
    mov     es, ax
    mov     ax, [es:VBE_MODE_INFO]
    test    ax, 0x0081
    jz      .vbe_mode_loop

    ; Check BitsPerPixel == 32
    cmp     byte [es:VBE_MODE_INFO + 0x19], 32
    jne     .vbe_mode_loop

    ; Check MemoryModel == 6 (Direct Color)
    cmp     byte [es:VBE_MODE_INFO + 0x1B], 6
    jne     .vbe_mode_loop

    ; Check XResolution >= 1024
    cmp     word [es:VBE_MODE_INFO + 0x12], 1024
    jb      .vbe_mode_loop

    ; Check YResolution >= 768
    cmp     word [es:VBE_MODE_INFO + 0x14], 768
    jb      .vbe_mode_loop

    ; This mode qualifies — check if it's exactly 1024x768
    cmp     word [es:VBE_MODE_INFO + 0x12], 1024
    jne     .vbe_not_exact
    cmp     word [es:VBE_MODE_INFO + 0x14], 768
    jne     .vbe_not_exact

    ; Exact 1024x768 match — use this mode
    mov     [vbe_best_mode], cx
    jmp     .vbe_mode_done

.vbe_not_exact:
    ; Accept as fallback if no match yet
    cmp     word [vbe_best_mode], 0xFFFF
    jne     .vbe_mode_loop
    mov     [vbe_best_mode], cx
    jmp     .vbe_mode_loop

.vbe_mode_done:
    cmp     word [vbe_best_mode], 0xFFFF
    je      .vbe_fail                       ; No suitable mode found

    ; --- Step 4: Re-query mode info for the chosen mode ---
    mov     cx, [vbe_best_mode]
    xor     ax, ax
    mov     es, ax
    mov     ax, 0x4F01
    mov     di, VBE_MODE_INFO
    int     0x10
    cmp     ax, 0x004F
    jne     .vbe_fail

    ; --- Step 5: Set the VBE mode (bit 14 = use LFB) ---
    mov     bx, [vbe_best_mode]
    or      bx, 0x4000
    mov     ax, 0x4F02
    int     0x10
    cmp     ax, 0x004F
    jne     .vbe_fail

    ; --- Step 6: Write framebuffer info to Stage2Info ---
    xor     ax, ax
    mov     es, ax
    mov     di, STAGE2_INFO_ADDR

    ; framebuffer_addr (offset 72, uint64) = PhysBasePtr (mode info offset 0x28)
    mov     eax, [es:VBE_MODE_INFO + 0x28]
    mov     [es:di + 72], eax
    mov     dword [es:di + 76], 0

    ; framebuffer_width (offset 80, uint32) = XResolution (mode info offset 0x12)
    movzx   eax, word [es:VBE_MODE_INFO + 0x12]
    mov     [es:di + 80], eax

    ; framebuffer_height (offset 84, uint32) = YResolution (mode info offset 0x14)
    movzx   eax, word [es:VBE_MODE_INFO + 0x14]
    mov     [es:di + 84], eax

    ; framebuffer_pitch (offset 88, uint32) = BytesPerScanLine (mode info offset 0x10)
    movzx   eax, word [es:VBE_MODE_INFO + 0x10]
    mov     [es:di + 88], eax

    ; framebuffer_bpp (offset 92, uint32) = BitsPerPixel (mode info offset 0x19)
    movzx   eax, byte [es:VBE_MODE_INFO + 0x19]
    mov     [es:di + 92], eax

    ; Pixel format fields (VBE mode info):
    ; 0x1F RedMaskSize, 0x20 RedFieldPosition,
    ; 0x21 GreenMaskSize, 0x22 GreenFieldPosition,
    ; 0x23 BlueMaskSize, 0x24 BlueFieldPosition.
    mov     al, [es:VBE_MODE_INFO + 0x20]  ; RedFieldPosition
    mov     [es:di + 136], al
    mov     al, [es:VBE_MODE_INFO + 0x1F]  ; RedMaskSize
    mov     [es:di + 137], al
    mov     al, [es:VBE_MODE_INFO + 0x22]  ; GreenFieldPosition
    mov     [es:di + 138], al
    mov     al, [es:VBE_MODE_INFO + 0x21]  ; GreenMaskSize
    mov     [es:di + 139], al
    mov     al, [es:VBE_MODE_INFO + 0x24]  ; BlueFieldPosition
    mov     [es:di + 140], al
    mov     al, [es:VBE_MODE_INFO + 0x23]  ; BlueMaskSize
    mov     [es:di + 141], al

    ; Set STAGE2_FLAG_HAS_FRAMEBUFFER in flags (offset 12)
    or      dword [es:di + 12], 0x08

    mov     si, msg_vbe_ok
    call    print16
    jmp     .vbe_done

.vbe_fail:
    mov     si, msg_vbe_fail
    call    print16

.vbe_done:
    pop     dx
    pop     cx
    pop     bx
    pop     si
    pop     di
    pop     fs
    pop     es
    ret

; ============================================================================
; Build Stage2Info Structure
; ============================================================================

build_stage2_info:
    push    es
    push    di

    xor     ax, ax
    mov     es, ax
    mov     di, STAGE2_INFO_ADDR

    ; Clear the structure
    mov     cx, 256 / 2
    xor     ax, ax
    rep     stosw

    mov     di, STAGE2_INFO_ADDR

    ; Magic: "STAG"
    mov     dword [es:di], 0x53544147
    ; Version
    mov     word [es:di + 4], 1
    ; Arch: ARCH_X86 (4) - 32-bit protected mode
    mov     word [es:di + 6], 4
    ; Boot mode: BIOS
    mov     dword [es:di + 8], 1
    ; Flags: A20 enabled (Stage 3 will set more after mode switch)
    mov     dword [es:di + 12], 0x01    ; STAGE2_FLAG_A20_ENABLED

    ; Boot drive
    mov     al, [boot_drive]
    mov     [es:di + 16], al

    ; Manifest LBA
    mov     dword [es:di + 24], BRA_START_LBA
    mov     dword [es:di + 28], 0

    ; Memory map (MEMMAP_BUFFER = 0x30000, use segment addressing)
    mov     dword [es:di + 32], MEMMAP_BUFFER + 4
    mov     dword [es:di + 36], 0
    push    es
    push    di
    mov     ax, 0x3000
    mov     es, ax
    movzx   eax, word [es:0]        ; Entry count at linear 0x30000
    pop     di
    pop     es
    mov     ecx, eax                ; Save count before zeroing AX
    xor     ax, ax
    mov     es, ax                  ; Restore ES=0
    mov     di, STAGE2_INFO_ADDR    ; Restore DI
    mov     [es:di + 40], ecx       ; Use saved count (xor ax,ax zeroed EAX low bits)
    mov     word [es:di + 44], 24       ; Entry size
    mov     byte [es:di + 46], 1        ; E820 format

    ; PML4 address: 0 (not set up yet - Stage 3 will do this)
    mov     dword [es:di + 96], 0
    mov     dword [es:di + 100], 0

    ; Stage 3 info
    mov     dword [es:di + 104], STAGE3_LOAD_ADDR
    mov     dword [es:di + 108], 0
    mov     dword [es:di + 112], STAGE3_SECTORS * 512
    mov     dword [es:di + 116], 0

    ; Kernel preload: 0 (Stage 3 will load via BTX)
    mov     dword [es:di + 120], 0
    mov     dword [es:di + 124], 0
    mov     dword [es:di + 128], 0
    mov     dword [es:di + 132], 0

    pop     di
    pop     es
    ret

; ============================================================================
; 16-bit Print
; ============================================================================

print16:
    push    ax
    push    bx
.loop:
    lodsb
    test    al, al
    jz      .done
    mov     ah, 0x0E
    mov     bx, 0x0007
    int     0x10
    jmp     .loop
.done:
    pop     bx
    pop     ax
    ret

halt16:
    cli
    hlt
    jmp     halt16

; ============================================================================
; 32-bit Protected Mode
; ============================================================================

[BITS 32]
section .text

protected_mode:
    ; Set up segment registers
    mov     ax, 0x10            ; Data segment
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax
    mov     esp, PROT_MODE_STACK

    ; Pass Stage2Info address in EDI (SysV ABI first argument for 32-bit is stack,
    ; but we'll pass in EDI for simplicity - Stage 3 entry expects this)
    mov     edi, STAGE2_INFO_ADDR

    ; Jump to Stage 3 (32-bit entry point)
    mov     eax, STAGE3_LOAD_ADDR
    jmp     eax

halt32:
    cli
    hlt
    jmp     halt32

; ============================================================================
; Data
; ============================================================================

section .data

boot_drive:     db 0

msg_stage2:     db 'Stage 2 BIOS', 13, 10, 0
msg_a20_ok:     db '  A20: OK', 13, 10, 0
msg_a20_fail:   db '  A20: FAIL', 13, 10, 0
msg_e820_ok:    db '  E820: OK', 13, 10, 0
msg_e820_fail:  db '  E820: FAIL', 13, 10, 0
msg_stage3_ok:  db '  Stage 3: OK', 13, 10, 0
msg_stage3_fail: db '  Stage 3: FAIL', 13, 10, 0
msg_vbe_ok:     db '  VBE: OK', 13, 10, 0
msg_vbe_fail:   db '  VBE: N/A', 13, 10, 0
msg_prot_mode:  db '  -> Protected Mode', 13, 10, 0

vbe_best_mode:  dw 0xFFFF

; Disk Address Packet
align 4
dap:
    dw 16               ; Size
    dw 0                ; Sector count
    dd 0                ; Buffer address (segment:offset)
    dq 0                ; LBA

; GDT for 32-bit protected mode
align 16
gdt_start:
    ; Null descriptor (0x00)
    dq 0

    ; 32-bit code segment (0x08)
    dw 0xFFFF           ; Limit low
    dw 0x0000           ; Base low
    db 0x00             ; Base middle
    db 0x9A             ; Access: Present, Ring 0, Code, Executable, Readable
    db 0xCF             ; Granularity: 4KB, 32-bit
    db 0x00             ; Base high

    ; 32-bit data segment (0x10)
    dw 0xFFFF           ; Limit low
    dw 0x0000           ; Base low
    db 0x00             ; Base middle
    db 0x92             ; Access: Present, Ring 0, Data, Writable
    db 0xCF             ; Granularity: 4KB, 32-bit
    db 0x00             ; Base high
gdt_end:

gdt_ptr:
    dw gdt_end - gdt_start - 1  ; Limit
    dd gdt_start                ; Base
