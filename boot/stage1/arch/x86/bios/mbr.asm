; SPDX-License-Identifier: GPL-2.0-only
;
; SaltyOS Bootloader - Stage 1 (MBR)
;
; This is the Master Boot Record, loaded by BIOS at 0x7C00.
; Responsibilities:
;   1. Set up minimal real-mode environment
;   2. Load Stage 2 from fixed LBA using INT 13h extended read
;   3. Jump to Stage 2 at 0x8000
;
; Size constraint: Must fit in 446 bytes (MBR boot code area)
;

[BITS 16]
[ORG 0x7C00]

; ============================================================================
; Constants
; ============================================================================

STAGE2_LOAD_SEG     equ 0x0000
STAGE2_LOAD_OFF     equ 0x8000
STAGE2_LBA_LOW      equ 2112        ; BRA_START_LBA(2048) + MANIFEST_SECTORS(64)
STAGE2_LBA_HIGH     equ 0
STAGE2_SECTORS      equ 128         ; 64 KB = 128 sectors

STACK_TOP           equ 0x7C00      ; Stack grows down from MBR

; ============================================================================
; Entry Point
; ============================================================================

start:
    ; Disable interrupts during setup
    cli

    ; Set up segments
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     sp, STACK_TOP

    ; Re-enable interrupts
    sti

    ; Save boot drive number (passed by BIOS in DL)
    mov     [boot_drive], dl

    ; Print welcome message
    mov     si, msg_loading
    call    print_string

    ; Check for INT 13h extensions
    call    check_int13_ext
    jc      .no_ext

    ; Load Stage 2 using extended read
    call    load_stage2
    jc      .load_failed

    ; Print success message
    mov     si, msg_ok
    call    print_string

    ; Jump to Stage 2
    ; Pass boot drive in DL
    mov     dl, [boot_drive]
    jmp     STAGE2_LOAD_SEG:STAGE2_LOAD_OFF

.no_ext:
    mov     si, msg_no_ext
    call    print_string
    jmp     halt

.load_failed:
    mov     si, msg_failed
    call    print_string
    jmp     halt

; ============================================================================
; Check INT 13h Extensions
; ============================================================================
; Output: CF=0 if extensions available, CF=1 if not

check_int13_ext:
    push    bx
    push    dx

    mov     ah, 0x41
    mov     bx, 0x55AA
    mov     dl, [boot_drive]
    int     0x13

    jc      .not_available
    cmp     bx, 0xAA55
    jne     .not_available

    ; Check if packet access (bit 0) is supported
    test    cx, 0x01
    jz      .not_available

    pop     dx
    pop     bx
    clc
    ret

.not_available:
    pop     dx
    pop     bx
    stc
    ret

; ============================================================================
; Load Stage 2
; ============================================================================
; Uses INT 13h extended read (AH=42h)
; Output: CF=0 on success, CF=1 on failure

load_stage2:
    push    es
    push    di
    push    si

    ; Set up Disk Address Packet (DAP)
    mov     byte [dap_size], 16
    mov     byte [dap_reserved], 0
    mov     word [dap_sectors], STAGE2_SECTORS
    mov     word [dap_offset], STAGE2_LOAD_OFF
    mov     word [dap_segment], STAGE2_LOAD_SEG
    mov     dword [dap_lba_low], STAGE2_LBA_LOW
    mov     dword [dap_lba_high], STAGE2_LBA_HIGH

    ; Extended read
    mov     ah, 0x42
    mov     dl, [boot_drive]
    mov     si, dap
    int     0x13

    pop     si
    pop     di
    pop     es
    ret

; ============================================================================
; Print String
; ============================================================================
; Input: SI = pointer to null-terminated string

print_string:
    push    ax
    push    bx
    push    si

.loop:
    lodsb
    test    al, al
    jz      .done

    mov     ah, 0x0E        ; BIOS teletype
    mov     bh, 0x00        ; Page number
    mov     bl, 0x07        ; Attribute (light gray)
    int     0x10

    jmp     .loop

.done:
    pop     si
    pop     bx
    pop     ax
    ret

; ============================================================================
; Halt
; ============================================================================

halt:
    cli
    hlt
    jmp     halt

; ============================================================================
; Data
; ============================================================================

boot_drive:     db 0

msg_loading:    db 'SaltyOS Stage 1', 13, 10, 0
msg_ok:         db 'OK', 13, 10, 0
msg_no_ext:     db 'No INT13 ext', 13, 10, 0
msg_failed:     db 'Load failed', 13, 10, 0

; Disk Address Packet (must be aligned to word boundary)
align 2
dap:
dap_size:       db 16           ; Size of packet (1 byte per INT 13h spec)
dap_reserved:   db 0            ; Reserved (1 byte per INT 13h spec)
dap_sectors:    dw 0            ; Number of sectors to read
dap_offset:     dw 0            ; Destination offset
dap_segment:    dw 0            ; Destination segment
dap_lba_low:    dd 0            ; LBA (low 32 bits)
dap_lba_high:   dd 0            ; LBA (high 32 bits)

; ============================================================================
; Padding and Boot Signature
; ============================================================================

; Pad to 446 bytes (leaving room for partition table)
times 446 - ($ - $$) db 0

; Partition table (64 bytes) - leave empty for raw disk boot
times 64 db 0

; Boot signature
dw 0xAA55
