; SaltyOS Stage 1 - Master Boot Record
; SPDX-License-Identifier: GPL-2.0-only
;
; Loaded by BIOS at 0x7C00 (512 bytes max)
; Loads Stage 2 from fixed LBA sectors

[bits 16]
[org 0x7C00]

; Constants
STAGE2_LOAD_ADDR    equ 0x7E00      ; Load Stage 2 right after MBR
STAGE2_START_LBA    equ 1           ; Stage 2 starts at LBA 1
STAGE2_SECTORS      equ 128         ; 64KB for Stage 2

start:
    ; Set up segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x5000              ; Stack at safe location (20KB)

    ; Save boot drive
    mov [boot_drive], dl

    ; Print boot message
    mov si, msg_boot
    call print_string

    ; Load Stage 2 using LBA
    mov ah, 0x42                ; Extended read
    mov dl, [boot_drive]
    mov si, dap                 ; Disk Address Packet
    int 0x13
    jc disk_error

    ; Print success
    mov si, msg_loaded
    call print_string

    ; Jump to Stage 2
    jmp 0x0000:STAGE2_LOAD_ADDR

disk_error:
    mov si, msg_disk_error
    call print_string
    jmp halt

halt:
    cli
    hlt
    jmp halt

; Print null-terminated string
; SI = string pointer
print_string:
    pusha
.loop:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E
    mov bx, 0x0007
    int 0x10
    jmp .loop
.done:
    popa
    ret

; Data
boot_drive:     db 0
msg_boot:       db "S1: SaltyOS MBR", 13, 10, 0
msg_loaded:     db "S1: Starting stage2", 13, 10, 0
msg_disk_error: db "S1: Disk error!", 13, 10, 0

; Disk Address Packet for LBA read
align 4
dap:
    db 0x10                     ; Size of DAP (16 bytes)
    db 0                        ; Reserved
    dw STAGE2_SECTORS           ; Number of sectors
    dw STAGE2_LOAD_ADDR         ; Offset
    dw 0x0000                   ; Segment
    dq STAGE2_START_LBA         ; Starting LBA

; Padding and boot signature
times 446-($-$$) db 0           ; Pad to partition table

; Empty partition table (64 bytes)
times 64 db 0

; Boot signature
dw 0xAA55
