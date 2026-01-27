; SaltyOS Stage 1.5 - Volume Boot Record
; SPDX-License-Identifier: GPL-2.0-only
;
; Alternative entry point for partition boot
; Similar to MBR but partition-aware

[bits 16]
[org 0x7C00]

STAGE2_LOAD_ADDR    equ 0x7E00
STAGE2_START_LBA    equ 1
STAGE2_SECTORS      equ 128

start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00

    mov [boot_drive], dl

    ; Load Stage 2
    mov ah, 0x42
    mov dl, [boot_drive]
    mov si, dap
    int 0x13
    jc disk_error

    jmp 0x0000:STAGE2_LOAD_ADDR

disk_error:
    mov si, msg_error
    call print_string
halt:
    cli
    hlt
    jmp halt

print_string:
    pusha
.loop:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E
    int 0x10
    jmp .loop
.done:
    popa
    ret

boot_drive:     db 0
msg_error:      db "VBR Error", 0

align 4
dap:
    db 0x10
    db 0
    dw STAGE2_SECTORS
    dw STAGE2_LOAD_ADDR
    dw 0x0000
    dq STAGE2_START_LBA

times 510-($-$$) db 0
dw 0xAA55
