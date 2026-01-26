; ==============================================================================
; SaltyOS Stage 1: MBR
; ==============================================================================
bits 16
org 0x7c00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti

    mov [boot_drive], dl

    ; Print "Load.."
    mov si, msg_load
    call print_string

    ; --------------------------------------------------------------------------
    ; Load Stage 2 (Increased Size: 16KB)
    ; --------------------------------------------------------------------------
    ; We read 32 sectors to cover the expanded Stage 2 code logic.
    ; Destination: 0x0000:0x7e00
    
    mov bx, 0x7e00
    mov ah, 0x02        ; BIOS Read Sectors
    mov al, 32          ; Read 32 sectors (16KB)
    mov ch, 0
    mov cl, 2           ; Start at Sector 2 (1-based CHS)
    mov dh, 0
    mov dl, [boot_drive]
    int 0x13
    jc disk_error

    ; --------------------------------------------------------------------------
    ; Verify & Jump
    ; --------------------------------------------------------------------------
    ; Check if first byte of Stage 2 is non-zero
    mov al, [0x7e00]
    test al, al
    jz empty_error

    mov si, msg_jump
    call print_string

    jmp 0x0000:0x7e00

disk_error:
    mov si, msg_err
    call print_string
    hlt

empty_error:
    mov si, msg_empty
    call print_string
    hlt

print_string:
    pusha
    mov ah, 0x0e
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .loop
.done:
    popa
    ret

boot_drive: db 0
msg_load:   db "Load..", 0
msg_jump:   db " Go!", 0
msg_err:    db " Err!", 0
msg_empty:  db " 00!", 0

times 510-($-$$) db 0
dw 0xaa55
