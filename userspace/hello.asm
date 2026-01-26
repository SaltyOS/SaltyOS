BITS 64

GLOBAL _start

SECTION .text
_start:
    mov rax, 0xff        ; SYS_DEBUG_PRINT
    mov rdi, 'U'
    syscall
.loop:
    jmp .loop
