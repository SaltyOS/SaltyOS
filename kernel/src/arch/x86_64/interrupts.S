.section .text
.intel_syntax noprefix

# Macro for interrupt entry trampoline WITHOUT error code
.macro INT_HANDLER num
.global interrupt_handler_\num
interrupt_handler_\num:
    push 0       # Dummy error code
    mov rax, \num
    push rax     # Interrupt vector number
    jmp interrupt_entry_common
.endm

# Macro for interrupt entry trampoline WITH error code
.macro INT_HANDLER_ERR num
.global interrupt_handler_\num
interrupt_handler_\num:
    mov rax, \num
    push rax     # Interrupt vector number (error code already pushed by CPU)
    jmp interrupt_entry_common
.endm

# Common interrupt entry point
interrupt_entry_common:
    # Save all callee-saved registers
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    # Save all caller-saved registers too
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    # Align stack to 16 bytes (required by ABI)
    mov r15, rsp
    and rsp, -16
    sub rsp, 8
    sub rsp, 64

    # vec_ptr = r15 + (15 * 8)
    lea rbx, [r15 + 120]

    # vector number -> rax
    mov rax, [rbx + 0]

    # Build normalized interrupt frame on the stack
    mov rdi, rsp
    mov [rdi + 0], rax         # vector
    mov rcx, [rbx + 8]
    mov [rdi + 8], rcx         # error_code
    mov rcx, [rbx + 16]
    mov [rdi + 16], rcx        # rip
    mov rcx, [rbx + 24]
    mov [rdi + 24], rcx        # cs
    mov rcx, [rbx + 32]
    mov [rdi + 32], rcx        # rflags

    # If CPL=3, stack frame includes RSP/SS
    mov rcx, [rbx + 24]
    and rcx, 3
    cmp rcx, 3
    jne .no_user_frame
    mov rcx, [rbx + 40]
    mov [rdi + 40], rcx        # rsp
    mov rcx, [rbx + 48]
    mov [rdi + 48], rcx        # ss
    jmp .frame_ready

.no_user_frame:
    mov qword ptr [rdi + 40], 0
    mov qword ptr [rdi + 48], 0

.frame_ready:
    # Get vector number from [rbp + 8]
    mov rax, [rbp + 8]

    # Check if it's an exception (0-31) or IRQ (32+)
    cmp rax, 32
    jae .irq

    # Exception handlers - jump based on vector number
    cmp rax, 0
    je .call_divide
    cmp rax, 1
    je .call_debug
    cmp rax, 2
    je .call_nmi
    cmp rax, 3
    je .call_breakpoint
    cmp rax, 4
    je .call_overflow
    cmp rax, 5
    je .call_bound_range
    cmp rax, 6
    je .call_invalid_opcode
    cmp rax, 7
    je .call_device_not_available
    cmp rax, 8
    je .call_double_fault
    cmp rax, 9
    je .call_x87_fpu_error
    cmp rax, 10
    je .call_invalid_tss
    cmp rax, 11
    je .call_segment_not_present
    cmp rax, 12
    je .call_stack_segment
    cmp rax, 13
    je .call_general_protection
    cmp rax, 14
    je .call_page_fault
    cmp rax, 15
    je .call_reserved
    cmp rax, 16
    je .call_x87_fpu_error
    cmp rax, 17
    je .call_alignment_check
    cmp rax, 18
    je .call_machine_check
    cmp rax, 19
    je .call_simd_fp
    cmp rax, 20
    je .call_virtualization
    cmp rax, 21
    je .call_security
    jmp .call_unknown

.call_divide:
    call handle_divide_error
    jmp .done

.call_debug:
    call handle_debug
    jmp .done

.call_nmi:
    call handle_nmi
    jmp .done

.call_breakpoint:
    call handle_breakpoint
    jmp .done

.call_overflow:
    call handle_overflow
    jmp .done

.call_bound_range:
    call handle_bound_range_exceeded
    jmp .done

.call_invalid_opcode:
    call handle_invalid_opcode
    jmp .done

.call_device_not_available:
    call handle_device_not_available
    jmp .done

.call_double_fault:
    call handle_double_fault
    jmp .done

.call_x87_fpu_error:
    call handle_x87_fpu_error
    jmp .done

.call_invalid_tss:
    call handle_invalid_tss
    jmp .done

.call_segment_not_present:
    call handle_segment_not_present
    jmp .done

.call_stack_segment:
    call handle_stack_segment_fault
    jmp .done

.call_general_protection:
    call handle_general_protection_fault
    jmp .done

.call_page_fault:
    call handle_page_fault
    jmp .done

.call_reserved:
    call handle_unknown
    jmp .done

.call_simd_fp:
    call handle_simd_floating_point
    jmp .done

.call_alignment_check:
    call handle_alignment_check
    jmp .done

.call_machine_check:
    call handle_machine_check
    jmp .done

.call_virtualization:
    call handle_virtualization
    jmp .done

.call_security:
    call handle_security
    jmp .done

.call_unknown:
    call handle_unknown
    jmp .done

.irq:
    call handle_irq
    jmp .done

.done:
    # Restore stack pointer
    mov rsp, r15

    # Restore all registers (reverse order)
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp

    # Remove error code and vector from stack
    add rsp, 16

    # Return from interrupt
    iretq

# Generate all 256 interrupt handlers explicitly
# This avoids the .rept/.set issues in gas

# Exception 0 - Divide error
INT_HANDLER 0

# Exception 1 - Debug
INT_HANDLER 1

# Exception 2 - NMI
INT_HANDLER 2

# Exception 3 - Breakpoint
INT_HANDLER 3

# Exception 4 - Overflow
INT_HANDLER 4

# Exception 5 - Bound range exceeded
INT_HANDLER 5

# Exception 6 - Invalid opcode
INT_HANDLER 6

# Exception 7 - Device not available
INT_HANDLER 7

# Exception 8 - Double fault (HAS ERROR CODE)
INT_HANDLER_ERR 8

# Exception 9 - Coprocessor segment overrun
INT_HANDLER 9

# Exception 10 - Invalid TSS (HAS ERROR CODE)
INT_HANDLER_ERR 10

# Exception 11 - Segment not present (HAS ERROR CODE)
INT_HANDLER_ERR 11

# Exception 12 - Stack segment fault (HAS ERROR CODE)
INT_HANDLER_ERR 12

# Exception 13 - General protection fault (HAS ERROR CODE)
INT_HANDLER_ERR 13

# Exception 14 - Page fault (HAS ERROR CODE)
INT_HANDLER_ERR 14

# Exception 15 - Reserved
INT_HANDLER 15

# Exception 16 - x87 FPU error
INT_HANDLER 16

# Exception 17 - Alignment check (HAS ERROR CODE)
INT_HANDLER_ERR 17

# Exception 18 - Machine check
INT_HANDLER 18

# Exception 19 - SIMD floating point
INT_HANDLER 19

# Exception 20 - Virtualization
INT_HANDLER 20

# Exception 21 - Control protection (HAS ERROR CODE)
INT_HANDLER_ERR 21

# Exception 22 - Reserved
INT_HANDLER 22

# Exception 23 - Reserved
INT_HANDLER 23

# Exception 24 - Reserved
INT_HANDLER 24

# Exception 25 - Reserved
INT_HANDLER 25

# Exception 26 - Reserved
INT_HANDLER 26

# Exception 27 - Reserved
INT_HANDLER 27

# Exception 28 - Reserved
INT_HANDLER 28

# Exception 29 - Reserved
INT_HANDLER 29

# Exception 30 - Security (HAS ERROR CODE)
INT_HANDLER_ERR 30

# Exception 31 - Reserved
INT_HANDLER 31

# IRQs and remaining vectors (32-255)
# For now, all use the standard handler
INT_HANDLER 32
INT_HANDLER 33
INT_HANDLER 34
INT_HANDLER 35
INT_HANDLER 36
INT_HANDLER 37
INT_HANDLER 38
INT_HANDLER 39
INT_HANDLER 40
INT_HANDLER 41
INT_HANDLER 42
INT_HANDLER 43
INT_HANDLER 44
INT_HANDLER 45
INT_HANDLER 46
INT_HANDLER 47
INT_HANDLER 48
INT_HANDLER 49
INT_HANDLER 50
INT_HANDLER 51
INT_HANDLER 52
INT_HANDLER 53
INT_HANDLER 54
INT_HANDLER 55
INT_HANDLER 56
INT_HANDLER 57
INT_HANDLER 58
INT_HANDLER 59
INT_HANDLER 60
INT_HANDLER 61
INT_HANDLER 62
INT_HANDLER 63
INT_HANDLER 64
INT_HANDLER 65
INT_HANDLER 66
INT_HANDLER 67
INT_HANDLER 68
INT_HANDLER 69
INT_HANDLER 70
INT_HANDLER 71
INT_HANDLER 72
INT_HANDLER 73
INT_HANDLER 74
INT_HANDLER 75
INT_HANDLER 76
INT_HANDLER 77
INT_HANDLER 78
INT_HANDLER 79
INT_HANDLER 80
INT_HANDLER 81
INT_HANDLER 82
INT_HANDLER 83
INT_HANDLER 84
INT_HANDLER 85
INT_HANDLER 86
INT_HANDLER 87
INT_HANDLER 88
INT_HANDLER 89
INT_HANDLER 90
INT_HANDLER 91
INT_HANDLER 92
INT_HANDLER 93
INT_HANDLER 94
INT_HANDLER 95
INT_HANDLER 96
INT_HANDLER 97
INT_HANDLER 98
INT_HANDLER 99
INT_HANDLER 100
INT_HANDLER 101
INT_HANDLER 102
INT_HANDLER 103
INT_HANDLER 104
INT_HANDLER 105
INT_HANDLER 106
INT_HANDLER 107
INT_HANDLER 108
INT_HANDLER 109
INT_HANDLER 110
INT_HANDLER 111
INT_HANDLER 112
INT_HANDLER 113
INT_HANDLER 114
INT_HANDLER 115
INT_HANDLER 116
INT_HANDLER 117
INT_HANDLER 118
INT_HANDLER 119
INT_HANDLER 120
INT_HANDLER 121
INT_HANDLER 122
INT_HANDLER 123
INT_HANDLER 124
INT_HANDLER 125
INT_HANDLER 126
INT_HANDLER 127
INT_HANDLER 128
INT_HANDLER 129
INT_HANDLER 130
INT_HANDLER 131
INT_HANDLER 132
INT_HANDLER 133
INT_HANDLER 134
INT_HANDLER 135
INT_HANDLER 136
INT_HANDLER 137
INT_HANDLER 138
INT_HANDLER 139
INT_HANDLER 140
INT_HANDLER 141
INT_HANDLER 142
INT_HANDLER 143
INT_HANDLER 144
INT_HANDLER 145
INT_HANDLER 146
INT_HANDLER 147
INT_HANDLER 148
INT_HANDLER 149
INT_HANDLER 150
INT_HANDLER 151
INT_HANDLER 152
INT_HANDLER 153
INT_HANDLER 154
INT_HANDLER 155
INT_HANDLER 156
INT_HANDLER 157
INT_HANDLER 158
INT_HANDLER 159
INT_HANDLER 160
INT_HANDLER 161
INT_HANDLER 162
INT_HANDLER 163
INT_HANDLER 164
INT_HANDLER 165
INT_HANDLER 166
INT_HANDLER 167
INT_HANDLER 168
INT_HANDLER 169
INT_HANDLER 170
INT_HANDLER 171
INT_HANDLER 172
INT_HANDLER 173
INT_HANDLER 174
INT_HANDLER 175
INT_HANDLER 176
INT_HANDLER 177
INT_HANDLER 178
INT_HANDLER 179
INT_HANDLER 180
INT_HANDLER 181
INT_HANDLER 182
INT_HANDLER 183
INT_HANDLER 184
INT_HANDLER 185
INT_HANDLER 186
INT_HANDLER 187
INT_HANDLER 188
INT_HANDLER 189
INT_HANDLER 190
INT_HANDLER 191
INT_HANDLER 192
INT_HANDLER 193
INT_HANDLER 194
INT_HANDLER 195
INT_HANDLER 196
INT_HANDLER 197
INT_HANDLER 198
INT_HANDLER 199
INT_HANDLER 200
INT_HANDLER 201
INT_HANDLER 202
INT_HANDLER 203
INT_HANDLER 204
INT_HANDLER 205
INT_HANDLER 206
INT_HANDLER 207
INT_HANDLER 208
INT_HANDLER 209
INT_HANDLER 210
INT_HANDLER 211
INT_HANDLER 212
INT_HANDLER 213
INT_HANDLER 214
INT_HANDLER 215
INT_HANDLER 216
INT_HANDLER 217
INT_HANDLER 218
INT_HANDLER 219
INT_HANDLER 220
INT_HANDLER 221
INT_HANDLER 222
INT_HANDLER 223
INT_HANDLER 224
INT_HANDLER 225
INT_HANDLER 226
INT_HANDLER 227
INT_HANDLER 228
INT_HANDLER 229
INT_HANDLER 230
INT_HANDLER 231
INT_HANDLER 232
INT_HANDLER 233
INT_HANDLER 234
INT_HANDLER 235
INT_HANDLER 236
INT_HANDLER 237
INT_HANDLER 238
INT_HANDLER 239
INT_HANDLER 240
INT_HANDLER 241
INT_HANDLER 242
INT_HANDLER 243
INT_HANDLER 244
INT_HANDLER 245
INT_HANDLER 246
INT_HANDLER 247
INT_HANDLER 248
INT_HANDLER 249
INT_HANDLER 250
INT_HANDLER 251
INT_HANDLER 252
INT_HANDLER 253
INT_HANDLER 254
INT_HANDLER 255
