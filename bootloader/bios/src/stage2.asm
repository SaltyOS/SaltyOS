; =============================================================================
; SaltyOS BIOS Stage 2
; Kernel/bootcore ELF64 loader + minimal paging for bootcore handoff
; =============================================================================
;
; What this stage does:
;   1) Stay in 16-bit real mode for BIOS disk reads (INT 13h AH=42h).
;   2) Enter Unreal Mode (aka "Big Real Mode") so we can write above 1MiB.
;   3) Read kernel ELF header + program headers from disk.
;   4) Compute:
;        - vaddr_base = min(p_vaddr) among PT_LOAD
;        - entry      = e_entry
;      and then load segments to:
;        phys_dst = KERNEL_PHYS_BASE + (p_vaddr - vaddr_base)
;   5) Zero BSS for each PT_LOAD when p_memsz > p_filesz.
;   6) Load bootcore ELF and initrd into memory.
;   7) Build BootInfo + BootHandoff and enter Long Mode with a minimal identity map.
;   8) Jump to bootcore entry with RDI = BootHandoff pointer.
;
; Notes:
;   - Kernel must be PIE (ET_DYN); relocations are applied by bootcore.
;   - All addresses here are "physical" until paging is enabled.
; =============================================================================

BITS 16
ORG 0x7E00

; -----------------------------------------------------------------------------
; Tunables / constants
; -----------------------------------------------------------------------------
%include "layout.inc"
%include "ska.inc"
%include "bootcore.inc"
%define VGA_SEG                 0xB800
%define VGA_LINEAR              0xB8000

%define DAP_PHYS                0x0400          ; DAP in low memory (safe, below TMP)
%define DAP_SEG                 0x0000
%define DAP_OFF                 0x0700          ; avoid BIOS data area (0x0400-0x04FF) and TMP buffer

%define TMP_SECTOR_BUF          0x0500          ; 512B read buffer in low memory (avoid stage2 overlap)
%define TMP_SECTOR_BUF_SEG      0x0000
%define TMP_SECTOR_BUF_OFF      0x0500

%define KERNEL_LBA_START        33              ; must match mkdisk-bios.sh seek
%define BOOTCORE_LBA_START      4096
%define INITRD_LBA_START        2048
; KERNEL_PHYS_BASE/KERNEL_VIRT_BASE constants come from layout.inc

%define BOOTINFO_PHYS_ADDR      0x00006000      ; low memory BootInfo for now
%define BOOTCORE_HANDOFF_PHYS   0x00006800      ; low memory handoff buffer
%define BOOTCORE_PT_ARENA_BASE  0x00018000
%define BOOTCORE_PT_ARENA_SIZE  0x00010000
%define BOOTEXTRA_PHYS          0x0000A000

%define PML4_ADDR               0x00001000
%define PDPT_LOW_ADDR           0x00002000
%define PD_LOW_ADDR             0x00003000
; Only identity paging tables are needed to reach bootcore.
%define PD_LOW1_ADDR            0x00015000
%define PD_LOW2_ADDR            0x00016000
%define PD_LOW3_ADDR            0x00017000

%define CHS_HEADS               16
%define CHS_SECTORS             63

%define CR0_PE                  0x00000001
%define CR0_MP                  0x00000002
%define CR0_EM                  0x00000004
%define CR0_PG                  0x80000000
%define CR4_PAE                 0x00000020
%define CR4_OSFXSR              0x00000200
%define CR4_OSXMMEXCPT          0x00000400

; Serial I/O (COM1)
%define COM1_PORT               0x3F8

; ELF constants
%define ELF_MAGIC               0x464C457F      ; bytes: 7F 45 4C 46, reversed for 16-bit dword comparison
%define EI_CLASS_64             2
%define EI_DATA_LE              1
%define ET_EXEC                 2               ; Static executable
%define ET_DYN                  3               ; PIE / shared object
%define EM_X86_64               62

%define PT_LOAD                 1
%define PT_DYNAMIC              2

; E820 memory map (BIOS INT 15h, EAX=E820h)
%define E820_BUF_PHYS            0x00007000      ; safe low memory buffer (< 0x7C00)
%define E820_ENTRY_SIZE          24              ; extended E820 entry size
%define E820_MAX_ENTRIES         64              ; max entries to store
%define E820_SMAP_SIG            0x534D4150      ; 'SMAP' signature

; -----------------------------------------------------------------------------
; Entry: BIOS jumps here from stage1, DL=boot drive
; -----------------------------------------------------------------------------
start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7E00
    sti

    ; Setup GS for VGA debug writes
    mov ax, VGA_SEG
    mov gs, ax

    mov [boot_drive], dl
    mov dword [rf_base_lba], KERNEL_LBA_START

    ; Enable A20 (fast A20 gate)
    in  al, 0x92
    or  al, 2
    out 0x92, al

    ; Enter Unreal Mode so we can write to KERNEL_PHYS_BASE easily
    call enter_unreal_mode
    call detect_int13_extensions
    call detect_chs_geometry

    ; Initialize serial for debug output
    call serial_init
    ; Debug: Boot started
    mov al, 'B'
    call serial_putc

    ; Load and validate ELF header + compute vaddr_base
    call elf_read_and_analyze
    jc  fatal_elf

    ; Debug: kernel ELF analyzed OK
    mov al, 'K'
    call serial_putc

    ; Load PT_LOAD segments into KERNEL_PHYS_BASE + (p_vaddr - vaddr_base)
    call elf_load_segments_unreal
    jc  fatal_disk

    ; Debug: kernel segments loaded OK
    mov al, 'S'
    call serial_putc

    ; Load bootcore ELF (common bootloader core)
    call bootcore_elf_read_and_analyze
    jc  fatal_elf
    call bootcore_elf_load_segments_unreal
    jc  fatal_disk
    ; Debug: bootcore loaded OK
    mov al, 'C'
    call serial_putc

    ; Load initrd into physical memory
    call initrd_load
    jc  fatal_disk
    ; Debug: initrd loaded OK
    mov al, 'I'
    call serial_putc

    ; Query BIOS memory map (E820) BEFORE building BootInfo
    call e820_get_map
    call e820_to_memory_map

    ; Optional serial debug: print 'M' then count
    mov al, 'M'
    call serial_putc
    mov al, [e820_count]
    call serial_put_hex8
    mov al, 0x0D
    call serial_putc
    mov al, 0x0A
    call serial_putc

    ; Build BootInfo AFTER we have the memory map
    call build_bootinfo
    ; Initialize bootcore handoff structure
    call init_bootcore_handoff

    ; Setup paging and enter long mode
    cli
    lgdt [gdt32_desc]
    mov eax, cr0
    or eax, CR0_PE
    mov cr0, eax
    jmp 0x08:pm32_entry

; =============================================================================
; 32-bit protected mode: build paging, enable long mode
; =============================================================================
BITS 32
pm32_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    mov esp, 0x90000

    ; Build page tables (identity mapping only)
    call setup_page_tables

    ; Enable PAE and SSE support
    mov eax, cr4
    or eax, (CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT)
    mov cr4, eax

    ; Load CR3 (PML4 base)
    mov eax, PML4_ADDR
    mov cr3, eax

    ; Enable EFER.LME (long mode enable)
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    ; Enable paging (CR0.PG) and clear EM/set MP for SSE
    mov eax, cr0
    and eax, ~CR0_EM
    or eax, (CR0_PG | CR0_MP)
    mov cr0, eax

    ; Load 64-bit GDT and far jump to long mode
    lgdt [gdt64_desc]
    jmp 0x08:lm64_entry

; =============================================================================
; 64-bit long mode: jump to bootcore entry
; =============================================================================
BITS 64
lm64_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    ; Ensure SysV ABI stack alignment (RSP % 16 == 8 at function entry)
    mov rsp, 0x8fff8

    ; Fill BootHandoff kernel fields for bootcore
    mov rbx, BOOTCORE_HANDOFF_PHYS

    mov rax, KERNEL_PHYS_BASE
    mov [rbx + BOOTHANDOFF_OFF_KERNEL_PHYS_BASE], rax

    mov rax, [elf_vaddr_base]
    mov [rbx + BOOTHANDOFF_OFF_KERNEL_VADDR], rax

    mov rax, [elf_e_entry]
    mov [rbx + BOOTHANDOFF_OFF_KERNEL_ENTRY], rax

    mov rax, [elf_dyn_vaddr]
    test rax, rax
    jz .no_dyn
    mov rcx, [elf_vaddr_base]
    sub rax, rcx
    add rax, KERNEL_PHYS_BASE
    mov [rbx + BOOTHANDOFF_OFF_KERNEL_DYN_PHYS], rax
    mov rax, [elf_dyn_size]
    mov [rbx + BOOTHANDOFF_OFF_KERNEL_DYN_SIZE], rax
    jmp .dyn_done
.no_dyn:
    mov qword [rbx + BOOTHANDOFF_OFF_KERNEL_DYN_PHYS], 0
    mov qword [rbx + BOOTHANDOFF_OFF_KERNEL_DYN_SIZE], 0
.dyn_done:

    ; Jump to bootcore entry (identity mapped)
    mov rax, [bootcore_e_entry]
    mov rcx, [bootcore_vaddr_base]
    sub rax, rcx
    mov rdx, BOOTCORE_PHYS_BASE
    add rax, rdx

    mov rdi, BOOTCORE_HANDOFF_PHYS
    jmp rax

.hang:
    hlt
    jmp .hang

; =============================================================================
; 16-bit helpers: debug / unreal mode / BIOS reads / ELF analysis & loading
; =============================================================================
BITS 16

; -----------------------------------------------------------------------------
; Debug helpers (write char to VGA via GS)
; -----------------------------------------------------------------------------
dbg_put2: mov word [gs:0], 0x0F32  ; '2'
         ret
dbg_putU: mov word [gs:2], 0x0F55  ; 'U'
         ret
dbg_putH: mov word [gs:4], 0x0F48  ; 'H'
         ret
dbg_putL: mov word [gs:6], 0x0F4C  ; 'L'
         ret
dbg_putB: mov word [gs:8], 0x0F42  ; 'B'
         ret
dbg_putG: mov word [gs:10], 0x0F47 ; 'G'
         ret
dbg_putR: mov word [gs:12], 0x0F52 ; 'R'
         ret

; Serial helpers (COM1)
; Initializes 115200 8N1 if not already.
serial_init:
    ; disable interrupts
    mov dx, COM1_PORT + 1
    mov al, 0x00
    out dx, al
    ; enable DLAB
    mov dx, COM1_PORT + 3
    mov al, 0x80
    out dx, al
    ; set divisor to 1 (115200 baud)
    mov dx, COM1_PORT + 0
    mov al, 0x01
    out dx, al
    mov dx, COM1_PORT + 1
    mov al, 0x00
    out dx, al
    ; 8N1, clear DLAB
    mov dx, COM1_PORT + 3
    mov al, 0x03
    out dx, al
    ; enable FIFO, clear, 14-byte threshold
    mov dx, COM1_PORT + 2
    mov al, 0xC7
    out dx, al
    ; modem control: RTS/DSR set
    mov dx, COM1_PORT + 4
    mov al, 0x0B
    out dx, al
    ret

serial_putc:
    push ax
    push dx
    mov ah, al           ; save char in AH
.wait:
    mov dx, COM1_PORT + 5
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, COM1_PORT
    mov al, ah
    out dx, al
    pop dx
    pop ax
    ret

serial_puts:
    pusha
.next:
    lodsb
    test al, al
    jz .done
    call serial_putc
    jmp .next
.done:
    popa
    ret

serial_put_hex8:
    push ax
    push bx
    push dx
    mov bl, al
    mov cl, 4
    shr al, cl
    and al, 0x0F
    add al, '0'
    cmp al, '9'
    jbe .nibble_hi
    add al, 7
.nibble_hi:
    call serial_putc
    mov al, bl
    and al, 0x0F
    add al, '0'
    cmp al, '9'
    jbe .nibble_lo
    add al, 7
.nibble_lo:
    call serial_putc
    pop dx
    pop bx
    pop ax
    ret

fatal_disk:
    mov word [gs:10], 0x4F44       ; 'D' red
    mov al, 'D'
    call serial_putc
    cli
    hlt
    jmp $

fatal_elf:
    mov word [gs:10], 0x4F45       ; 'E' red
    mov al, 'E'
    call serial_putc
    cli
    hlt
    jmp $

; -----------------------------------------------------------------------------
; enter_unreal_mode
;   - Temporarily enter protected mode to load a 4GiB data descriptor into FS,
;     then return to real mode. The hidden segment cache retains 4GiB limit.
;   - After this, we can use FS with 32-bit addressing to access >1MiB memory
;     while still using BIOS interrupts (real mode).
;   - DS/ES stay at 0 for BIOS calls; FS is used for high memory writes.
; -----------------------------------------------------------------------------
enter_unreal_mode:
    cli
    lgdt [gdt_unreal_desc]

    mov eax, cr0
    or  eax, 1                     ; PE=1 (enter protected mode)
    mov cr0, eax
    jmp 0x08:unreal_pm_entry       ; load protected-mode CS

unreal_pm_entry:
    ; Load a flat 4GiB data selector into FS (for high memory access)
    mov ax, 0x10                   ; unreal data selector (base=0, limit=4GiB)
    mov fs, ax

    mov eax, cr0
    and eax, 0xFFFFFFFE            ; PE=0 (back to real mode)
    mov cr0, eax
    jmp 0x0000:unreal_rm_entry     ; reload real-mode CS

unreal_rm_entry:
    sti

    ; IMPORTANT: Do NOT reload FS here - keep 4GiB cached limit
    ; Keep DS/ES = 0 for BIOS reads and low memory access
    xor ax, ax
    mov ds, ax
    mov es, ax
    ret

; -----------------------------------------------------------------------------
; BIOS read: read 1 sector at LBA -> TMP_SECTOR_BUF
; Inputs:
;   EAX = LBA (32-bit)
; Output:
;   CF set on error
; -----------------------------------------------------------------------------
bios_read_sector_lba_to_tmp:
    pusha
    mov [bios_lba_arg], eax
    push ds
    push es

    xor ax, ax
    mov ds, ax              ; DS = 0
    mov es, ax              ; ES = 0

    ; ------------------------------------------------------------
    ; Build DAP at 0000:0400 (physical 0x0400)
    ; DAP format (size=16):
    ;   +0  u8  size (0x10)
    ;   +1  u8  reserved (0)
    ;   +2  u16 sector count
    ;   +4  u16 buffer offset
    ;   +6  u16 buffer segment
    ;   +8  u64 LBA
    ; ------------------------------------------------------------
    mov byte [DAP_OFF + 0], 0x10
    mov byte [DAP_OFF + 1], 0x00
    mov word [DAP_OFF + 2], 1
    mov word [DAP_OFF + 4], TMP_SECTOR_BUF_OFF
    mov word [DAP_OFF + 6], TMP_SECTOR_BUF_SEG

    ; LBA (EAX input)
    mov eax, [bios_lba_arg]
    mov dword [DAP_OFF + 8], eax
    mov dword [DAP_OFF + 12], 0

    ; Try LBA (INT13 extensions) first unless forced to CHS
    cmp byte [force_chs], 0
    jne .chs_fallback

    mov dl, [boot_drive]
    mov si, DAP_OFF
    mov ah, 0x42
    int 0x13
    mov [last_int13_status], ah
    jnc .lba_ok

.chs_fallback:
    ; LBA -> CHS with H=16, S=63
    mov eax, [DAP_OFF + 8]     ; low 32 LBA
    xor edx, edx
    movzx ebx, word [chs_spt]    ; sectors per track
    div ebx                      ; eax=q1 (LBA/63), edx=r1 (sector-1)
    mov esi, eax                 ; q1
    mov bh, dl                   ; sector-1
    inc bh                       ; sector (1..63)

    mov eax, esi
    xor edx, edx
    movzx ebx, word [chs_heads]  ; heads
    div ebx                      ; eax=cylinder, edx=head
    mov dh, dl                   ; head
    mov ch, al                   ; cylinder low 8
    mov cl, bh                   ; sector in low bits
    mov bl, ah                   ; cylinder high bits (bits 8-9)
    and bl, 0x03
    shl bl, 6
    or cl, bl                    ; sector + cyl high

    mov ax, TMP_SECTOR_BUF_SEG
    mov es, ax
    mov bx, TMP_SECTOR_BUF_OFF
    mov dl, [boot_drive]
    mov ax, 0x0201               ; AH=02 read, AL=1 sector
    int 0x13
    mov [last_int13_status], ah
    ; Log: C=CHS fallback ok, F=CHS failed (LBA failed)
    pushf
    jnc .chs_ok
    mov al, 'F'
    call serial_putc
    popf
    jmp .done
.chs_ok:
    mov al, 'C'
    call serial_putc
    popf
    jmp .done

.lba_ok:
    ; Log: L=LBA ok (no fallback)
    pushf
    mov al, 'L'
    call serial_putc
    popf

.done:
    pop es
    pop ds
    popa
    ret

; -----------------------------------------------------------------------------
; detect_int13_extensions
;   - Sets force_chs=1 if INT13h extensions are not available
; -----------------------------------------------------------------------------
detect_int13_extensions:
    pusha
    mov ax, 0x4100
    mov bx, 0x55AA
    mov dl, [boot_drive]
    int 0x13
    jc .no_ext
    cmp bx, 0xAA55
    jne .no_ext
    jmp .done
.no_ext:
    mov byte [force_chs], 1
.done:
    popa
    ret

; -----------------------------------------------------------------------------
; detect_chs_geometry
;   - Reads BIOS drive geometry for CHS fallback
; -----------------------------------------------------------------------------
detect_chs_geometry:
    pusha
    mov ah, 0x08
    mov dl, [boot_drive]
    int 0x13
    jc .use_default

    ; CL bits 0-5: sectors per track (1-63)
    mov al, cl
    and ax, 0x003F
    test ax, ax
    jz .use_default
    mov [chs_spt], ax

    ; DH: max head number (0-based)
    movzx ax, dh
    inc ax
    mov [chs_heads], ax
    jmp .done

.use_default:
    mov word [chs_spt], CHS_SECTORS
    mov word [chs_heads], CHS_HEADS
.done:
    popa
    ret

; -----------------------------------------------------------------------------
; read_file_bytes_to_phys
;   - Reads "len" bytes from kernel file starting at "file_off" into physical dst
;   - Uses 1-sector reads to TMP buffer and copies partial bytes.
;
; Inputs:
;   [rf_file_off_lo] (dword) file offset
;   [rf_len_lo]      (dword) length in bytes
;   [rf_dst_phys]    (dword) destination physical address (<= 4GiB)
; Output:
;   CF set on disk error
; -----------------------------------------------------------------------------
read_file_bytes_to_phys:
    pusha

.next_chunk:
    mov eax, [rf_len_lo]
    test eax, eax
    jz .done

    ; sector_index = file_off / 512, intra = file_off % 512
    mov eax, [rf_file_off_lo]
    mov edx, eax
    and edx, 511                 ; intra
    shr eax, 9                   ; sector_index
    mov [tmp_sector_index32], eax

    ; lba = base_lba + sector_index
    add eax, [rf_base_lba]
    call bios_read_sector_lba_to_tmp
    jc .fail

    ; bytes_this = min(512 - intra, len)
    mov eax, 512
    sub eax, edx                 ; 512 - intra
    mov ebx, [rf_len_lo]
    cmp eax, ebx
    jbe .use_eax
    mov eax, ebx
.use_eax:
    mov [rf_bytes_this], ax
    xor ebx, ebx
    mov bx, ax

    ; Copy bytes_this from TMP_SECTOR_BUF+intra -> dst_phys
    ; Use DS=0, read from [TMP+intra], write to [dst_phys] using addr-size override.
    mov si, TMP_SECTOR_BUF_OFF
    add si, dx                   ; si = src offset in TMP (<= 0x8200)
    mov edi, [rf_dst_phys]       ; 32-bit dst

    mov cx, [rf_bytes_this]      ; <=512
.copy_loop:
    mov al, [ds:si]
    ; 32-bit address override for destination write via FS (4GiB limit)
    db 0x64                      ; FS segment override prefix
    db 0x67                      ; 32-bit address override
    mov [edi], al
    inc si
    inc edi
    dec cx
    jnz .copy_loop

    ; Advance file_off += bytes_this
    mov eax, [rf_file_off_lo]
    add eax, ebx
    mov [rf_file_off_lo], eax

    ; Advance dst_phys += bytes_this
    mov eax, [rf_dst_phys]
    add eax, ebx
    mov [rf_dst_phys], eax

    ; len -= bytes_this
    mov eax, [rf_len_lo]
    sub eax, ebx
    mov [rf_len_lo], eax

    jmp .next_chunk

.done:
    clc
    popa
    ret

.fail:
    stc
    popa
    ret

; -----------------------------------------------------------------------------
; elf_read_and_analyze
;   - Reads ELF header (first 512 bytes) and enough program headers
;   - Validates: magic, class, endianness, machine, type(ET_DYN)
;   - Computes vaddr_base = min(p_vaddr) among PT_LOAD
;   - Stores e_entry, e_phoff, e_phentsize, e_phnum, vaddr_base
;
; Output:
;   CF set on error
; -----------------------------------------------------------------------------
elf_read_and_analyze:
    pusha

    ; Read sector 0 of kernel file via common reader
    mov dword [rf_base_lba], KERNEL_LBA_START
    mov dword [rf_file_off_lo], 0
    mov dword [rf_len_lo], 512
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .bad

    ; Validate ELF magic
    cmp dword [TMP_SECTOR_BUF + 0x00], ELF_MAGIC
    jne .bad

    ; Validate class/data
    cmp byte  [TMP_SECTOR_BUF + 0x04], EI_CLASS_64
    jne .bad
    cmp byte  [TMP_SECTOR_BUF + 0x05], EI_DATA_LE
    jne .bad

    ; Validate e_type == ET_EXEC or ET_DYN (both supported)
    mov ax, word [TMP_SECTOR_BUF + 0x10]
    cmp ax, ET_EXEC
    je .type_ok
    cmp ax, ET_DYN
    jne .bad
.type_ok:

    ; Validate e_machine == EM_X86_64
    cmp word  [TMP_SECTOR_BUF + 0x12], EM_X86_64
    jne .bad

    ; Save e_entry (u64 @ 0x18)
    mov eax, dword [TMP_SECTOR_BUF + 0x18]
    mov dword [elf_e_entry], eax
    mov eax, dword [TMP_SECTOR_BUF + 0x1C]
    mov dword [elf_e_entry+4], eax

    ; Save e_phoff (u64 @ 0x20) low32 (we assume small file offsets early)
    mov eax, dword [TMP_SECTOR_BUF + 0x20]
    mov [elf_phoff_lo], eax

    ; e_phentsize (u16 @ 0x36), e_phnum (u16 @ 0x38)
    mov ax, word [TMP_SECTOR_BUF + 0x36]
    mov [elf_phentsize], ax
    mov ax, word [TMP_SECTOR_BUF + 0x38]
    mov [elf_phnum], ax

    ; vaddr_base = 0xFFFFFFFFFFFFFFFF initially
    mov dword [elf_vaddr_base], 0xFFFFFFFF
    mov dword [elf_vaddr_base+4], 0xFFFFFFFF

    ; We now read program headers one-by-one from disk, without assuming they fit in 1 sector.
    xor cx, cx
.ph_loop:
    cmp cx, [elf_phnum]
    jae .done

    ; ph_off = e_phoff + cx * e_phentsize
    movzx eax, cx
    movzx ebx, word [elf_phentsize]
    imul eax, ebx
    add eax, [elf_phoff_lo]              ; low32 file offset for this PHDR
    mov [tmp_ph_file_off], eax

    ; Read 56 bytes (Elf64_Phdr) into TMP buffer at TMP_SECTOR_BUF
    mov dword [rf_file_off_lo], eax
    mov dword [rf_len_lo], 56
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .bad

    ; If p_type != PT_LOAD skip
    cmp dword [TMP_SECTOR_BUF + 0x00], PT_LOAD
    jne .next

    ; p_vaddr (u64 @ 0x10)
    ; Compare and keep min
    mov eax, dword [TMP_SECTOR_BUF + 0x10]
    mov edx, dword [TMP_SECTOR_BUF + 0x14]

    ; if (p_vaddr < vaddr_base) update
    ; Compare high dword first (signedness irrelevant for canonical here, treat unsigned)
    mov ebx, dword [elf_vaddr_base+4]
    cmp edx, ebx
    jb  .update
    ja  .next
    mov ebx, dword [elf_vaddr_base]
    cmp eax, ebx
    jae .next

.update:
    mov dword [elf_vaddr_base], eax
    mov dword [elf_vaddr_base+4], edx

.next:
    inc cx
    jmp .ph_loop

.done:
    ; vaddr_base must be found
    cmp dword [elf_vaddr_base+4], 0xFFFFFFFF
    je .bad

    clc
    popa
    ret

.bad:
    stc
    popa
    ret

; -----------------------------------------------------------------------------
; elf_load_segments_unreal
;   - Iterates all PT_LOAD and PT_DYNAMIC program headers
;   - Loads bytes from file (p_offset..p_offset+p_filesz) into:
;       phys = KERNEL_PHYS_BASE + (p_vaddr - vaddr_base)
;   - Zeros BSS part if p_memsz > p_filesz
;   - Captures PT_DYNAMIC p_vaddr for relocation processing
;
; Output:
;   CF set on disk error
; -----------------------------------------------------------------------------
elf_load_segments_unreal:
    pusha

    ; Initialize elf_dyn_vaddr to 0 (no PT_DYNAMIC found yet)
    mov dword [elf_dyn_vaddr], 0
    mov dword [elf_dyn_vaddr+4], 0
    mov dword [elf_dyn_size], 0
    mov dword [elf_dyn_size+4], 0
    mov dword [max_phys_end], KERNEL_PHYS_BASE

    xor cx, cx
.seg_loop:
    cmp cx, [elf_phnum]
    jae .done

    ; ph_off = e_phoff + cx * e_phentsize
    movzx eax, cx
    movzx ebx, word [elf_phentsize]
    imul eax, ebx
    add eax, [elf_phoff_lo]

    ; Read PHDR (56 bytes) into TMP buffer
    mov dword [rf_file_off_lo], eax
    mov dword [rf_len_lo], 56
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .fail

    ; Check for PT_DYNAMIC - capture p_vaddr for relocation processing
    cmp dword [TMP_SECTOR_BUF + 0x00], PT_DYNAMIC
    jne .not_dynamic
    ; Save PT_DYNAMIC p_vaddr (u64 @ offset 0x10)
    mov eax, dword [TMP_SECTOR_BUF + 0x10]
    mov dword [elf_dyn_vaddr], eax
    mov eax, dword [TMP_SECTOR_BUF + 0x14]
    mov dword [elf_dyn_vaddr+4], eax
    ; Save PT_DYNAMIC p_memsz (u64 @ offset 0x28, low32 only)
    mov eax, dword [TMP_SECTOR_BUF + 0x28]
    mov dword [elf_dyn_size], eax
    mov dword [elf_dyn_size+4], 0
    jmp .next_seg

.not_dynamic:
    ; Only PT_LOAD
    cmp dword [TMP_SECTOR_BUF + 0x00], PT_LOAD
    jne .next_seg

    ; p_offset (u64 @ 0x08) -> low32 for early boot
    mov eax, dword [TMP_SECTOR_BUF + 0x08]
    mov [seg_file_off], eax

    ; p_vaddr (u64 @ 0x10) -> low32 + high32
    mov eax, dword [TMP_SECTOR_BUF + 0x10]
    mov edx, dword [TMP_SECTOR_BUF + 0x14]
    mov [seg_vaddr_lo], eax
    mov [seg_vaddr_hi], edx

    ; p_filesz (u64 @ 0x20) low32
    mov eax, dword [TMP_SECTOR_BUF + 0x20]
    mov [seg_filesz], eax

    ; p_memsz (u64 @ 0x28) low32
    mov eax, dword [TMP_SECTOR_BUF + 0x28]
    mov [seg_memsz], eax

    ; Compute seg_offset_from_base = p_vaddr - vaddr_base (64-bit)
    ; If offset doesn't fit in 32-bit, fail early.
    mov eax, [seg_vaddr_lo]
    mov edx, [seg_vaddr_hi]
    sub eax, dword [elf_vaddr_base]
    sbb edx, dword [elf_vaddr_base+4]
    mov [seg_off_from_base], eax
    mov [seg_off_from_base_hi], edx
    test edx, edx
    jne .fail

    ; phys_dst = KERNEL_PHYS_BASE + offset
    mov eax, KERNEL_PHYS_BASE
    add eax, [seg_off_from_base]
    mov [seg_phys_dst], eax

    ; Track highest loaded physical address
    mov eax, [seg_phys_dst]
    add eax, [seg_memsz]
    cmp eax, [max_phys_end]
    jbe .load_seg
    mov [max_phys_end], eax

.load_seg:
    ; Load file bytes into phys
    mov eax, [seg_file_off]
    mov [rf_file_off_lo], eax
    mov eax, [seg_filesz]
    mov [rf_len_lo], eax
    mov eax, [seg_phys_dst]
    mov [rf_dst_phys], eax
    call read_file_bytes_to_phys
    jc .fail

    ; Zero BSS if memsz > filesz: memset(phys_dst+filesz, 0, memsz-filesz)
    mov eax, [seg_memsz]
    cmp eax, [seg_filesz]
    jbe .next_seg

    mov ebx, [seg_memsz]
    sub ebx, [seg_filesz]        ; bss_len
    mov edi, [seg_phys_dst]
    add edi, [seg_filesz]        ; bss_start phys
    xor al, al

.zero_loop:
    test ebx, ebx
    jz .next_seg
    ; 32-bit addr override store via FS (4GiB limit)
    db 0x64                      ; FS segment override prefix
    db 0x67                      ; 32-bit address override
    mov [edi], al
    inc edi
    dec ebx
    jmp .zero_loop

.next_seg:
    inc cx
    jmp .seg_loop

.done:
    clc
    popa
    ret

.fail:
    stc
    popa
    ret

; -----------------------------------------------------------------------------
; bootcore_elf_read_and_analyze
;   - Reads bootcore ELF header (BOOTCORE_LBA_START)
;   - Computes vaddr_base among PT_LOAD
; -----------------------------------------------------------------------------
bootcore_elf_read_and_analyze:
    pusha

    mov dword [rf_base_lba], BOOTCORE_LBA_START
    mov dword [rf_file_off_lo], 0
    mov dword [rf_len_lo], 512
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .bad

    cmp dword [TMP_SECTOR_BUF + 0x00], ELF_MAGIC
    jne .bad

    cmp byte  [TMP_SECTOR_BUF + 0x04], EI_CLASS_64
    jne .bad
    cmp byte  [TMP_SECTOR_BUF + 0x05], EI_DATA_LE
    jne .bad

    mov ax, word [TMP_SECTOR_BUF + 0x10]
    cmp ax, ET_EXEC
    je .type_ok
    cmp ax, ET_DYN
    jne .bad
.type_ok:

    cmp word  [TMP_SECTOR_BUF + 0x12], EM_X86_64
    jne .bad

    mov eax, dword [TMP_SECTOR_BUF + 0x18]
    mov dword [bootcore_e_entry], eax
    mov eax, dword [TMP_SECTOR_BUF + 0x1C]
    mov dword [bootcore_e_entry+4], eax

    mov eax, dword [TMP_SECTOR_BUF + 0x20]
    mov [bootcore_phoff_lo], eax

    mov ax, word [TMP_SECTOR_BUF + 0x36]
    mov [bootcore_phentsize], ax
    mov ax, word [TMP_SECTOR_BUF + 0x38]
    mov [bootcore_phnum], ax

    mov dword [bootcore_vaddr_base], 0xFFFFFFFF
    mov dword [bootcore_vaddr_base+4], 0xFFFFFFFF

    xor cx, cx
.ph_loop:
    cmp cx, [bootcore_phnum]
    jae .done

    movzx eax, cx
    movzx ebx, word [bootcore_phentsize]
    imul eax, ebx
    add eax, [bootcore_phoff_lo]

    mov dword [rf_file_off_lo], eax
    mov dword [rf_len_lo], 56
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .bad

    cmp dword [TMP_SECTOR_BUF + 0x00], PT_LOAD
    jne .next

    mov eax, dword [TMP_SECTOR_BUF + 0x10]
    mov edx, dword [TMP_SECTOR_BUF + 0x14]

    mov ebx, dword [bootcore_vaddr_base+4]
    cmp edx, ebx
    jb  .update
    ja  .next
    mov ebx, dword [bootcore_vaddr_base]
    cmp eax, ebx
    jae .next
.update:
    mov dword [bootcore_vaddr_base], eax
    mov dword [bootcore_vaddr_base+4], edx

.next:
    inc cx
    jmp .ph_loop

.done:
    cmp dword [bootcore_vaddr_base+4], 0xFFFFFFFF
    je .bad
    clc
    popa
    ret

.bad:
    stc
    popa
    ret

; -----------------------------------------------------------------------------
; bootcore_elf_load_segments_unreal
;   - Loads bootcore PT_LOAD segments into BOOTCORE_PHYS_BASE
; -----------------------------------------------------------------------------
bootcore_elf_load_segments_unreal:
    pusha

    mov dword [rf_base_lba], BOOTCORE_LBA_START

    xor cx, cx
.seg_loop:
    cmp cx, [bootcore_phnum]
    jae .done

    movzx eax, cx
    movzx ebx, word [bootcore_phentsize]
    imul eax, ebx
    add eax, [bootcore_phoff_lo]

    mov dword [rf_file_off_lo], eax
    mov dword [rf_len_lo], 56
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .fail

    cmp dword [TMP_SECTOR_BUF + 0x00], PT_LOAD
    jne .next_seg

    mov eax, dword [TMP_SECTOR_BUF + 0x08]
    mov [seg_file_off], eax

    mov eax, dword [TMP_SECTOR_BUF + 0x10]
    mov edx, dword [TMP_SECTOR_BUF + 0x14]
    mov [seg_vaddr_lo], eax
    mov [seg_vaddr_hi], edx

    mov eax, dword [TMP_SECTOR_BUF + 0x20]
    mov [seg_filesz], eax

    mov eax, dword [TMP_SECTOR_BUF + 0x28]
    mov [seg_memsz], eax

    mov eax, [seg_vaddr_lo]
    mov edx, [seg_vaddr_hi]
    sub eax, dword [bootcore_vaddr_base]
    sbb edx, dword [bootcore_vaddr_base+4]
    mov [seg_off_from_base], eax
    mov [seg_off_from_base_hi], edx
    test edx, edx
    jne .fail

    mov eax, BOOTCORE_PHYS_BASE
    add eax, [seg_off_from_base]
    mov [seg_phys_dst], eax

    mov eax, [seg_file_off]
    mov [rf_file_off_lo], eax
    mov eax, [seg_filesz]
    mov [rf_len_lo], eax
    mov eax, [seg_phys_dst]
    mov [rf_dst_phys], eax
    call read_file_bytes_to_phys
    jc .fail

    mov eax, [seg_memsz]
    cmp eax, [seg_filesz]
    jbe .next_seg

    mov ebx, [seg_memsz]
    sub ebx, [seg_filesz]
    mov edi, [seg_phys_dst]
    add edi, [seg_filesz]
    xor al, al

.zero_loop:
    test ebx, ebx
    jz .next_seg
    db 0x64
    db 0x67
    mov [edi], al
    inc edi
    dec ebx
    jmp .zero_loop

.next_seg:
    inc cx
    jmp .seg_loop

.done:
    clc
    popa
    ret

.fail:
    stc
    popa
    ret

; -----------------------------------------------------------------------------
; initrd_load
;   - Reads initrd size header at INITRD_LBA_START (first 8 bytes)
;   - Loads initrd data from INITRD_LBA_START+1 into memory
; -----------------------------------------------------------------------------
initrd_load:
    pusha

    mov dword [rf_base_lba], INITRD_LBA_START
    mov dword [rf_file_off_lo], 0
    mov dword [rf_len_lo], 512
    mov dword [rf_dst_phys], TMP_SECTOR_BUF
    call read_file_bytes_to_phys
    jc .bad

    mov eax, [TMP_SECTOR_BUF + 0x00]
    mov dword [initrd_size], eax
    mov eax, [TMP_SECTOR_BUF + 0x04]
    mov dword [initrd_size+4], eax

    mov eax, [initrd_size]
    mov edx, [initrd_size+4]
    test eax, eax
    jnz .load
    test edx, edx
    jnz .load
    clc
    popa
    ret

.load:
    mov eax, [max_phys_end]
    add eax, 0x0FFF
    and eax, 0xFFFFF000
    mov [initrd_phys], eax

    mov dword [rf_base_lba], INITRD_LBA_START + 1
    mov dword [rf_file_off_lo], 0
    mov eax, [initrd_size]
    mov [rf_len_lo], eax
    mov eax, [initrd_phys]
    mov [rf_dst_phys], eax
    call read_file_bytes_to_phys
    jc .bad

    mov eax, [initrd_phys]
    add eax, [initrd_size]
    mov [max_phys_end], eax

    clc
    popa
    ret

.bad:
    stc
    popa
    ret

; -----------------------------------------------------------------------------
; build_bootinfo
;   Minimal BootInfo for your Rust kernel.
;   Layout must match saltyos_ska::BootInfo exactly:
;     +0:  magic     [u8; 4]  = "SKA\0"
;     +4:  version   u32      = 0x0001
;     +8:  flags     u32      = BootFlags::BIOS (0x02)
;     +12: (padding for alignment)
;     +16: memory_map PhysAddr = 0
;     +24: memory_map_entries u32 = 0
;     ... (rest zeroed)
; -----------------------------------------------------------------------------
build_bootinfo:
    pusha
    mov di, BOOTINFO_PHYS_ADDR

    ; Clear first 256 bytes for safety (BootInfo struct may grow)
    push di
    mov cx, 256
    xor al, al
.clear_loop:
    mov [di], al
    inc di
    dec cx
    jnz .clear_loop
    pop di

    ; magic "SKA\0"
    mov dword [di + BOOTINFO_OFF_MAGIC], BOOTINFO_MAGIC_DWORD

    ; version
    mov dword [di + BOOTINFO_OFF_VERSION], BOOTINFO_VERSION

    ; flags = BIOS
    mov dword [di + BOOTINFO_OFF_FLAGS], BOOTFLAG_BIOS

    ; size = 0 (bootcore will write correct size)
    mov dword [di + BOOTINFO_OFF_SIZE], 0

    ; memory_map (u64 physical address)
    mov dword [di + BOOTINFO_OFF_MEMORY_MAP], E820_BUF_PHYS   ; low 32 bits
    mov dword [di + BOOTINFO_OFF_MEMORY_MAP + 4], 0           ; high 32 bits

    ; memory_map_entries
    xor eax, eax
    mov al, [e820_count]
    mov dword [di + BOOTINFO_OFF_MEMORY_MAP_ENT], eax

    ; All other fields (framebuffer, initrd, cmdline, rsdp) are already 0
    ; which is safe - kernel will check flags before using them

    popa
    ret

; -----------------------------------------------------------------------------
; init_bootcore_handoff
;   Initialize BootHandoff structure for bootcore (BootContext + pointers).
; -----------------------------------------------------------------------------
init_bootcore_handoff:
    pusha
    mov di, BOOTCORE_HANDOFF_PHYS

    ; Zero the whole handoff area
    mov cx, BOOTHANDOFF_SIZE
    xor al, al
.handoff_clear:
    mov [di], al
    inc di
    dec cx
    jnz .handoff_clear

    mov di, BOOTCORE_HANDOFF_PHYS

    ; Build extra TLV: reserved ranges
    ; [kind=u32][len=u32][count=u32][(base:u64,size:u64)*count]
    push di
    mov di, BOOTEXTRA_PHYS
    mov dword [di + 0], 1            ; EXTRA_KIND_MEM_RESERVED
    mov dword [di + 4], 52           ; len = 4 + 3*16
    mov dword [di + 8], 3            ; count
    ; entry 0: bootcore (1 MiB, 1 MiB)
    mov dword [di + 12], BOOTCORE_PHYS_BASE
    mov dword [di + 16], 0
    mov dword [di + 20], 0x00100000
    mov dword [di + 24], 0
    ; entry 1: bootinfo+handoff+extra (0x6000..0xC000)
    mov dword [di + 28], 0x00006000
    mov dword [di + 32], 0
    mov dword [di + 36], 0x00006000
    mov dword [di + 40], 0
    ; entry 2: page table arena (0x18000..0x28000)
    mov dword [di + 44], BOOTCORE_PT_ARENA_BASE
    mov dword [di + 48], 0
    mov dword [di + 52], BOOTCORE_PT_ARENA_SIZE
    mov dword [di + 56], 0
    pop di

    ; BootContext.flags = BIOS (+ INITRD if available)
    mov eax, BOOTFLAG_BIOS
    mov ebx, [initrd_size]
    mov ecx, [initrd_size+4]
    test ebx, ebx
    jnz .set_initrd_flag
    test ecx, ecx
    jz .flags_done
.set_initrd_flag:
    or eax, BOOTFLAG_INITRD
.flags_done:
    mov dword [di + BOOTCTX_OFF_FLAGS], eax

    ; BootContext.memory_map = E820 buffer (phys)
    mov dword [di + BOOTCTX_OFF_MEMORY_MAP], E820_BUF_PHYS
    mov dword [di + BOOTCTX_OFF_MEMORY_MAP + 4], 0

    ; BootContext.memory_map_entries = e820_count
    xor eax, eax
    mov al, [e820_count]
    mov dword [di + BOOTCTX_OFF_MEMORY_MAP_ENT], eax

    ; BootHandoff.bootinfo_ptr = BOOTINFO_PHYS_ADDR
    mov dword [di + BOOTHANDOFF_OFF_BOOTINFO_PTR], BOOTINFO_PHYS_ADDR
    mov dword [di + BOOTHANDOFF_OFF_BOOTINFO_PTR + 4], 0

    ; BootContext.initrd (ModuleInfo) if available
    mov eax, [initrd_size]
    mov ecx, [initrd_size+4]
    test eax, eax
    jnz .set_initrd
    test ecx, ecx
    jz .skip_initrd
.set_initrd:
    mov eax, [initrd_phys]
    mov dword [di + BOOTCTX_OFF_INITRD], eax
    mov dword [di + BOOTCTX_OFF_INITRD + 4], 0
    mov eax, [initrd_size]
    mov dword [di + BOOTCTX_OFF_INITRD + 8], eax
    mov dword [di + BOOTCTX_OFF_INITRD + 12], 0
.skip_initrd:

    ; BootHandoff.user_image_phys/pages (disabled)
    xor eax, eax
    mov dword [di + BOOTHANDOFF_OFF_USER_IMAGE_PHYS], eax
    mov dword [di + BOOTHANDOFF_OFF_USER_IMAGE_PHYS + 4], 0
    xor eax, eax
    mov dword [di + BOOTHANDOFF_OFF_USER_IMAGE_PAGES], eax
    mov dword [di + BOOTHANDOFF_OFF_USER_IMAGE_PAGES + 4], 0

    ; BootHandoff.user_stack_phys/pages
    xor eax, eax
    mov dword [di + BOOTHANDOFF_OFF_USER_STACK_PHYS], eax
    mov dword [di + BOOTHANDOFF_OFF_USER_STACK_PHYS + 4], 0
    xor eax, eax
    mov dword [di + BOOTHANDOFF_OFF_USER_STACK_PAGES], eax
    mov dword [di + BOOTHANDOFF_OFF_USER_STACK_PAGES + 4], 0

    ; BootHandoff page table arena
    mov dword [di + BOOTHANDOFF_OFF_PT_ALLOC_BASE], BOOTCORE_PT_ARENA_BASE
    mov dword [di + BOOTHANDOFF_OFF_PT_ALLOC_BASE + 4], 0
    mov dword [di + BOOTHANDOFF_OFF_PT_ALLOC_SIZE], BOOTCORE_PT_ARENA_SIZE
    mov dword [di + BOOTHANDOFF_OFF_PT_ALLOC_SIZE + 4], 0

    ; BootHandoff identity map size (GiB)
    mov dword [di + BOOTHANDOFF_OFF_IDENTITY_GIB], 4
    mov dword [di + BOOTHANDOFF_OFF_IDENTITY_GIB + 4], 0

    ; BootHandoff extra pointer/len
    mov dword [di + BOOTHANDOFF_OFF_EXTRA_PTR], BOOTEXTRA_PHYS
    mov dword [di + BOOTHANDOFF_OFF_EXTRA_PTR + 4], 0
    mov dword [di + BOOTHANDOFF_OFF_EXTRA_LEN], 60
    mov dword [di + BOOTHANDOFF_OFF_EXTRA_LEN + 4], 0

    popa
    ret

; -----------------------------------------------------------------------------
; e820_get_map
;   Uses BIOS INT 15h, EAX=E820h to retrieve the system memory map.
;
; Output:
;   e820_count = number of entries written
;   Buffer at E820_BUF_PHYS contains raw E820 entries (24 bytes each):
;     +0  u64 base
;     +8  u64 length
;     +16 u32 type
;     +20 u32 acpi_ext (may be 0 if BIOS returns only 20 bytes)
;
; Notes:
;   - Buffer in low memory so identity mapping covers it
;   - Must be called in real mode (BIOS interrupt requirement)
; -----------------------------------------------------------------------------
e820_get_map:
    pusha
    push es

    ; ES = 0 for low memory pointer
    xor ax, ax
    mov es, ax

    ; count = 0
    mov byte [e820_count], 0

    ; continuation = 0 (EBX=0 for first call)
    xor ebx, ebx

.next:
    ; Stop if max entries reached
    mov al, [e820_count]
    cmp al, E820_MAX_ENTRIES
    jae .done

    ; DI = E820_BUF_PHYS + count * 24
    xor ah, ah
    movzx ax, byte [e820_count]         ; AX = count
    mov cx, E820_ENTRY_SIZE             ; CX = 24
    mul cx                               ; DX:AX = count*24
    mov di, E820_BUF_PHYS
    add di, ax

    ; Zero the 24-byte slot (some BIOS return only 20 bytes)
    push di
    mov cx, E820_ENTRY_SIZE
    xor al, al
.zero_slot:
    stosb
    loop .zero_slot
    pop di

    ; INT 15h E820
    mov eax, 0xE820
    mov ecx, E820_ENTRY_SIZE
    mov edx, E820_SMAP_SIG
    int 0x15
    jc .done                             ; carry => no more / error

    ; BIOS must return 'SMAP' in EAX
    cmp eax, E820_SMAP_SIG
    jne .done

    ; Count this entry
    inc byte [e820_count]

    ; If EBX == 0, this was the last entry
    test ebx, ebx
    jnz .next

.done:
    pop es
    popa
    clc
    ret

; -----------------------------------------------------------------------------
; e820_to_memory_map
;   Convert E820 entries in-place to SKA MemoryEntry format:
;     type mapping:
;       1 -> Usable
;       2 -> Reserved
;       3 -> AcpiReclaimable
;       4 -> AcpiNvs
;       5 -> Unusable
;       other -> Reserved
; -----------------------------------------------------------------------------
e820_to_memory_map:
    pusha

    movzx cx, byte [e820_count]
    mov si, E820_BUF_PHYS

.loop:
    test cx, cx
    jz .done

    mov eax, [si + 16]
    cmp eax, 1
    je .type_usable
    cmp eax, 3
    je .type_acpi_reclaim
    cmp eax, 4
    je .type_acpi_nvs
    cmp eax, 5
    je .type_unusable
    mov eax, SKA_MEM_RESERVED
    jmp .store

.type_usable:
    mov eax, SKA_MEM_USABLE
    jmp .store
.type_acpi_reclaim:
    mov eax, SKA_MEM_ACPI_RECLAIM
    jmp .store
.type_acpi_nvs:
    mov eax, SKA_MEM_ACPI_NVS
    jmp .store
.type_unusable:
    mov eax, SKA_MEM_UNUSABLE

.store:
    mov [si + 16], eax
    add si, E820_ENTRY_SIZE
    dec cx
    jmp .loop

.done:
    popa
    ret

; =============================================================================
; 32-bit paging builder
; =============================================================================
BITS 32
setup_page_tables:
    ; Clear PML4 + PDPT + PDs (identity map only)
    mov edi, PML4_ADDR
    xor eax, eax
    mov ecx, 4096 / 4
    rep stosd
    mov edi, PDPT_LOW_ADDR
    mov ecx, 4096 / 4
    rep stosd
    mov edi, PD_LOW_ADDR
    mov ecx, 4096 / 4
    rep stosd
    mov edi, PD_LOW1_ADDR
    mov ecx, 4096 / 4
    rep stosd
    mov edi, PD_LOW2_ADDR
    mov ecx, 4096 / 4
    rep stosd
    mov edi, PD_LOW3_ADDR
    mov ecx, 4096 / 4
    rep stosd

    ; PML4[0] -> PDPT_LOW (identity low mapping, supervisor-only)
    mov dword [PML4_ADDR + 0x000], (PDPT_LOW_ADDR | 0x003)
    mov dword [PML4_ADDR + 0x004], 0

    ; PDPT_LOW[0..3] -> PD_LOW0..3 (maps 0..4GiB identity, supervisor-only)
    mov dword [PDPT_LOW_ADDR + 0x000], (PD_LOW_ADDR | 0x003)
    mov dword [PDPT_LOW_ADDR + 0x004], 0
    mov dword [PDPT_LOW_ADDR + 0x008], (PD_LOW1_ADDR | 0x003)
    mov dword [PDPT_LOW_ADDR + 0x00C], 0
    mov dword [PDPT_LOW_ADDR + 0x010], (PD_LOW2_ADDR | 0x003)
    mov dword [PDPT_LOW_ADDR + 0x014], 0
    mov dword [PDPT_LOW_ADDR + 0x018], (PD_LOW3_ADDR | 0x003)
    mov dword [PDPT_LOW_ADDR + 0x01C], 0

    ; Fill PD_LOW with 2MiB identity pages (0..1GiB, supervisor-only)
    mov edi, PD_LOW_ADDR
    mov eax, 0x00000083                  ; Present | Write | PS(2MiB)
    mov ecx, 512
.pd_low_loop:
    mov dword [edi + 0], eax
    mov dword [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop .pd_low_loop
    ; Fill PD_LOW1 with 2MiB identity pages (1..2GiB, supervisor-only)
    mov edi, PD_LOW1_ADDR
    mov eax, 0x40000083                  ; 1GiB | Present | Write | PS(2MiB)
    mov ecx, 512
.pd_low1_loop:
    mov dword [edi + 0], eax
    mov dword [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop .pd_low1_loop
    ; Fill PD_LOW2 with 2MiB identity pages (2..3GiB, supervisor-only)
    mov edi, PD_LOW2_ADDR
    mov eax, 0x80000083                  ; 2GiB | Present | Write | PS(2MiB)
    mov ecx, 512
.pd_low2_loop:
    mov dword [edi + 0], eax
    mov dword [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop .pd_low2_loop
    ; Fill PD_LOW3 with 2MiB identity pages (3..4GiB, supervisor-only)
    mov edi, PD_LOW3_ADDR
    mov eax, 0xC0000083                  ; 3GiB | Present | Write | PS(2MiB)
    mov ecx, 512
.pd_low3_loop:
    mov dword [edi + 0], eax
    mov dword [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop .pd_low3_loop

    ret

; =============================================================================
; Unreal-mode GDT (for 4GiB data segment cache)
; =============================================================================
BITS 16
align 8
gdt_unreal:
    dq 0
    ; 0x08: 16-bit code (for protected-mode transition)
    dw 0xFFFF, 0x0000
    db 0x00, 0x9A, 0x00, 0x00
    ; 0x10: data, base=0, limit=4GiB (for unreal mode cache)
    dw 0xFFFF, 0x0000
    db 0x00, 0x92, 0xCF, 0x00
gdt_unreal_end:
gdt_unreal_desc:
    dw gdt_unreal_end - gdt_unreal - 1
    dd gdt_unreal

; =============================================================================
; 32-bit and 64-bit GDTs for mode switching
; =============================================================================
align 8
gdt32:
    dq 0
    ; 0x08: 32-bit code
    dw 0xFFFF, 0x0000
    db 0x00, 0x9A, 0xCF, 0x00
    ; 0x10: 32-bit data
    dw 0xFFFF, 0x0000
    db 0x00, 0x92, 0xCF, 0x00
gdt32_end:
gdt32_desc:
    dw gdt32_end - gdt32 - 1
    dd gdt32

align 8
gdt64:
    dq 0
    ; 0x08: 64-bit code (L=1, D=0)
    dq 0x00209A0000000000
    ; 0x10: 64-bit data
    dq 0x0000920000000000
gdt64_end:
gdt64_desc:
    dw gdt64_end - gdt64 - 1
    dd gdt64

; =============================================================================
; Data / state
; =============================================================================
boot_drive:          db 0
last_int13_status:   db 0
e820_count:          db 0
force_chs:           db 0
chs_spt:             dw CHS_SECTORS
chs_heads:           dw CHS_HEADS

; ELF info extracted from header
elf_e_entry:         dq 0
elf_phoff_lo:        dd 0
elf_phentsize:       dw 0
elf_phnum:           dw 0
elf_vaddr_base:      dq 0

; Bootcore ELF info
bootcore_e_entry:    dq 0
bootcore_phoff_lo:   dd 0
bootcore_phentsize:  dw 0
bootcore_phnum:      dw 0
bootcore_vaddr_base: dq 0

; PT_DYNAMIC vaddr (link-time) captured during segment parse (IMPORTANT)
; We'll set this while loading segments (need to capture PT_DYNAMIC PHDR).
elf_dyn_vaddr:       dq 0
elf_dyn_size:        dq 0
max_phys_end:        dd 0
initrd_phys:         dd 0
initrd_size:         dq 0

; temp fields for file reads
rf_file_off_lo:      dd 0
rf_len_lo:           dd 0
rf_dst_phys:         dd 0
rf_bytes_this:       dw 0
rf_base_lba:         dd 0

tmp_ph_file_off:     dd 0
tmp_sector_index32:  dd 0
bios_lba_arg:        dd 0

; segment temp
seg_file_off:        dd 0
seg_vaddr_lo:        dd 0
seg_vaddr_hi:        dd 0
seg_filesz:          dd 0
seg_memsz:           dd 0
seg_off_from_base:   dd 0
seg_off_from_base_hi: dd 0
seg_phys_dst:        dd 0

; Convenience constant so we can refer as memory in 16-bit
%define TMP_SECTOR_BUF TMP_SECTOR_BUF_OFF
