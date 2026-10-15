bits 64
default rel
org 0x38d4b0

; ---- Address Library format-5 loader (entered from 0x2b3704) ----
cave_fmt:
    cmp dword [rsp+0x4c], ebx
    je  near 0x2b370e              ; same format as expected -> original v1/v2 path
    cmp ebx, 2                     ; only the AE (versionlib-*.bin) path gets v5 support
    jne near 0x2b3aeb
    cmp dword [rsp+0x4c], 5
    jne near 0x2b3aeb

    mov edx, 16+64                 ; skip gameVersion[4] + char name[64]
    mov r8d, 1                     ; ios_base::cur
    lea rcx, [rbp-0x70]
    call 0x23d020                  ; istream::seekg

    mov r8d, 4                     ; pointerSize (ignored)
    lea rdx, [rsp+0x40]
    lea rcx, [rbp-0x70]
    call 0xcb010
    mov r8d, 4                     ; dataFormat (ignored)
    lea rdx, [rsp+0x40]
    lea rcx, [rbp-0x70]
    call 0xcb010
    mov r8d, 4                     ; offsetCount
    lea rdx, [rsp+0x74]
    lea rcx, [rbp-0x70]
    call 0xcb010

    mov rax, [rbp-0x70]            ; stream ok?
    movsxd rcx, dword [rax+4]
    test byte [rbp+rcx-0x60], 6
    jnz near 0x2b3aeb

    movsxd rsi, dword [rsp+0x74]
    test rsi, rsi
    jle near 0x2b3aeb
    cmp rsi, 0x1000000
    ja near 0x2b3aeb

    mov [rsp+0x50], rsi            ; reserve(count)
    lea rdx, [rsp+0x50]
    mov rcx, r14
    call 0x2a1f70

    xor edi, edi                   ; id = 0
.loop:
    mov r8d, 4
    lea rdx, [rsp+0x7c]
    lea rcx, [rbp-0x70]
    call 0xcb010
    mov eax, [rsp+0x7c]            ; offset (zero-extends into rax)
    test eax, eax
    jz .next
    mov rdx, [r14+8]
    cmp rdx, [r14+0x10]
    je .slow
    mov [rdx], rdi
    mov [rdx+8], rax
    add qword [r14+8], 0x10
    jmp .next
.slow:
    mov [rsp+0x50], rdi
    mov [rsp+0x58], rax
    lea r9, [rsp+0x58]
    lea r8, [rsp+0x50]
    mov rcx, r14
    call 0x2b3bd0                  ; vector::_Emplace_reallocate
.next:
    inc rdi
    cmp rdi, rsi
    jl .loop

    mov rax, [rbp-0x70]            ; stream still ok after reading the table?
    movsxd rcx, dword [rax+4]
    test byte [rbp+rcx-0x60], 6
    jnz near 0x2b3aeb
    jmp 0x2b3ace                   ; sort + return true
cave_fmt_end:

; ---- BSGraphics::State grey default texture (1.7.99+: +0x80) ----
    align 4, int3
cave_grey:
    lea rax, [rcx+0x80]
    jmp 0x25ada
cave_end:
