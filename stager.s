BITS 64

    global main;
    extern gets;
    extern puts;
    extern fflush;
    extern strlen;
    extern memcmp;
    section .text
main:
    ; mmap a RW section
    push byte 0x9;
    pop rax 
    cdq;
    push rdx;
    pop rdi;
    push rdx;
    pop rsi;
    push rdx;
    pop r8;
    push rdx;
    pop r9;
    push rdx;
    pop r10;
    or rsi, [section_size];
    inc rdx;
    inc rdx;
    inc rdx;
    dec r8;
    add r10, 0x22;

    syscall;

    ; Save the start
    push rax;
    pop r10;

    mov r12, rsp;
    mov rsp, chain;
generic_ret:
    ret;

make_exec_and_jmp:
    ; Restore stack
    mov rsp, r12;
    
    ; bind the external functions
    mov qword [r10], gets;
    mov qword [r10 + 8], puts;
    mov qword [r10 + 0x10], fflush;
    mov qword [r10 + 0x18], strlen;
    mov qword [r10 + 0x20], memcmp;

    ; mprotect to RE instead of RW
    push byte 0xa;
    pop rax;
    push r10;
    pop rdi;
    mov rsi, [section_size];
    push byte 0x5;
    pop rdx;

    push r10;
    syscall;

    ; jmp to the inner code
    pop r10;
    mov r15, r10;
    add r10, 0x28;
    jmp r10;

; Gadgets
set_key:
    mov rdx, key;
    ret;
set_inner_encoded:
    mov rsi, inner_encoded;
    ret;
set_counter:
    xor rdi, rdi;
    ret;
set_data_end:
    mov r9, r10;
    add r9, junk - inner_encoded
    ret;
inc_regs:
    add rax, 8;
    sub rsi, -8;
    add rdi, 8;
    ret;
; Also used as a Write/What/Where gadget
push_data:
    mov [rax], rbx;
    ret;
load_data:
    mov rbx, [rdx + rdi];
    mov rcx, [rsi];
    ret;
xor_data:
    xor rbx, rcx;
    ret;
reset_counter:
    and rdi, 0x1f;
    ret;
verify_and_return:
    cmp rax, r9;
    jge generic_ret;
    sub rsp, rop_loop_end - rop_loop_start;
    ret;
pop_rax_rbx_gadget:
    pop rax;
    pop rbx;
    ret;

    section .rodata
chain:
    ; Init
    dq set_key;
    dq set_inner_encoded;
    dq set_counter;
    dq set_data_end;

    ; loop
rop_loop_start:
    dq load_data;
    dq xor_data;
    dq push_data;
    dq inc_regs;
    dq reset_counter;
    dq verify_and_return;
rop_loop_end:
    dq make_exec_and_jmp;

section_size: dq 0x5000
inner_encoded: db "ENCODED_INNER"
junk: db 0x72, 0x98, 0x31, 0xc9, 0xda, 0xe7, 0xbc, 0x92, 0x71, 0x73, 0x56, 0x53, 0x51, 0xd4, 0xbf, 0xfa, 0xd5, 0xa0, 0x47, 0xa5, 0xec, 0x54, 0x35, 0xc6, 0x25, 0x23, 0xbd, 0xbc, 0xc1, 0x71, 0x4a, 0xe5
key: db 0x28, 0xec, 0xea, 0xb4, 0x30, 0xd3, 0xde, 0x26, 0xd9, 0xb7, 0xb8, 0xee, 0xa0, 0x5e, 0x46, 0xb7, 0xc0, 0x76, 0x7e, 0x7f, 0x51, 0xae, 0xe1, 0x3e, 0xd1, 0xab, 0xef, 0x54, 0xb8, 0xc0, 0xc2, 0xe8
