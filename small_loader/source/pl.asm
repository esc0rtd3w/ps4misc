BITS 64

mov rax, 0x1337
ret

;alloc some stack space for outputs?
push rbp
mov rbp, rsp
sub rsp, 0x40

call name1
db 'libkernel.sprx'
db 0
name1:
pop rax
mov qword [rbp - 0x4], rax ;store kernel name

call name2
db 'sceKernelLoadStartModule'
db 0
name2:
pop rax
mov qword [rbp - 0x8], rax ;store whatever func

mov rcx, qword [rbp - 0x4]
call getlibbase
mov qword [rbp - 0x4], rax ;store kernel base

;call getfuncaddr

add rsp, 0x40
pop rbp

ret

getlibbase:
    ;which lib on which register?
    push rcx
    mov rax, 594
    syscall
    ret

getfuncaddr:
    ;which lib on which register?
    push qword [rbp - 0x4]
    mov rax, 591
    syscall
    ret
