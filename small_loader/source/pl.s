.pushsection .text
.global ps4RelocPayload
.type ps4RelocPayload, @function
.intel_syntax

ps4RelocPayload:

#alloc some stack space for outputs?
push rbp
mov rbp, rsp
sub rsp, 0x200

movdqu xmmword ptr [rbp - 0x10], xmm7
movdqu xmmword ptr [rbp - 0x20], xmm6
movdqu xmmword ptr [rbp - 0x30], xmm5
movdqu xmmword ptr [rbp - 0x40], xmm4
movdqu xmmword ptr [rbp - 0x50], xmm3
movdqu xmmword ptr [rbp - 0x60], xmm2
movdqu xmmword ptr [rbp - 0x70], xmm1
movdqu xmmword ptr [rbp - 0x80], xmm0

mov qword ptr [rbp - 0x90],  r15
mov qword ptr [rbp - 0x98],  r14
mov qword ptr [rbp - 0x100],  r13
mov qword ptr [rbp - 0x108],  r12
mov qword ptr [rbp - 0x110],  r11
mov qword ptr [rbp - 0x118],  r10
mov qword ptr [rbp - 0x120],  r9
mov qword ptr [rbp - 0x128],  r8
mov qword ptr [rbp - 0x130],  rcx
mov qword ptr [rbp - 0x138],  rdx
mov qword ptr [rbp - 0x140],  rsi
mov qword ptr [rbp - 0x148],  rdi
mov qword ptr [rbp - 0x150],  rbx

#here we do something, really safe (?)

call name1
.ascii "libkernel.sprx\n"
.byte 0
name1:
pop rax
mov qword ptr [rbp - 0x160], rax

mov rcx, 15 #arg3 
mov r10, 15 #arg3 
mov rdx, qword ptr [rbp - 0x160] #arg2
mov rsi, 1 #arg1 stdout
mov rdi, 4 #syscall
mov rax, 0
syscall

# mov r11, 9
# shl r11, 32
# add r11, 0x3a4ffff8
# mov r11, qword ptr [r11]
# call r11


mov r15, qword ptr [rbp - 0x90]
mov r14, qword ptr [rbp - 0x98]
mov r13, qword ptr [rbp - 0x100]
mov r12, qword ptr [rbp - 0x108]
mov r11, qword ptr [rbp - 0x110]
mov r10, qword ptr [rbp - 0x118]
mov r9, qword ptr [rbp - 0x120]
mov r8, qword ptr [rbp - 0x128]
mov rcx, qword ptr [rbp - 0x130]
mov rdx, qword ptr [rbp - 0x138]
mov rsi, qword ptr [rbp - 0x140]
mov rdi, qword ptr [rbp - 0x148]
mov rbx, qword ptr [rbp - 0x150]

movdqu xmm7, xmmword ptr [rbp - 0x10]
movdqu xmm6, xmmword ptr [rbp - 0x20]
movdqu xmm5, xmmword ptr [rbp - 0x30] 
movdqu xmm4, xmmword ptr [rbp - 0x40] 
movdqu xmm3, xmmword ptr [rbp - 0x50] 
movdqu xmm2, xmmword ptr [rbp - 0x60] 
movdqu xmm1, xmmword ptr [rbp - 0x70] 
movdqu xmm0, xmmword ptr [rbp - 0x80] 

mov rsp, rbp
pop rbp

ret

getlibbase:
    #which lib on which register?
    push rcx
    mov rax, 594
    syscall
    ret

getfuncaddr:
    #which lib on which register?
    push qword ptr [rbp - 0x4]
    mov rax, 591
    syscall
    ret

.ascii "ENDHERE\n"

.att_syntax

.size ps4StubResolveSystemCall, .-ps4StubResolveSystemCall
.popsection
