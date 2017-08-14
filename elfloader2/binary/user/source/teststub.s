.pushsection .text
.global teststub
.type teststub, @function

.intel_syntax

.macro popstring areg unique_identifier text
    call \unique_identifier\()_definition
    .asciz "\text\()"
    \unique_identifier\()_definition:
    pop \areg
.endm

.macro resolvefunc fname dest
    call \fname\()_definition
    .asciz "\fname\()"
    \fname\()_definition:
    pop rdx

    lea rax, qword ptr \dest\()
    
    mov rsi, qword ptr [rbp - 0x168] #libid

    mov rcx, rax #dest 
    mov r10, rax #dest 

    mov rdx, rdx #function name
    mov rsi, rsi #libid
    mov rdi, 0x24f
    mov rax, 0
    call r13


    test eax, eax
    jnz result_error

.endm

.macro doprinttext labeldef text
    call \labeldef\()_definition
    .asciz "\text\()"
    \labeldef\()_definition:
    pop rdx

    mov rdi, rdx
    call _strlen

    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, rdx #arg2
    mov rsi, 1 #arg1 stdout
    mov rdi, 4 #syscall
    mov rax, 0
    call r13
.endm

teststub:
.att_syntax
    mov $0x93a4FFFF8, %rax
.intel_syntax
    mov r13, qword ptr [rax]

    push rbp
    mov rbp, rsp
    sub rsp, 0x400

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

    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, 0 #arg1 stdout

    call name3
    .asciz "heythere.sprx"
    name3:
    pop rsi

    mov rdi, 594
    mov rax, 0
    call r13

    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, 0 #arg1 stdout

    call name2
    .asciz "libkernel.sprx"
    name2:
    pop rsi

    mov rdi, 594
    mov rax, 0
    call r13

    #if eax != 0, error
    test eax, eax
    jnz result_error

    resolvefunc sceKernelLoadStartModule "[rbp - 0x178]"
    resolvefunc socket "[rbp - 0x190]"
    resolvefunc connect "[rbp - 0x198]"
    resolvefunc close "[rbp - 0x200]"
    resolvefunc read "[rbp - 0x208]"
    resolvefunc write "[rbp - 0x210]"
    #0x218 socket fd
    resolvefunc fork "[rbp - 0x230]"
    resolvefunc execve "[rbp - 0x238]"
    resolvefunc dup2 "[rbp - 0x240]"

    resolvefunc sceKernelJitCreateSharedMemory "[rbp - 0x250]"
    resolvefunc sceKernelJitCreateAliasOfSharedMemory "[rbp - 0x258]"
    resolvefunc mmap "[rbp - 0x260]"
    resolvefunc open "[rbp - 0x290]"
    resolvefunc munmap "[rbp - 0x2a8]"
    resolvefunc mprotect "[rbp - 0xb0]"

    doprinttext hito_start_hello_world_ "hello from hito\n"



result_error:

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

_strlen:
  push  rcx            # save and clear out counter
  xor   rcx, rcx
_strlen_next:
  cmp   byte ptr [rdi], 0  # null byte yet?
  jz    _strlen_null   # yes, get out
  inc   rcx            # char is ok, count it
  inc   rdi            # move to next char
  jmp   _strlen_next   # process again
_strlen_null:
  mov   rax, rcx       # rcx = the length (put in rax)
  pop   rcx            # restore rcx
  ret                  # get out

stage2:
    ret

.att_syntax

.size teststub, .-teststub
.popsection
