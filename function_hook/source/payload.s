.pushsection .text
.global ps4RelocPayload
.type ps4RelocPayload, @function
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

.macro dosendtext labeldef text
    call \labeldef\()_definition
    .asciz "\text\()"
    \labeldef\()_definition:
    pop rsi
    mov rdi, rsi
    call _strlen
    mov edx, eax

    mov     edi, [r15 - 0x218] # fd
    mov     eax, 0
    call    [r15 - 0x210] #_write
.endm


ps4RelocPayload:



#alloc some stack space for outputs?
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

#to use the stack base as symbol table
mov r15, rbp


call inputdata
.ascii "USER_INPUT_DATA"
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
inputdata:
pop r14

# call inputdata2
# .ascii "USER_INPUT_DATA"
# .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
# inputdata2:
# pop r14
mov r13, [r14] #syscall 0 gadget



    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, 0 #arg1 stdout

    call libkernelname1
    .asciz "libkernel.sprx"
    libkernelname1:
    pop rsi

    mov rdi, 594
    mov rax, 0
    call r13


doprinttext hellothere "hellothere\n"

#160 = "libkernel.sprx"
#168 = libkernel.sprx solved module addr
#170 = "sceKernelLoadStartModule"
#178 = function ptr


# ps4StubResolveSystemCall(594, "libkernel.sprx", 0, &outaddr_kernelbase, 0)#
    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, 0 #arg1 stdout

    call name1
    .asciz "libkernel.sprx"
    name1:
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

#resolve libc calls
    call populate_libc

doprinttext pttextout_got_socket34 "all lib calls resolved\n"


#socket
    mov     edx, 0          # protocol
    mov     esi, 2          # type, TCP = 1 UDP = 2
    mov     edi, 2          # domain
    call    [r15 - 0x190] #socket

    mov     [r15 - 0x218], eax
    cmp     dword ptr [r15 - 0x218], 0
    js     result_error

#init address struct and connect
    lea     rdi, [rbp+0x10]
    mov qword ptr [rdi], 0
    mov qword ptr [rdi+8], 0

    mov     byte ptr [rbp-15], 2
    mov     word ptr [rbp-14], 0x2923
    mov     dword ptr [rbp-12], 0x2702A8C0
    lea     rsi, [rbp-0x10]  # addr
    mov     edx, 0x10        # len
    mov     edi, [r15 - 0x218] # fd
    call    [r15 - 0x198] #connect

    test    eax, eax
    js     result_error

    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, 0 #arg1 stdout

    call name2
    .asciz "hellosystem.sprx"
    name2:
    pop rsi

    mov rdi, 594
    mov rax, 0
    call r13


#dup2 the socket to STDOUT
    mov rdi, [r15 - 0x218]
    mov rsi, 1 #STDOUT_FILENO
    call [rbp - 0x240]

    mov rdx, 10
    popstring rsi udphellostr1 "udp hello\n"
    mov rdi, [r15 - 0x218]
    call [rbp - 0x210]


doprinttext udphellostr "udp hello\n"

mov rdi, 0x900000
call primitive_hexdump

#get pid
    mov rdi, 20
    mov rax, 0
    call r13 
    mov [rbp - 0x2c0], rax

popstring rdi printpid "pid: %d\n"
mov rsi, [rbp - 0x278]
mov edx, eax
call [rbp - 0x248]


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

mov rax, 0
ret

testcall:
    mov rcx, 15 #arg3 
    mov r10, 15 #arg3 
    mov rdx, qword ptr [rbp - 0x160] #arg2
    mov rsi, 1 #arg1 stdout
    mov rdi, 4 #syscall
    mov rax, 0
    syscall
    ret

    # this is setup from the rop on webkit

    # mov r11, 9
    # shl r11, 32
    # add r11, 0x3a4ffff8
    # mov r11, qword ptr [r11]
    # call r11

populate_libc:
    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, 0 #arg2

    call libSceLibcInternal_name1
    .asciz "libSceLibcInternal.sprx"
    libSceLibcInternal_name1:
    pop rsi

    mov rdi, 594
    mov rax, 0
    call r13

    test eax, eax
    jnz result_error

    resolvefunc printf "[rbp - 0x248]"
    ret

primitive_hexdump:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30

    mov qword ptr [rbp - 0x20], rdi
    mov qword ptr [rbp - 0x10], 0

    xor rcx, rcx

    primitive_hexdump_loop:
    mov rsi, qword ptr [rbp - 0x20]

    add rsi, qword ptr [rbp - 0x10]

    mov cl, byte ptr [rsi]
    mov rsi, rcx

    call somestr2
    .asciz "%02X "
    somestr2:
    pop rdi

    call [r15 - 0x248]

    inc qword ptr [rbp - 0x10]
    cmp qword ptr [rbp - 0x10], 0x10
    jnz primitive_hexdump_loop

    doprinttext primitive_hexdump_outro "\n"

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


slave_thread:

#set debug var with malloc
#set stub as next func
    # call nextstubmarker
    # jmp stage2
    # nextstubmarker:
    # pop rax
    # mov rcx, [r14 + 8]
    # mov [rcx], rax

    doprinttext pttextout41 "i'm a slave!\n"
    doprinttext pttextout31 "everything started, waiting instructions\n"

    mov rax, 20
    syscall 
    mov [rbp - 0x2c0], rax

    popstring rdi loadfailedmsg "native exec page = %llX pid: %d\n"
    mov rsi, [rbp - 0x278]
    mov edx, eax
    call [rbp - 0x248]


#create tcp socket
    mov     edx, 0          # protocol
    mov     esi, 1          # type, TCP = 1 UDP = 2
    mov     edi, 2          # domain
    call    [r15 - 0x190] #socket

    mov     [r15 - 0x2b8], eax
    cmp     dword ptr [r15 - 0x218], 0
    js     slave_exit

#init address struct and connect
    lea     rdi, [rbp+0x10]
    mov qword ptr [rdi], 0
    mov qword ptr [rdi+8], 0

    mov     byte ptr [rbp-15], 2
    mov     word ptr [rbp-14], 0x1127 #10001
    mov     dword ptr [rbp-12], 0x0100007f #127.0.0.1
    lea     rsi, [rbp-0x10]  # addr
    mov     edx, 0x10        # len
    mov     edi, [r15 - 0x2b8] # fd
    call    [r15 - 0x198] #connect

    test    eax, eax
    js     slave_exit

    popstring rdi connected_to_proc "connected to local proc\n"
    call [rbp - 0x248]



#alloc a writeable section
    mov rdi, 0x50000000
    mov rsi, 0x20000
    mov edx, 3 #PROT_READ | PROT_WRITE
    mov ecx, 4111 #MAP_ANONYMOUS | MAP_TYPE
    mov r8d, 0xffffffff
    mov r9, 0
    call [rbp - 0x260]

    mov [rbp - 0x288], rax



#write the pid
    mov edi, [r15 - 0x2b8]
    lea rsi, [rbp - 0x2c0] #pid
    mov edx, 4
    call [r15 - 0x210] #write

#write the bss addr
    mov edi, [r15 - 0x2b8]
    lea rsi, [rbp - 0x288] #bss
    mov edx, 8
    call [r15 - 0x210] #write


#read the jmp and call it
    mov edi, [r15 - 0x2b8]
    lea rsi, [rbp - 0x278] #will become jump img
    mov edx, 8
    call [rbp - 0x208] #read

    popstring rdi connected_to_proc2 "disconnected from local proc\n"
    call [rbp - 0x248]

    mov edi, [r15 - 0x2b8]
    call [rbp - 0x200] #close



doprinttext pttextout_executing_elf2 "printing hex...\n"

popstring rdi hexcode "hex code: %x\n"
mov rsi, [rbp - 0x278]
mov rsi, [rsi]
call [rbp - 0x248]

doprinttext pttextout_executing_elf4 "executing elf before...\n"

mov rax, [rbp - 0x278]
call rax

doprinttext pttextout_executing_elf3 "execution done, exiting\n"


slave_exit:
    #exit syscall
    mov rdi, 0
    mov rax, 1
    syscall



.asciz "$_$APP_TEXT_SECTION$_$"
.asciz "/mnt/sandbox/CUSA00001_0000"

.ascii "PAYLOADENDSHERE\n"

.att_syntax

.size ps4StubResolveSystemCall, .-ps4StubResolveSystemCall
.popsection
