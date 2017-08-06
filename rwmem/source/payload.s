.pushsection .text
.global ps4RelocPayload
.type ps4RelocPayload, @function
.intel_syntax

.macro resolvefunc fname dest
    call \fname\()_definition
    .asciz "\fname\()"
    \fname\()_definition:
    pop rax
    mov qword ptr [rbp - 0x170], rax
    lea rax, qword ptr \dest\()
    mov rsi, qword ptr [rbp - 0x170]
    mov rdi, qword ptr [rbp - 0x168]

    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, rax #dest
    mov rsi, rsi #function name
    mov rdi, rdi #lib addr
    mov rax, 0x24f
    syscall

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
    syscall
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



mov eax, 0x40 #initial value
mov rbx, [r14]
mov ecx, 0 #new value
lock cmpxchg dword ptr [rbx], ecx
jz first_run

#if the printer has been sucessfully initialized
    test eax, eax
    jnz printf_the_stuff

jmp result_sucess

first_run:

#here we do something, really safe (?)
#160 = "libkernel.sprx"
#168 = libkernel.sprx solved module addr
#170 = "sceKernelLoadStartModule"
#178 = function ptr


# ps4StubResolveSystemCall(594, "libkernel.sprx", 0, &outaddr_kernelbase, 0)#
    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, rax #arg2
    mov rsi, 0 #arg1 stdout

    call name1
    .asciz "libkernel.sprx"
    name1:
    pop rdi

    mov rdi, rdi
    mov rax, 594
    syscall

    #if eax != 0, error
    test eax, eax
    jnz result_error

#doprinttext pttextout12 "starting 2...\n"

resolvefunc sceKernelLoadStartModule "[rbp - 0x178]"
resolvefunc socket "[rbp - 0x190]"
resolvefunc connect "[rbp - 0x198]"
resolvefunc close "[rbp - 0x200]"
resolvefunc read "[rbp - 0x208]"
resolvefunc write "[rbp - 0x210]"
#0x218 socket fd
resolvefunc sceKernelSpawn "[rbp - 0x220]"
resolvefunc sceKernelStat "[rbp - 0x228]"
resolvefunc fork "[rbp - 0x230]"
resolvefunc execve "[rbp - 0x238]"
resolvefunc dup2 "[rbp - 0x240]"

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


#dup2 the socket to STDOUT
    mov rdi, [r15 - 0x218]
    mov rsi, 1 #STDOUT_FILENO
    call [rbp - 0x240]

#set debug var with malloc
#set stub as next func
    # call nextstubmarker
    # jmp stage2
    # nextstubmarker:
    # pop rax
    # mov rcx, [r14 + 8]
    # mov [rcx], rax

dosendtext pttextout31 "everything started, waiting instructions\n"

# resolvefunc exit "[rbp - 0x228]"

# dosendtext pttextout310 "exit resolved\n"


#fork
    # call [rbp - 0x230]
    # test eax, eax
    # jnz checkforkerror

    # jmp slave_thread

    # checkforkerror:
    # test eax, eax
    # jns fork_ok

    # dosendtext pttextout33 "fork error!\n"
    # jmp result_error

    # fork_ok:
    # dosendtext pttextout34 "fork ok!\n"



mov eax, 0 #initial second value
mov rbx, [r14]
mov ecx, 1 #new value
lock cmpxchg dword ptr [rbx], ecx

printf_the_stuff:
mov rax, 0

# #send 200 bytes of the resolved imports
#     lea rsi, [rbp - 0x400]
#     mov edx, 0x400

#     mov     edi, [r15 - 0x218] # fd
#     mov     eax, 0
#     call    [r15 - 0x210] #_write

# #send the import table
#     mov rsi, [r14 + 8]
#     mov edx, 10032

#     mov     edi, [r15 - 0x218] # fd
#     mov     eax, 0
#     call    [r15 - 0x210] #_write

#close socket
    # mov     edi, [r15 - 0x218] # fd
    # mov     eax, 0
    # call    [r15 - 0x200] #_close

#call testcall
#call connect_and_send

#mov rax, qword ptr [rbp - 0x178]
#doprinttext pttextout_got_socket "connection finished\n"

# mov rdi, [r14+0x10]
# add rdi, 0x8925d0
# mov rdi, [rdi]

# call primitive_hexdump

#final stuff
jmp result_sucess

result_error:
mov eax, 0xffffffff

result_sucess:

test eax,eax
jnz skip_printf

#the lib has to be resolved on each call to the logger
#as the context gets lost
    lea rax, qword ptr [rbp - 0x168] #destination
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, rax #arg2
    mov rsi, 0 #arg1 stdout

    call libSceLibcInternal_name
    .asciz "libSceLibcInternal.sprx"
    libSceLibcInternal_name:
    pop rdi

    mov rdi, rdi
    mov rax, 594
    syscall

    resolvefunc printf "[rbp - 0x248]"

#printf the caller address
    call somestr
    .asciz "%016llX\n"
    somestr:
    pop rdi

    mov rsi, [rbp + 8]
    mov rax, [r14 + 0x10]
    sub rsi, rax

    call [rbp - 0x248]

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

#do printf
# #send the import table
call [rbp - 0x248]

skip_printf:

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



primitive_hexdump:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30

    mov qword ptr [rbp - 0x20], rdi
    mov qword ptr [rbp - 0x10], 0

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

    mov rax, qword ptr [rbp - 0x10]
    inc rax
    mov qword ptr [rbp - 0x10], rax
    cmp rax, 0x10
    jnz primitive_hexdump_loop

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
    dosendtext pttextout41 "i'm a slave!\n"

    mov rdi, 0
    mov rax, 1
    syscall

    call params
    .byte 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    params:
    pop rcx
    mov rdx, rcx
    mov rsi, rcx

    call filename
    .asciz "/data/app0/1eboot.bin"
    filename:
    pop rdi
    call [rbp - 0x238] #execve

    #if execve sucess context dissapeared

    # call execvefailed_str
    # .asciz "execve failed! %016llX\n"
    # execvefailed_str:
    # pop rdi
    # mov esi, eax
    # mov ecx, eax

    # call [rbp - 0x248]


slave_exit:

    #exit syscall
    mov rdi, 0
    mov rax, 1
    syscall



.asciz "$_$APP_TEXT_SECTION$_$"
.asciz "/mnt/sandbox/CUSA00001_0004"

.ascii "PAYLOADENDSHERE\n"

.att_syntax

.size ps4StubResolveSystemCall, .-ps4StubResolveSystemCall
.popsection
