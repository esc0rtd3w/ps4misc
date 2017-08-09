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

.macro dosendtext labeldef socket text
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

mov r15, rbp

#here we do something, really safe (?)
#160 = "libkernel.sprx"
#168 = libkernel.sprx solved module addr
#170 = "sceKernelLoadStartModule"
#178 = function ptr
#180 = ptr to data sector

doprinttext pttextout1 "starting...\n"


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

doprinttext pttextout_dasdasdas "solving sceKernelJitCreateSharedMemory\n"

resolvefunc sceKernelJitCreateSharedMemory "[rbp - 0x250]"
resolvefunc sceKernelJitCreateAliasOfSharedMemory "[rbp - 0x258]"
resolvefunc mmap "[rbp - 0x260]"
resolvefunc open "[rbp - 0x290]"
resolvefunc munmap "[rbp - 0x2a8]"

doprinttext pttextout_ggdfgdgfdg "solved sceKernelJitCreateSharedMemory\n"

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

doprinttext pttextout_got_socket34 "all lib calls resolved\n"

#convert output to udp

    doprinttext pttextout_got_socket2 "connected to udp\n"


#RDI, RSI, RDX, RCX, R8, R9, XMM0–7

#fork
    call [rbp - 0x230]
    test eax, eax
    jnz checkforkerror

    jmp slave_thread

    checkforkerror:
    test eax, eax
    jns fork_ok

    doprinttext pttextout33 "fork error!\n"
    jmp result_error

    fork_ok:
    doprinttext pttextout34 "fork ok!\n"

#dosendtext pttextout3 "[rbp-0x428]" "everything started, waiting instructions\n"

#close socket
    # mov     edi, [r15 - 0x218] # fd
    # mov     eax, 0
    # call    [r15 - 0x200] #_close
    # mov     dword ptr [rbp-0x42C], 0

#call testcall
#call connect_and_send

#mov rax, qword ptr [rbp - 0x178]
#doprinttext pttextout_got_socket "connection finished\n"

#final stuff
jmp result_sucess

result_error:
mov rax, -1

result_sucess:

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

testcall:
    mov rcx, 15 #arg3 
    mov r10, 15 #arg3 
    mov rdx, qword ptr [rbp - 0x160] #arg2
    mov rsi, 1 #arg1 stdout
    mov rdi, 4 #syscall
    mov rax, 0
    syscall
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

    # this is setup from the rop on webkit

    # mov r11, 9
    # shl r11, 32
    # add r11, 0x3a4ffff8
    # mov r11, qword ptr [r11]
    # call r11

#arguments rdi = name, rax = dest
solvelib:
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, rax #arg2
    mov rsi, 0 #arg1 stdout
    mov rdi, rdi
    mov rax, 594
    syscall
    ret

solvename:
    mov rcx, rax #arg3 
    mov r10, rax #arg3 
    mov rdx, rax #dest
    mov rsi, rsi #function name
    mov rdi, rdi #lib addr
    mov rax, 0x24f
    syscall
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



slave_thread:

#perform memory magic

# sceKernelJitCreateSharedMemory(0, m->size, PROT_READ | PROT_WRITE | PROT_EXEC, &executableHandle);
    mov rdi, 0
    mov rsi, 0x20000
    mov edx, 7
    lea rcx, [rbp - 0x268]
    call [rbp - 0x250] #sceKernelJitCreateSharedMemory

# sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_READ | PROT_WRITE, &writableHandle);
    mov rdi, [rbp - 0x268] #executable handle
    mov esi, 3
    lea rdx, [rbp - 0x270] #writeable handle
    call [rbp - 0x258] #sceKernelJitCreateAliasOfSharedMemory


    # mov rdi, 0x20000
    # mov rsi, 0x20000
    # call [rbp - 0x2a8] #ummap

# m->executable = mmap(NULL, m->size, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
    mov rdi, 0x20000
    mov rsi, 0x20000
    mov edx, 5 #PROT_READ | PROT_EXEC
    mov rcx, 1 #MAP_SHARED
    mov r8, [rbp - 0x268]
    mov r9, 0
    call [rbp - 0x260] 

    mov [rbp - 0x278], rax

    # cmp rax, 0x4000
    # jz continue_loading

    popstring rdi loadfailedmsg "FAILED, exec page != 0x4000: %llX\n"
    mov rsi, [rbp - 0x278]
    call [rbp - 0x248]

    # jmp result_error

    # continue_loading:

    # m->writable = mmap(NULL, m->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);
    mov rdi, 0
    mov rsi, 0x20000
    mov edx, 3 #PROT_READ | PROT_WRITE
    mov ecx, 0x0f #MAP_PRIVATE | MAP_TYPE
    mov r8, [rbp - 0x270]
    mov r9, 0
    call [rbp - 0x260]

    mov [rbp - 0x280], rax

    mov rdi, 0x40000
    mov rsi, 0x10000
    mov edx, 3 #PROT_READ | PROT_WRITE
    mov ecx, 4111 #MAP_ANONYMOUS | MAP_TYPE
    mov r8d, 0xffffffff
    mov r9, 0
    call [rbp - 0x260]

    mov [rbp - 0x288], rax


    popstring rdi aprintfforu "data page: %llX exec: %llX write: %llX h1: %x h2: %x\n"
    mov rsi, [rbp - 0x288]
    mov rdx, [rbp - 0x278]
    mov rcx, [rbp - 0x280]
    mov r8, [rbp - 0x268]
    mov r9, [rbp - 0x270]
    call [rbp - 0x248]

    mov rdi, [rbp - 0x290]
    call primitive_hexdump

#open a file and read to those sections
    popstring rdi loaderfile "/data/rcved"
    mov rsi, 0
    call [rbp - 0x290]

    mov [rbp - 0x2a0], rax

    popstring rdi aprintfforu2 "openfile: %llX\n"
    mov rsi, [rbp - 0x2a0]
    call [rbp - 0x248]

#skip the first 0x4000 bytes
    mov rdi, [rbp - 0x2a0]
    mov rsi, [rbp - 0x280] #buffer addr
    mov rdx, 0x4000
    call [rbp - 0x208]

    popstring rdi aprintfforu3 "first read: %llX\n"
    mov rsi, rax
    call [rbp - 0x248]

#read the rest into the memory
    mov rdi, [rbp - 0x2a0]
    mov rsi, [rbp - 0x280] #buffer addr
    mov rdx, 0x20000
    call [rbp - 0x208]

    mov rax, [rbp - 0x280]
    mov byte ptr [rax], 0xc3

    popstring rdi aprintfforu4 "second read: %llX\n"
    mov rsi, rax
    call [rbp - 0x248]

    mov rdi, 0x4000
    call primitive_hexdump

    mov rdi, 0x4830
    call primitive_hexdump

    mov rdi, 0x0d571
    call primitive_hexdump

    mov rdi, 0x0d520
    call primitive_hexdump

doprinttext pttextout_executing_elf2 "executing elf\n"

#fork and jmp to 
mov rax, [rbp - 0x280]
call rax
#call [rbp - 0x278]

.ascii "PAYLOADENDSHERE\n"


.att_syntax

.size ps4StubResolveSystemCall, .-ps4StubResolveSystemCall
.popsection
