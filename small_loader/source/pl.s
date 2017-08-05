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
#180 = ?

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

doprinttext pttextout12 "starting 2...\n"


resolvefunc sceKernelLoadStartModule "[rbp - 0x178]"
resolvefunc socket "[rbp - 0x190]"
resolvefunc connect "[rbp - 0x198]"
resolvefunc close "[rbp - 0x200]"
resolvefunc read "[rbp - 0x208]"
resolvefunc write "[rbp - 0x210]"
#218 socket fd


#socket
    mov     edx, 0          # protocol
    mov     esi, 1          # type
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
    mov     dword ptr [rbp-12], 0x1f02A8C0
    lea     rsi, [rbp-0x10]  # addr
    mov     edx, 0x10        # len
    mov     edi, [r15 - 0x218] # fd
    call    [r15 - 0x198] #connect
    test    eax, eax
    js     result_error


dosendtext pttextout3 "[rbp-0x428]" "everything started, waiting instructions\n"

#close socket
    mov     edi, [r15 - 0x218] # fd
    mov     eax, 0
    call    [r15 - 0x200] #_close
    mov     dword ptr [rbp-0x42C], 0

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

connect_and_send:
                 push    rbp
                 mov     rbp, rsp
                 sub     rsp, 0x430
                 mov     edx, 0          # protocol
                 mov     esi, 1          # type
                 mov     edi, 2          # domain
                 call    [r15 - 0x190] #socket

                 mov     [rbp-0x428], eax
                 cmp     dword ptr [rbp-0x428], 0
                 jns     loc_4007B7


                 #do some error msg
                 #mov     edi, offset s   # "socket"
                 #call    _perror

                 mov     dword ptr [rbp-0x42c], 1
                 jmp     connect_return_400875
 # ---------------------------------------------------------------------------

 loc_4007B7:
                #doprinttext pttextout_got_socket "got socket\n"


                 lea     rdi, [rbp+0x10]
                 mov qword ptr [rdi], 0
                 mov qword ptr [rdi+8], 0
                 # mov     esi, 0x10        # n
                 # call    _bzero #bzero?

                 mov     byte ptr [rbp-15], 2
                 mov     word ptr [rbp-14], 0x2923
                 mov     dword ptr [rbp-12], 0x1f02A8C0
                 lea     rsi, [rbp-0x10]  # addr
                 mov     edx, 0x10        # len
                 mov     edi, [rbp-0x428] # fd
                 call    [r15 - 0x198] #connect
                 test    eax, eax
                 jns     after_connect_ok

                 #another error msg
                 #mov     edi, offset aConnect # "connect"
                 #call    _perror

                 mov     edi, [rbp-0x428] # fd
                 mov     eax, 0
                 call    [r15 - 0x200] # _close
                 mov     dword ptr [rbp-0x42C], 2
                 jmp     connect_return_400875
 # ---------------------------------------------------------------------------

 after_connect_ok:
                 #doprinttext pttextout_connect_ok "connect ok\n"

                 mov byte ptr [rbp-0x420], 'h'
                 mov byte ptr [rbp-0x41f], 'e'
                 mov byte ptr [rbp-0x41e], 'l'
                 mov byte ptr [rbp-0x41d], 'l'
                 mov byte ptr [rbp-0x41c], 'x'
                 mov dword ptr [rbp-0x424], 5

 loc_400814:                             
                 lea     rsi, [rbp-0x420] # buf
                 mov     edx, [rbp-0x424] # n

                 # call sendtext
                 # .asciz "helloworld"
                 # sendtext:
                 # pop rsi
                 # mov rdi, rsi
                 # call _strlen
                 # mov edx, eax

                 mov     edi, [rbp-0x428] # fd
                 mov     eax, 0
                 call    [r15 - 0x210] #_write

 do_we_read:                             
                 lea     rsi, [rbp-0x420] # buf
                 mov     edx, 0x400       # nbytes
                 mov     edi, [rbp-0x428] # fd
                 mov     eax, 0
                 call    [r15 - 0x208] #_read

                 mov     [rbp-0x424], eax
                 cmp     dword ptr [rbp-0x424], 0
                 #loop?
                 #jg      loc_400814 

dont_read:
                 mov     edi, [rbp-0x428] # fd
                 mov     eax, 0
                 call    [r15 - 0x200] #_close
                 mov     dword ptr [rbp-0x42C], 0

 connect_return_400875:                             
                                         
                 mov     eax, [rbp-0x42C]
                 leave
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




.ascii "PAYLOADENDSHERE\n"


.att_syntax

.size ps4StubResolveSystemCall, .-ps4StubResolveSystemCall
.popsection
