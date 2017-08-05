.pushsection .text
.global ps4RelocPayload
.type ps4RelocPayload, @function
.intel_syntax

ps4RelocPayload:

call inputdata
.ascii "USER_INPUT_DATA"
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
inputdata:
pop rax





# first section should check if has to run or return
# to run, at leats 1 thread gets the userdata marked as c0fec0feh

# push rax


# mov dword ptr [rax], 0xc0fe1338

# mov eax, dword ptr [rax]

# test eax, eax
# jz gw_continue

# #exit path, already run once(or more)
# pop rax

# mov rax, 0
# ret


# gw_continue:
# pop rax
# mov dword ptr [rax], 0xc0fe1337


















#alloc some stack space for outputs?
push rbp
mov rbp, rsp
sub rsp, 0x400

mov rax, qword ptr [rax]
mov qword ptr [rbp - 0x180],  rax

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
#160 = "libkernel.sprx"
#168 = libkernel.sprx solved module addr
#170 = "sceKernelLoadStartModule"
#178 = function ptr
#180 = ptr to data sector

call name1
.ascii "libkernel.sprx"
.byte 0
name1:
pop rax
mov qword ptr [rbp - 0x160], rax

call name2
.ascii "sceKernelSpawn"
.byte 0
.ascii "sceKernelLoadStartModule"
.byte 0
.ascii "malloc"
.byte 0
name2:
pop rax
mov qword ptr [rbp - 0x170], rax #store whatever func

call testcall

mov dword ptr [rbp - 0x168], 0

# ps4StubResolveSystemCall(594, "libkernel.sprx", 0, &outaddr_kernelbase, 0)#
lea rax, qword ptr [rbp - 0x168]

mov rcx, rax #arg3 
mov r10, rax #arg3 
mov rdx, rax #arg2
mov rsi, 0 #arg1 stdout
mov rdi, qword ptr [rbp - 0x160] #syscall
mov rax, 594
syscall

#if eax != 0, error
test eax, eax
jnz result_error

# 591, module_addr, name, 0, &outaddr
lea rax, qword ptr [rbp - 0x178]

mov rcx, rax #arg3 
mov r10, rax #arg3 
mov rdx, rax
mov rsi, qword ptr [rbp - 0x170]
mov rdi, qword ptr [rbp - 0x168] #syscall
mov rax, 0x24f
syscall

test eax, eax
jnz result_error

original:

call clientname
.ascii "/mnt/usb0/client"
.byte 0
clientname:
pop rdx #filename goes to rdx

lea rdi, [rbp - 0x190] #seems something goes out? or in struct
xor esi, esi
xor rcx, rcx
mov rax, qword ptr [rbp - 0x178]
call rax

mov rcx, qword ptr [rbp - 0x180]
mov qword ptr [rcx+4], rax

#connect a socket, send, close

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

.ascii "PAYLOADENDSHERE\n"
extern:
.ascii "USER_INPUT_STUFF\n"

.att_syntax

.size ps4StubResolveSystemCall, .-ps4StubResolveSystemCall
.popsection
