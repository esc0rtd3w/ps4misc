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

