#define _WANT_UCRED
#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/elf64.h>
#include <ps4/standard_io.h>
#include <kernel.h>
#include <ps4/kernel.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <ps4/socket.h>

#include <netinet/in.h>

#include <ps4/util.h>
#include <ps4/error.h>

void syscall2(uint64_t i_rdi, ...) {
   __asm__(
   "push %%r11\n\
   mov $0x93a4FFFF8, %%r11\n\
   mov (%%r11), %%r11\n\
   mov %0, %%rdi;\n\
   mov $0, %%rax;\n\
   call *%%r11\n\
   pop %%r11" : : "r" (i_rdi)
   );
}

int main(uint64_t stackbase) {
    //syscall2(4, 1, "hi_there", 8);

    uint64_t cur_stack;

   __asm__(
    "mov %%rbp, %0" 
        : "=r" (cur_stack) :
   );

    printf("hello world, stackbase: %llx curstackptr: %llx\n", stackbase, cur_stack);
    uint64_t argc = *(uint64_t*)stackbase;

    printf("argc = %d \n", argc);

    for (int i=0; i<10; i++)
    {
        printf("stack[i]: %llx\n", *(uint64_t*)(cur_stack + i*8 ));
    }

    //try bind sock
    //can't, exit
    return 0;
}