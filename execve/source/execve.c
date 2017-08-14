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

#include "kmain.h"
#include "jailbreak.h"


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <ps4/util.h>
#include <ps4/error.h>

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define TRUE 1
#define FALSE 0

int mysocket;


//59  AUE_EXECVE  STD { int execve(char *fname, char **argv, char **envv); }
//74  AUE_MPROTECT    STD { int mprotect(void *addr, size_t len, int prot); }
int syscall2(int rsi, ...);
__asm__("syscall2: mov $0, %rax \n syscall\n ret");


int main(int argc, char **argv)
{
    char* args[10];
    int64_t f, e;


    printf("hello1\n");

    int64_t ret;

    printf("getuid() : %d\n", getuid());
    if (getuid() != 0) {
        ps4KernelExecute((void*)jailbreak, NULL, &ret, NULL);
        printf("jailbreak!!\n");
    }

    // uint64_t x = mmap(0x9000000, 0x10000,  PROT_READ |  PROT_WRITE,  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    // printf("mmap returned: %llx\n", x);

    // *(uint64_t*) x = 0xc3;
    // printf("1 byte set\n");

    f = fork();
    if (f == 0)
    {
        sleep(1);
        printf("fork: %d\n", f);

        //e = syscall2(4, 1, "/data/ls", 8); //R/W

        // uint64_t x = mmap(0x9000000, 0x10000,  PROT_READ |  PROT_WRITE,  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        // printf("mmap returned: %llx\n", x);
        // *(uint64_t*) x = 1;
        // printf("1 byte set\n");
        // // e = syscall2(74, x, 0x4000, 3); //R/W
        // // printf("mprotect: %d\n", e);

        // // void (*aproc)() = x;
        // // aproc();

        // printf("func returned\n");

        args[0] = "";
        args[1] = NULL;

        //e = syscall2(59, "/data/rcved", args, args);
        e = syscall2(59, "/mnt/usb0/app0/eboot.bin", args, args);

        printf("execve: %d\n", e);
        //e = execv("/mnt/usb0/sh", args);

        __asm__("mov $1, %rax \n mov $0, %rdi \n syscall");
    }
    if (f < 0)
    {
        printf("fork exception: %d\n", f);
    }
    
    return EXIT_SUCCESS;
}
