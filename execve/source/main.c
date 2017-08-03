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


int main(int argc, char **argv)
{
    char* args[10];
    int64_t f, e;

    args[0] = NULL;

    printf("hello1\n");

    int64_t ret;

    printf("getuid() : %d\n", getuid());
    if (getuid() != 0) {
        ps4KernelExecute((void*)jailbreak, NULL, &ret, NULL);
        printf("jailbreak!!\n");
    }

    f = fork();
    printf("fork: %d\n", f);

    if (f == 0)
    {
        e = execv("/mnt/usb0/sh", args);
        printf("execve: %d\n", e);
    }
    
    return EXIT_SUCCESS;
}
