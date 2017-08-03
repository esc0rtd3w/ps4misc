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


#include <include/jailbreak.h>

#include <ps4/standard_io.h>
#include <ps4/kernel.h>
#include <stdlib.h>

uint64_t ps4RelocPayload();

int main(int argc, char *argv[]) {

    // int jret;
    // printf("getuid() : %d\n", getuid());
    // if (getuid() != 0) {
    //     ps4KernelExecute((void*)jailbreak, NULL, &jret, NULL);
    //     printf("jailbreak!!\n");
    // }

    printf("hello world\n");

    // uint64_t ret = *(uint64_t*)0x93a4ffff8;
    // printf("the ptr: %016llX\n", ret);
    // ps4StandardIoPrintHexDump(ret, 0x100);

    uint64_t (*functionPtr)() = &ps4RelocPayload;

    uint64_t ret2 = functionPtr();
    printf("after func call\n");
    printf("ret %016llX\n", ret2);


    return EXIT_SUCCESS;
}