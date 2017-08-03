#define _XOPEN_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ps4/memory.h>
#include <ps4/file.h>
#include <ps4/socket.h>
#include <ps4/util.h>
#include <ps4/standard_io.h>
#include <ps4/kernel.h>

#include <kernel.h>


#include <include/jailbreak.h>

#include <ps4/standard_io.h>
#include <ps4/kernel.h>
#include <stdlib.h>

uint64_t ps4RelocPayload();
uint64_t ps4StubResolve_ps4StubResolveLoadStartModule;

int main(int argc, char *argv[]) {

    int64_t jret;
    printf("getuid() : %d\n", getuid());
    if (getuid() != 0) {
        ps4KernelExecute((void*)jailbreak, NULL, &jret, NULL);
        printf("jailbreak!!\n");
    }

    printf("hello world\n");

    // uint64_t ret = *(uint64_t*)0x93a4ffff8;
    // printf("the ptr: %016llX\n", ret);
    // ps4StandardIoPrintHexDump(ret, 0x100);

    //int f = fork();
    //printf("fork result: %d\n", f);
    //if (f == 0) {
        uint64_t (*functionPtr)() = &ps4RelocPayload;

        // uint64_t ret3 = sceKernelLoadStartModule("libkernel.sprx", 0, NULL, 0, 0, 0);
        // printf("that lib? %016llX\n", ret3);

        // printf("sceKernelLoadStartModule %016llX\n", ps4StubResolve_ps4StubResolveLoadStartModule);

        uint64_t payloadret = functionPtr();
        printf("after func call\n");
        printf("ret %016llX\n", payloadret);

        ps4StandardIoPrintHexDump(payloadret, 0x100);

        //exit(0);
    //}

    return EXIT_SUCCESS;
}