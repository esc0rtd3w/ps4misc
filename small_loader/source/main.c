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

#include <sys/stat.h>

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

    cp("/data/ls", "/mnt/usb0/ls");
    cp("/data/cat", "/mnt/usb0/cat");
    cp("/data/sh1", "/mnt/usb0/sh");
    cp("/data/client", "/mnt/usb0/client");

    // uint64_t ret = *(uint64_t*)0x93a4ffff8;
    // printf("the ptr: %016llX\n", ret);
    // ps4StandardIoPrintHexDump(ret, 0x100);

    //sleep(1);

    // int f = fork();
    // if (f == 0) {
    //     printf("fork result: %d\n", f);

 

        uint64_t (*functionPtr)() = &ps4RelocPayload;

        // FILE *f = fopen("/mnt/usb0/client", "r");
        // dup2(f, STDOUT_FILENO);

        // write(f, "hi", 1);
        // printf("opening file: %016llX\n", f);
        // close(f);

        // uint64_t ret3 = sceKernelLoadStartModule("libkernel.sprx", 0, NULL, 0, 0, 0);
        // printf("that lib? %016llX\n", ret3);

        // printf("sceKernelLoadStartModule %016llX\n", ps4StubResolve_ps4StubResolveLoadStartModule);

        uint64_t payloadret = functionPtr();
        printf("after func call\n");
        printf("ret %016llX\n", payloadret);

        // ps4StandardIoPrintHexDump(payloadret, 0x100);

    //     exit(0);
    // }

    return EXIT_SUCCESS;
}

#define O_RDONLY 0
#define O_WRONLY    0x0001  
#define O_CREAT 0x0200
#define O_EXCL  0x0800

int cp(const char *to, const char *from)
{
    int errno;
    int fd_to, fd_from;
    char buf[4096];
    ssize_t nread;
    int saved_errno;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0777);
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, nread);

            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);

        /* Success! */
        return 0;
    }

  out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
    return -1;
}