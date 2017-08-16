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

#include "kmain.h"
#include "jailbreak.h"


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

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define TRUE 1
#define FALSE 0

int mysocket;

int sockconnect() {
    
    char * buffer = "NULL";

    int port = 9000;

    struct sockaddr_in address;

    int cres;

    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = IP(192, 168, 2, 31);
    address.sin_port = htons(port);

    mysocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(mysocket < 0)
    {
        printf("socket -1\n");
        return -1;
    }

    cres = connect(mysocket, (struct sockaddr *)&address, sizeof(address));
    printf("connection result %d\n", cres);
    if (cres != 0) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("hello2\n");

    int64_t ret;

    printf("getuid() : %d\n", getuid());
    if (getuid() != 0) {
        ps4KernelExecute((void*)jailbreak, NULL, &ret, NULL);
        printf("jailbreak!!\n");
    }


    int port = 8099;

    printf("listening on port %d\n", port);

    int outsock;

    ps4SocketTCPServerCreateAcceptThenDestroy(&outsock, port);

    printf("connection accepted, waiting file\n");
    
    char * buf = malloc(4096 * 10);
    char * wbuf;
    int readed;
    int nameset = 0;
    int f = 0;

    while (1)
    {
        readed = read(outsock, buf, 4096 * 10);
        wbuf = buf;
        if (nameset == 0) {
            for (int i=0; i<readed;i++)
            {
                if (buf[i] == 0) {
                    f = open(buf, O_WRONLY | O_CREAT);
                    printf("setting name to %s\n", buf);
                    //name comes to here
                    wbuf = buf + i + 1;
                    readed -= i + 1;
                    nameset = 1;
                    break;
                }
            }
        }
        if (readed < 1)
            break;
        //ps4StandardIoPrintHexDump(wbuf, 0x10);
        write(f, wbuf, readed);
        printf("readed = %d\n", readed);
    }
    close(f);
    close(outsock);
    printf("read = 0, closed\n");

    return EXIT_SUCCESS;
}

