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


int main(int argc, char **argv) {
    printf("hello world %d %llx\n", argc, argv);

    //try bind sock
    //can't, exit

}