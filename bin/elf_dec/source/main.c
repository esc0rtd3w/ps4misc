#include <dirent.h>

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

typedef struct {
    int index;
    uint64_t fileoff;
    size_t bufsz;
    size_t filesz;
} SegmentBufInfo;


void hexdump(uint8_t *raw, size_t size) {
    for (int i = 1; i <= size; i += 1) {
        printf("%02X ", raw[i - 1]);
        if (i % 16 == 0) {
            printf("\n");
        }
    }
}


void print_phdr(Elf64_Phdr *phdr) {
    printf("=================================\n");
    printf("     p_type %08x\n", phdr->p_type);
    printf("     p_flags %08x\n", phdr->p_flags);
    printf("     p_offset %016llx\n", phdr->p_offset);
    printf("     p_vaddr %016llx\n", phdr->p_vaddr);
    printf("     p_paddr %016llx\n", phdr->p_paddr);
    printf("     p_filesz %016llx\n", phdr->p_filesz);
    printf("     p_memsz %016llx\n", phdr->p_memsz);
    printf("     p_align %016llx\n", phdr->p_align);
}


void dumpfile(char *name, uint8_t *raw, size_t size) {
    FILE *fd = fopen(name, "wb");
    if (fd != NULL) {
        fwrite(raw, 1, size, fd);
        fclose(fd);
    }
    else {
        printf("dump err.\n");
    }
}


int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out) {
    uint64_t realOffset = (index << 32) | offset;
    uint8_t *addr = (uint8_t*)mmap(0, size, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
    if (addr != MAP_FAILED) {
        memcpy(out, addr, size);
        munmap(addr, size);
        return TRUE;
    }
    else {
        printf("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
        return FALSE;
    }
}



int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *p = &phdrs[i];
        if (i != index) {
            if (p->p_filesz > 0) {
                // printf("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
                // printf("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}


SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
    printf("segment num : %d\n", num);
    SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
    int segindex = 0;
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *phdr = &phdrs[i];
        // print_phdr(phdr);

        if (phdr->p_filesz > 0 && phdr->p_type != 0x6fffff01) {
            if (!is_segment_in_other_segment(phdr, i, phdrs, num)) {
                SegmentBufInfo *info = &infos[segindex];
                segindex += 1;
                info->index = i;
                info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
                info->filesz = phdr->p_filesz;
                info->fileoff = phdr->p_offset;

                // printf("seg buf info %d -->\n", segindex);
                // printf("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
                // printf("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
            }
        }
    }
    *segBufNum = segindex;
    return infos;
}


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

void send_filestart(char * filename){
    int cmd = 0x02;
    int nsize;
    nsize = strlen(filename);

    send(mysocket, (char*)&(cmd), 4, 0);
    send(mysocket, (char*)&(nsize), 4, 0);
    send(mysocket, filename, nsize, 0);
}

void send_fileend(){
    int cmd = 0x03;
    send(mysocket, (char*)&(cmd), 4, 0);
}

void send_block(int offset, int size, char *blockdata){
    int sent;
    int cmd = 0x01;
    send(mysocket, (char*)&(cmd), 4, 0);
    send(mysocket, (char*)&(offset), 4, 0);
    send(mysocket, (char*)&(size), 4, 0);


    sent = send(mysocket, blockdata, size, 0);

    if (sent < size)
    {
        printf("[WARN] sent less data than requested %d -> %d\n", size, sent);
    }

    printf("[WARN] sent %d -> %d\n", size, sent);
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
    // FILE *sf = fopen(saveFile, "wb");
    // if (sf != NULL) {
    size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
    printf("elf header + phdr size : 0x%08X\n", elfsz);
    // fwrite(ehdr, elfsz, 1, sf);


    send_filestart(saveFile);

    send_block(0, elfsz, ehdr);

    for (int i = 0; i < segBufNum; i += 1) {
        printf("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz);
        uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
        memset(buf, 0, segBufs[i].bufsz);
        if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {

            // fseek(sf, segBufs[i].fileoff, SEEK_SET);
            // fwrite(buf, segBufs[i].bufsz, 1, sf);

            send_block(segBufs[i].fileoff, segBufs[i].bufsz, buf);
        }
        
        free(buf);
    }

    send_fileend();

    //     fclose(sf);
    // }
    // else {
    //     printf("fopen %s err : %s\n", saveFile, strerror(errno));
    // }
}


void decrypt_and_dump_self(char *selfFile, char *saveFile) {
    int fd = open(selfFile, O_RDONLY);
    if (fd != -1) {
        void *addr = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            printf("mmap %s : %p\n", selfFile, addr);

            uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
            printf("ehdr : %p\n", ehdr);

            Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
            printf("phdrs : %p\n", phdrs);

            int segBufNum = 0;
            SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
            do_dump(selfFile, fd, segBufs, segBufNum, ehdr);
            printf("dump completed\n");

            free(segBufs);
            munmap(addr, 0x4000);
        }
        else {
            printf("mmap file %s err : %s\n", selfFile, strerror(errno));
        }
    }
    else {
        printf("open %s err : %s\n", selfFile, strerror(errno));
    }
}




static void decrypt_dir (const char * dir_name)
{
    char fname[512];

    DIR * d;

    /* Open the directory specified by "dir_name". */

    d = opendir (dir_name);

    /* Check it was opened. */
    if (! d) {
        printf ("Cannot open directory '%s'\n",
                 dir_name);
        return ;
    }
    while (1) {
        struct dirent * entry;
        const char * d_name;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir (d);
        if (! entry) {
            /* There are no more entries in this directory, so break
               out of the while loop. */
            break;
        }
        d_name = entry->d_name;
        /* Print the name of the file and directory. */
    printf ("%s/%s\n", dir_name, d_name);

    if ((strstr(d_name, ".prx") != NULL) || (strstr(d_name, ".sprx") != NULL) || (strstr(d_name, ".elf") != NULL) || (strstr(d_name, ".self") != NULL)) {
        snprintf(fname, 512, "%s/%s", dir_name, d_name);
        decrypt_and_dump_self(fname, "");
    }

#if 0
    /* If you don't want to print the directories, use the
       following line: */

        if (! (entry->d_type & DT_DIR)) {
        printf ("%s/%s\n", dir_name, d_name);
    }

#endif /* 0 */


        if (entry->d_type & DT_DIR) {

            /* Check that the directory is not "d" or d's parent. */
            
            if (strcmp (d_name, "..") != 0 &&
                strcmp (d_name, ".") != 0) {
                int path_length;
                char path[PATH_MAX];
 
                path_length = snprintf (path, PATH_MAX,
                                        "%s/%s", dir_name, d_name);
                printf ("%s\n", path);
                if (path_length >= PATH_MAX) {
                    printf ("Path length has got too long.\n");
                    return ;
                }
                /* Recursively call "list_dir" with the new path. */
                decrypt_dir (path);
            }
    }
    }
    /* After going through all the entries, close the directory. */
    if (closedir (d)) {
        printf ("Could not close '%s'\n",
                 dir_name);
        return ;
    }
}

int main(int argc, char **argv)
{
    printf("hello1\n");

    if (sockconnect() != 0)
    {
        printf("exiting, connection error\n");
        return EXIT_SUCCESS;
    }

    printf("hello2\n");
    
    int64_t ret;

    printf("getuid() : %d\n", getuid());
    if (getuid() != 0) {
        ps4KernelExecute((void*)jailbreak, NULL, &ret, NULL);
        printf("jailbreak!!\n");
    }

    printf("kernel hook\n");

    ps4KernelExecute((void*)path_self_mmap_check_function, NULL, &ret, NULL);

	//decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/SceShellCore.elf");
	//decrypt_and_dump_self("/mini-syscore.elf", "/mnt/usb0/mini-syscore.elf");
    //decrypt_and_dump_self("/system/sys/SceSysCore.elf", "");
    //decrypt_and_dump_self("/system/common/lib/libkernel.sprx", "");

    decrypt_dir("/system/sys");

    //decrypt_and_dump_self("/system/common/lib/libc.sprx", "");

    printf("kernel unhook\n");
    ps4KernelExecute((void*)unpath_self_mmap_check_function, NULL, &ret, NULL);

    close(mysocket);
    
    return EXIT_SUCCESS;
}
