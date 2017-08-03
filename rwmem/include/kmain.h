#ifndef KMainH
#define KMainH

#include <sys/sysent.h>

typedef int (*RunnableInt)();


struct ReadMemArgs {
    int pid;
    uint64_t offset;
    void *buff;
    int len;
};

struct WriteMemArgs{
	int pid;
	uint64_t offset;
	char *buff;
	int len;
};

int is_dev_kit_function(struct thread *td, void *uap);
int sys_read_process_mem(struct thread *td, void *uap);
int sys_write_process_mem(struct thread *td, void *uap);
int jailbreak(struct thread *td, void *uap);

#endif
