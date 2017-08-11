#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1
#define _KERNEL
#define _STANDALONE
#define _WANT_UCRED
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/limits.h>
#include <sys/param.h>
#include <sys/kernel.h>
//#include <sys/libkern.h>
#include <sys/systm.h>

#include <sys/sysproto.h>
//#include <sys/unistd.h>
#include <sys/syscallsubr.h>

#include <ps4/kernel.h>

#define SERVER_PORT 5088

Ps4KernelSocket *patch_another_sock;

#include <stddef.h>
#include <sys/proc.h>
#include <sys/kthread.h>

int probe() {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

	ps4KernelSocketPrint(td, patch_another_sock, "printf \n");

	pause("paused", 10000);

	ps4KernelSocketPrint(td, patch_another_sock, "unpaused\n");
}

int printf_hook(int rdi, int rsi, int rdx, int rcx) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

	ps4KernelSocketPrint(td, patch_another_sock, "printf %s\n", rdi, rsi, rdx, rcx);

	pause("paused", 1000);

	ps4KernelSocketPrint(td, patch_another_sock, "unpaused\n");
}


int panic_hook(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

	ps4KernelSocketPrint(td, patch_another_sock, "panic\n");
	ps4KernelSocketPrint(td, patch_another_sock, rdi, rsi, rdx, rcx);

	pause("hooked", 15000);
}

int myhook1(struct thread *td, Ps4KernelFunctionHookArgument *arg) {
    arg->returns->rax = 1;
    return PS4_KERNEL_FUNCTION_HOOK_CONTROL_CONTINUE;
}

int myhook2(struct thread *td, Ps4KernelFunctionHookArgument *arg) {
    arg->returns->rax = 0;
    return PS4_KERNEL_FUNCTION_HOOK_CONTROL_CONTINUE;
}

int path_self_mmap_check_function(struct thread *td, void *uap) {
    void *func1 = ps4KernelDlSym("sceSblACMgrIsAllowedToMmapSelf");
    void *func2 = ps4KernelDlSym("sceSblAuthMgrIsLoadable");
    ps4KernelFunctionPosthook(func1, myhook1);
    ps4KernelFunctionPosthook(func2, myhook2);
    return 0;
}

int unpath_self_mmap_check_function(struct thread *td, void *uap) {
    void *func1 = ps4KernelDlSym("sceSblACMgrIsAllowedToMmapSelf");
    void *func2 = ps4KernelDlSym("sceSblAuthMgrIsLoadable");
    ps4KernelFunctionUnhook(func1);
    ps4KernelFunctionUnhook(func2);
    return 0;
}

int exec_shell_imgact_patch();

char * msearch(char * start, char * haystack, int size) 
{
    char* mymem = start;
    for(;;){
        if (strncmp(mymem, haystack, size) == 0){
            return mymem;
        }
        mymem ++;
    }
}

int justanother_imgact(struct image_params *imgp);

uint64_t solveprint_symbol(struct thread *td, struct socket * sock, char * name) {
	uint64_t exec_shell_imgact = ps4KernelDlSym(name);
	ps4KernelSocketPrint(td, sock, "%s => %llX\n", name, exec_shell_imgact);
	return exec_shell_imgact;
}

int flag = 0;

int main(int argc, char **argv)
{
	struct thread *td;
	struct socket *client;

	Ps4KernelFunctionHook *h;
	int r;

	if(ps4KernelIsInKernel() != PS4_OK)
	{
		printf("This is not a user space application.\n");
		return PS4_ERROR_IS_KERNEL_ELF;
	}

	ps4KernelThreadGetCurrent(&td);

	//sock = ps4KernelSocketCreate(td, sock, PF_INET, 2, IPPROTO_TCP)

	r = ps4KernelSocketTCPServerCreateAcceptThenDestroy(td, &client, SERVER_PORT);

	patch_another_sock = client;

	r = ps4KernelSocketPrintHexDump(td, client, 0xffffffff832b3e00, 0x8);
	r = ps4KernelSocketPrintHexDump(td, client, 0xffffffff832b3e08, 0x8);
	r = ps4KernelSocketPrintHexDump(td, client, 0xfffffe002987d880, 0x10);
	
	r = ps4KernelSocketPrintHexDump(td, client, 0xfffffe0028266db0, 0x10);
	

	//uint64_t mybuffer = malloc(1024 * 1024);
	//ps4KernelSocketPrint(td, sock, "allocated data buffer: %llX\n", mybuffer);


	uint64_t activate_self_info = 0xffffffff82647030;

	uint64_t exec_self_imgact = 0xffffffff82649940; //doesn't have symbol

	solveprint_symbol(td, client, "self_orbis_sysvec");

	solveprint_symbol(td, client, "VOP_UNLOCK_APV");
	//solveprint_symbol(td, client, "vm_map_unlock");
	
	solveprint_symbol(td, client, "exec_new_vmspace");
	solveprint_symbol(td, client, "_vm_map_lock");
	solveprint_symbol(td, client, "_vm_map_unlock");
	solveprint_symbol(td, client, "vm_object_reference");
	solveprint_symbol(td, client, "vm_map_insert");
	solveprint_symbol(td, client, "vm_object_deallocate");
	solveprint_symbol(td, client, "_vn_lock");

	uint64_t printf_ref = solveprint_symbol(td, client, "printf");

	uint64_t exec_shell_imgact = solveprint_symbol(td, client, "exec_shell_imgact"); //1.76 0xffffffff82e39d30;
	uint64_t dynlib_proc_initialize_step3 = solveprint_symbol(td, client, "dynlib_proc_initialize_step3");
	uint64_t panic = solveprint_symbol(td, client, "panic");

	ps4KernelProtectionWriteDisable();

	int size = (uint64_t)msearch(justanother_imgact, "PATCH_END", 9) - (uint64_t)justanother_imgact;
	ps4KernelSocketPrint(td, patch_another_sock, "patch size: %d\n", size);

	r = ps4KernelSocketPrintHexDump(td, client, justanother_imgact, 0x60);

	*(uint64_t*)(0xffffffff83263f60) = justanother_imgact;
	// *(uint64_t*)(0xffffffff83263f60) = probe;

	//memcpy(exec_self_imgact, justanother_imgact, size);
	//bcopy(activate_self_info_patch, fn2, size);


	r = ps4KernelSocketPrintHexDump(td, client, exec_self_imgact, 0x60);

	uint64_t check_segments = 0xffffffff82648ff0;
	ps4KernelSocketPrint(td, patch_another_sock, "current_data %llX\n", *(uint64_t*)check_segments);

	// char jmp_panic[] = {0x48, 0xbb, 1,2,3,4,5,6,7,8, 0xff, 0xe3};
	// *(uint64_t*)&(jmp_panic[2]) = panic_hook;
	// memcpy(panic, jmp_panic, 12);


	// char mark_flag[] = {
	// 	//0x48, 0xbb, 1,2,3,4,5,6,7,8, //mov rbx, addr
	// 	//0x48, 0xc7, 0x30, 0x01, 0x00, 0x00, 0x00, //mov [rbx], 1
	// 	0xf3, 0x90,
	// 	0xeb, 0xfc,
	// 	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

	//*(uint64_t*)&(mark_flag[2]) = (uint64_t)&flag;

	char jmp_probe[] = {0x49, 0xbb, 1,2,3,4,5,6,7,8, 0x41, 0xff, 0xe3, 
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	*(uint64_t*)&(jmp_probe[2]) = (uint64_t)printf_hook;

	// char jmp_probe[] = {0xe8, 0x08, 0x00, 0x00, 0x00, 1,2,3,4,5,6,7,8, 0x41, 0x5b, 0x41, 0xff, 0x23};
	// *(uint64_t*)&(jmp_probe[5]) = (uint64_t)probe;

	bcopy(jmp_probe, printf_ref, 18);

	r = ps4KernelSocketPrintHexDump(td, client, 0xffffffff8240511e, 0x60);
	ps4KernelSocketPrint(td, patch_another_sock, "\n");

	//bcopy(mark_flag, 0xffffffff8240511e, 25);

	r = ps4KernelSocketPrintHexDump(td, client, 0xffffffff8240511e, 0x60);
	ps4KernelSocketPrint(td, patch_another_sock, "\n");
	
	r = ps4KernelSocketPrintHexDump(td, client, probe, 0x60);

	ps4KernelProtectionWriteEnable();

	while (1)
	{
		pause("hooked", 500);
		if (flag == 1)
		{
			ps4KernelSocketPrint(td, patch_another_sock, "flag got updated!\n");
			flag = 0;
		}
	}

	ps4KernelSocketPrint(td, patch_another_sock, "exiting!\n");

	return PS4_OK;

}
