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

#include <imgact.h>

void ps4RelocPayload();


int probe() {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

	ps4KernelSocketPrint(td, patch_another_sock, "probe \n");

	pause("paused", 10000);

	ps4KernelSocketPrint(td, patch_another_sock, "unpaused\n");
}

char dump[0x1000];

#include <pmap.h>

#include <machine/pmap.h>
#include <vm/vm.h>
#include <vm/vm_map.h>

int write_mem(struct thread *td, struct proc *p, uint64_t base, char *buff, int size) {
    struct uio uio;
    struct iovec iov;
    iov.iov_base = (void*)buff;
    iov.iov_len = size;

    uio.uio_iov = &iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = base;
    uio.uio_resid = size;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = UIO_WRITE;
    uio.uio_td = td;

    int ret = proc_rwmem(p, &uio);
    return ret;
}


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

char dump2[0x4000];
void socketprintsection(struct thread *td, char * title, uint64_t pos, uint64_t size)
{
		ps4KernelSocketPrint(td, patch_another_sock, title);
	    bzero(dump2, size);
	    copyin(pos, dump2, size);
	    ps4KernelSocketPrintHexDump(td, patch_another_sock, dump2, size);
		ps4KernelSocketPrint(td, patch_another_sock, "\n");
}

//exec_setregs(td, imgp, (u_long)(uintptr_t)stack_base);
uint64_t hook_exec_set_regs(struct thread *td, struct image_params *imgp, uint64_t stack_base) {
	uint64_t (*f)(uint64_t td, struct image_params *imgp, uint64_t stack_base) = 0xffffffff82603ce0;

	ps4KernelSocketPrint(td, patch_another_sock, "setting regs for %s rip(should be libkernel->start): %llx \n", imgp->args->fname, imgp->entry_addr);

	uint64_t kernel_start = imgp->entry_addr;

	int ret = f(td, imgp, stack_base);

    bzero(dump, 0x100);
    copyin(imgp->entry_addr, dump, 100);
    ps4KernelSocketPrintHexDump(td, patch_another_sock, dump, 0x20);
	ps4KernelSocketPrint(td, patch_another_sock, "\n");

	if ((imgp->args->fname != NULL) & (strstr(imgp->args->fname,"WebProcess.self") > 0))
	{
		pause("paused", 100);

		*(uint64_t*)(dump+0x70) = 0x400000; //overwrite the program entry

		ps4KernelSocketPrint(td, patch_another_sock, "setting regs for %s\n", imgp->args->fname);
		

	    bzero(dump, 0x100);
	    copyin(stack_base, dump, 0xc0*2);

		socketprintsection(td, "stack_base:\n", stack_base, 0xc0);


		uint64_t program_entry = *(uint64_t*)(dump+0x70);

//overwrite the program entry
		*(uint64_t*)(dump+0x70) = 0x400000; 
	    copyout(dump, stack_base, 0xc0*2); 

		socketprintsection(td, "program entry before:\n", program_entry, 0x20);


		//not possible to use copyout, would need proc_rwmem
	    //copyout(ps4RelocPayload, 0x400000, 0x100); 

		uint64_t gadget = kernel_start + (0x45a - 0x1bd58);


		socketprintsection(td, "gadget:\n", gadget, 0x60);

        char * userdata = msearch(ps4RelocPayload, "USER_INPUT_DATA", 15);
        uint64_t offset = (uint64_t)userdata - (uint64_t)ps4RelocPayload;
        uint64_t psize = (uint64_t)msearch(ps4RelocPayload, "PAYLOADENDSHERE", 15) - (uint64_t)ps4RelocPayload;
        

		//pause("paused", 100);

		uint64_t webprocess_invalid_args = program_entry + 0x742 - 0x8c0;

        int ret = write_mem(td, imgp->proc, 0x400000, ps4RelocPayload, psize);
		ret = write_mem(td, imgp->proc, 0x400000 + offset, &gadget, 8);
		uint64_t gadget2 = program_entry + 0x16a0 - 0x8c0;
		ret = write_mem(td, imgp->proc, 0x400000 + offset + 8, &gadget2, 8);

//write a jmp to 0x400000
		char ajmp [] = {0x48, 0xbb, 1,2,3,4,5,6,7,8, 0xff, 0xe3};
		*(uint64_t*)&(ajmp[2]) = 0x400000;

		// ret = write_mem(td, imgp->proc, program_entry, &ajmp, 12);

		socketprintsection(td, "after injecting payload:\n", program_entry, 0x100);

		pause("paused", 100);

		//0x400000

   //      struct vmspace *vmspace;
   //      vm_map_t map;

   //      vmspace = imgp->proc->p_vmspace;
   //      map = &vmspace->vm_map;

		 // vm_map_protect 	( 	map,
			// 	0x400000,
			// 	0x410000,
			// 	VM_PROT_READ | VM_PROT_EXECUTE,
			// 	1 
			// );

		ps4KernelSocketPrint(td, patch_another_sock, "pmap_protect returned v35\n");
	}

	return ret;
}

uint64_t hook_sys_dynlib_load_prx(uint64_t rdi, uint64_t rsi)
{
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

	uint64_t (*sys_dynlib_load_prx)(uint64_t rdi, uint64_t rsi) = 0xffffffff825e28f0;

	char name[0x400];
	copyin(*(uint64_t*)rsi, name, 0x400);

	ps4KernelSocketPrint(td, patch_another_sock, "sys_dynlib_load_prx loading lib %s\n", name);

	int error = sys_dynlib_load_prx(rdi, rsi);

	ps4KernelSocketPrint(td, patch_another_sock, "sys_dynlib_load_prx ret: %d\n", error);

	return error;
}

//might be disruptive, can be turned off
int printf_hook(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r1, uint64_t r2) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

	ps4KernelSocketPrint(td, patch_another_sock, "print hook, %s\n", rdi);
	ps4KernelSocketPrint(td, patch_another_sock, rdi, rsi, rdx, rcx, r1, r2);
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
	uint64_t NDINIT = solveprint_symbol(td, client, "_NDINIT");
	uint64_t NDFREE = solveprint_symbol(td, client, "NDFREE");
	uint64_t namei = solveprint_symbol(td, client, "namei");
	uint64_t NDHASGIANT = solveprint_symbol(td, client, "_NDHASGIANT");
	

	uint64_t printf_ref = solveprint_symbol(td, client, "printf");

	uint64_t exec_shell_imgact = solveprint_symbol(td, client, "exec_shell_imgact"); //1.76 0xffffffff82e39d30;
	uint64_t dynlib_proc_initialize_step3 = solveprint_symbol(td, client, "dynlib_proc_initialize_step3");
	uint64_t panic = solveprint_symbol(td, client, "panic");

	ps4KernelProtectionWriteDisable();

	int size = (uint64_t)msearch(ps4RelocPayload, "PAYLOADENDSHERE", 15) - (uint64_t)ps4RelocPayload;
	ps4KernelSocketPrint(td, patch_another_sock, "patch size: %d\n", size);

	//r = ps4KernelSocketPrintHexDump(td, client, justanother_imgact, 0x60);

	*(uint64_t*)(0xffffffff83263f60) = justanother_imgact;
	*(uint64_t*)(0xffffffff83263ed8) = hook_exec_set_regs;
	*(uint64_t*)(0xffffffff83234bd8) = hook_sys_dynlib_load_prx;
	// *(uint64_t*)(0xffffffff83263f60) = probe;

	//memcpy(exec_self_imgact, justanother_imgact, size);
	//bcopy(activate_self_info_patch, fn2, size);


	//r = ps4KernelSocketPrintHexDump(td, client, exec_self_imgact, 0x60);

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

	char jmp_probe[] = {0x49, 0xbb, 1,2,3,4,5,6,7,8, 0x41, 0xff, 0xe3, 0x90};
	*(uint64_t*)&(jmp_probe[2]) = (uint64_t)printf_hook;

	// char jmp_probe[] = {0xe8, 0x08, 0x00, 0x00, 0x00, 1,2,3,4,5,6,7,8, 0x41, 0x5b, 0x41, 0xff, 0x23};
	// *(uint64_t*)&(jmp_probe[5]) = (uint64_t)probe;

	//too much chance of crashing at start time just for some dbg output
	// critical_enter();
	// if (memcmp(jmp_probe, printf_ref, 14) != 0)
	// 	bcopy(jmp_probe, printf_ref, 14);
	// critical_exit();

	ps4KernelProtectionWriteEnable();

	ps4KernelSocketPrint(td, patch_another_sock, "started sucessfully\n");

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
