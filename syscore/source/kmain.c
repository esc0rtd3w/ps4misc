#undef _SYS_CDEFS_H_
#undef _SYS_TYPES_H_
#undef _SYS_PARAM_H_
#undef _SYS_MALLOC_H_

#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1
#define _KERNEL
#define _WANT_UCRED

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/filedesc.h>
#include <sys/file.h>

#include <sys/proc.h>
#include <sys/ptrace.h>

#undef offsetof
#include <kernel.h>
#include <ps4/kernel.h>

#include "kmain.h"



int myhook(struct thread *td, Ps4KernelFunctionHookArgument *arg) {

	RunnableInt sceSblRcMgrIsAllowDisablingAslr = (RunnableInt)ps4KernelDlSym("sceSblRcMgrIsAllowDisablingAslr");
	sceSblRcMgrIsAllowDisablingAslr();

	RunnableInt sceSblRcMgrIsSoftwagnerQafForAcmgr = (RunnableInt)ps4KernelDlSym("sceSblRcMgrIsSoftwagnerQafForAcmgr");
	sceSblRcMgrIsSoftwagnerQafForAcmgr();

	RunnableInt sysdump_output_establish_secure_context_on_dump = (RunnableInt)ps4KernelDlSym("sysdump_output_establish_secure_context_on_dump");
	sysdump_output_establish_secure_context_on_dump();

	RunnableInt sceSblRcMgrIsAllowSLDebugger = (RunnableInt)ps4KernelDlSym("sceSblRcMgrIsAllowSLDebugger");
	sceSblRcMgrIsAllowSLDebugger();

	RunnableInt sceSblRcMgrIsAllowULDebugger = (RunnableInt)ps4KernelDlSym("sceSblRcMgrIsAllowULDebugger");
	sceSblRcMgrIsAllowULDebugger();

	RunnableInt sceSblRcMgrIsAllowDataExecutionInFselfProcess = (RunnableInt)ps4KernelDlSym("sceSblRcMgrIsAllowDataExecutionInFselfProcess");
	sceSblRcMgrIsAllowDataExecutionInFselfProcess();

	RunnableInt sceSblAIMgrIsDiag = (RunnableInt)ps4KernelDlSym("sceSblAIMgrIsDiag");
	sceSblAIMgrIsDiag();

    arg->returns->rax = 1;
    return PS4_KERNEL_FUNCTION_HOOK_CONTROL_CONTINUE;
}




int read_mem(struct thread *td, struct proc *p, uint64_t base, char *buff, int size) {
    struct uio uio;
    struct iovec iov;
    iov.iov_base = (void*)buff;
    iov.iov_len = size;

    uio.uio_iov = &iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = base;
    uio.uio_resid = size;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = UIO_READ;
    uio.uio_td = td;

    int ret = proc_rwmem(p, &uio);
    return ret;
}

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

int sys_read_process_mem(struct thread *td, void *uap) {
    char *mem = (char *)uap;    // ** user memory
    struct malloc_type *mt = ps4KernelDlSym("M_TEMP");
    void *kmem = malloc(sizeof(struct ReadMemArgs), mt, M_ZERO | M_WAITOK);
    struct ReadMemArgs *args = (struct ReadMemArgs*)kmem;
    copyin(mem, kmem, sizeof(struct ReadMemArgs));

    struct proc *p = pfind(args->pid);
    if (p != NULL) {
        void *buff = malloc(args->len, mt, M_ZERO | M_WAITOK);
        int ret = read_mem(td, p, args->offset, buff, args->len);
        if (ret == 0) {
            copyout(buff, args->buff, args->len);
        }
        free(buff, mt);

        PROC_UNLOCK(p);
        ps4KernelThreadSetReturn(td, ret);
    }
    else {
        ps4KernelThreadSetReturn(td, -1);
    }

    free(kmem, mt);
    return 0;
}

int sys_write_process_mem(struct thread *td, void *uap) {
    char *mem = (char *)uap;    // ** user memory
    struct malloc_type *mt = ps4KernelDlSym("M_TEMP");
    void *kmem = malloc(sizeof(struct WriteMemArgs), mt, M_ZERO | M_WAITOK);
    struct WriteMemArgs *args = (struct WriteMemArgs*)kmem;
    copyin(mem, kmem, sizeof(struct WriteMemArgs));

    struct proc *p = pfind(args->pid);
    if (p != NULL) {
        void *buff = malloc(args->len, mt, M_ZERO | M_WAITOK);
        copyin(args->buff, buff, args->len);
        //((char*)buff)[0] = 'E';
        int ret = write_mem(td, p, args->offset, buff, args->len);
        free(buff, mt);

        PROC_UNLOCK(p);
        ps4KernelThreadSetReturn(td, ret);
    }
    else {
        ps4KernelThreadSetReturn(td, -1);
    }

    free(kmem, mt);
    return 0;
}
