#define __BSD_VISIBLE 1
#define _KERNEL
#include <sys/types.h>
#include <sys/cdefs.h>


#include <sys/param.h>
//#include <sys/exec.h>
//#include <sys/imgact_aout.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
//#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/systm.h>
//#include <sys/vnode.h>

#include <machine/frame.h>
//#include <machine/md_var.h>

#include <pmap.h>

#include <machine/pmap.h>
#include <vm/vm.h>
#include <vm/vm_map.h>
//#include <vm/vm_object.h>
#include <vm/vm_param.h>

#include <imgact.h>

#include <ps4/kernel.h>

///home/user/projects/freebsd/sys/sys/namei.h
//#include </home/user/projects/freebsd/sys/sys/bufobj.h>
#include </home/user/projects/freebsd/sys/sys/namei.h>
//#include </home/user/projects/freebsd/sys/sys/vnode.h>

#define LK_EXCLUSIVE    0x080000
#define LK_RETRY        0x000400

#define AT_FDCWD        -100

Ps4KernelSocket *patch_another_sock;

int justanother_imgact(struct image_params *imgp) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    struct proc *p = td->td_proc;
    struct nameidata nd;
    struct ucred *newcred = NULL, *oldcred;
    struct uidinfo *euip;
    register_t *stack_base;
    int error, i;
    //struct image_params image_params, *imgp;

    int (*img_first)(struct image_params *);
    struct pargs *oldargs = NULL, *newargs = NULL;
    struct sigacts *oldsigacts, *newsigacts;
    struct vnode *textvp = NULL, *binvp = NULL;
    int credential_changing;
    int vfslocked;
    int textset;
    static const char fexecv_proc_title[] = "(fexecv)";

    vfslocked = 0;

    // ps4KernelProtectionWriteDisable();
    // *(uint64_t*)(0xffffffff83263f60) = 0xffffffff82649940; //restore original exec
    // ps4KernelProtectionWriteEnable();

    ps4KernelSocketPrint(td, patch_another_sock, "executing %s\n", imgp->args->fname);

    ps4KernelSocketPrint(td, patch_another_sock, "header %llx\n", *(uint64_t *)(imgp->image_header + 0));

    if (*(uint8_t *)(imgp->image_header + 0) != 0x78)
    {
        ps4KernelSocketPrint(td, patch_another_sock, "forwarding to exec_self_imgact\n");
        int (*exec_self_imgact)(struct image_params *imgp) = 0xffffffff82649940;
        return exec_self_imgact(imgp);
    }

    //should unmount my own file ?
    char * fname = "/system/common/lib/MonoCompiler.elf";

    NDINIT(&nd, LOOKUP, ISOPEN | LOCKLEAF | FOLLOW | SAVENAME
        | MPSAFE | AUDITVNODE1, UIO_SYSSPACE, fname, td);

    error = namei(&nd);
    ps4KernelSocketPrint(td, patch_another_sock, "namei returned: %d\n", error);
    if (error)
        goto exec_fail;

    vfslocked = NDHASGIANT(&nd);
    binvp  = nd.ni_vp;
    imgp->vp = binvp;

    error = exec_check_permissions(imgp);
    ps4KernelSocketPrint(td, patch_another_sock, "exec_check_permissions returned: %d\n", error);
    if (error)
        goto exec_fail_dealloc;

    imgp->object = *(uint64_t*)((uint64_t)imgp->vp + 0x1a8); //vp->v_object
    if (imgp->object != NULL)
        vm_object_reference(imgp->object);

    error = exec_map_first_page(imgp);
    ps4KernelSocketPrint(td, patch_another_sock, "exec_map_first_page returned: %d\n", error);
    if (error)
        goto exec_fail_dealloc;

    
    ps4KernelSocketPrintHexDump(td, patch_another_sock, imgp->image_header, 0x20);

    ps4KernelSocketPrint(td, patch_another_sock, "forwarding to exec_self_imgact\n");
    int (*exec_self_imgact)(struct image_params *imgp) = 0xffffffff82649940;
    int ret = exec_self_imgact(imgp);

    ps4KernelSocketPrint(td, patch_another_sock, "exec_self_imgact returned: %d\n", ret);

    if (ret)
        goto exec_fail_dealloc;


    ps4KernelSocketPrint(td, patch_another_sock, "entry point: %llx\n", imgp->entry_addr);


    uint64_t prevrbp;
    __asm__ ("mov %%rbp, %0" : "=r"(prevrbp));

    ps4KernelSocketPrint(td, patch_another_sock, "ret addr: %llx\n", prevrbp);
    ps4KernelSocketPrintHexDump(td, patch_another_sock, prevrbp, 0x20);

    prevrbp = *(uint64_t*)prevrbp;

    ps4KernelSocketPrint(td, patch_another_sock, "prev rbp: %llx\n", prevrbp);

    //should be a if
    ps4KernelSocketPrint(td, patch_another_sock, "prev imgp: %llx cur: %llx\n", *(uint64_t*)(prevrbp - 0x1e8), imgp);

    uint64_t procstruct = *(uint64_t*)(prevrbp - 0x208);
    ps4KernelSocketPrint(td, patch_another_sock, "proc: %llx\n", procstruct);


    //proc+0x7d0 -> orbis sysvec
    ps4KernelSocketPrint(td, patch_another_sock, "proc->0x7d0\n", *(uint64_t*)(procstruct + 0x7d0));
    uint64_t self_orbis_sysvec = *(uint64_t*)(procstruct + 0x7d0);
    uint64_t unk1 = *(uint64_t*)(self_orbis_sysvec + 0x38); //??? many suword64
    uint64_t exec_copyout_strings = *(uint64_t*)(self_orbis_sysvec + 0x98); //exec_copyout_strings
    uint64_t exec_set_regs = *(uint64_t*)(self_orbis_sysvec + 0xa0); //set_regs

    //dtrace_fasttrap_exec can be used

    return 0;

exec_fail_dealloc:
    //need to free the file lock
exec_fail:
    return 9;
}
