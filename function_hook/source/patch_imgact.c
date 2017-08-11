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

enum vtype      { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD,
                  VMARKER };

struct vattr {
        enum vtype      va_type;        /* vnode type (for create) */
        u_short         va_mode;        /* files access mode and type */
        short           va_nlink;       /* number of references to file */
        uid_t           va_uid;         /* owner user id */
        gid_t           va_gid;         /* owner group id */
        dev_t           va_fsid;        /* filesystem id */
        long            va_fileid;      /* file id */
        u_quad_t        va_size;        /* file size in bytes */
        long            va_blocksize;   /* blocksize preferred for i/o */
        struct timespec va_atime;       /* time of last access */
        struct timespec va_mtime;       /* time of last modification */
        struct timespec va_ctime;       /* time file changed */
        struct timespec va_birthtime;   /* time file created */
        u_long          va_gen;         /* generation number of file */
        u_long          va_flags;       /* flags defined for file */
        dev_t           va_rdev;        /* device the special file represents */
        u_quad_t        va_bytes;       /* bytes of disk space held by file */
        u_quad_t        va_filerev;     /* file modification number */
        u_int           va_vaflags;     /* operations flags, see below */
        long            va_spare;       /* remain quad aligned */
};


int hihack_exec(struct image_params *imgp) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    struct image_args args;
    args.buf = "";
    args.begin_argv = "";
    args.begin_envv = "";
    args.fname = "/system/common/lib/WebProcess.self";
    args.fname_buf = NULL;
    args.argc = 0;
    args.envc = 0;
    args.fd = 0;


    struct vattr attr;

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

    imgp->proc = p;
    imgp->execlabel = NULL;
    imgp->attr = &attr;
    imgp->entry_addr = 0;
    imgp->reloc_base = 0;
    imgp->vmspace_destroyed = 0;
    imgp->interpreted = 0;
    imgp->opened = 0;
    imgp->interpreter_name = NULL;
    imgp->auxargs = NULL;
    imgp->vp = NULL;
    imgp->object = NULL;
    imgp->firstpage = NULL;
    imgp->ps_strings = 0;
    imgp->auxarg_size = 0;
    imgp->args = &args;
    imgp->execpath = imgp->freepath = NULL;
    imgp->execpathp = 0;
    imgp->canary = 0;
    imgp->canarylen = 0;
    imgp->pagesizes = 0;
    imgp->pagesizeslen = 0;
    imgp->stack_prot = 0;

    imgp->image_header = NULL;

    //should unmount my own file ?
    NDINIT(&nd, LOOKUP, ISOPEN | LOCKLEAF | FOLLOW | SAVENAME
        | MPSAFE | AUDITVNODE1, UIO_SYSSPACE, args.fname, td);

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

    imgp->proc->p_osrel = 0;

    if (imgp->image_header != NULL)
        ps4KernelSocketPrintHexDump(td, patch_another_sock, imgp->image_header, 0x20);

    ps4KernelSocketPrint(td, patch_another_sock, "calling exec_self_imgact\n");
    int (*exec_self_imgact)(struct image_params *imgp) = 0xffffffff82649940;
    error = exec_self_imgact(imgp);

    ps4KernelSocketPrint(td, patch_another_sock, "exec_self_imgact returned: %d\n", error);

    if (error)
        goto exec_fail_dealloc;


    ps4KernelSocketPrint(td, patch_another_sock, "entry point: %llx\n", imgp->entry_addr);

    return 0;

exec_fail_dealloc:
    //need to free the file lock
    
exec_fail:
    return error;

}

int justanother_imgact(struct image_params *imgp) {
    int (*vm_map_insert)(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
              vm_offset_t start, vm_offset_t end, vm_prot_t prot, vm_prot_t max,
              int cow) = 0xFFFFFFFF825AD410;


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

        error = exec_self_imgact(imgp);

        
        ps4KernelSocketPrint(td, patch_another_sock, "exec_self_imgact: %d\n", error);
        if (error)
            return 9; 

        if (strstr(imgp->args->fname, "WebProcess.self") < 1)
            return 0;

        ps4KernelSocketPrint(td, patch_another_sock, "entry point: %llx\n", imgp->entry_addr);

        struct vmspace *vmspace;
        vm_map_t map;

        vmspace = imgp->proc->p_vmspace;
        map = &vmspace->vm_map;

            //empty exec mapping, needs to be initialized with proc_rwmem
        error = vm_map_insert(map, NULL, 0,
            0x400000, 0x410000,
            VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_ALL, 0);
        ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert(VM_PROT_READ | VM_PROT_EXECUTE): %d\n", error);

        error = vm_map_insert(map, NULL, 0,
            0x480000, 0x4A0000,
            VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, 0);

        ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert(VM_PROT_READ | VM_PROT_WRITE): %d\n", error);

// //open the real executable
//         NDINIT(&nd, LOOKUP, ISOPEN | LOCKLEAF | FOLLOW | SAVENAME
//             | MPSAFE | AUDITVNODE1, UIO_SYSSPACE, "/data/rcved", td);

//         error = namei(&nd);
//         ps4KernelSocketPrint(td, patch_another_sock, "namei returned: %d\n", error);
//         if (error)
//             goto exec_fail;

//         vfslocked = NDHASGIANT(&nd);
//         binvp  = nd.ni_vp;

//         uint64_t object = *(uint64_t*)((uint64_t)binvp + 0x1a8); //vp->v_object
//         // if (object != NULL)
//         //     vm_object_reference(object);

//         error = vm_map_insert(map, object, 
//             0, //file_offset
//             0x400000, 0x400200, //virtual_offset, text_end,
//             VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_ALL, 
//             MAP_COPY_ON_WRITE | MAP_PREFAULT);


//         ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert(VM_PROT_READ | VM_PROT_EXECUTE): %d\n", error);

        // error = vm_map_insert(map, NULL, 0,
        //     0x480000, 0x4A0000,
        //     VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, 0);

        // error = vm_map_insert(map, object,
        //     file_offset,
        //     virtual_offset, text_end,
        //     VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_ALL,
        //     MAP_COPY_ON_WRITE | MAP_PREFAULT);


//         ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert(VM_PROT_READ | VM_PROT_WRITE): %d\n", error);

        // ps4KernelSocketPrint(td, patch_another_sock, "ndfree");
        // NDFREE(&nd, 0xffffffdf);

        // vm_object_deallocate(object);
        // ps4KernelSocketPrint(td, patch_another_sock, "vm_object_deallocate");

        //ps4KernelSocketPrint(td, patch_another_sock, "after free and deallocate", error);

        return 0;

    }

    struct image_params new_image_params;
    error = hihack_exec(&new_image_params);
    ps4KernelSocketPrint(td, patch_another_sock, "hihack exec_self_imgact rets: %d\n", error);
    


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

    if (procstruct != 0)
    {
        //proc+0x7d0 -> orbis sysvec
        ps4KernelSocketPrint(td, patch_another_sock, "proc->0x7d0\n", *(uint64_t*)(procstruct + 0x7d0));
        uint64_t self_orbis_sysvec = *(uint64_t*)(procstruct + 0x7d0);
        uint64_t unk1 = *(uint64_t*)(self_orbis_sysvec + 0x38); //??? many suword64
        uint64_t exec_copyout_strings = *(uint64_t*)(self_orbis_sysvec + 0x98); //exec_copyout_strings
        uint64_t exec_set_regs = *(uint64_t*)(self_orbis_sysvec + 0xa0); //set_regs
    }

    //dtrace_fasttrap_exec can be used

    return 0;

exec_fail_dealloc:
    //need to free the file lock
exec_fail:
    return 9;
}
