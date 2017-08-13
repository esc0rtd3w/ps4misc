#define __ELF_WORD_SIZE 64
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

#include <machine/elf.h>

#define LK_EXCLUSIVE    0x080000
#define LK_RETRY        0x000400

#define AT_FDCWD        -100

char * msearch(char * start, char * haystack, int size) ;

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

vm_prot_t __elfN(trans_prot)(Elf_Word flags);

#define FREAD 0x0001

int
__elfN(load_section)(struct vmspace *vmspace,
    vm_object_t object, vm_offset_t offset,
    caddr_t vmaddr, size_t memsz, size_t filsz, vm_prot_t prot,
    size_t pagesize);

int 
__elfN(load_file)(struct proc *p, const char *file, u_long *addr,
    u_long *entry, size_t pagesize);

uint64_t 
hihack_proc(struct image_params *imgp, uint64_t * outprocentry) 
{
    int (*vm_map_insert)(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
              vm_offset_t start, vm_offset_t end, vm_prot_t prot, vm_prot_t max,
              int cow) = 0xFFFFFFFF825AD410;


    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    const Elf64_Ehdr *hdr = NULL;
    const Elf64_Phdr *phdr = NULL;

    struct vnode *binvp = NULL;
    struct proc *p = td->td_proc;
    struct nameidata nd;
    struct ucred *newcred = NULL, *oldcred;
    struct uidinfo *euip;
    int error = 0;

    struct vmspace *vmspace;
    vm_map_t map;

    vmspace = imgp->proc->p_vmspace;
    map = &vmspace->vm_map;


// //open the real executable
    NDINIT(&nd, LOOKUP, ISOPEN | FOLLOW | SAVENAME // | LOCKLEAF
        | AUDITVNODE1, UIO_SYSSPACE, "/data/rcved", td);

    ps4KernelSocketPrint(td, patch_another_sock, "after NDINIT v2\n");

    error = namei(&nd);
    ps4KernelSocketPrint(td, patch_another_sock, "namei returned: %d\n", error);
    if (error)
        goto exec_fail;

//         vfslocked = NDHASGIANT(&nd); //only when passing MP_SAFE to NDINIT
    binvp  = nd.ni_vp;

    struct vattr attr;
    struct image_params nimgp;
    nimgp.vp = binvp;
    nimgp.firstpage = 0;
    nimgp.object = NULL;
    nimgp.attr = &attr;

    uint64_t cp_error = exec_check_permissions(&nimgp);
    
    ps4KernelSocketPrint(td, patch_another_sock, "exec_check_permissions: %d, opened: %d\n", cp_error, nimgp.opened);


    //could do some checks with map/unmap, ignore for now
    uint64_t ma = exec_map_first_page(&nimgp);

    ps4KernelSocketPrint(td, patch_another_sock, "exec_map_first_page: %d %llx\n", ma, nimgp.image_header);

    nimgp.object = *(uint64_t*)((uint64_t)binvp + 0x1a8); //vp->v_object

    ps4KernelSocketPrint(td, patch_another_sock, "binvp->v_object: %llx\n", nimgp.object);

    if (nimgp.object != NULL)
        vm_object_reference(nimgp.object);

    ps4KernelSocketPrint(td, patch_another_sock, "after vm_object_reference\n");

    hdr = (const Elf64_Ehdr *)(nimgp.image_header);
    phdr = (const Elf64_Phdr *)((uint64_t)nimgp.image_header + hdr->e_phoff);

    uint64_t rbase = 0;
    uint64_t base_addr = 0;
    uint64_t prot = 0;
    uint64_t pagesize = 0x4000;


    ps4KernelSocketPrintHexDump(td, patch_another_sock, nimgp.image_header, 0x100);

    ps4KernelSocketPrint(td, patch_another_sock, "Elf64_Ehdr {\n    unsigned char   e_ident[EI_NIDENT]; /* File identification. */\n    Elf64_Half  e_type    = %d;     /* File type. */\n    Elf64_Half  e_machine = %d;  /* Machine architecture. */\n    Elf64_Word  e_version = %d;  /* ELF format version. */\n    Elf64_Addr  e_entry = %llx;    /* Entry point. */\n    Elf64_Off   e_phoff = %llx;    /* Program header file offset. */\n    Elf64_Off   e_shoff;    /* Section header file offset. */\n    Elf64_Word  e_flags;    /* Architecture-specific flags. */\n    Elf64_Half  e_ehsize;   /* Size of ELF header in bytes. */\n    Elf64_Half  e_phentsize;    /* Size of program header entry. */\n    Elf64_Half  e_phnum;    /* Number of program header entries. */\n    Elf64_Half  e_shentsize;    /* Size of section header entry. */\n    Elf64_Half  e_shnum;    /* Number of section header entries. */\n    Elf64_Half  e_shstrndx; /* Section name strings section. */\n}\n", 
            hdr->e_type,
            hdr->e_machine,
            hdr->e_version,
            hdr->e_entry,
            hdr->e_phoff
            );

    ps4KernelSocketPrintHexDump(td, patch_another_sock, phdr, 0x40);

    * outprocentry = hdr->e_entry + rbase;

    for (int i = 0, numsegs = 0; i < hdr->e_phnum; i++) {
            ps4KernelSocketPrint(td, patch_another_sock, "section \n { type: %d offset: %llx vaddr: %llx memsz: %llx filesz: %llx prot: %x } \n", 
                phdr[i].p_type,
                phdr[i].p_offset,
                (caddr_t)(uintptr_t)phdr[i].p_vaddr + rbase,
                phdr[i].p_memsz, phdr[i].p_filesz, prot);

        if ((phdr[i].p_memsz != 0) & (phdr[i].p_type != 1)) {
            /* Loadable segment */
            prot = __elfN(trans_prot)(phdr[i].p_flags);

            // error = vm_map_insert(map, nimgp.object, 
            //     phdr[i].p_offset, //file_offset
            //     (caddr_t)(uintptr_t)phdr[i].p_vaddr + rbase, 
            //     (caddr_t)(uintptr_t)phdr[i].p_vaddr + rbase + phdr[i].p_memsz, //virtual_offset, text_end,
            //     VM_PROT_READ | VM_PROT_EXECUTE, 
            //     VM_PROT_ALL, 
            //     MAP_COPY_ON_WRITE | MAP_PREFAULT);

            if ((error = __elfN(load_section)(vmspace,
                nimgp.object, phdr[i].p_offset,
                (caddr_t)(uintptr_t)phdr[i].p_vaddr + rbase,
                phdr[i].p_memsz, phdr[i].p_filesz, prot,
                pagesize)) != 0)
            {
                ps4KernelSocketPrint(td, patch_another_sock, "ERROR: FAILED %d\n", error);

                goto fail;
            }
            /*
             * Establish the base address if this is the
             * first segment.
             */
            if (numsegs == 0)
                base_addr = trunc_page(phdr[i].p_vaddr + rbase);
            numsegs++;
        }
    }
    
fail:

    exec_unmap_first_page(&nimgp);

    // error = vm_map_insert(map, nimgp.object, 
    //     0, //file_offset
    //     0x900000, 
    //     0x900200, //virtual_offset, text_end,
    //     VM_PROT_READ | VM_PROT_EXECUTE, 
    //     VM_PROT_ALL, 
    //     MAP_COPY_ON_WRITE | MAP_PREFAULT);

    // ps4KernelSocketPrint(td, patch_another_sock, "map_insert %d\n", error);

    //only if LOCK_LEAF applied, otherwise use vrele
    //int unlockerror = vput(binvp); 
    //ps4KernelSocketPrint(td, patch_another_sock, "vop_unlock %d\n", unlockerror);

    char dump2[0x100];
    ps4KernelSocketPrint(td, patch_another_sock, "readed from vmem\n");
    bzero(dump2, 0x100);
    copyin(hdr->e_entry + rbase, dump2, 0x100);
    ps4KernelSocketPrintHexDump(td, patch_another_sock, dump2, 0x20);


cleanup_adelloc:
    //vrele(binvp);

    //FIXME: will be leaking references!!!
    if (nimgp.vp != NULL) {
        NDFREE(&nd, NDF_ONLY_PNBUF);
        // if (nimgp.opened)
        //     VOP_CLOSE_APV(nimgp.vp, FREAD, td->td_ucred, td); //

        vput(nimgp.vp);
        //vn_close(nimgp.vp);
    }

    if (nimgp.object != NULL)
        vm_object_deallocate(nimgp.object);

    // if ((error != 0) && (binvp != NULL))
    //     vrele(binvp);

    ps4KernelSocketPrint(td, patch_another_sock, "all dellocated\n\n");

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
    vfslocked = 0;

    // ps4KernelProtectionWriteDisable();
    // *(uint64_t*)(0xffffffff83263f60) = 0xffffffff82649940; //restore original exec
    // ps4KernelProtectionWriteEnable();

    ps4KernelSocketPrint(td, patch_another_sock, "executing %s\n", imgp->args->fname);
    ps4KernelSocketPrint(td, patch_another_sock, "argc %d\n", imgp->args->argc);
    ps4KernelSocketPrintHexDump(td, patch_another_sock, imgp->args->buf, imgp->args->endp - imgp->args->buf);

    ps4KernelSocketPrint(td, patch_another_sock, "header %llx\n", *(uint64_t *)(imgp->image_header + 0));

    if (*(uint8_t *)(imgp->image_header + 0) != 0x78) 
    {
        ps4KernelSocketPrint(td, patch_another_sock, "forwarding to exec_self_imgact\n");
        int (*exec_self_imgact)(struct image_params *imgp) = 0xffffffff82649940;

        error = exec_self_imgact(imgp);

        
        ps4KernelSocketPrint(td, patch_another_sock, "exec_self_imgact: %d\n", error);
        if (error)
            return 9; 

        // if (strstr(imgp->args->fname, "WebProcess.self") < 1)
        //     return 0;


        ps4KernelSocketPrint(td, patch_another_sock, "entry point: %llx\n", imgp->entry_addr);



        return 0;

    }





        //these mappings are innofensive

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


        // u_long dest_addr = 0;
        // u_long dest_entry = 0;
        // error = __elfN(load_file)(td->td_proc, "/data/rcved", &dest_addr, &dest_entry, 16384);





    struct image_params new_image_params;
    error = hihack_exec(&new_image_params);
    
    u_long dest_addr = 0;
    u_long dest_entry = 0;
    error = __elfN(load_file)(td->td_proc, "/data/rcved", &dest_addr, &dest_entry, 16384);

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
}
