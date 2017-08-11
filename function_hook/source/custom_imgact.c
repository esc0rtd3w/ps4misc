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

int custom_imgact(struct image_params *imgp) {
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
    
    ps4KernelSocketPrint(td, patch_another_sock, "starting our own executor\n");

    //const struct exec *a_out = (const struct exec *) imgp->image_header; //0x28
    //will use orbis sysentvec
    struct sysentvec * aout_sysvec = (struct sysentvec *) 0xFFFFFFFF83263E38;

    //read dinamically
    uint64_t a_text = 0x1ad;
    uint64_t a_data = 0;
    uint64_t a_entry = *(uint64_t *)(imgp->image_header + 0x18);

    struct vmspace *vmspace;
    vm_map_t map;
    vm_object_t object;
    vm_offset_t text_end, data_end;
    unsigned long virtual_offset= 0x400000;
    unsigned long file_offset = 0;
    unsigned long bss_size = 0;

    // 1.76 retail addrs

    // VOP_UNLOCK_APV => FFFFFFFF822A10A0
    // exec_new_vmspace => FFFFFFFF82406A10
    int (*exec_new_vmspace)(struct image_params *, struct sysentvec *) = 0xFFFFFFFF82406A10;
    // vm_map_lock => 0
    // vm_map_unlock => 0
    // vm_object_reference => FFFFFFFF825B92E0
    void (*vm_object_reference)(vm_object_t object) = 0xFFFFFFFF825B92E0;
    // vm_map_insert => FFFFFFFF825AD410
    int (*vm_map_insert)(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
              vm_offset_t start, vm_offset_t end, vm_prot_t prot, vm_prot_t max,
              int cow) = 0xFFFFFFFF825AD410;
    // vm_object_deallocate => FFFFFFFF825B9380
    void (*vm_object_deallocate)(vm_object_t object) = 0xFFFFFFFF825B9380;
    // _vn_lock => FFFFFFFF824D18C0
    int (*vn_lock)(struct vnode *vp, int flags, char *file, int line) = 0xFFFFFFFF824D18C0;
    // exec_shell_imgact => FFFFFFFF823E9D30


    error = exec_new_vmspace(imgp, aout_sysvec);

    ps4KernelSocketPrint(td, patch_another_sock, "exec_new_vmspace returned: %d\n", error);

    vn_lock(imgp->vp, LK_EXCLUSIVE | LK_RETRY, NULL, 0);
    if (error){
        ps4KernelSocketPrint(td, patch_another_sock, "vn_lock returned: %d\n", error);
        return (error);
    }

    //
    // The vm space can be changed by exec_new_vmspace
    //
    vmspace = imgp->proc->p_vmspace;

    object = imgp->object;
    map = &vmspace->vm_map;
    //vm_map_lock(map);
    vm_object_reference(object);

    ps4KernelSocketPrint(td, patch_another_sock, "after vm_object_reference\n");

    text_end = virtual_offset + a_text;
    error = vm_map_insert(map, object,
        file_offset,
        virtual_offset, text_end,
        VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_ALL,
        MAP_COPY_ON_WRITE | MAP_PREFAULT);
    if (error) {
        ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert error %d\n", error);
        //vm_map_unlock(map);
        vm_object_deallocate(object);
        return (error);
    }

    ps4KernelSocketPrint(td, patch_another_sock, "after vm_map_insert\n");

    data_end = text_end + a_data;
    if (a_data) {
        vm_object_reference(object);
        ps4KernelSocketPrint(td, patch_another_sock, "after 2nd vmreference fo: %llx vs: %llx ve: %llx\n", file_offset + a_text, text_end, data_end );
        error = vm_map_insert(map, object,
            file_offset + a_text,
            text_end, data_end,
            VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL,
            MAP_COPY_ON_WRITE | MAP_PREFAULT);
        if (error) {
            ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert error %d\n", error);
            //vm_map_unlock(map);
            vm_object_deallocate(object);
            return (error);
        }
    }

    ps4KernelSocketPrint(td, patch_another_sock, "after vm_map_insert2\n");

    bss_size = 0x10000;
    data_end = 0x50000;

    if (bss_size) {
        error = vm_map_insert(map, NULL, 0,
            data_end, data_end + bss_size,
            VM_PROT_ALL, VM_PROT_ALL, 0);
        if (error) {
            ps4KernelSocketPrint(td, patch_another_sock, "vm_map_insert error %d\n", error);
            //vm_map_unlock(map);
            return (error);
        }
    }

    ps4KernelSocketPrint(td, patch_another_sock, "after vm_map_insert3\n");

    //vm_map_unlock(map);

    imgp->interpreted = 0; //get from 

    imgp->entry_addr = a_entry;

    imgp->proc->p_sysent = aout_sysvec;

    ps4KernelSocketPrint(td, patch_another_sock, "returning, entrypoint: %llx\n",a_entry);


    uint64_t lol;
    __asm__ ("mov %%rbp, %0" : "=r"(lol));

    ps4KernelSocketPrint(td, patch_another_sock, "ret addr: %llx\n", lol);
    ps4KernelSocketPrintHexDump(td, patch_another_sock, lol, 0x20);

    return 0;
}
