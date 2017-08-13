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

#include <addresses.h>

///home/user/projects/freebsd/sys/sys/namei.h
//#include </home/user/projects/freebsd/sys/sys/bufobj.h>
#include </home/user/projects/freebsd/sys/sys/namei.h>
//#include </home/user/projects/freebsd/sys/sys/vnode.h>

#include <machine/elf.h>

struct sf_buf;

#include <vm_page.h>

#define VM_PAGE_TO_PHYS(entry)  ((entry)->phys_addr)

static __inline vm_offset_t
sf_buf_kva(struct sf_buf *sf)
{

    return (PHYS_TO_DMAP(VM_PAGE_TO_PHYS((vm_page_t)sf)));
}

static __inline vm_page_t
sf_buf_page(struct sf_buf *sf)
{

    return ((vm_page_t)sf);
}

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

#define trunc_page_ps(va, ps)   ((va) & ~(ps - 1))
#define round_page_ps(va, ps)   (((va) + (ps - 1)) & ~(ps - 1))
#define aligned(a, t)   (trunc_page_ps((u_long)(a), sizeof(t)) == (u_long)(a))

vm_prot_t __elfN(trans_prot)(Elf_Word flags);
Elf_Word __elfN(untrans_prot)(vm_prot_t prot);

int
__elfN(map_partial)(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
    vm_offset_t start, vm_offset_t end, vm_prot_t prot)
{
    struct sf_buf *sf;
    int error;
    vm_offset_t off;

    /*
     * Create the page if it doesn't exist yet. Ignore errors.
     */
    vm_map_lock(map);
    vm_map_insert(map, NULL, 0, trunc_page(start), round_page(end),
        VM_PROT_ALL, VM_PROT_ALL, 0);
    vm_map_unlock(map);

    /*
     * Find the page from the underlying object.
     */
    if (object) {
        sf = vm_imgact_map_page(object, offset);
        if (sf == NULL)
            return (KERN_FAILURE);
        off = offset - trunc_page(offset);
        error = copyout((caddr_t)sf_buf_kva(sf) + off, (caddr_t)start,
            end - start);
        vm_imgact_unmap_page(sf);
        if (error) {
            return (KERN_FAILURE);
        }
    }

    return (KERN_SUCCESS);
}

int
__elfN(map_insert)(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
    vm_offset_t start, vm_offset_t end, vm_prot_t prot, int cow)
{
   struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "[INFO] got to a map_insert \n { off: %llx start: %llx end: %llx prot: %d}\n", offset, start, end, prot);

    struct sf_buf *sf;
    vm_offset_t off;
    vm_size_t sz;
    int error, rv;

    if (start != trunc_page(start)) {
        rv = __elfN(map_partial)(map, object, offset, start,
            round_page(start), prot);
        if (rv)
            return (rv);
        offset += round_page(start) - start;
        start = round_page(start);
    }
    if (end != round_page(end)) {
        rv = __elfN(map_partial)(map, object, offset +
            trunc_page(end) - start, trunc_page(end), end, prot);
        if (rv)
            return (rv);
        end = trunc_page(end);
    }
    if (end > start) {
        if (offset & PAGE_MASK) {
            /*
             * The mapping is not page aligned. This means we have
             * to copy the data. Sigh.
             */
            rv = vm_map_find(map, NULL, 0, &start, end - start,
                FALSE, prot | VM_PROT_WRITE, VM_PROT_ALL, 0);
            if (rv)
                return (rv);
            if (object == NULL)
                return (KERN_SUCCESS);
            for (; start < end; start += sz) {
                sf = vm_imgact_map_page(object, offset);
                if (sf == NULL)
                    return (KERN_FAILURE);
                off = offset - trunc_page(offset);
                sz = end - start;
                if (sz > PAGE_SIZE - off)
                    sz = PAGE_SIZE - off;
                error = copyout((caddr_t)sf_buf_kva(sf) + off,
                    (caddr_t)start, sz);
                vm_imgact_unmap_page(sf);
                if (error) {
                    return (KERN_FAILURE);
                }
                offset += sz;
            }
            rv = KERN_SUCCESS;
        } else {
            vm_object_reference(object);
            vm_map_lock(map);
            rv = vm_map_insert(map, object, offset, start, end,
                prot, VM_PROT_ALL, cow);
            vm_map_unlock(map);
            if (rv != KERN_SUCCESS)
                vm_object_deallocate(object);
        }
        return (rv);
    } else {
        return (KERN_SUCCESS);
    }
}


int
__elfN(load_section)(struct vmspace *vmspace,
    vm_object_t object, vm_offset_t offset,
    caddr_t vmaddr, size_t memsz, size_t filsz, vm_prot_t prot,
    size_t pagesize)
{
    struct sf_buf *sf;
    size_t map_len;
    vm_offset_t map_addr;
    int error, rv, cow;
    size_t copy_len;
    vm_offset_t file_addr;

    /*
     * It's necessary to fail if the filsz + offset taken from the
     * header is greater than the actual file pager object's size.
     * If we were to allow this, then the vm_map_find() below would
     * walk right off the end of the file object and into the ether.
     *
     * While I'm here, might as well check for something else that
     * is invalid: filsz cannot be greater than memsz.
     */
    // FIXME: vm_object incomplete
    // if ((off_t)filsz + offset > object->un_pager.vnp.vnp_size ||
    //     filsz > memsz) {
    //     uprintf("elf_load_section: truncated ELF file\n");
    //     return (ENOEXEC);
    // }

    map_addr = trunc_page_ps((vm_offset_t)vmaddr, pagesize);
    file_addr = trunc_page_ps(offset, pagesize);

    /*
     * We have two choices.  We can either clear the data in the last page
     * of an oversized mapping, or we can start the anon mapping a page
     * early and copy the initialized data into that first page.  We
     * choose the second..
     */
    if (memsz > filsz)
        map_len = trunc_page_ps(offset + filsz, pagesize) - file_addr;
    else
        map_len = round_page_ps(offset + filsz, pagesize) - file_addr;

    if (map_len != 0) {
        /* cow flags: don't dump readonly sections in core */
        cow = MAP_COPY_ON_WRITE | MAP_PREFAULT |
            (prot & VM_PROT_WRITE ? 0 : MAP_DISABLE_COREDUMP);

        rv = __elfN(map_insert)(&vmspace->vm_map,
                      object,
                      file_addr,    /* file offset */
                      map_addr,     /* virtual start */
                      map_addr + map_len,/* virtual end */
                      prot,
                      cow);
        if (rv != KERN_SUCCESS)
            return (EINVAL);

        /* we can stop now if we've covered it all */
        if (memsz == filsz) {
            return (0);
        }
    }


    /*
     * We have to get the remaining bit of the file into the first part
     * of the oversized map segment.  This is normally because the .data
     * segment in the file is extended to provide bss.  It's a neat idea
     * to try and save a page, but it's a pain in the behind to implement.
     */
    copy_len = (offset + filsz) - trunc_page_ps(offset + filsz, pagesize);
    map_addr = trunc_page_ps((vm_offset_t)vmaddr + filsz, pagesize);
    map_len = round_page_ps((vm_offset_t)vmaddr + memsz, pagesize) -
        map_addr;

    /* This had damn well better be true! */
    if (map_len != 0) {
        rv = __elfN(map_insert)(&vmspace->vm_map, NULL, 0, map_addr,
            map_addr + map_len, VM_PROT_ALL, 0);
        if (rv != KERN_SUCCESS) {
            return (EINVAL);
        }
    }

    if (copy_len != 0) {
        vm_offset_t off;

        sf = vm_imgact_map_page(object, offset + filsz);
        if (sf == NULL)
            return (EIO);

        /* send the page fragment to user space */
        off = trunc_page_ps(offset + filsz, pagesize) -
            trunc_page(offset + filsz);
        error = copyout((caddr_t)sf_buf_kva(sf) + off,
            (caddr_t)map_addr, copy_len);
        vm_imgact_unmap_page(sf);
        if (error) {
            return (error);
        }
    }

    /*
     * set it to the specified protection.
     * XXX had better undo the damage from pasting over the cracks here!
     */
    vm_map_protect(&vmspace->vm_map, trunc_page(map_addr),
        round_page(map_addr + map_len),  prot, FALSE);

    return (0);
}

int __elfN(load_file)(struct proc *p, const char *file, u_long *addr,
    u_long *entry, size_t pagesize)
{
    struct {
        struct nameidata nd;
        struct vattr attr;
        struct image_params image_params;
    } *tempdata;
    const Elf_Ehdr *hdr = NULL;
    const Elf_Phdr *phdr = NULL;
    struct nameidata *nd;
    struct vmspace *vmspace = p->p_vmspace;
    struct vattr *attr;
    struct image_params *imgp;
    vm_prot_t prot;
    u_long rbase;
    u_long base_addr = 0;
    int vfslocked, error, i, numsegs;

    tempdata = malloc(sizeof(*tempdata), M_TEMP, M_WAITOK);
    nd = &tempdata->nd;
    attr = &tempdata->attr;
    imgp = &tempdata->image_params;

    /*
     * Initialize part of the common data
     */
    imgp->proc = p;
    imgp->attr = attr;
    imgp->firstpage = NULL;
    imgp->image_header = NULL;
    imgp->object = NULL;
    imgp->execlabel = NULL;

    NDINIT(nd, LOOKUP, LOCKLEAF|FOLLOW, UIO_SYSSPACE, file, //FIXME: MPSAFE unlockgiant isnt reversed
        curthread);
    vfslocked = 0;
    if ((error = namei(nd)) != 0) {
        nd->ni_vp = NULL;
        goto fail;
    }
    //vfslocked = NDHASGIANT(nd);
    NDFREE(nd, NDF_ONLY_PNBUF);
    imgp->vp = nd->ni_vp;

    /*
     * Check permissions, modes, uid, etc on the file, and "open" it.
     */
    error = exec_check_permissions(imgp);
    if (error)
        goto fail;

    error = exec_map_first_page(imgp);
    if (error)
        goto fail;

    /*
     * Also make certain that the interpreter stays the same, so set
     * its VV_TEXT flag, too.
     */
    //nd->ni_vp->v_vflag |= VV_TEXT; FIXME, struct incomplete

    imgp->object = *(uint64_t*)((uint64_t)nd->ni_vp + v_object); //vp->v_object

    hdr = (const Elf_Ehdr *)imgp->image_header;

    // if ((error = __elfN(check_header)(hdr)) != 0)
    //     goto fail;
    // if (hdr->e_type == ET_DYN)
    //     rbase = *addr;
    // else if (hdr->e_type == ET_EXEC)
    //     rbase = 0;
    // else {
    //     error = ENOEXEC;
    //     goto fail;
    // }

    /* Only support headers that fit within first page for now      */
    /*    (multiplication of two Elf_Half fields will not overflow) */
    if ((hdr->e_phoff > PAGE_SIZE) ||
        (hdr->e_phentsize * hdr->e_phnum) > PAGE_SIZE - hdr->e_phoff) {
        error = ENOEXEC;
        goto fail;
    }

    phdr = (const Elf_Phdr *)(imgp->image_header + hdr->e_phoff);
    if (!aligned(phdr, Elf_Addr)) {
        error = ENOEXEC;
        goto fail;
    }


    for (i = 0, numsegs = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz != 0) {
            /* Loadable segment */
            prot = __elfN(trans_prot)(phdr[i].p_flags);

            if ((error = __elfN(load_section)(vmspace,
                imgp->object, phdr[i].p_offset,
                (caddr_t)(uintptr_t)phdr[i].p_vaddr + rbase,
                phdr[i].p_memsz, phdr[i].p_filesz, prot,
                pagesize)) != 0)
                goto fail;
            /*
             * Establish the base address if this is the
             * first segment.
             */
            if (numsegs == 0)
                base_addr = trunc_page(phdr[i].p_vaddr +
                    rbase);
            numsegs++;
        }
    }
    *addr = base_addr;
    *entry = (unsigned long)hdr->e_entry + rbase;

fail:
    if (imgp->firstpage)
        exec_unmap_first_page(imgp);

    if (nd->ni_vp)
        vput(nd->ni_vp);

    //VFS_UNLOCK_GIANT(vfslocked);
    free(tempdata, M_TEMP);

    return (error);
}


vm_prot_t
__elfN(trans_prot)(Elf_Word flags)
{
    vm_prot_t prot;

    prot = 0;
    if (flags & PF_X)
        prot |= VM_PROT_EXECUTE;
    if (flags & PF_W)
        prot |= VM_PROT_WRITE;
    if (flags & PF_R)
        prot |= VM_PROT_READ;
#if __ELF_WORD_SIZE == 32
#if defined(__amd64__) || defined(__ia64__)
    if (i386_read_exec && (flags & PF_R))
        prot |= VM_PROT_EXECUTE;
#endif
#endif
    return (prot);
}

Elf_Word
__elfN(untrans_prot)(vm_prot_t prot)
{
    Elf_Word flags;

    flags = 0;
    if (prot & VM_PROT_EXECUTE)
        flags |= PF_X;
    if (prot & VM_PROT_READ)
        flags |= PF_R;
    if (prot & VM_PROT_WRITE)
        flags |= PF_W;
    return (flags);
}
