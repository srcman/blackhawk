/*
 * Copyright (C) 2009-2010, Oy L M Ericsson Ab, NomadicLab.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of
 * the BSD license.
 *
 * See LICENSE and COPYING for more details.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/syscallsubr.h>
#include <sys/sf_buf.h>
#include <sys/mman.h>
#include <sys/resourcevar.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/libkern.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/event.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_kern.h>

#include "ps.h"
#include "ps_syscall.h"
#include "ps_map.h"
#include "ps_debug.h"

/*
 * Map the publication represented by object to thread's address space.
 *
 * Compare to vm_mmap.c:vm_mmap, but we allow any object and any process.
 */

int
ps_mmap(struct thread *td,
	  vm_offset_t *addr,
	  vm_ooffset_t size,
	  vm_prot_t prot,
	  vm_prot_t maxprot,
	  int flags,
	  vm_object_t object,
	  vm_ooffset_t foff)
{
#if 0
    vm_ooffset_t offset = 0;
#else
    vm_ooffset_t offset = foff; /* XXX: ? */
#endif
    boolean_t fitit;
    int docow, rv;
    vm_map_t map = &td->td_proc->p_vmspace->vm_map;

    if (size == 0)
	return (0);

    size = round_page(size);

    /*
     * If the given address is zero, pick one.
     */
    PROC_LOCK(td->td_proc);
    if (0 == *addr) {
	*addr = round_page((vm_offset_t)td->td_proc ->p_vmspace->vm_daddr 
			   + lim_max(td->td_proc, RLIMIT_DATA));
    }

    if (td->td_proc->p_vmspace->vm_map.size + size 
	> lim_cur(td->td_proc, RLIMIT_VMEM)) {
	PROC_UNLOCK(td->td_proc);
	return (ENOMEM);
    }
    PROC_UNLOCK(td->td_proc);

    if (foff & PAGE_MASK)
	return (EINVAL);

    if ((flags & MAP_FIXED) == 0) {
	fitit = TRUE;
	*addr = round_page(*addr);
    } else {
	fitit = FALSE;
	if (*addr != trunc_page(*addr))
	    return (EINVAL);
    }


    VM_OBJECT_LOCK(object);
    switch (object->type) {
    case OBJT_VNODE:
	VM_OBJECT_UNLOCK(object);
#if __FreeBSD_version < 800000
	object = vm_pager_allocate(OBJT_VNODE, object->handle, size, prot, foff);
#else
	object = vm_pager_allocate(OBJT_VNODE, object->handle, size, prot, foff, NULL /*td->td_ucred*/);
#endif
	if (NULL == object) {
	    return ENOMEM;
	}
	VM_OBJECT_LOCK(object);
	break;
    case OBJT_DEFAULT:
    case OBJT_SWAP:
	break;
    default:
	return EINVAL;
    }
    VM_OBJECT_UNLOCK(object);

    docow = MAP_PREFAULT_PARTIAL;
    if (flags & MAP_COPY_ON_WRITE)
	docow |= MAP_COPY_ON_WRITE;

    if ((flags & (MAP_ANON|MAP_SHARED)) == 0)
	docow |= MAP_COPY_ON_WRITE;
    if (flags & MAP_NOSYNC)
	docow |= MAP_DISABLE_SYNCER;
    if (flags & MAP_NOCORE)
	docow |= MAP_DISABLE_COREDUMP;

#if __FreeBSD_version < 800000
    if (fitit)
	*addr = pmap_addr_hint(object, *addr, size);
#endif
    
    VM_OBJECT_LOCK(object);
    vm_object_reference_locked(object); /* XXX: Is this needed? */
    vm_object_clear_flag(object, OBJ_ONEMAPPING);
    VM_OBJECT_UNLOCK(object);

    if (fitit)
	rv = vm_map_find(map, object, offset, addr, size, TRUE,
			 prot, maxprot, docow);
    else
#if __FreeBSD_version >= 702000 /* 800000 */
	rv = vm_map_fixed(map, object, offset, *addr, size,
			  prot, maxprot, docow);
#else
	rv = vm_map_fixed(map, object, offset, addr, size,
			  prot, maxprot, docow);
#endif

    if (rv != KERN_SUCCESS) {
	vm_object_deallocate(object);
    } else if (flags & MAP_SHARED) {
	/* Shared memory is also shared with children. */
	rv = vm_map_inherit(map, *addr, *addr + size, VM_INHERIT_SHARE);
	if (rv != KERN_SUCCESS) 
	    (void) vm_map_remove(map, *addr, *addr + size);
    }

    /*
     * XXX: Make sure the object is correctly mapped.
     *      We don't understand why this is needed; other similar
     *      kernel routines don't seem to need it.
     */
    VM_OBJECT_LOCK(object);
    vm_object_clear_flag(object, OBJ_ONEMAPPING);
    VM_OBJECT_UNLOCK(object);

    PS_PRINTF(PS_DEBUG_MAP, 
	      "rv=%d, *addr=0x%lx, size=0x%lx, offset=0x%lx\n",
	      rv, *addr, size, offset);

    /* XXX: Ensure that cow works here. */

    switch (rv) {
    case KERN_SUCCESS:
	return (0);
    case KERN_INVALID_ADDRESS:
    case KERN_NO_SPACE:
	return (ENOMEM);
    case KERN_PROTECTION_FAILURE:
	return (EACCES);
    default:
	return (EINVAL);
    }
}

/*
 * Find the vm_object based on the address in a process address space.
 */
int
ps_mfind(struct thread *td, vm_offset_t addr, vm_ooffset_t size, 
	   vm_object_t *objectp, vm_ooffset_t *offsetp) {
    vm_map_t vmmap_proc = &td->td_proc->p_vmspace->vm_map;
    vm_map_entry_t me;
    vm_ooffset_t offset = 0;
    vm_pindex_t numpages = 0;
    vm_object_t object = NULL;
    int error = 0;

    /* Verify that access to the given address is allowed from user-space. */
    if (vm_fault_quick((caddr_t)addr, VM_PROT_READ) < 0) {
        PS_PRINTF(PS_DEBUG_MAP | PS_DEBUG_ERROR,
		  "access to page at %ld denied\n", addr);
        error = EFAULT;
        goto done;
    }

    /*
     * Find map_entry and object containing user address addr. 
     */
    vm_map_lock(vmmap_proc);
    if (!vm_map_lookup_entry(vmmap_proc, addr, &me)) {
	vm_map_unlock(vmmap_proc);
	PS_PRINTF(PS_DEBUG_MAP | PS_DEBUG_ERROR, 
		  "vm map entry at %ld not found\n", addr);
	error = ENOENT;
	goto done;
    }
    object = me->object.vm_object;
    KASSERT(NULL != object, ("Failed to get the underlying object"));
    offset = addr - (me->start - me->offset);
    vm_map_unlock(vmmap_proc);

    VM_OBJECT_LOCK(object);
    PS_PRINTF(PS_DEBUG_MAP, 
	      "object=%p sz=%ld refs=%d shads=%d\n",
	      (void *)object, object->size, object->ref_count,
	      object->shadow_count);
    numpages = object->size;
    VM_OBJECT_UNLOCK(object);

    /* Check that the requested publication is not longer than the
       memory area. */
    if (size > numpages * PAGE_SIZE) /*XXX*/{
        PS_PRINTF(PS_DEBUG_MAP | PS_DEBUG_ERROR, 
		  "length %ld too long\n", size);
        error = E2BIG;
    }

 done:

    *objectp = object;
    *offsetp = offset;
    return error;
}

/*
 * Make the vm_object copy-on-write.  Compare to vm_map.c:vm_map_protect.
 */

int
ps_mcow(struct thread *td, vm_offset_t start, vm_ooffset_t len)
{
    int error = 0;
    vm_map_t vmmap_proc = &td->td_proc->p_vmspace->vm_map;
    vm_map_entry_t me;
    vm_offset_t end = start + len;
    
    vm_map_lock(vmmap_proc);
    if (vm_map_lookup_entry(vmmap_proc, start, &me)) {
	if (start != me->start) 
	    panic("ps_mcow: Cannot split map entry start:" 
		  "start=%ld, entry->start=%ld, entry->end=%ld",
		  start, me->start, me->end);
    } else {
	me = me->next;
    }
    while (me != &vmmap_proc->header && me->start < end) {
	/*
	 * XXX: vm_map_protect calls vm_map_clip_end here, which is static.
	 *      Ergo, we currently misbehave here if the end of the entry does not
	 *      match with the underlying object...  Sigh.
	 */

        /* Make sure the next possible write creates a new shadow object. */
	me->eflags |= MAP_ENTRY_COW|MAP_ENTRY_NEEDS_COPY;

	/* 
	 * This will cause a page fault when process tries to write.
	 * As the entry has the above flags, a shadow object will
	 * be created in vm_map_lookup().
	 */
	pmap_protect(vmmap_proc->pmap, me->start, me->end, VM_PROT_READ);

	vm_map_simplify_entry(vmmap_proc, me);
	me = me->next;
    }
    vm_map_unlock(vmmap_proc);

    return error;
}

int
ps_munmap(struct thread *td, vm_offset_t addr, vm_ooffset_t size) {
    int error;
    vm_object_t object;
    vm_ooffset_t offset;
    vm_offset_t end;
    vm_map_t vmmap_proc = &td->td_proc->p_vmspace->vm_map;

    error = ps_mfind(td, addr, 0, &object, &offset);
    if (error)
	return error;

    /*
     * XXX: Should we check that the object really is a publication
     *      data object?  Semantically maybe, but it works (should work?)
     *      also without such check.  The process can shoot only itself,
     *      anyway?  (Assuming this is called only from proper places.)
     */
    PS_PRINTF(PS_DEBUG_MAP, 
	      "map=%p, addr=0x%lx (%ld), addr+size=0x%lx (%ld)\n",
	      vmmap_proc, addr, addr, addr+size, addr+size);

    end = addr + round_page(size);
    error = vm_map_remove(vmmap_proc, addr, end);

    return error;
}

/*
 * Map a page of a user space memory object to the kernel address space.
 * Must be freed with ps_kunmap_page after use.
 * The actual access must be done through sf_buf.
 */
int
ps_kmap_page(vm_object_t object,
	     vm_pindex_t pindex,
	     vm_page_t *pp)
{
    vm_page_t p = NULL;
    vm_object_t backing_object, lobject;

    if (NULL == object) {
        PS_PRINTF(PS_DEBUG_MAP | PS_DEBUG_ERROR,
		  "object is NULL\n");
	panic("ps_kmap_page on NULL");
    }

    vm_object_reference(object);

    /*
     * Code stolen from vm_fault.c:vm_fault_prefault.
     *
     * Note that in FreeBSD7 vm_map_pmap_enter does not
     * understand shadow objects -- only page faulting code
     * does.  So, normally shadows don't work right in
     * kernel space.
     *
     * Here we try to look up the page at each object,
     * starting from the foremost one.  If the page is
     * found, we use it.  If not, we proceed downwards,
     * until we hit the bottom of the shadow stack.
     *
     * If there is no page in the stack, we allocate one
     * at the foremost shadow.
     */
    lobject = object;
    VM_OBJECT_LOCK(lobject);
    while (NULL == (p = vm_page_lookup(lobject, pindex))
	   && OBJT_DEFAULT == lobject->type
	   && NULL != (backing_object = lobject->backing_object)) {
	if (lobject->backing_object_offset & PAGE_MASK) {
	    PS_PRINTF(PS_DEBUG_MAP | PS_DEBUG_WARNING,
		      "Cannot handle non-page-size shadow offsets,"
                      "offset = %ld\n", lobject->backing_object_offset);
	    break;
	}
	pindex += OFF_TO_IDX(lobject->backing_object_offset);
	VM_OBJECT_LOCK(backing_object);
	VM_OBJECT_UNLOCK(lobject);
	lobject = backing_object;
    }
    VM_OBJECT_UNLOCK(lobject);

    if (p) {
	/* XXX: Do we need to do anything here? */
    } else {
	VM_OBJECT_LOCK(object);
	vm_object_pip_add(object, 1);
	p = vm_page_grab(object, pindex, 
			 VM_ALLOC_WIRED  | VM_ALLOC_ZERO 
			 | VM_ALLOC_NORMAL | VM_ALLOC_RETRY);
    
	if (p->valid != VM_PAGE_BITS_ALL) {
	    int behind, ahead;

	    PS_PRINTF(PS_DEBUG_MAP, "p->valid=0x%xd\n", p->valid);
	    if (vm_pager_has_page(object, pindex, &behind, &ahead)) {
		int error; 
		
		error = vm_pager_get_pages(object, &p, 1, 0);
		if (error) {
		    /* XXX: Something below may be wrong. */
		    PS_PRINTF(PS_DEBUG_MAP | PS_DEBUG_ERROR,
			      "get pages from pager: error %d\n", error);
		    vm_object_deallocate(object);
		    vm_object_pip_subtract(object, 1);
		    VM_OBJECT_UNLOCK(object);
		    return error;
		}
	    } else {
		vm_page_zero_invalid(p, TRUE);
	    }
	}
	vm_object_pip_subtract(object, 1);
	VM_OBJECT_UNLOCK(object);
    }			

    vm_page_lock_queues();
    vm_page_wire(p);
    vm_page_unlock_queues();

    PS_PRINTF(PS_DEBUG_MAP, "mapped physical page %ld\n", p->phys_addr);

    *pp = p;
    return 0;
}

int
ps_kunmap_page(vm_object_t object, vm_page_t p, boolean_t modified) {
#ifdef INVARIANTS
    /*
     * XXX: Assert that we are unmapping a valid object.
     */
#endif

    if (modified) {
	vm_page_dirty(p);
    }

    vm_page_lock_queues();
    vm_page_unwire(p, 0);
    vm_page_activate(p);
    vm_page_unlock_queues();
    VM_OBJECT_LOCK(object);

    /* should there be a corresponding vm_page_busy() call somewhere? */
    if (p->oflags & VPO_BUSY)
        vm_page_wakeup(p);

    VM_OBJECT_UNLOCK(object);
    vm_object_deallocate(object);
    
    return 0;
}

