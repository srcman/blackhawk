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

/*
 * PS system call kernel module
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/malloc.h>
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
#include <sys/sysctl.h>
#include <sys/conf.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>

#include <crypto/sha1.h> /* XXX */

#include "ps.h"
#include "ps_pubi.h"
#include "ps_obj.h"
#include "ps_event.h"
#include "ps_syscall.h"
#include "ps_pit.h"
#include "ps_socket.h"
#include "ps_scope.h"
#include "ps_map.h"
#include "ps_debug.h"

#include "psfs.h"

extern psirp_id_t root_id;	/* Defined in vfsops */

MALLOC_DEFINE(M_DEBUGPIT, "pitdebug", "Debug area for PIT");

/*
 * Local function prototypes
 *
 * TODO: Add documentation
 */
static int ps_syscall_init(void);
static int ps_syscall_cleanup(void);
static int ps_syscall_call(struct thread *td, void *arg);
static int ps_syscall_create(struct thread *td,
                           ps_syscall_arg_t *arg,
                           ps_syscall_sc_arg_t *sc_arg);
static int ps_syscall_publish(struct thread *td, ps_syscall_arg_t *arg,
                            ps_syscall_sc_arg_t *sc_arg);
static int ps_syscall_subscribe(struct thread *td, ps_syscall_arg_t *arg,
                              ps_syscall_sc_arg_t *sc_arg);

static void ps_syscall_print_map(vm_map_t map);
static int ps_syscall_status(ps_syscall_arg_t *arg);
static int  ps_syscall_open_fd(struct thread *td, struct vnode *vppub, int *fd);

static struct sysent ps_syscall_sysent = {
	2,                  /* sy_narg */
	ps_syscall_call    /* sy_call */
};

/*
 * sysctl nodes
 */
#define PS_DEBUG_BASELEVEL 0
#ifndef PS_DEBUG_LEVEL
#define PS_DEBUG_LEVEL				\
    (						\
       PS_DEBUG_BASELEVEL                       \
     | PS_DEBUG_ERROR				\
     | PS_DEBUG_WARNING				\
    )
#endif
#ifdef NOTNOW
     | PS_DEBUG_SYSCALL				\
     | PS_DEBUG_FILT                            \
     | PS_DEBUG_CRYPTO				\

#endif

unsigned long ps_debug_mask = PS_DEBUG_LEVEL;
SYSCTL_XLONG(_debug, OID_AUTO, pubsub_debug_mask, CTLFLAG_RW, &ps_debug_mask,
	     PS_DEBUG_LEVEL, "Pubsub debugging mask");

/*
 * System calls
 */
static int
ps_syscall_create_obj(struct thread *td, vm_ooffset_t size, 
		      vm_ooffset_t minsize, vm_ooffset_t maxsize, 
		      vm_object_t *objp, caddr_t *addrp) {
    int error = 0;

    if (size < minsize || size > maxsize) {
	PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_ERROR, 
		  "bad size %ld\n", size);
	return EINVAL;
    }

    error = ps_obj_alloc(td, size, objp);
    if (error) 
	return error;

    error = ps_mmap(td, (vm_offset_t *)addrp, size, VM_PROT_ALL, VM_PROT_ALL, 
		    MAP_SHARED, *objp, 0);
    if (error) {
        vm_object_deallocate(*objp); 
	return error;
    }

    PS_PRINTF(PS_DEBUG_SYSCALL, "object=%p sz=%ld\n", *objp, size);
    return 0;
}

static vm_ooffset_t minsize[] = { sizeof(ps_meta_t), 0               };
/*
 * XXX: We currently limit the published objects so that their descriptions
 *      fit into one memory page.  When changing this, there are likely to be
 *      a large number of places to be fixed, e.g. everywhere where PS_MD_SIZE
 *      or PS_META_SUB_OBJECT_COUNT are used.
 */
static vm_ooffset_t maxsize[] = { PS_MD_SIZE,        PS_META_SUB_OBJECT_COUNT * PAGE_SIZE };

static int
ps_syscall_create(struct thread *td,
	       ps_syscall_arg_t *arg,
	       ps_syscall_sc_arg_t *sc_arg)
{
    int i;
    int error = 0;
    vm_object_t obj[VMO_NUM];

    PS_PRINTF(PS_DEBUG_SYSCALL, "mlen = %lu, dlen = %lu\n", 
	      arg->a_mlen, arg->a_dlen);

    for (i = 0; i < VMO_NUM; i++) {
	error = ps_syscall_create_obj(td, arg->a_obj[i].so_len, 
				      minsize[i], maxsize[i],
				      &obj[i], &arg->a_obj[i].so_addr);
	if (error) {
	    while (--i > 0) {
		(void)ps_munmap(td, (vm_offset_t)arg->a_obj[i].so_addr, 
				arg->a_obj[i].so_len);
		vm_object_deallocate(obj[i]);
		arg->a_obj[i].so_addr = 0;
	    }
	    return error;
	}
    }
    ps_obj_init_meta_user(obj[VMO_META]);
	
    /*
     * Copy return values to userspace of the calling process. 
     */
    arg->a_retval = 0;
    copyout(arg, sc_arg->p, sizeof(ps_syscall_arg_t));

    PS_PRINTF(PS_DEBUG_SYSCALL, "created publication\n");

    return error;
}

static int
ps_syscall_publish(struct thread *td, ps_syscall_arg_t *arg,
                 ps_syscall_sc_arg_t *sc_arg)
{
    vm_offset_t meta, data;
    vm_ooffset_t mlen, moff;
    vm_object_t mobj;
    vm_ooffset_t dlen, doff;
    vm_object_t dobj;
    int error = 0;
    struct vnode *v = NULL;
    int v_fd = -1;
    int vindex = 0; /* index to current version */

    meta = (vm_offset_t) arg->a_meta;
    mlen = (vm_ooffset_t)arg->a_mlen;

    data = (vm_offset_t) arg->a_data;
    dlen = (vm_ooffset_t)arg->a_dlen;

    PS_PRINTF(PS_DEBUG_SYSCALL, "PID=%d, data=%p(%lu)\n", 
	      (int)td->td_proc->p_pid, (void *)data, dlen);

    /*
     * XXX We should handle the data object more intelligently
     *     here, to share memory more efficiently in the case
     *     the version is identical to some already existing
     *     version, or some pages are identical to already
     *     existing pages.
     *
     *     For that, we should
     *      a) unmap dobj from the memory before calling
     *         ps_kern_publish, just like we unmap the 
     *         metadata already
     *      b) pass both data and metadata via references,
     *         so that the layer underneath can change
     *         the actual objects pointed
     *      c) map the dobj COW after successful return.
     */

    /* Find the memory object with data. */
    error = ps_mfind(td, data, dlen, &dobj, &doff);
    if (error)
	goto err;

    /* Make the memory area copy-on-write to force shadows. */
    error = ps_mcow(td, data, dlen);
    if (error)
	goto err;

    /* Find the memory object with meta. */
    error = ps_mfind(td, meta, mlen, &mobj, &moff);
    if (error)
	goto err;

    /* Remove metadata from the calling object's VM space. */
    vm_object_reference(mobj);
    error = ps_munmap(td, meta, mlen);
    if (error) {
	PS_PRINTF(PS_DEBUG_WARNING, 
		  "unmapping of meta failed: mobj=%p, error=%d\n", mobj, error);
	meta = 0;
	goto err;
    }

    error = ps_kern_publish(td, arg->a_sid, arg->a_rid, 
			    dobj, dlen, doff, 
			    &mobj, mlen,
			    &v, &vindex);
    if (error)
	goto err;
    
    if (NULL != v) {
	if (ps_syscall_open_fd(td, v, &v_fd) != 0) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_WARNING, 
		      "WARNING: Could not open publication fd\n");
	}
    } else {
	v_fd = -1;
    }
   
    /*
     * Remap the meta object to the calling process VM space.
     */
    error = ps_mmap(td, &meta, PS_MD_SIZE, VM_PROT_READ, VM_PROT_READ, 
		    MAP_SHARED/* Flags: XXX */,
		    mobj, 0);
    if (error) {
	PS_PRINTF(PS_DEBUG_WARNING, 
		  "remapping of meta failed: mobj=%p, error=%d\n", mobj, error);
	meta = 0;
    } else {
	vm_object_deallocate(mobj);
    }

    /* Copy return values to userspace. */
    arg->a_retval = v_fd;
    arg->a_meta   = (caddr_t)meta;
    arg->a_mlen   = PS_MD_SIZE;
    arg->a_vridx  = vindex;
    copyout(arg, sc_arg->p, sizeof(ps_syscall_arg_t));

 err:
    PS_PRINTF(PS_DEBUG_SYSCALL, "returning -> %d\n", error);

    return error;
}

/*
 * Publish a new version.  
 *
 * XXX: Think through error cases.  Make sure we undo everything
 *      in the case of an error.
 */
static int
publish_version(struct thread *td, ps_pubi_t pi,
		vm_object_t dobj, vm_ooffset_t dlen, vm_ooffset_t doff,
                int *vindex)
{
    int error = 0, error1;
    vm_object_t vmobj;		/* (Temporary) version meta object */
    vm_page_t   vmpage;		/* (Temporary) version meta as a page */
    struct sf_buf *sf;
    ps_meta_t   vmeta;		/* (Temporary) version meta, as a pointer */
    ps_meta_t   pmeta;		/* Publication meta, as a pointer */
    vm_pindex_t pindex;
    psirp_id_t vrid = {{0}};	/* Version RID, sha1 over the metadata */
    ps_pubi_t vpi;		/* Version Pub Index */
    

    PS_PRINTF(PS_DEBUG_FUNTRACE, "ENTER: thread=%p, pubi=%p, dataobj=%p, datalen=%ld, dataoffset=%ld\n", td, pi, dobj, dlen, doff);

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

#ifdef PUBI_HAS_SIDS
    (void) /* XXX */ ps_pubi_add_sid(rid, sid, NOTE_PUBLISH);
#endif

    /*
     * Create a temporary meta object for this version.  This may later
     * get dropped if we find an identical one (which actually happens
     * quite often).  But we don't know if we find an identical one 
     * before we've computed the checksum over all of the data, and that
     * takes some time...
     * 
     * An alternative for creating the meta object here would be just
     * to allocate one page of memory e.g. with zalloc, but my estimate
     * is that the performance benefit would be neligible in most cases.
     * It would probably be better to optimise for the case of one or
     * at most a few pages of data...
     */
    error = ps_obj_alloc(td, PS_MD_SIZE, &vmobj);
    if (error)
	goto err;

    error = ps_obj_copy_meta2version(td, pi, vmobj, vrid, dlen);
    if (error) {
	PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_WARNING, 
		  "failed to copy metadata: error=%d\n", error);
	vm_object_deallocate(vmobj);
	goto err;
    }	

    error = ps_kmap_page(vmobj, 0, &vmpage);
    sf = sf_buf_alloc(vmpage, 0);
    vmeta = (ps_meta_t)sf_buf_kva(sf);

    /*
     * Create the per page PIT entries, and fill them in to 
     * the temporary meta page.
     */
    for (pindex = 0; pindex < dobj->size; pindex++) {
	vm_ooffset_t len;
	psirp_id_t prid = {{0}}; /* Page RID, sha1 over the page */
	ps_pubi_t ppi;		 /* Page Pub Index */

#if 0
        PS_PRINTF(PS_DEBUG_CRYPTO, "(dlen=%lu >= IDX_TO_OFF(pindex=%lu+1)=%lu) ? PAGE_SIZE=%d : dlen&PAGE_MASK=%lu\n", dlen, pindex, IDX_TO_OFF(pindex+1), PAGE_SIZE, dlen&PAGE_MASK); /* XXX */
#endif
	len = (dlen >= IDX_TO_OFF(pindex+1))? PAGE_SIZE: dlen&PAGE_MASK;

	error = ps_obj_sha1_page(dobj, pindex, 0, len, prid.id + PSIRP_ID_LEN - 20 /*XXX*/);

	/* XXXX: Hack alert! Set magic page-RId prefix. */
        *((u_int32_t *)prid.id) = PSIRP_PRID_PREFIX;

	PS_PRINTF(PS_DEBUG_CRYPTO,
                  "prid = %s, pindex = %lu\n",
                  psfs_id2str(prid, NULL), pindex);
	if (error) {
	    
	    goto erro;
	}

	error = ps_pit_getn(td, prid, &ppi);
	switch (error) {
	case EEXIST:
	    /* Existing page */
#if 0
            PS_PRINTF(PS_DEBUG_CRYPTO | PS_DEBUG_SYSCALL,
                      "prid already in pit: ...%s, pubi = %p\n",
                      &psfs_id2str(prid, NULL)[17], ppi);
#endif
	    /* XXX What we do here (i.e. nothing) is quite inefficient.
	     *     What we should do instead is
	     *      a) verify that the page really is identical (a safeguard)
	     *      b) replace the vm_page in the vm_object with the existing one
	     *     However, the latter requires that the vm_object is 
	     *     unmapped from the process map before getting here etc,
	     *     or otherwise things get complicated.
	     *     Anyway, we should not attempt to implement any of this
	     *     before we have a very comprehensive test suite in place.
	     */
#ifdef DEBUG
	    ps_obj_vrfy_meta_page(ppi);
#endif
	    break;
	case 0:
	    /* Completely new page, needs ppi data and metadata */
	    ppi->pi_object  = dobj;
	    ppi->pi_pindex  = pindex;
	    ppi->pi_uid     = UID_NOBODY;
	    ppi->pi_gid     = GID_NOBODY;
	    ppi->pi_mode    = S_IRUSR | S_IXUSR 
		            | S_IRGRP | S_IXGRP 
		            | S_IROTH | S_IXOTH;
	    error = ps_obj_init_meta_page(td, ppi, &prid);
	    if (!error)
		break;
	    /* FALLTHROUGH */
	default:
	    PS_OBJ_PUBI_UNLOCK(ppi);
	    goto erro;
	}
	ppi->pi_pindex = pindex;
	PS_OBJ_PUBI_UNLOCK(ppi);

	MPASS(vmeta->pm_page_count <= PS_META_SUB_OBJECT_COUNT);
	if (vmeta->pm_page_count < PS_META_SUB_OBJECT_COUNT) {
	    vmeta->pm_sub_object[vmeta->pm_page_count++] = prid;
	} else {
	    /* XXX: To be replaced with something else, but for now
	     * we simply don't support this big publications. 
	     * See the maxsize table above.
	     */
	    panic("Cannot currently handle objects larger than %ld pages",
		  PS_META_SUB_OBJECT_COUNT);
	}
    }

#if 0
    ps_debug_dump_meta_hdr("Version metadata header", vmeta);
    ps_debug_print_meta_sub("Version metadata sub-objects", vmeta);
#elif 0
    ps_debug_print_meta("vmeta", vmeta);
#endif

#if 0
    /*
     * Compute the SHA1 hash over the page-RIds in the temporary meta page
     */
    error = ps_obj_sha1_page(
                vmobj, 0,
                ((uintptr_t)&vmeta->pm_sub_object - (uintptr_t)vmeta),
                vmeta->pm_page_count * sizeof(vmeta->pm_sub_object[0]),
                vrid.id + PSIRP_ID_LEN - 20 /*XXX*/);
#else
    /*
     * Compute the root hash of a skewed merkle hash tree created from
     * the page-RIds in the temporary meta page (i.e., hashes over
     * data pages), and use it as the version-RId.
     *
     * XXX: Document why we cannot just use the already mapped data,
     *      but need to call a function that re-maps it.
     */
    error = ps_obj_sha1_mt_page(
                vmobj, 0,
                ((uintptr_t)&vmeta->pm_sub_object - (uintptr_t)vmeta),
                vmeta->pm_page_count,
                vrid.id + PSIRP_ID_LEN - SHA1_RESULTLEN /*XXX*/);
#endif

    /* XXXX: Hack alert! Set magic version-RId prefix. */
    *((u_int64_t *)vrid.id) = PSIRP_VRID_PREFIX;

    /*
     * Assign to the version's metadata the version-RId that we just computed.
     */
    vmeta->pm_id = vrid;

    /*
     * Release the temporary meta object KVA
     */
  erro:
    sf_buf_free(sf);
    error1 = ps_kunmap_page(vmobj, vmpage, TRUE);
    if (error || error1) {
	vm_object_deallocate(vmobj);
        PS_PRINTF(PS_DEBUG_FUNTRACE | PS_DEBUG_WARNING,
                  "EXIT: %d\n", error? error: error1);
	return error? error: error1;
    }

    /*
     * XXXXX: Anything we need to do here?
     */

    PS_PRINTF(PS_DEBUG_CRYPTO, "vrid = %s\n", psfs_id2str(vrid, NULL));

    /*
     * Add an entry to the PIT.  Note that while publication versions are 
     * in the PIT like all other publications (scopes, user level pubs),
     * they do not appear in any scope (at least not currently, April 20 2009).
     */
    error = ps_pit_getn(td, vrid, &vpi);
    PS_OBJ_PUBI_ASSERT_OWNED(vpi);
    
    switch (error) {
    case EEXIST:
	/*
	 * An identical version already exists.
	 * Throw away the temporary metadata object,
	 * and replaced the called dobj and dlen
	 * with the already existing version.
	 */
#if 0
	PS_PRINTF(PS_DEBUG_CRYPTO | PS_DEBUG_SYSCALL,
		  "vrid already in pit: ...%s, pubi = %p\n",
                  &psfs_id2str(vrid, NULL)[17], vpi);
#endif
	vm_object_deallocate(vmobj);
	error = ps_obj_get_dataobj(vpi, &dobj, &dlen, NULL);
	break;
    case 0:
	/*
	 * Create a new version.  Set up metadata and data.
	 */
	MPASS(NULL == vpi->pi_metaobj);
	MPASS(NULL == vpi->pi_object);

	/* 
	 * Note that it is crucial to clear ONEMAPPING, as otherwise the content
	 * may be lost at the process reapout time.
	 */
	VM_OBJECT_LOCK(dobj);
	vm_object_reference_locked(dobj); /* Reference for vpi->pi_object */
	vm_object_clear_flag(dobj, OBJ_ONEMAPPING);
	VM_OBJECT_UNLOCK(dobj);
	
	vpi->pi_metaobj = vmobj;
	vpi->pi_object  = dobj;
	vpi->pi_uid     = UID_NOBODY;
	vpi->pi_gid     = GID_NOBODY;
	vpi->pi_mode    = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	break;
    }

    MPASS(NULL != vpi->pi_metaobj);
    MPASS(NULL != vpi->pi_object);
    PS_OBJ_PUBI_ASSERT_OWNED(vpi);
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    PS_OBJ_PUBI_UNLOCK(vpi);

    if (error)
	goto err;

    /*
     * Add the version RID to the publication metadata and
     * replace the data to point to the version.
     */
    error = ps_obj_add_version(pi, vrid, dobj, dlen); /* Bumps dobj reference count */
    if (error) 
	goto err;

    error = ps_obj_get_page(pi, VMO_META, 0, (void **)&pmeta);
    if (error)
        goto err;

    /* record version RID index in meta header (but only if it's not first time
     * publish. 
     */
    if (vindex)
        *vindex = pmeta->pm_vers_count-1;

#if 0
    ps_debug_print_meta("pmeta", pmeta); /* XXXX */
#endif

#ifdef INVARIANTS

    MPASS(1 == pi->pi_metaobj->size);
    PS_OBJ_PUBI_LOCK(vpi);
    if (!ps_obj_get_page(vpi, VMO_META, 0, (void **)&vmeta)) {
        MPASS(pmeta->pm_size >= 0);
        MPASS(pmeta->pm_size == vmeta->pm_size);
        MPASS(OFF_TO_IDX(pmeta->pm_size - 1) + 1 == pi->pi_object->size);
        MPASS(pi->pi_object == vpi->pi_object);
        ps_obj_put_page(vpi, VMO_META, FALSE);
    }
    PS_OBJ_PUBI_UNLOCK(vpi);
    PS_OBJ_PUBI_ASSERT_NOT_OWNED(vpi);
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
#endif

    ps_obj_put_page(pi, VMO_META, FALSE);
    PS_PRINTF(PS_DEBUG_FUNTRACE, "EXIT: 0\n");
    return 0;

  err:
#ifdef INVARIANTS
    if (vpi)
	PS_OBJ_PUBI_ASSERT_NOT_OWNED(vpi);
#endif
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    MPASS(NULL == vpi || (NULL == vpi->pi_metaobj && NULL == vpi->pi_object));
    PS_PRINTF(PS_DEBUG_FUNTRACE, "EXIT: error=%d\n", error);
    return error;
}

/*
 * First time publish.
 */
static int
publish_first(struct thread *td, ps_pubi_t pi, psirp_id_t rid, 
	      vm_object_t dobj, vm_ooffset_t dlen, vm_ooffset_t doff,
	      vm_object_t mobj, vm_ooffset_t mlen)
{
    int error = 0;

    PS_PRINTF(PS_DEBUG_FUNTRACE, "ENTER: thread=%p, pubi=%p, "
              "rid=%s, dataobj=%p, datalen=%ld, dataoff=%ld, metaobj=%p, "
              "metalen=%ld\n", td, pi, psfs_id2str(rid, NULL), dobj, dlen, 
              doff, mobj, mlen);

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    MPASS(NULL == pi->pi_metaobj);
    MPASS(NULL != mobj);

    /*
     * XXXXXXXX: The metadata object may already be in use in some
     *           other publication.  The current plan is to fail, 
     *           but a better way would be to take a copy of the
     *           metadata.
     */

    /*
     * Verify that the metadata has the right format and if so,
     * put it to the PIT.
     */
    error = ps_obj_init_meta_kernel(mobj, PS_PUB_UNINITIALISED, rid, dlen);
    if (error)
	return error;
    pi->pi_metaobj = mobj;

    /* 
     * Bump the reference count for meta; this happens only during the
     * first publication, as then meta is placed in the PUBI.
     * Later on meta remains there, untouched, and controlled by the kernel.
     * 
     * Note that it is crucial to clear ONEMAPPING, as otherwise the content
     * will be lost at the process reapout time.
     */
    VM_OBJECT_LOCK(mobj);
    vm_object_reference_locked(mobj);
    vm_object_clear_flag(mobj, OBJ_ONEMAPPING);
    VM_OBJECT_UNLOCK(mobj);

    /*
     * Initialize access control fields
     */
    pi->pi_uid  = td->td_ucred->cr_uid;
    pi->pi_gid  = td->td_ucred->cr_groups[0];
    pi->pi_mode = ACCESSPERMS & ~td->td_proc->p_fd->fd_cmask; 

    error = publish_version(td, pi, dobj, dlen, doff, NULL);

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    return error;
}

/*
 * Republication. 
 */
static int
republish(struct thread *td, ps_pubi_t pi, psirp_id_t rid,
	  vm_object_t dobj, vm_ooffset_t dlen, vm_ooffset_t doff, int *vindex)
{
    int error = 0;
    enum ps_pub_type type;

    PS_PRINTF(PS_DEBUG_FUNTRACE, "ENTER: thread=%p, pubi=%p, rid=%s,"
              " dataobj=%p, datalen=%ld, dataoff=%ld\n", td, pi, 
              psfs_id2str(rid, NULL), dobj, dlen, doff);

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    MPASS(NULL != pi->pi_metaobj);
#ifdef RIDINPUBI
    MPASS(0 == memcmp(pi->pi_rid.id, rid.id, sizeof(struct psirp_id_t)));
#endif

    /*
     * Check access control
     */
    error = vaccess(VDIR, pi->pi_mode, pi->pi_uid, pi->pi_gid, VWRITE, 
		    td->td_ucred, NULL);
    if (error) {
	PS_PRINTF(PS_DEBUG_SYSCALL, "permission denied: mode=%o, uid=%d, gid=%d\n", 
		  pi->pi_mode, pi->pi_uid, pi->pi_gid);
	goto err;
    }

    /*
     * Verify that if this is expected to be a scope, this is a scope,
     * and vice versa.
     */
    error = ps_obj_get_type(pi, &type);
    if (error) 
	goto err;

    switch (type) {
    case PS_PUB_UNINITIALISED:
	panic("republish: uninitialized publication");
    case PS_PUB_UNKNOWN:
    case PS_PUB_DATA:
	/* Either not set yet or data.  Can write anything. */
	break;
    case PS_PUB_SCOPE:
	error = ps_scope_verify_format(dobj);
	if (error)
	    goto err;
	break;
    default:
	panic("republish: unknown publication type %d", type);
    }

    error = publish_version(td, pi, dobj, dlen, doff, vindex);
    //PS_PRINTF(PS_DEBUG_SYSCALL, "vindex=%d\n", *vindex);

  err:
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    PS_PRINTF(PS_DEBUG_FUNTRACE, "EXIT: %d\n", error);
    return error;
}


/*
 * Returns vppub locked in *vpp, if *vpp != NULL.
 * Otherwise vputs vppub.
 */
int 
ps_kern_publish(struct thread *td, psirp_id_t sid, psirp_id_t rid, 
		vm_object_t dobj, vm_ooffset_t dlen, vm_ooffset_t doff,
		vm_object_t *mobjp, vm_ooffset_t mlen,
		struct vnode **vpp, int *vindex) 
{
    vm_object_t mobj = *mobjp;
    int error = 0, vfslocked = 0;
    ps_pubi_t pi;
#ifdef DEBUG
    char tempstr[PSIRP_ID_LEN *2 + 1] = {0};
    
    psfs_id2str(sid, tempstr);
    PS_PRINTF(PS_DEBUG_SYSCALL, "SID=%s RID=%s\n", tempstr, psfs_id2str(rid, NULL));
#endif

    error = ps_pit_getn(td, rid, &pi);
    if (error && EEXIST != error)
	return error;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    MPASS((EEXIST == error && NULL != pi->pi_metaobj) ||
	  (EEXIST == error && NULL == pi->pi_metaobj && &ps_pubi_scope0 == pi) ||
	  (     0 == error && NULL == pi->pi_metaobj));

    if (NULL == pi->pi_metaobj) {
	error = publish_first (td, pi, rid, dobj, dlen, doff, mobj, mlen);
    } else { 
        if (mobj != pi->pi_metaobj) {
            PS_PRINTF(PS_DEBUG_SYSCALL,
                      "Replacing mobj: %p -> %p\n", mobj, pi->pi_metaobj);
            
            /* XXX: Replace the new meta object with the existing one. */
            vm_object_reference(pi->pi_metaobj);
            vm_object_deallocate(mobj);
            *mobjp = pi->pi_metaobj;
            mobj = *mobjp;
        }
        
	error = republish     (td, pi, rid, dobj, dlen, doff, vindex);
    }
    PS_OBJ_PUBI_UNLOCK(pi);
    if (error)
	return error;

    /*
     * The basic publication succeeded and the new version is now
     * in the PIT.  We next have to inform the rest of the system.
     */
    ps_event_add(PS_EVENT_PUB, &sid, &rid, 0x00 /* XXX */);
    if (psfs_mp) {
	struct vnode *vp = NULL;

	/* 
	 * Post a knote at the publication itself.
	 * 
	 * XXX: If vpp == NULL, we probably wouldn't need exclusive lock
	 */
	error = psfs_node_allocvp(td, psfs_mp, sid, rid, VPUB, LK_EXCLUSIVE, &vp);
	if (error) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_WARNING | PS_DEBUG_KNOTE,
		      "KNOTE: failed to allocate VPUB for %s\n", psfs_id2str(rid, NULL));
	    goto err1;
	}
	
	MPASS(NULL != vp);
	PS_PRINTF(PS_DEBUG_KNOTE, "KNOTE: Posting PUBLISH | WRITE KNOTE %s\n", 
		  psfs_id2str(rid, NULL));
	VFS_KNOTE_LOCKED(vp, NOTE_PUBLISH | NOTE_WRITE);
	if (vpp) {
	    *vpp = vp;
	} else {
            vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	    vput(vp);
            VFS_UNLOCK_GIANT(vfslocked);
	}

	/* 
	 * Post a KNOTE at /pubsub/pubs.
	 */
	error = psfs_node_allocvp(td, psfs_mp, root_id, root_id, 
				  VEVENTPUBS, LK_SHARED, &vp);
	if (error) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_WARNING | PS_DEBUG_KNOTE,
		      "KNOTE: failed to allocate VROOT\n");
	    goto err1;
	}
	MPASS(NULL != vp);
	PS_PRINTF(PS_DEBUG_KNOTE, "KNOTE: Posting PUBLISH on /pubsub/pubs\n"); 
	VFS_KNOTE_LOCKED(vp, NOTE_PUBLISH | NOTE_WRITE | NOTE_EXTEND);
        vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	vput(vp);
        VFS_UNLOCK_GIANT(vfslocked);
    }
  err1:
    PS_OBJ_PUBI_ASSERT_NOT_OWNED(pi);
    
    PS_PRINTF(PS_DEBUG_FUNTRACE, "EXIT: %d\n", error);

    return error;
}

static int
ps_syscall_open_fd(struct thread *td, struct vnode *vp, int *fd)
{
    struct file *fp;
    struct filedesc *fdp;
    int error, vfslocked = 0;

    /* we need file descriptor table for the process */
    fdp = td->td_proc->p_fd;

#ifdef MAC
    error = mac_check_vnode_open(td->td_ucred, vp, VREAD);
    if (error) {
        vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	vput(vp);
        VFS_UNLOCK_GIANT(vfslocked);
	goto done;
    }
#endif

    error = VOP_ACCESS(vp, VREAD, td->td_ucred, td);
    if (error) {
        vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	vput(vp);
        VFS_UNLOCK_GIANT(vfslocked);
	goto done;
    }
    
    error = falloc(td, &fp, fd);
    if (error) {
        vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	vput(vp);
        VFS_UNLOCK_GIANT(vfslocked);
	goto done;
    }
    
    error = VOP_OPEN(vp, FREAD, td->td_ucred, td, fp);
    if (error) {
	fdclose(fdp, fp, *fd, td);
	fdrop(fp, td);
	*fd = -1;
        vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	vput(vp);
        VFS_UNLOCK_GIANT(vfslocked);
	goto done;
    }
    ASSERT_VOP_ELOCKED(vp, "ps_syscall_subscribe");
#if __FreeBSD_version >= 800000
    VOP_UNLOCK(vp, 0);
#else
    VOP_UNLOCK(vp, 0, td);
#endif
#if __FreeBSD_version >= 800000
    FILEDESC_XLOCK(fdp);
#else
    FILE_LOCK(fp);
#endif
    fp->f_ops = &vnops;
    fp->f_vnode = vp;
#if __FreeBSD_version >= 800000
    FILEDESC_XUNLOCK(fdp);
#else
    FILE_UNLOCK(fp);
#endif

    /* falloc() takes 2 references! So we drop one of them */
    fdrop(fp, td);
  done:
    return error;
}

static int
ps_syscall_get_rid(psirp_id_t sid, psirp_id_t rid, off_t *idxp) {
    int error = 0;
    ps_pubi_t pi;
    enum ps_pub_type type;

    error = ps_pit_get(sid, &pi);
    if (ENOENT == error)
	return ESRCH;
    if (error)
	return error;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    error = ps_obj_get_type(pi, &type);

    if (!error) {
        switch (type) {
        case PS_PUB_SCOPE:
            /*
             * XXX: Because of this type check, we cannot subscribe to
             *      a specific scope version, at least not via a
             *      generic subscribe(sid, vrid) call. We always
             *      assume that if the type of the publication that
             *      was looked up with the 'sid' parameter is
             *      PS_PUB_SCOPE, then the next step is to get the RId
             *      from the scope's data page instead of the
             *      version-RId from its metadata. Anyway, some kind
             *      of a workaround could quite easily be implemented
             *      if this functionality is needed.
             */
            error = ps_scope_get_rid(pi, &rid, idxp);
            break;
        case PS_PUB_DATA:
        case PS_PUB_VERSION:
            error = ps_obj_get_rid(pi, &rid, idxp, type);
            break;
        default:
            PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_WARNING,
                      "WARNING: attempt to access scope with bad type %d\n",
                      type);
            error = ENOTDIR;
            break;
        }
    }

    PS_OBJ_PUBI_UNLOCK(pi);
    return error;
}

enum sub_case { COMPLETELY_NEW, EXISTS_ELSEWHERE, SUBSCRIBED_HERE, PUBLISHED_HERE };

static int
ps_syscall_subscribe(struct thread *td,
		     ps_syscall_arg_t *arg,
		     ps_syscall_sc_arg_t *sc_arg)
{
    int error = 0, vfslocked = 0;
    off_t idx = 0;
    ps_pubi_t pi;
    psirp_id_t sid, rid;
    ps_flags_t flags;
    
    char tempstr[PSIRP_ID_LEN * 2 + 1] = {0};

    psfs_id2str(arg->a_sid, tempstr);
    PS_PRINTF(PS_DEBUG_SYSCALL, "PID=%d, SID=%s, RID=%s\n", 
	   (int)td->td_proc->p_pid, tempstr, psfs_id2str(arg->a_rid, NULL));

    arg->a_meta = 0;
    arg->a_mlen = 0;
    arg->a_data = 0;
    arg->a_dlen = 0;
    arg->a_retval = -1;

    sid = arg->a_sid;
    rid = arg->a_rid;

    flags = arg->a_flags;

    /*
     * If mounted, post KNOTEs anyway, before checking anything.
     */
    ps_event_add(PS_EVENT_SUB, &sid, &rid, flags);
    if (psfs_mp) {
	struct vnode *vp = NULL;

	/* 
	 * Post a note at /pubsub/subs.
	 */
	error = psfs_node_allocvp(td, psfs_mp, root_id, root_id, 
				  VEVENTSUBS, LK_SHARED, &vp);
	if (!error) {
	    PS_PRINTF(PS_DEBUG_KNOTE, "KNOTE: Posting SUBSCRIBE on /pubsub/subs\n");
	    VFS_KNOTE_LOCKED(vp, NOTE_SUBSCRIBE);
            vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	    vput(vp);
            VFS_UNLOCK_GIANT(vfslocked);
	}

	/*
	 * Post a note at the scope.
	 */
	error = psfs_node_allocvp(td, psfs_mp, root_id, sid, 
				  VSCOPE, LK_SHARED, &vp);
	if (!error) {
	    PS_PRINTF(PS_DEBUG_KNOTE, "KNOTE: Posting SUBSCRIBE on %s\n", 
		      psfs_id2str(sid, NULL));
	    VFS_KNOTE_LOCKED(vp, NOTE_SUBSCRIBE); 
            vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	    vput(vp);
            VFS_UNLOCK_GIANT(vfslocked);
	}
    }

    /*
     * If the publication does not exist in the scope,
     * or the scope doesn't exist, fail just as if 
     * the publication did not exist at all.
     */
    error = ps_syscall_get_rid(sid, rid, &idx);
    if (error) {
	return error;
    }
    
    /*
     * If the publication does not exist, we fail here.
     * It is then the responsibilty of the user level to 
     * subscribe to the scope instead.
     */
    error = ps_pit_get(rid, &pi);
    if (error) {
	return error;
    }

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    /* 
     * Map metadata to the caller's address space.
     */
    {
	vm_offset_t addr;
        ps_meta_t pmeta;

	MPASS(NULL != pi->pi_metaobj);

	addr = 0;
	error = ps_mmap(td, &addr, PS_MD_SIZE, VM_PROT_READ, VM_PROT_READ, 
			MAP_SHARED,
			pi->pi_metaobj, 0);
	if (error) 
	    goto done;
	PS_PRINTF(PS_DEBUG_SYSCALL, "mapped meta at 0x%lx(0x%x)\n", addr, PS_MD_SIZE);
	
	arg->a_meta = (caddr_t)addr;
	arg->a_mlen = PS_MD_SIZE;
        
        /* Set version index. */
        error = ps_obj_get_page(pi, VMO_META, 0, (void **)&pmeta);
#if 0
        ps_debug_print_meta("subscribe: pmeta", pmeta);
#endif
        if (error || NULL == pmeta) {
            goto done;
        }
        arg->a_vridx = pmeta->pm_vers_count-1;
        PS_PRINTF(PS_DEBUG_SYSCALL, "version-rid index=%d\n", arg->a_vridx);
        ps_obj_put_page(pi, VMO_META, FALSE);
    }

    /*
     * If available, map the present version of the data to the caller
     */
    {
	vm_object_t obj;
	vm_ooffset_t size;
	vm_offset_t addr;
	vm_ooffset_t offset;
        enum ps_pub_type type;

	error = ps_obj_get_dataobj(pi, &obj, &size, &type);
	if (error || NULL == obj) 
	    goto done;

#ifdef DEBUG
	PS_PRINTF(PS_DEBUG_SYSCALL, "obj:");
#ifdef INVARIANTS
	if (ps_debug_mask & PS_DEBUG_SYSCALL)
	    vm_object_print((long)obj, TRUE, 0, 0);
#endif
	if (obj->backing_object) {
	    PS_PRINTF(PS_DEBUG_SYSCALL, "obj->backing_object:");
#ifdef INVARIANTS
	    if (ps_debug_mask & PS_DEBUG_SYSCALL)
		vm_object_print((long)obj->backing_object, TRUE, 0, 0);
#endif
	}
#endif
	
	addr = 0;
        offset = 0;
        if (type == PS_PUB_PAGE) {
            size &= PAGE_MASK;
            offset = pi->pi_pindex*PAGE_SIZE;
        }
	error = ps_mmap(td, &addr, size, VM_PROT_ALL, VM_PROT_ALL, 
			MAP_SHARED | MAP_COPY_ON_WRITE /* XXX */,
			obj, offset);
	if (error) 
	    goto done;
	PS_PRINTF(PS_DEBUG_SYSCALL, "mapped data at 0x%lx(0x%lx)\n", addr, size);
	
	arg->a_data = (caddr_t)addr;
	arg->a_dlen = size;
    }
 done:
    PS_OBJ_PUBI_UNLOCK(pi);
    
    /*
     * If mounted, open an FD for future NOTE_PUBLISH events.
     */
    if (psfs_mp) {
	struct vnode *vp = NULL;
	int vppub_fd = -1;

	/*
	 * Get the vnode for the publication.
	 */
	error = psfs_node_allocvp(td, psfs_mp, sid, rid, VPUB, LK_EXCLUSIVE, &vp);
	if (error)
	    goto err;

	/*
	 * Open vp as a file descriptor.  Eats vp, no need to release.
	 */
	error = ps_syscall_open_fd(td, vp, &vppub_fd);
	if (error) {
	    /* open_fd does vput on error -- no need to do it here. */
	    goto err;
	}

	arg->a_retval = vppub_fd;
    }

  err:
    PS_OBJ_PUBI_ASSERT_NOT_OWNED(pi);
    /* 
     * Copy return values to userspace.  Note that the meta
     * and data objects have already been assigned to arg.
     */
    copyout(arg, sc_arg->p, sizeof(ps_syscall_arg_t));

    PS_PRINTF(PS_DEBUG_SYSCALL, "returning -> %d\n", error);

    return error;
}

/*
 * Houskeeping functions
 */

static void
ps_syscall_print_map(vm_map_t map)
{
    vm_map_entry_t map_entry;
    vm_object_t object;

    vm_map_lock(map);

    map_entry = map->header.next;
    while (map_entry != &map->header) {
        object = NULL;
        printf("map_entry: %p-%p ooffset=%p",
               (void *)map_entry->start,
               (void *)map_entry->end,
               (void *)map_entry->offset);
        if (map_entry->eflags & MAP_ENTRY_PUBLICATION)
            printf(" PUB");
        if (map_entry->eflags & MAP_ENTRY_COW)
            printf(" COW");
        if (map_entry->eflags & MAP_ENTRY_NEEDS_COPY)
            printf(" NC");
        printf("\n");
        object = map_entry->object.vm_object;
        if (object == NULL) {
            printf("object=NULL\n");
        } else {
            int i = 0, j = 1;
            while (object != NULL) {
                VM_OBJECT_LOCK(object);
                for (i = 0; i < j; i++)
                    printf("*");
                printf(" object=%p sz=%ld refs=%d shads=%d\n",
                       (void *)object, object->size,
                       object->ref_count, object->shadow_count);
                VM_OBJECT_UNLOCK(object);
                object = object->backing_object;
                j++;
            }
        }   
        map_entry = map_entry->next;
    }

    vm_map_unlock(map);
}


static int
ps_syscall_status(ps_syscall_arg_t *sa)
{
    char *ptr;
    int len;

    printf("\nMemory map of current process:\n");
    ps_syscall_print_map(&curproc->p_vmspace->vm_map);
    printf("\n");

    if (sa->a_retbuf_len == 0)
        return 0;

    MALLOC(ptr, char *, sa->a_retbuf_len, M_DEBUGPIT, M_WAITOK);
#ifdef DEBUG
    len = ps_pit_status(ptr, sa->a_retbuf_len);
#else
    len = -1;
#endif
    copyout(ptr, sa->a_retbuf, sa->a_retbuf_len);
    FREE(ptr, M_DEBUGPIT);

    return len;
}

static int
ps_syscall_call(struct thread *td, void *sa)
{
    ps_syscall_sc_arg_t *sc_arg;
    ps_syscall_arg_t arg;
    int retval = 0;

    memset(&arg, 0, sizeof(arg));

    sc_arg = (ps_syscall_sc_arg_t *)sa;
    copyin(sc_arg->p, &arg, sizeof(arg));

    PS_PRINTF(PS_DEBUG_SYSCALL, "SYSENTER: op=%d\n", arg.a_op);
    switch (arg.a_op) {
    case PS_SYSCALL_NOP:
        printf("ps_syscall: nop\n");
        break;
    case PS_SYSCALL_STA:
        retval = ps_syscall_status(&arg);
        break;
    case PS_SYSCALL_CRE:
        retval = ps_syscall_create(td, &arg, sc_arg);
        break;
    case PS_SYSCALL_PUB:
        retval = ps_syscall_publish(td, &arg, sc_arg);
        break;
    case PS_SYSCALL_SUB:
        retval = ps_syscall_subscribe(td, &arg, sc_arg);
        break;
    default:
        PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_ERROR,
		  "unsupported opcode (%d)\n", arg.a_op);
        retval = EINVAL;
        break;
    }

    PS_PRINTF(PS_DEBUG_SYSCALL, "SYSEXIT: op=%d -> %d\n", arg.a_op, retval);
    return retval;
}

static int
ps_syscall_init()
{
    return 0;
}

static int
ps_syscall_cleanup()
{
    return 0;
}

static int offset = NO_SYSCALL;

static int
ps_mod_event (struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
	error = ps_pit_init();
	if (error) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_ERROR,
		      "failed to init pit: %d\n", error);
	    break;
	}
	error = ps_pubi_init();
	if (error) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_ERROR,
		      "failed to init pubi: %d\n", error);
	    break;
	}
	error = ps_event_init(curthread);
	if (error) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_ERROR,
		      "failed to init events: %d\n", error);
	    break;
	}
        error = ps_syscall_init();
	if (error) {
	    PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_ERROR,
		      "failed to init syscalls: %d\n", error);
	    break;
	}
	error = ps_socket_init();
	if (!error) {
	    printf ("psfs: loaded at %d\n", offset);
	} else {
	    printf ("psfs: load failed, error=%d\n", error);
	}
	break;
    case MOD_UNLOAD:
	error = ps_socket_cleanup();
	if (error) {
	    printf ("psfs: unload failed, error=%d\n", error);
	    break;
	}
	ps_event_cleanup();
	ps_pubi_cleanup();
	ps_pit_cleanup();
        ps_syscall_cleanup();
	printf ("psfs: unloaded from %d\n", offset);
	break;
    default:
	error = EOPNOTSUPP;
	break;
    }
    return error;
}

SYSCALL_MODULE(ps_syscall, &offset, &ps_syscall_sysent, ps_mod_event, NULL);
