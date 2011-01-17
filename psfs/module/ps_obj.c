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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sf_buf.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>
#include <vm/vm_pager.h>

#include <crypto/sha1.h>
//#include <crypto/sha2/sha2.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_obj.h"
#include "ps_magic.h"
#include "ps_syscall.h"
#include "ps_pit.h"
#include "ps_map.h"
#include "ps_debug.h"

#include "psfs.h"		/* For pretty printing etc. */

typedef int (*meta_access_f)(ps_pubi_t pi, ps_meta_t meta, boolean_t *written, 
			     void *arg1, void *arg2);

static int
meta_access(ps_pubi_t pi, meta_access_f f, void *arg1, void *arg2);

static void
ps_obj_set_datasize(ps_pubi_t pi, ps_meta_t meta, vm_ooffset_t size);

int
ps_obj_alloc(struct thread *td, vm_ooffset_t size, vm_object_t *objp) 
{
    int error = 0;
    vm_object_t obj;

    /* Create a VM object. */
#if __FreeBSD_version < 800000
    obj = vm_pager_allocate(OBJT_SWAP, NULL, size, VM_PROT_ALL, 0);
#else
    obj = vm_pager_allocate(OBJT_SWAP, NULL, size, VM_PROT_ALL, 0,
			    NULL /*td->td_ucred*/);
#endif
    if (obj == NULL) {
	PS_PRINTF(PS_DEBUG_OBJ | PS_DEBUG_ERROR,
		  "cannot allocate object: size=%ld\n", size);
	error = ENOMEM;
	goto done;
    }
    *objp = obj;

  done:
    return error;
}

int
ps_obj_init_meta_user(vm_object_t metaobj)
{
    int error;
    vm_page_t page;
    struct sf_buf *sf;
    ps_meta_t meta;

    error = ps_kmap_page(metaobj, 0, &page); /* metaobj->reference++ */
    if (error) 
	return error;

    sched_pin();
    sf = sf_buf_alloc(page, SFB_CPUPRIVATE);
    meta = (ps_meta_t)sf_buf_kva(sf);

    meta->pm_magic = PS_META_MAGIC;
    meta->pm_type  = PS_PUB_UNINITIALISED;
#if 1
    /* XXXXXXX: Remove this once the user level has been fixed. */
    meta->pm_type  = PS_PUB_DATA;
#endif
#if 0
    /* XXX */
    bzero(&meta->pm_id, sizeof(meta->pm_id));
#endif
    meta->pm_size  = -1;
    meta->pm_vers_count = 0;

    sf_buf_free(sf);
    sched_unpin();

    return ps_kunmap_page(metaobj, page, TRUE);
}

#ifdef PS_META_BF
static inline void id_into_bf(psirp_id_t *idp, u_int8_t *bf, int k) {
    u_int32_t crc;
    u_int8_t  bi; /* bit index */
    int i;
    //int bitcount = 0;

    crc = crc32((const unsigned char *)idp, sizeof(psirp_id_t));
    for (i = 0; i < k; i++) {
        bi = (crc >> (i << 3)) & 0xff; /* XXX: bf must be at least 256 bits */
        bf[(bi >> 3)] |= 1 << (bi % 8);
        //bitcount += __builtin_popcount(bf[(bi >> 3)]);
    }
}
#endif

MALLOC_DEFINE(M_METALOCK, "psmeta", "pubsub meta interlock");

int
ps_obj_init_meta_kernel(vm_object_t metaobj, enum ps_pub_type type, psirp_id_t rid, vm_ooffset_t dlen)
{
    int error, error1;
    vm_page_t page;
    struct sf_buf *sf;
    ps_meta_t meta;

    PS_PRINTF(PS_DEBUG_OBJ,
	      "obj=%p, type=%d, rid=%s, dlen=%ld\n",
	      metaobj, type, psfs_id2str(rid, NULL), dlen);

    error = ps_kmap_page(metaobj, 0, &page); /* metaobj->reference++ */
    if (error) 
	return error;

    sched_pin();
    sf = sf_buf_alloc(page, SFB_CPUPRIVATE);
    meta = (ps_meta_t)sf_buf_kva(sf);

    if (type != PS_PUB_UNINITIALISED) {
	meta->pm_type = type;
    }
    if (!PS_MAGIC_TEST(meta->pm_magic, PS_META_MAGIC)) {
	PS_PRINTF(PS_DEBUG_WARNING | PS_DEBUG_OBJ, 
		  "bad meta magic: %s\n", psfs_id2str(meta->pm_magic, NULL));
	error = EFTYPE;
	goto err;
    }
    if (! PS_PUB_CHECK_TYPE(meta)) {
	PS_PRINTF(PS_DEBUG_WARNING | PS_DEBUG_OBJ, 
		  "bad meta type: %d\n", PS_PUB_TYPE(meta));
	error = EFTYPE;
	goto err;
    }

    meta->pm_id   = rid;
    meta->pm_size = dlen;

#ifdef PS_META_BF
    if (type == PS_PUB_PAGE) {
        id_into_bf(&rid, meta->pm_bf_idh.bf, PS_META_BF_K);
    }
#endif

    if (PS_PUB_MUTABLE(meta)) {
	PS_PRINTF(PS_DEBUG_OBJ, "Initialising as mutable.\n");
	meta->pm_vers_count = 0;
	meta->pm_interlock = malloc(sizeof(struct mtx), M_METALOCK, M_WAITOK);
	memset(meta->pm_interlock, 0, sizeof(struct mtx));
	mtx_init((meta->pm_interlock), "psfs meta interlock", NULL, MTX_DEF);
    } else {
	PS_PRINTF(PS_DEBUG_OBJ, "Initialising as static.\n");
	meta->pm_page_count = 0;
    }

#ifdef NOTYET
    /*
     * Vattrs
     */
    getnanotime(&meta->pm_atime);
    meta->pm_birthtime = meta->pm_ctime = meta->pm_mtime 
	= meta->pm_atime;
#endif

    PS_OBJ_META_ASSERT(meta);

  err:
    sf_buf_free(sf);
    sched_unpin();

    error1 = ps_kunmap_page(metaobj, page, TRUE);

    return error? error: error1;
}

static vm_object_t ps_page_metaobj = NULL;

int
ps_obj_init_meta_page(struct thread *td, ps_pubi_t pi, psirp_id_t *pridp)
{
    static psirp_id_t null_id = { { 0 } };
    int error = 0;
    
    if (NULL == ps_page_metaobj) {
	error = ps_obj_alloc(td, PS_MD_SIZE, &ps_page_metaobj);
	if (error) 
	    return error;
	error = ps_obj_init_meta_user(ps_page_metaobj);
	if (error) 
	    goto err;
	error = ps_obj_init_meta_kernel(ps_page_metaobj,
                                        PS_PUB_PAGE,
                                        ((NULL == pridp) ? null_id : *pridp),
                                        PAGE_SIZE);
	if (error)
	    goto err;
	    
    }

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    vm_object_reference(ps_page_metaobj);
    pi->pi_metaobj = ps_page_metaobj;
    return 0;

  err:
    vm_object_deallocate(ps_page_metaobj);
    return error;
} 

#ifdef DEBUG
void
ps_obj_vrfy_meta_page(ps_pubi_t pi) {
    PS_OBJ_PUBI_ASSERT(pi);
    MPASS(pi->pi_metaobj == ps_page_metaobj);
}
#endif

int
ps_obj_copy_meta2version(struct thread *td, ps_pubi_t pi, vm_object_t vmobj,
			 psirp_id_t vrid, vm_ooffset_t dlen)
{
    int error = 0;
    vm_page_t vpage;
    struct sf_buf *sf;
    ps_meta_t pmeta, vmeta;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

/*
 *  XXX 
 *  for (all pages in pi meta, starting from last) {
 */
    error = ps_obj_get_page( pi, VMO_META, 0, (void **)&pmeta);
    if (error)
	goto err;

    error = ps_kmap_page(vmobj, 0, &vpage);
    if (error) {
	ps_obj_put_page(pi, VMO_META, FALSE);
	goto err;
    }
    sched_pin();
    sf = sf_buf_alloc(vpage, SFB_CPUPRIVATE);
    vmeta = (ps_meta_t)sf_buf_kva(sf);
	
    memcpy(vmeta, pmeta, PAGE_SIZE);

    sf_buf_free(sf);
    (void) ps_kunmap_page(vmobj, vpage, TRUE);
    ps_obj_put_page(pi, VMO_META, TRUE);
/*  } XXX: end for */

    error = ps_obj_init_meta_kernel(vmobj, PS_PUB_VERSION, vrid, dlen);

  err:
    return error;
}

int
ps_obj_get_page(ps_pubi_t pi, ps_vmo_t type, vm_pindex_t pindex, void **ptr) 
{
    int error = 0;
    vm_page_t page;

    MPASS(type >= 0 && type < sizeof(pi->pi_vmobject)/sizeof(pi->pi_vmobject[0]));
    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    if (pi->pi_sf_buf[type])
	panic("recursive access: pi=%p, type=%d, pindex=%ld ", pi, type, pindex);

    error = ps_kmap_page(pi->pi_vmobject[type], pindex, &page);
    if (error)
	return error;

    pi->pi_sf_buf[type] = sf_buf_alloc(page, 0);
    *ptr = (void *)sf_buf_kva(pi->pi_sf_buf[type]);

    return 0;
}

void
ps_obj_put_page(ps_pubi_t pi, ps_vmo_t type, boolean_t written)
{
    int error = 0;
    vm_page_t page;
    
    MPASS(NULL != pi->pi_sf_buf[type]);
    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    page = sf_buf_page(pi->pi_sf_buf[type]);
    sf_buf_free(pi->pi_sf_buf[type]);
    pi->pi_sf_buf[type] = NULL;

    error = ps_kunmap_page(pi->pi_vmobject[type], page, written);
    if (error)
	panic("page unmap failed: pi=%pi, type=%d, written=%d", pi, type, written);
}

int
ps_obj_get_dataobj(ps_pubi_t pi, vm_object_t *dobjp, vm_ooffset_t *sizep,
                   enum ps_pub_type *typep)
{
    int error = 0;
    ps_meta_t meta;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    error = ps_obj_get_page(pi, VMO_META, 0, (void **)&meta);
    if (error)
	return error;

    MPASS(0 == meta->pm_size || NULL != pi->pi_object);

    if (dobjp)
        *dobjp = pi->pi_object;
    if (sizep)
	*sizep = meta->pm_size;
    if (typep)
        *typep = meta->pm_type;

    ps_obj_put_page(pi, VMO_META, FALSE);

    return 0;
}

static int
meta_access(ps_pubi_t pi, meta_access_f f, void *arg1, void *arg2) 
{
    
    int error = 0;
    ps_meta_t meta;
    boolean_t written;

    error = ps_obj_get_page(pi, VMO_META, 0, (void **)&meta);
    if (error)
	return error;

    error = f(pi, meta, &written, arg1, arg2);
    
    ps_obj_put_page(pi, VMO_META, written);

    return error;
}

static int
obj_get_type(ps_pubi_t pi, ps_meta_t meta, boolean_t *written, void *arg, void *dummy)
{
    enum ps_pub_type *typep = arg;

    *written = FALSE;
    *typep = PS_PUB_TYPE(meta);
    
    return 0;
}

int
ps_obj_get_type(ps_pubi_t pi, enum ps_pub_type *typep) 
{
    int error = 0;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    if (NULL == pi->pi_metaobj) {
	/* Metadata doesn't exist, we don't know the type */
        printf("ps_obj_get_type: Metadata does not exist!\n");
	*typep = PS_PUB_UNKNOWN;
    } else {
	error = meta_access(pi, obj_get_type, typep, NULL);
    }
    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    return error;
}

#ifdef PUBI_HAS_SIDS

enum sid_op { CHECK, CHECK_AND_ADD, CHECK_AND_REMOVE };

static int
obj_handle_sid(struct ps_pubi_sids *sp, psirp_id_t *sidp, enum sid_op op) 
{
    int i;

    for (i = 0; i < sp->sid_count; i++) 
	if (0 == memcmp(sp->sid_table[i].id, sidp->id, sizeof(sidp->id))) {
	    if (CHECK_AND_REMOVE == op) {
		memmove( sp->sid_table + i, 
			 sp->sid_table + i + 1, 
			(sp->sid_count - i - 1) * sizeof(sp->sid_table[i]));
		sp->sid_count--;
	    }
	    return EALREADY;
	}

    if (CHECK_AND_ADD == op) {
	if (sp->sid_count >= sp->sid_slots) {
	    /* XXX: Grow the table instead */
	    return ENOSPC;
	}
	sp->sid_table[sp->sid_count++] = *sidp;
    }
    return 0;
}

static int 
obj_add_sid(ps_pubi_t pi, ps_meta_t meta, boolean_t *written, void *arg1, void *arg2) 
{
    int error = 0;
    psirp_id_t *sidp = arg1;
    int type = *(int *)arg2
    struct ps_pubi_sids *sp;

    PS_OBJ_PUBI_LOCK(pi);
    switch (type) {
    case NOTE_PUBLISH:
	/*
	 * If this publication has been subscribed to in this scope,
	 * but now we are publishing it, remove this scope from the
	 * set of subscribed-only scopes 
	 */
	obj_handle_sid(pi->ps_subs, sidp, CHECK_AND_REMOVE);
	/*
	 * Add the scope as one where this has been published in.
	 */
	error = obj_handle_sid(pi->ps_pubs, sidp, CHECK_AND_ADD);
	break;
    case NOTE_SUBSCRIBE:
	/*
	 * If this publication has been published already,
	 * we don't need to do anything (EALREADY).
	 */
	error = obj_handle_sid(pi->ps_pubs, sidp, CHECK);
	if (EALREADY == error) 
	    goto out;
	if (error)
	    return error;

	/*
	 * Add to the set of scopes where this publication has
	 * been subscribed to, but not published (yet).
	 */
	error = obj_handle_sid(pi->ps_subs, sidp, CHECK_AND_ADD);
	break;
    default:
	panic("Unknown type %d", type);
    }

    *written = FALSE;
  out:
    PS_OBJ_PUBI_UNLOCK(pi);
    return error;
}

int
ps_obj_add_sid(ps_pubi_t pi, psirp_id_t sid, int type)
{
    return meta_access(pi, obj_add_sid, &sid, &type);
}

static int
obj_get_sids(ps_pubi_t pi, ps_meta_t meta, boolean_t *written, void *arg1, void *arg2)
{
    psirp_id_t *sids = arg1;
    int *countp = arg2;

    PS_OBJ_META_LOCK(meta);
    memcpy(sids, meta->pm_sids, 
	   min(*countp, meta->pm_sid_count) * sizeof(sids[0]));
    PS_OBJ_META_UNLOCK(meta);
    *written = FALSE;

    return 0;
}

int
ps_obj_get_sids(ps_pubi_t pi, psirp_id_t *sids, int *countp) 
{
    int error;

    PS_PRINTF(PS_DEBUG_OBJ, "id=%s, count=%d\n", psfs_id2str(id, NULL), *countp);
    error = meta_access(pi, obj_get_sids, sids, countp);
    PS_PRINTF(PS_DEBUG_OBJ, "id=%s, count=%d -> %d\n", psfs_id2str(id, NULL), *countp, error);
    return error;
}

#endif

static int 
obj_add_version(ps_pubi_t pi, ps_meta_t meta, boolean_t *written, void *arg1, void *arg2) 
{
    psirp_id_t *vridp = arg1;
    vm_ooffset_t dlen = *(vm_ooffset_t *)arg2;

    ps_obj_set_datasize(pi, meta, dlen);

    if (meta->pm_vers_count < sizeof(meta->pm_sub_object)/sizeof(meta->pm_sub_object[0])) {
	meta->pm_vers_count++;
    } else {
	/*
	 * Move everything down one slot, destroying the oldest version at the top.
	 */
	bcopy(meta->pm_sub_object + 1, 
	      meta->pm_sub_object, 
	      sizeof(meta->pm_sub_object) - sizeof(meta->pm_sub_object[0]));
    }
    meta->pm_sub_object[meta->pm_vers_count-1] = *vridp;

    *written = TRUE;
    return 0;
}

int
ps_obj_add_version(ps_pubi_t pi, psirp_id_t vrid, vm_object_t dobj, vm_ooffset_t dlen)
{
    int error = 0;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    error = meta_access(pi, obj_add_version, &vrid, &dlen);
    if (error) {
	return error;
    }	

    vm_object_deallocate(pi->pi_object);
    /* 
     * Note that it is crucial to clear ONEMAPPING, as otherwise the content
     * will be lost at the process reapout time.
     */
    VM_OBJECT_LOCK(dobj);
    vm_object_reference_locked(dobj);
    vm_object_clear_flag(dobj, OBJ_ONEMAPPING);
    VM_OBJECT_UNLOCK(dobj);

    pi->pi_object = dobj;

    return error;
}

static int
obj_get_version_count(ps_pubi_t pi, ps_meta_t meta, boolean_t *written, 
		      void *arg1, void *arg2) 
{
    off_t *cnt = (off_t *)arg1;

    *cnt = meta->pm_vers_count;

    *written = FALSE;
    return 0;
}


int
ps_obj_get_version_count(ps_pubi_t pi, off_t *cnt)
{
    int error = 0;
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    error = meta_access(pi, obj_get_version_count, cnt, NULL); 
    return error;
}

static void
ps_obj_set_datasize(ps_pubi_t pi, ps_meta_t meta, vm_ooffset_t size) 
{
    enum psfs_node_type i;
    struct psfs_node *pnode = NULL;
    struct vnode *vp;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    PS_OBJ_META_ASSERT_NOT_OWNED(meta);

    PS_OBJ_META_LOCK(meta);
    if (meta->pm_size == size) {
	PS_OBJ_META_UNLOCK(meta);
	goto out;
    }
    meta->pm_size = size;
    PS_OBJ_META_UNLOCK(meta);

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    for (i = ISCOPE; i < ICOUNT; i++) {
	PS_OBJ_PUBI_ASSERT_OWNED(pi);
	pnode = pi->pi_node[i]; 
	if (pnode) {
	    PSFS_NODE_LOCK(pnode);
	    PS_OBJ_PUBI_UNLOCK(pi);
	    vp = pnode->pn_vnode;
	    PSFS_NODE_UNLOCK(pnode);
	    if (vp) {

		/* 
		 * We assume that vnode_pager_setsize
		 * does not require the vnode to be locked.
		 * In FreeBSD 7.1 the situation is (was) so,
		 * as vnode_pager_setsize simply grabs
		 * the vm_object from the vnode.  
		 */
		vnode_pager_setsize(vp, size);
	    }
	    PS_OBJ_PUBI_LOCK(pi);
	}
	PS_OBJ_PUBI_ASSERT_OWNED(pi);
    }

  out:
    MPASS(meta->pm_size >= 0 && meta->pm_size == size);
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    PS_OBJ_META_ASSERT_NOT_OWNED(meta);
#ifdef INVARIANTS
    if (pnode)
	PSFS_NODE_ASSERT_NOT_OWNED(pnode);
#endif
}

#if 0
int
ps_obj_sha1_data(vm_object_t dobj, vm_ooffset_t dlen, caddr_t digest) 
{
    int error = 0;
    struct sha1_ctxt sc;
    vm_pindex_t pindex;
    vm_page_t p;
    struct sf_buf *sf;

    sha1_init(&sc);

    /* XXX: Locking? */
    for (pindex = 0; pindex < OFF_TO_IDX(dlen-1) + 1; pindex++) {
	size_t len;

	error = ps_kmap_page(dobj, pindex, &p);
	if (error)
	    goto err;

	sched_pin();
	sf = sf_buf_alloc(p, SFB_CPUPRIVATE);

	len = (dlen <= IDX_TO_OFF(pindex+1))? PAGE_SIZE: dlen & PAGE_MASK;

	sha1_loop(&sc, (u_int8_t *)sf_buf_kva(sf), len);

	sf_buf_free(sf);
	sched_unpin();

	error = ps_kunmap_page(dobj, p, FALSE);
	if (error)
	    goto err;
    }
    
    sha1_result(&sc, digest);

  err:
    /* XXX: Locking? */
    return error;
}
#endif

int
ps_obj_sha1_page(vm_object_t dobj, vm_pindex_t pindex,
                 vm_ooffset_t offset, vm_ooffset_t len,
                 caddr_t digest) 
{
    int error = 0;
    SHA1_CTX sc;
    vm_page_t p;
    struct sf_buf *sf;

    SHA1Init(&sc);

    error = ps_kmap_page(dobj, pindex, &p);
    if (error)
	goto err;

    sched_pin();
    sf = sf_buf_alloc(p, SFB_CPUPRIVATE);

    SHA1Update(&sc, (u_int8_t *)(sf_buf_kva(sf) + offset), len);

    sf_buf_free(sf);
    sched_unpin();

    error = ps_kunmap_page(dobj, p, FALSE);
    if (error)
	goto err;
    
    SHA1Final(digest, &sc);

  err:
    return error;
}

#ifdef NOTYET
static int
obj_get_vattr(ps_meta_t meta, boolean_t *written, void *arg, void *dummy) {
    struct vattr *vap = arg;

    vap->va_atime = meta->pm_atime;
    
    *written = FALSE;
    return 0;
}

int
ps_obj_get_vattr(ps_pubi_t pi, struct vattr *vap) {
    return meta_access(pi, obj_get_vattr, vap, NULL);
}

static int
obj_set_vattr(ps_meta_t meta, boolean_t *written, void *arg, void *dummy) {
    struct vattr *vap = arg;

    meta->pm_atime = vap->va_atime;
    
    *written = TRUE;
    return 0;
}

int
ps_obj_set_vattr(psirp_id_t id, struct vattr *vap) {
    return meta_access(id, obj_set_vattr, vap, NULL);
}

#endif

/*
 * Use page metadata similarly as a scope (i.e., a collection of RIds).
 * Returns the index of a version-RId if it exists, or ENOENT otherwise.
 */
static int
data_get_vrid(ps_pubi_t pi, ps_meta_t pm, boolean_t *written,
              void *arg1, void *arg2) 
{
    psirp_id_t *vridp = arg1;
    off_t      *idxp  = arg2;
    int i;

    *written = FALSE;

    for (i = 0; i < pm->pm_vers_count; i++) {
	if (!memcmp(vridp->id, pm->pm_sub_object[i].id,
                    sizeof(pm->pm_sub_object[0].id))) {
	    if (idxp)
		*idxp = i;
	    return 0;
	    break;
	}
    }

    return ENOENT;
}

/*
 * Use version metadata similarly as a scope (i.e., a collection of RIds).
 * Returns the index of a page-RId if it exists, or ENOENT otherwise.
 */
static int
version_get_prid(ps_pubi_t pi, ps_meta_t pm, boolean_t *written,
                 void *arg1, void *arg2) 
{
    psirp_id_t *pridp = arg1;
    off_t      *idxp  = arg2;
    int i;

    *written = FALSE;

    for (i = 0; i < pm->pm_page_count; i++) {
	if (!memcmp(pridp->id, pm->pm_sub_object[i].id,
                    sizeof(pm->pm_sub_object[0].id))) {
	    if (idxp)
		*idxp = i;
	    return 0;
	    break;
	}
    }
    
    return ENOENT;
}

int ps_obj_get_rid(ps_pubi_t pi, psirp_id_t *ridp, off_t *idxp,
                   enum ps_pub_type type) {
    int error = 0;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    /*
     * In this function we try to find the given RId (version- or
     * page-RId) in the metadata that the given publication index
     * points to. Scopes are treated as data publications.
     */

    switch (type) {
    case PS_PUB_DATA:
    case PS_PUB_SCOPE:
        error = meta_access(pi, data_get_vrid, ridp, idxp);
        break;
    case PS_PUB_VERSION:
        error = meta_access(pi, version_get_prid, ridp, idxp);
        break;
    default:
	PS_PRINTF(PS_DEBUG_OBJ | PS_DEBUG_WARNING,
		  "WARNING: type %d cannot be accessed with this function\n",
                  type);
	error = ENOTDIR;
        break;
    }

    return error;

}

static void sha1_hash2(const u_int8_t *data1, size_t len1,
                       const u_int8_t *data2, size_t len2,
                       u_int8_t *digest) {
    SHA1_CTX sc;
    
    SHA1Init(&sc);
    SHA1Update(&sc, data1, len1);
    SHA1Update(&sc, data2, len2);
    SHA1Final((caddr_t)digest, &sc);
}

static void mt_metrics(int nblocks, int *skewed_leaves, int *balanced_height) {
  int pow2   =  1;
  int height = -1;
  
  while (pow2 <= nblocks) {
      pow2   <<= 1;
      height  += 1;
  }
  
  *skewed_leaves   = (nblocks - (pow2 >> 1)) << 1; /* 2*(N-2^(H-1)) */
  *balanced_height = height;                       /* H-1 */
}

typedef struct {
    const u_int8_t *dp;
    u_int8_t       digest[SHA1_RESULTLEN]; /* XXX */
    int            height;
} mt_stack_node_t;

static int sn_eq_h(mt_stack_node_t *sn1, mt_stack_node_t *sn2) {
    return ((sn1 != NULL && sn2 != NULL && sn2 - sn1 > 1)
            ? ((sn2 - 2)->height == (sn2 - 1)->height)
            : 0);
}

void
ps_obj_sha1_mt(psirp_id_t *rids, int count, caddr_t digest) 
{
    int max_skewed_leaves = 0;
    int max_height = 0;
    
    mt_metrics(count, &max_skewed_leaves, &max_height);
    
    PS_PRINTF(PS_DEBUG_OBJ /* | PS_DEBUG_WARNING */,
              "mt: count=%d, max_skewed_leaves=%d, max_height=%d\n",
              count, max_skewed_leaves, max_height);
    
    {
        mt_stack_node_t s[max_height+2]; /* XXX: ? */
        mt_stack_node_t *sp  = s;
        int skewed_leaves = 0;
        int height = 0;
        int i = 0;
        
        /* XXX: This is a very inelegant way of handling special cases. */
        switch(count) {
        case 0:
            /* H() */
            sha1_hash2(NULL, 0, NULL, 0, sp->digest);
            sp->dp = sp->digest;
            break;
        case 1:
            /* H0 */
            sp->dp = rids[0].id + PSIRP_ID_LEN - SHA1_RESULTLEN;
            break;
        case 2:
            /* H(H0, H1) */
            sha1_hash2(rids[0].id + PSIRP_ID_LEN - SHA1_RESULTLEN,
                       SHA1_RESULTLEN,
                       rids[1].id + PSIRP_ID_LEN - SHA1_RESULTLEN,
                       SHA1_RESULTLEN,
                       sp->digest);
            sp->dp = sp->digest;
            break;
        case 3:
            /* H(H(H0, H1), H2) */
            sha1_hash2(rids[0].id + PSIRP_ID_LEN - SHA1_RESULTLEN,
                       SHA1_RESULTLEN,
                       rids[1].id + PSIRP_ID_LEN - SHA1_RESULTLEN,
                       SHA1_RESULTLEN,
                       sp->digest);
            sp->dp = sp->digest;
            sha1_hash2(sp->dp,
                       SHA1_RESULTLEN,
                       rids[1].id + PSIRP_ID_LEN - SHA1_RESULTLEN,
                       SHA1_RESULTLEN,
                       sp->digest);
            sp->dp = sp->digest;
            break;
        default:
            while (height < max_height) {
                if (sn_eq_h(s, sp)) {
                    sp -= 2;
                    sha1_hash2(sp->dp,       SHA1_RESULTLEN,
                               (sp + 1)->dp, SHA1_RESULTLEN,
                               sp->digest);
                    sp->dp = sp->digest;
                    sp->height = (sp + 1)->height + 1;
                    sp++;
                }
                else {
                    if (i < count) {
                        sp->dp = rids[i++].id + PSIRP_ID_LEN - SHA1_RESULTLEN;
                        PS_PRINTF(PS_DEBUG_OBJ /* | PS_DEBUG_WARNING */,
                                  "i=%d, h=%d, sl=%d\n",
                                  i, height, skewed_leaves);
                        if (skewed_leaves < max_skewed_leaves) {
                            sp->height = -1;
                            skewed_leaves++;
                        }
                        else {
                            sp->height = 0;
                        }
                        sp++;
                    }
                }
                height = s->height;
            }
        }   
        
        memcpy(digest, s->dp, SHA1_RESULTLEN); /* XXX */
    }
}

int
ps_obj_sha1_mt_page(vm_object_t dobj, vm_pindex_t pindex,
                    vm_ooffset_t offset, int id_count,
                    caddr_t digest)
{
    int error = 0;
    vm_page_t p;
    struct sf_buf *sf;

    error = ps_kmap_page(dobj, pindex, &p);
    if (error)
	goto err;

    sched_pin();
    sf = sf_buf_alloc(p, SFB_CPUPRIVATE);

    ps_obj_sha1_mt((psirp_id_t *)(sf_buf_kva(sf) + offset), id_count, digest);

    sf_buf_free(sf);
    sched_unpin();

    error = ps_kunmap_page(dobj, p, FALSE);
    if (error)
	goto err;

err:
    return error;
}
