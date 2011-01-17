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
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <sys/sched.h>
#include <sys/sf_buf.h>
#include <machine/_inttypes.h>
#include <sys/file.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/kernel.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_map.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_obj.h"
#include "ps_event.h"
#include "ps_syscall.h"
#include "ps_scope.h"
#include "ps_pit.h"
#include "ps_map.h"
#include "ps_debug.h"

#include "psfs.h"
#include "psfs_dir.h"

#ifndef IMPLIES
#define IMPLIES(a, b) (!(a) || (b))
#endif

extern struct psfs_mount *psfs_pmp;	/* XXX: TBRM */

static char a2n[256] = {
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,

    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
     0,  1,  2,  3,   4,  5,  6,  7,
     8,  9, -1, -1,  -1, -1, -1, -1,

    -1, 10, 11, 12,  13, 14, 15, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,

    -1, 10, 11, 12,  13, 14, 15, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,
};

static int
psfs_name2id(struct componentname *cnp, psirp_id_t *idp) {
    int i;

    if (cnp->cn_namelen != PSIRP_ID_LEN * 2) 
	return EINVAL;

    for (i = 0; i < PSIRP_ID_LEN; i++) {
	int c1, c2;
	
	c1 = a2n[(int)cnp->cn_nameptr[2*i]];
	c2 = a2n[(int)cnp->cn_nameptr[2*i+1]];
	if (c1 < 0 || c2 < 0)
	    return EILSEQ;
	idp->id[i] = c1 << 4 | c2;
    }
    return 0;
}

static int
psfs_create(struct vop_create_args *v) {
    return EOPNOTSUPP;
}

static int
psfs_mknod(struct vop_mknod_args *v) {
    return EOPNOTSUPP;
}

extern psirp_id_t root_id; /* Defined in vfsops.  XXX: Should not be used. */

#if __FreeBSD_version >= 800000
#define MPASS_VOP_ISLOCKED(vp, td) MPASS(VOP_ISLOCKED(vp))
#else
#define MPASS_VOP_ISLOCKED(vp, td) MPASS(VOP_ISLOCKED(vp, td))
#endif


static int
psfs_mkdir(struct vop_mkdir_args *v) 
{
    return EOPNOTSUPP;
}


/* 'name' must be a literal string */
#define LOOKUP_NAMEMATCH(cnp, name)        \
    (sizeof((name))-1 == (cnp)->cn_namelen    \
     && 0 == memcmp((cnp)->cn_nameptr, (name), sizeof((name))-1))

static int
psfs_lookup(struct vop_cachedlookup_args *v)
{
    struct vnode *dvp = v->a_dvp;
    struct mount *mp= dvp->v_mount;
    struct vnode **vpp = v->a_vpp;
    struct componentname *cnp = v->a_cnp;
    struct thread *td = cnp->cn_thread;
    struct psfs_node *dnode;
    int error = ENOENT, id_error, pit_error = ENOENT;
    psirp_id_t rid;
    enum psfs_node_type type;

    PS_PRINTF(PS_DEBUG_VFS, " dvp=%p, nam=%s\n", dvp, cnp->cn_nameptr);

    dnode = dvp->v_data;
    *vpp  = NULL;

    error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred, td);
    if (error)
	goto out;

    /* The VOP api never asks dotdot of the root */
    MPASS(IMPLIES(dnode->pn_type == VROOT, !(cnp->cn_flags & ISDOTDOT)));

    /* Handle the '.' and '..' pseudo-directories */
    if (LOOKUP_NAMEMATCH(cnp, ".")) {
	VREF(dvp);
	*vpp = dvp;
	error = 0;
	goto out;
    } else if (LOOKUP_NAMEMATCH(cnp, "..")) {
	psirp_id_t gpdid;	/* Grandparent directory id */

	KASSERT(cnp->cn_flags & ISDOTDOT, ("psfs_lookup: !.."));
	type = dnode->pn_type-1;
	switch (dnode->pn_type) {
	case VROOT:
	    panic("psfs_lookup: impossible pn_type == VROOT && '..'");
	case VSCOPE:
	case VPUB:
	    gpdid = root_id;
	    break;
	case VVER:
	case VPAGE:
	    return ESRCH;	/* XXX: Not implemented yet.  And hard to implement. */
	    break;
	case VPUBMETA:
	case VPUBDATA:
	case VEVENTPUBS:
	case VEVENTSUBS:
	    panic("psfs_lookup: lookup on a non-directory");
	default:
	    panic("psfs_lookup: unknown psfs_node type %d", dnode->pn_type);
	}
	error = psfs_node_allocvp(td, mp, gpdid, dnode->pn_did, type,
				  cnp->cn_lkflags, vpp);
    } else {
	memset(&rid, 0, sizeof(rid));
	id_error = psfs_name2id(cnp, &rid);
	if (!id_error)
	    pit_error = ps_pit_get(rid, NULL);
	if (id_error) {
	    rid = dnode->pn_rid;
	    KASSERT(0 == ps_pit_get(rid, NULL), 
		    ("psfs_node %p pn_rid %p not found it PIT", 
		     dnode, psfs_id2str(rid, NULL)));
	} else if (ENOENT == pit_error
		   && (cnp->cn_flags & ISLASTCN) 
		   && (   CREATE == cnp->cn_nameiop 
			  || RENAME == cnp->cn_nameiop)) {

	    /*
	     * If the rid is not found in the PIT, this is OK if we are
	     * creating or deleting the rid
	     */
	    error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred, td);
	    if (error)
		goto out;
	    cnp->cn_flags |= SAVENAME;
	    error = EJUSTRETURN;
	    goto out;
	} else if (pit_error && ENOENT != pit_error) {
	    /* Some other error during PIT lookup */
	    error = pit_error;
	    goto out;
	}

	switch (dnode->pn_type) {
	case VSCOPE:
	    /* Do not allow "meta", "data", etc in scope level */
	    if (id_error) {
		error = id_error;
		goto out;
	    }
	    break;
	case VROOT:
	case VPUB:
	case VVER:
	case VPAGE:
	    break;
	case VPUBDATA:
	case VPUBMETA:
	case VEVENTPUBS:
	case VEVENTSUBS:
	    error = ENOTDIR;
	    goto out;
	    
	default:
	    panic("psfs_lookup: unknown type: dvp %p dnode %p pn_type %d\n", 
		  dvp, dnode, dnode->pn_type);
	}
	
	/*
	 * If the looked up name is an id and there is a next level, 
	 * then return a vnode pointing to the same id put as 
	 * the "next level" view. Of course, that may fail, e.g.
	 * since version may not have the same RID as a pub.
	 * 
	 * Otherwise, try the convenience names "meta", "data", etc.
	 */
	if (0 == id_error && 0 == pit_error && dnode->pn_type < VLASTDIR) {
	    type = dnode->pn_type+1;
	} else if (LOOKUP_NAMEMATCH(cnp, VPUBMETA_NAME)) {
	    type = VPUBMETA;
	} else if (LOOKUP_NAMEMATCH(cnp, VPUBDATA_NAME)) {
	    type = VPUBDATA;
	} else if (LOOKUP_NAMEMATCH(cnp, VEVENTPUBS_NAME)) {
	    type = VEVENTPUBS;
	} else if (LOOKUP_NAMEMATCH(cnp, VEVENTSUBS_NAME)) {
	    type = VEVENTSUBS;
	} else {
	    error = ENOENT;
	    goto out;
	}

	error = psfs_node_allocvp(td, mp, dnode->pn_rid, rid, type, 
				  cnp->cn_lkflags, vpp);
    }

    /* Store the result of this lookup in the cache.  Avoid this if the
     * request was for creation, as it does not improve timings on
     * emprical tests. */
    if ((cnp->cn_flags & MAKEENTRY) && cnp->cn_nameiop != CREATE)
	cache_enter(dvp, *vpp, cnp);

  out:
    /* If there were no errors, *vpp cannot be null and it must be
     * locked. */
#if __FreeBSD_version < 800000
    MPASS(IMPLIES(error == 0, *vpp != NULLVP && VOP_ISLOCKED(*vpp, td)));
#else
    MPASS(IMPLIES(error == 0, *vpp != NULLVP && VOP_ISLOCKED(*vpp)));
#endif

    PS_PRINTF(PS_DEBUG_VFS, " dvp=%p, nam=%s\n", dvp, cnp->cn_nameptr);
    PS_PRINTF(PS_DEBUG_VFS, "*vpp=%p, error=%d\n", *vpp, error);
    return error;
}

#undef LOOKUP_NAMEMATCH

static int
psfs_open(struct vop_open_args *v)
{
    struct vnode *vp = v->a_vp;
    int mode = v->a_mode;

    int error;
    struct psfs_node *pnode;
    ps_pubi_t pi;
    enum ps_pub_type type;

    MPASS_VOP_ISLOCKED(vp, v->a_td);

    pnode = vp->v_data;
    PSFS_NODE_ASSERT(pnode);

    PS_PRINTF(PS_DEBUG_VFS, "    vp=%p, sid=%s\n", vp, psfs_id2str(pnode->pn_did, NULL));
    PS_PRINTF(PS_DEBUG_VFS, "                           rid=%s\n", psfs_id2str(pnode->pn_rid, NULL));

#if 0
    error = ps_pit_get(pnode->pn_rid, &pi);
#endif
    pi = pnode->pn_pubi;
    if (NULL == pi) {
	PS_PRINTF(PS_DEBUG_VFS | PS_DEBUG_ERROR,
		  "    publication not found for RID=%s, error = %d?\n",
		  psfs_id2str(pnode->pn_rid, NULL), ENOENT);
	return ENOENT;
    }
    PS_OBJ_PUBI_LOCK(pi);

    /*
     * Write is permitted only on regular publications
     */
    error = ps_obj_get_type(pi, &type);
    PS_OBJ_PUBI_UNLOCK(pi);
    if (error) {
	PS_PRINTF(PS_DEBUG_VFS | PS_DEBUG_ERROR,
		  "    type not found for RID=%s, error = %d?\n",
		  psfs_id2str(pnode->pn_rid, NULL), error);
	return ENOENT;
    }

    switch (pnode->pn_type) {
    case VPUBDATA:
	if (PS_PUB_UNKNOWN == type) {
	    type = PS_PUB_DATA;
	    /* XXX: this is not yet implemented, as we effectively
	     * need to create the publication here.
	     */
	    return ENOSPC;
	}
	if (PS_PUB_DATA != type) {
    case VROOT:
    case VSCOPE:
    case VPUB:
    case VVER:
    case VPAGE:
    case VPUBMETA:
    case VEVENTPUBS:
    case VEVENTSUBS:
	    if (mode & FWRITE)
   	        return EISDIR;
	}
	break;
    default:
	panic("psfs_open: unknown or unimplemented pnode type %d\n", pnode->pn_type);
    }
       
    if (mode & FWRITE) {
#ifdef NOTYET
	vm_object_t dobj;

	/* XXXXXX: Handle version pubdata; it cannot be written */
	PS_OBJ_PUBI_LOCK(pi);
        error = ps_obj_get_dataobj(pi, &dobj, NULL, NULL);
	PS_OBJ_PUBI_UNLOCK(pi);
        if (error) {
            PS_PRINTF(PS_DEBUG_VFS | PS_DEBUG_ERROR,
		      "    data object not found for RID=%s?\n",
		      psfs_id2str(pnode->pn_rid, NULL));
            return ENOENT;
        }
	/*
	 * We are writing a to a publication.
	 * Create a new shadow so that all writes go
	 * to the shadow.  This shadow will then be
	 * published on close.
	 */
	vm_ooffset_t offset = 0;

	KASSERT(NULL == pnode->pn_shadow, 
		("Opening a vnode for write but shadow != NULL, pnode=%p, shadow=%p\n",
		 pnode, pnode->pn_shadow));
	vm_object_reference(dobj); /* Will be "eaten" by vm_object_shadow */
	pnode->pn_shadow = dobj;
	vm_object_shadow(&pnode->pn_shadow, &offset, dobj->size);

	// ps_obj_put_dataobj(dobj); /* XXXX: Needed in future for locking? */
#endif
    }

    MPASS_VOP_ISLOCKED(vp, v->a_td);

    PS_PRINTF(PS_DEBUG_VFS, "    vp=%p, sid=%s\n", vp, psfs_id2str(pnode->pn_did, NULL));
    PS_PRINTF(PS_DEBUG_VFS, "                           rid=%s -> %d\n", psfs_id2str(pnode->pn_rid, NULL), error);

    return error;
}

static int
psfs_close(struct vop_close_args *v)
{
    struct vnode *vp = v->a_vp;
    struct psfs_node *pnode;

    PS_PRINTF(PS_DEBUG_VFS, "   vp=%p\n", vp);

    MPASS_VOP_ISLOCKED(vp, v->a_td);

    pnode = vp->v_data;

#ifdef NOTYET
    if (NULL != pnode->pn_shadow) {
	/*
	 * This file was opened for writing; hence closing it will
	 * publish a new version.
	 */
	ps_kern_publish(v->a_td, pnode->pn_did, pnode->pn_rid, 
			pnode->pn_shadow, IDX_TO_OFF(pnode->pn_shadow->size), 0,
			pnode->pn_pubi->pi_metaobj, PS_MD_SIZE,
			NULL, );

	pnode->pn_shadow = NULL;
    }
#endif

#ifdef NOTYET
    psfs_node_update_vattr(vp);
#endif

    PS_PRINTF(PS_DEBUG_VFS, "   vp=%p -> %d\n", vp, 0);

    return 0;
}

static int
psfs_access(struct vop_access_args *v)
{
    struct vnode *vp = v->a_vp;
#if __FreeBSD_version < 800000
    int mode = v->a_mode;
#else
    int mode = v->a_accmode;
#endif
    struct ucred *cred = v->a_cred;

    int error = 0;
    struct psfs_node *pnode;
    ps_pubi_t pi;

    PS_PRINTF(PS_DEBUG_VFS, "  vp=%p\n", vp);

    MPASS_VOP_ISLOCKED(vp, v->a_td);

    pnode = vp->v_data;

#if 0
    error = ps_pit_get(pnode->pn_pubi->pi_rid, &pi);
#endif
    pi = pnode->pn_pubi;
    if (NULL == pi) {
        error = ENOENT;
	goto out;
    }
    PS_OBJ_PUBI_LOCK(pi);

    error = vaccess(vp->v_type, pi->pi_mode, pi->pi_uid,
		    pi->pi_gid, mode, cred, NULL);
    PS_OBJ_PUBI_UNLOCK(pi);

  out:
    MPASS_VOP_ISLOCKED(vp, v->a_td);

    PS_PRINTF(PS_DEBUG_VFS, "  vp=%p -> %d\n", vp, error);

    return error;
}

static int
psfs_getattr(struct vop_getattr_args *v)
{
    struct vnode *vp = v->a_vp;
    struct vattr *vap = v->a_vap;
    
    ps_pubi_t pi;
    struct psfs_node *pnode;

    int error = 0;

    VATTR_NULL(vap);

    pnode = vp->v_data;
    PSFS_NODE_ASSERT(pnode);

    PS_PRINTF(PS_DEBUG_VFS, " vp=%p, rid=%s\n", vp, psfs_id2str(pnode->pn_rid, NULL));

    error = ps_pit_get(pnode->pn_rid, &pi);
    if (error)
	return error;

#ifdef NOTYET
    error = ps_obj_get_vattr(pnode->pn_rid, vap);
#endif

    vap->va_type   = vp->v_type;
    vap->va_mode   = pi->pi_mode;
    vap->va_uid    = pi->pi_uid;
    vap->va_gid    = pi->pi_gid;
    // XXX: Start
    vap->va_nlink  = 5;
    vap->va_fsid   = vp->v_mount->mnt_stat.f_fsid.val[0];
// XXXXXXXXX: Hack alert
    vap->va_fileid = pi->pi_ino + pnode->pn_type;
// XXXXXXXXX: Hack end
    PS_OBJ_PUBI_UNLOCK(pi);	/* XXX: Move to later? */
    vap->va_size   = 1;
    vap->va_blocksize = PAGE_SIZE;
    {
	struct timespec now;

	vfs_timestamp(&now);
	vap->va_atime  = now;
	vap->va_mtime  = now;
	vap->va_ctime  = now;;
	vap->va_birthtime = now;
    }
    vap->va_gen    = 1;
    vap->va_flags  = 1;
    vap->va_rdev   = VNOVAL;
    vap->va_bytes  = round_page(1);
    // XXX: End
    vap->va_filerev = VNOVAL;
    vap->va_vaflags = 0;
    vap->va_spare   = VNOVAL; /* XXX */

    PS_PRINTF(PS_DEBUG_VFS, " vp=%p, rid=%s -> %d\n", 
	      vp, psfs_id2str(pnode->pn_rid, NULL), error);

    return error;
}


static int
psfs_setattr(struct vop_setattr_args *v)
{
    struct vnode *vp = v->a_vp;
    struct vattr *vap = v->a_vap;
#ifdef NOTYET
    struct ucred *cred = v->a_cred;
#if __FreeBSD_version < 800000
    struct thread *td = v->a_td;
#else
    struct thread *td = curthread;
#endif
#endif

    int error;
    struct psfs_node *pnode;
    
    MPASS_VOP_ISLOCKED(vp, v->a_td);
    
    pnode = vp->v_data;
    PSFS_NODE_ASSERT(pnode);

    PS_PRINTF(PS_DEBUG_VFS, " vp=%p, rid=%s\n", vp, psfs_id2str(pnode->pn_rid, NULL));

    error = 0;

    /* Abort if any unsettable attribute is given. */
    if (vap->va_type != VNON ||
	vap->va_nlink != VNOVAL ||
	vap->va_fsid != VNOVAL ||
	vap->va_fileid != VNOVAL ||
	vap->va_blocksize != VNOVAL ||
	vap->va_gen != VNOVAL ||
	vap->va_rdev != VNOVAL ||
	vap->va_bytes != VNOVAL)
	error = EINVAL;

#ifdef NOTYET
    if (error == 0 && (vap->va_flags != VNOVAL))
	error = tmpfs_chflags(vp, vap->va_flags, cred, td);
    
    if (error == 0 && (vap->va_size != VNOVAL)) {
	error = tmpfs_chsize(vp, vap->va_size, cred, td);
    }

    if (error == 0 && (vap->va_uid != VNOVAL || vap->va_gid != VNOVAL))
	error = tmpfs_chown(vp, vap->va_uid, vap->va_gid, cred, td);

    if (error == 0 && (vap->va_mode != (mode_t)VNOVAL))
	error = tmpfs_chmod(vp, vap->va_mode, cred, td);

    if (error == 0 && ((vap->va_atime.tv_sec != VNOVAL &&
			vap->va_atime.tv_nsec != VNOVAL) ||
		       (vap->va_mtime.tv_sec != VNOVAL &&
			vap->va_mtime.tv_nsec != VNOVAL) ||
		       (vap->va_birthtime.tv_sec != VNOVAL &&
			vap->va_birthtime.tv_nsec != VNOVAL)))
	error = tmpfs_chtimes(vp, &vap->va_atime, &vap->va_mtime,
			      &vap->va_birthtime, vap->va_vaflags, cred, td);

    /* Update the node times.  We give preference to the error codes
     * generated by this function rather than the ones that may arise
     * from tmpfs_update. */
    tmpfs_update(vp);

    PSFS_VOP_VSWAP_FROM(vp, pnode, swopped);
#endif

    PS_PRINTF(PS_DEBUG_VFS, " vp=%p, rid=%s -> %d\n", 
	      vp, psfs_id2str(pnode->pn_rid, NULL), error);

    MPASS_VOP_ISLOCKED(vp, v->a_td);

    return error;
}


static int
psfs_mappedread(vm_object_t dobj, size_t len, struct uio *uio,
                vm_pindex_t *vpage_pindexp)
{
    off_t	offset, addr;
    vm_pindex_t	pindex;
    vm_page_t	page;
    struct sf_buf *sf;
    caddr_t	va;
    int		error;

    addr = uio->uio_offset;
    pindex = OFF_TO_IDX(addr);
    if (NULL != vpage_pindexp) {
        /* This is a single page */
        if (pindex > 0) {
            return EINVAL; /* XXX: Is this right? */
        }
        pindex = *vpage_pindexp;
    }
    offset = addr & PAGE_MASK;
    len = MIN(PAGE_SIZE - offset, len);

    error = ps_kmap_page(dobj, pindex, &page);
    if (error)
	return error;

    sched_pin();
    sf = sf_buf_alloc(page, SFB_CPUPRIVATE);
    va = (caddr_t)sf_buf_kva(sf);
    error = uiomove(va + offset, len, uio);
    sf_buf_free(sf);
    sched_unpin();

    error = ps_kunmap_page(dobj, page, FALSE);

    return error;
}

static int
psfs_read(struct vop_read_args *v)
{
    struct vnode *vp = v->a_vp;
    struct uio *uio = v->a_uio;

    struct psfs_node *pnode;
    vm_object_t obj;
    vm_ooffset_t size;
    size_t len;
    int resid;

    vm_pindex_t vpage_pindex = 0;
    vm_pindex_t *pindexp = NULL;

    int error = 0;

    pnode = vp->v_data;

    if (uio->uio_offset < 0) {
	error = EINVAL;
	goto out;
    }

    pnode->pn_vattr_state |= PSFS_VATTR_ACCESSED;

    MPASS(NULL != pnode->pn_pubi);

    PS_OBJ_PUBI_LOCK(pnode->pn_pubi);
    switch (pnode->pn_type) {
    case VPUB:
    case VPUBMETA:
	if (NULL == pnode->pn_pubi) {
	    error = ENOMEM;
	    break;
	}
	obj  = pnode->pn_pubi->pi_metaobj;
	size = PS_MD_SIZE;
	break;
    case VEVENTPUBS:
	error = ps_event_read_prepare(PS_EVENT_PUB, &obj, &size);
	break;
    case VEVENTSUBS:
	error = ps_event_read_prepare(PS_EVENT_SUB, &obj, &size);
	break;
    case VPAGE:
        vpage_pindex = pnode->pn_pubi->pi_pindex;
        pindexp = &vpage_pindex;
        /* fall through */
    case VROOT:
    case VSCOPE:
    case VPUBDATA:
    case VVER:
	error = ps_obj_get_dataobj(pnode->pn_pubi, &obj, &size, NULL);
	break;
    default:
	panic("psfs_write: unknown or unimplemented pnode type %d\n", pnode->pn_type);
    }
    PS_OBJ_PUBI_UNLOCK(pnode->pn_pubi);
    if (error)
	goto out;

    MPASS(NULL != obj || 0 == size);

    while ((resid = uio->uio_resid) > 0) {
	error = 0;
	if (size <= uio->uio_offset)
	    break;
	len = MIN(size - uio->uio_offset, resid);
	if (len == 0)
	    break;
	error = psfs_mappedread(obj, len, uio, pindexp);
	if ((error != 0) || (resid == uio->uio_resid))
	    break;
    }


    // ps_obj_put_obj(obj); /* Needed in future? */
out:
    switch(pnode->pn_type) {
    case VEVENTPUBS:
	error = ps_event_read_done(PS_EVENT_PUB, obj);
	break;
    case VEVENTSUBS:
	error = ps_event_read_done(PS_EVENT_SUB, obj);
	break;
    default:
	break;
    }
    return error;
}

static int
psfs_mappedwrite(vm_object_t dobj, size_t len, struct uio *uio)
{
    off_t	offset, addr;
    vm_pindex_t	pindex;
    vm_page_t	page;
    struct sf_buf *sf;
    caddr_t	va;
    int		error;

    addr = uio->uio_offset;
    pindex = OFF_TO_IDX(addr);
    offset = addr & PAGE_MASK;
    len = MIN(PAGE_SIZE - offset, len);

    error = ps_kmap_page(dobj, pindex, &page);
    if (error)
	return error;

    sched_pin();
    sf = sf_buf_alloc(page, SFB_CPUPRIVATE);
    va = (caddr_t)sf_buf_kva(sf);
    error = uiomove(va + offset, len, uio);
    sf_buf_free(sf);
    sched_unpin();

    /*
     * XXX: We do NOT clean up the rest of the page; see tmpfs_mappedwrite
     */

    error = ps_kunmap_page(dobj, page, TRUE);

    return error;
}

static int
psfs_write(struct vop_write_args *v)
{
    struct vnode *vp = v->a_vp;
    struct uio *uio = v->a_uio;
    int ioflag = v->a_ioflag;
    struct thread *td = uio->uio_td;

    int error = 0;
    off_t oldsize;
    struct psfs_node *pnode;
    ps_pubi_t pi;
    size_t len;
    int resid;

    pnode = vp->v_data;

    KASSERT(NULL != pnode && NULL != pnode->pn_shadow, 
	    ("writing a pnode without its shadow: pnode=%p\n", pnode));

    if (uio->uio_offset < 0) {
	return EINVAL;
    }

    if (ioflag & IO_APPEND) {
	return ENOTSUP;
    }

    switch (pnode->pn_type) {
    case VROOT:
    case VSCOPE:
    case VPUB:
    case VVER:
    case VPAGE:
	return EISDIR;
    case VPUBMETA:
    case VEVENTPUBS:
    case VEVENTSUBS:
	return EINVAL;
    case VPUBDATA:
	oldsize = IDX_TO_OFF(pnode->pn_shadow->size); /* XXX */
	break;
    default:
	panic("psfs_write: unknown or unimplemented pnode type %d\n", pnode->pn_type);
    }
    
    if (vp->v_type == VREG && td != NULL) {
	PROC_LOCK(td->td_proc);
	if (uio->uio_offset + uio->uio_resid >
	    lim_cur(td->td_proc, RLIMIT_FSIZE)) {
	    psignal(td->td_proc, SIGXFSZ);
	    PROC_UNLOCK(td->td_proc);
	    error = EFBIG;
	    goto out;
	}
	PROC_UNLOCK(td->td_proc);
    }

    if (uio->uio_offset + uio->uio_resid > oldsize) {
	/* XXX: One cannot currently write past end of the publication. FIX THIS! */
	error = ENOTSUP;
	goto out;
    }

    if (uio->uio_resid == 0) {
	error = 0;
	goto out;
    }

    error = ps_pit_get(pnode->pn_rid, &pi);
    if (error) 
	goto out;

    if (pi->pi_mode & (S_ISUID | S_ISGID)) {
	if (priv_check_cred(v->a_cred, PRIV_VFS_RETAINSUGID, 0))
	    pi->pi_mode &= ~(S_ISUID | S_ISGID);
    }
    PS_OBJ_PUBI_UNLOCK(pi);

    while ((resid = uio->uio_resid) > 0) {
	if (oldsize <= uio->uio_offset)
	    break;
	len = MIN(oldsize - uio->uio_offset, resid);
	if (len == 0)
	    break;
	error = psfs_mappedwrite(pnode->pn_shadow, len, uio);
	if ((error != 0) || (resid == uio->uio_resid))
	    break;
    }

    pnode->pn_vattr_state |= PSFS_VATTR_ACCESSED | PSFS_VATTR_MODIFIED;

out:
    MPASS(IMPLIES(error == 0, uio->uio_resid == 0));
#ifdef NOMORE
    MPASS(IMPLIES(error != 0, oldsize == pnode->pn_tmpfs_node->tn_size));
#endif

    return error;
}

static int
psfs_fsync(struct vop_fsync_args *v)
{
#ifdef INVARIANTS
    struct vnode *vp = v->a_vp;

    MPASS_VOP_ISLOCKED(vp, v->a_td);
    /* XXX: Update itimes attributes */
    // tmpfs_update(vp);
#endif
    return 0;
}

static int
psfs_link(struct vop_link_args *v) {
    return EOPNOTSUPP;
}

static int
psfs_symlink(struct vop_symlink_args *v) {
    return EOPNOTSUPP;
}

static int
psfs_readdir(struct vop_readdir_args *v)
{
    struct vnode *vp = v->a_vp;
    struct uio *uio = v->a_uio;
    int *eofflag = v->a_eofflag;
    u_long **cookies = v->a_cookies;
    int *ncookies = v->a_ncookies;

    int error;
    off_t cnt = 0;
    struct psfs_node *pnode;

    /* This operation only makes sense on directory nodes. */
    if (vp->v_type != VDIR) {
	PS_PRINTF(PS_DEBUG_VFS | PS_DEBUG_ERROR, 
		  " Read on a non-directory: vp=%p\n", vp);
	return ENOTDIR;
    }

    pnode = vp->v_data;
    PSFS_NODE_ASSERT(pnode);

    PS_PRINTF(PS_DEBUG_VFS, " vp=%p, rid=%s\n", vp, psfs_id2str(pnode->pn_rid, NULL));

    error = psfs_dir_cntdents(pnode, &cnt);
    if (error)
	return error;

    /* Setup NFS-related variables. */
    if (cookies != NULL && ncookies != NULL) {
	*ncookies = cnt;
	 *cookies = malloc(cnt * sizeof(u_long), M_TEMP, M_WAITOK);
    }

    error = psfs_dir_getdents(pnode, uio, cookies? *cookies: NULL, cnt, eofflag);
    
    PS_PRINTF(PS_DEBUG_VFS, " vp=%p, rid=%s -> %d\n", 
	      vp, psfs_id2str(pnode->pn_rid, NULL), error);

    return error;
}



static int
psfs_readlink(struct vop_readlink_args *v) {
    return EOPNOTSUPP;
}

static int
psfs_inactive(struct vop_inactive_args *v)
{
    struct vnode *vp = v->a_vp;
    struct thread *l = v->a_td;
    
    struct psfs_node *pnode;

#if __FreeBSD_version >= 800000
    MPASS(VOP_ISLOCKED(vp));
#else
    MPASS(VOP_ISLOCKED(vp, l));
#endif

    PS_PRINTF(PS_DEBUG_VFS, "vp=%p\n", vp);
    pnode = vp->v_data;
    PSFS_NODE_ASSERT(pnode);

    if (1) 
	/* XXX: SHOULD WE CALL RECYCLE OR NOT, if we can??? */
	/* Con: Recycling is less efficient */
	/* Pro: Makes unmounting easier.  Otherwise we need to explicitly 
	 *      reclaim all vnodes pointed from publications. */
	vrecycle(vp, l);

    PS_PRINTF(PS_DEBUG_VFS, "vp=%p -> 0\n", vp);
    return 0;
}

static int
psfs_reclaim(struct vop_reclaim_args *v)
{
    struct vnode *vp = v->a_vp;
    struct psfs_mount *pmp = vp->v_mount->mnt_data;
    struct psfs_node *pnode;

    pnode = vp->v_data;
    PS_PRINTF(PS_DEBUG_VFS, " vp=%p\n", vp);

    vnode_destroy_vobject(vp);
    cache_purge(vp);
    psfs_node_freevp(vp);
    /*
     * We destroy the root pnode only at umount, as it is used so often.
     */
    MPASS(NULL == pnode->pn_vnode);
    if (pnode) {
	switch (pnode->pn_type) {
	case VROOT:
	case VEVENTPUBS:
	case VEVENTSUBS:
	    break;
	default:
	    psfs_node_free(pmp, pnode);
	    break;
	}
    }
    MPASS(NULL == vp->v_data);

    PS_PRINTF(PS_DEBUG_VFS, " vp=%p -> 0\n", vp);
    return 0;
}

static int
psfs_print(struct vop_print_args *v)
{
    struct vnode *vp = v->a_vp;
    struct psfs_node *pnode;

    pnode = vp->v_data;

    PSFS_NODE_ASSERT(pnode);

    printf("\ttag VT_PSFS, psfs_node %p, type=%d, iidx=%d, vnode=%p, vpstate=%d\n", pnode, 
	   pnode->pn_type, pnode->pn_iidx, pnode->pn_vnode, pnode->pn_vpstate);
    printf("\tdid=%s\n", psfs_id2str(pnode->pn_did, NULL));
    printf("\trid=%s\n", psfs_id2str(pnode->pn_rid, NULL));
    printf("\tshadow=%p, vattr_state=%d\n", pnode->pn_shadow, pnode->pn_vattr_state);
    return 0;
}

static int
psfs_pathconf(struct vop_pathconf_args *v)
{
	int name = v->a_name;
	register_t *retval = v->a_retval;

	int error;

	error = 0;

	switch (name) {
	case _PC_LINK_MAX:         *retval = LINK_MAX; break;
	case _PC_NAME_MAX:         *retval = NAME_MAX; break;
	case _PC_PATH_MAX:         *retval = PATH_MAX; break;
	case _PC_PIPE_BUF:         *retval = PIPE_BUF; break;
	case _PC_CHOWN_RESTRICTED: *retval = 1;        break;
	case _PC_NO_TRUNC:         *retval = 1;	       break;
	case _PC_SYNC_IO:	   *retval = 1;	       break;
	    /* XXX Don't know which value should I return. */
	case _PC_FILESIZEBITS:	   *retval = 0;	       break;
	default:
	    error = EINVAL;
	}

	return error;
}

static int
psfs_vptofh(struct vop_vptofh_args *ap)
{
    struct psfs_nfsid *nsp;
    struct psfs_node  *pnode;

    nsp = (struct psfs_nfsid *)ap->a_fhp;
    pnode = ap->a_vp->v_data;

    nsp->ns_len  = sizeof(struct psfs_nfsid);
    nsp->ns_type = pnode->pn_type;
    nsp->ns_did  = pnode->pn_did;
    nsp->ns_rid  = pnode->pn_rid;

    return (0);
}

static int
psfs_remove(struct vop_remove_args *v)
{
    return EOPNOTSUPP;
}

static int
psfs_rmdir(struct vop_rmdir_args *v)
{
    return EOPNOTSUPP;
}

static int 
psfs_rename(struct vop_rename_args *v)
{ 
    return EOPNOTSUPP; 
} 

static int
psfs_getpages(struct vop_getpages_args *v) {
    return vop_stdgetpages(v);
}

static int
psfs_putpages(struct vop_putpages_args *v) {
    return vop_stdputpages(v);
}

/*
 * The following code is hacked to utilise the underlying EVFILT_VNODE
 * code as much as possible.
 */
static int    attach_psfs_vnode(struct knote *kn);
static int  (*attach_vfs_vnode)(struct knote *kn);
static void   detach_psfs_vnode(struct knote *kn);
static void (*detach_vfs_vnode)(struct knote *kn);
static int    filt_psfs_pubevents(struct knote *kn, long hint);
static int    filt_psfs_subevents(struct knote *kn, long hint);
static int    filt_psfs_pub    (struct knote *kn, long hint);
static int  (*filt_vfs_vnode)  (struct knote *kn, long hint);

static struct filterops vfsps_pubs_filtops = { 
    1, attach_psfs_vnode, detach_psfs_vnode, filt_psfs_pubevents
};

static struct filterops vfsps_subs_filtops = { 
    1, attach_psfs_vnode, detach_psfs_vnode, filt_psfs_subevents
};

static struct filterops vfsps_pub_filtops = { 
    1, attach_psfs_vnode, detach_psfs_vnode, filt_psfs_pub
};

static int
psfs_kqfilter(struct vop_kqfilter_args *ap) {
    int error;
    struct knote *kn = ap->a_kn;
    struct psfs_node *pnode;

    switch (kn->kn_filter) {
    case EVFILT_VNODE:
	break;
    default:
	return vop_stdkqfilter(ap);
    }

    error = vop_stdkqfilter(ap);
    if (error)
	return (error);

    attach_vfs_vnode = kn->kn_fop->f_attach;
    detach_vfs_vnode = kn->kn_fop->f_detach;
    filt_vfs_vnode  = kn->kn_fop->f_event;

    pnode = kn->kn_fp->f_vnode->v_data;
    switch (pnode->pn_type) {
    case VEVENTPUBS:
	PS_PRINTF(PS_DEBUG_FILT, "pubs filter attached, pnode=%p\n", pnode);
	kn->kn_fop = &vfsps_pubs_filtops;
	break;
    case VEVENTSUBS:
	PS_PRINTF(PS_DEBUG_FILT, "subs filter attached, pnode=%p\n", pnode);
	kn->kn_fop = &vfsps_subs_filtops;
	break;
    case VPUB:
	PS_PRINTF(PS_DEBUG_FILT, "pub filter attached, pnode=%p\n", pnode);
	kn->kn_fop = &vfsps_pub_filtops;
	break;
    case VVER:
    case VPAGE:
    case VPUBMETA:
    case VPUBDATA:
	return EOPNOTSUPP;
    default:
	panic("Unknown or unimplemented pnode %p type %d\n", pnode, pnode->pn_type);
    }

    return 0;
}

/*
 * Unmap the old publication data from the caller's address space.
 */
static void
filt_unmap(struct knote *kn) 
{
    int error;
    struct psfs_pub upub;

    /*
     * XXXXXX: If udata does not look like a 64-bit address, try to
     *         make it one. This horrible hack is needed because
     *         Python's kevent API only allows 32-bit udata.
     */
    if (kn->kn_kevent.udata && (int64_t)kn->kn_kevent.udata < 0x800000000) {
        int64_t *udatap, udata_original;
        
        udatap = (int64_t *)&kn->kn_kevent.udata;
        udata_original = *udatap;
        *udatap |= 0x800000000;
        
        PS_PRINTF(PS_DEBUG_FILT /*| PS_DEBUG_WARNING*/,
                  "INFO: converted udata: %p -> %p\n",
                  (void *)udata_original, (void *)*udatap);
    }

    error = copyin(kn->kn_kevent.udata, &upub, sizeof(upub));
    if (error) {
        PS_PRINTF(PS_DEBUG_FILT | PS_DEBUG_WARNING, 
                  "WARNING: copyin failed: error=%d\n", error);
	return;
    }

    if (NULL != upub.pub_data && upub.pub_dlen != 0) {
	error = ps_munmap(curthread, (vm_offset_t)upub.pub_data, 
			  upub.pub_dlen);
	if (error) {
	    PS_PRINTF(PS_DEBUG_FILT | PS_DEBUG_WARNING, 
		      "WARNING: ps_munmap failed: " "error=%d\n", error);
	}
    }

    upub.pub_data = NULL;
    upub.pub_dlen = 0;
    
    upub.pub_vidx = -1;
    
    copyout(&upub, kn->kn_kevent.udata, sizeof(upub));
}

/*
 * Map the publication data (and meta) to the caller's address space.
 */
static void
filt_map(struct knote *kn, struct psfs_node *pnode)
{
    int error;
    struct psfs_pub upub;
    vm_object_t object;
    vm_offset_t addr;
    vm_ooffset_t size;
    vm_ooffset_t offset;
    enum ps_pub_type type;
    
    /*
     * XXXXXX: If udata does not look like a 64-bit address, try to
     *         make it one. This horrible hack is needed because
     *         Python's kevent API only allows 32-bit udata.
     */
    if (kn->kn_kevent.udata && (int64_t)kn->kn_kevent.udata < 0x800000000) {
        int64_t *udatap, udata_original;
        
        udatap = (int64_t *)&kn->kn_kevent.udata;
        udata_original = *udatap;
        *udatap |= 0x800000000;
        
        PS_PRINTF(PS_DEBUG_FILT /*| PS_DEBUG_WARNING*/,
                  "INFO: converted udata: %p -> %p\n",
                  (void *)udata_original, (void *)*udatap);
    }

    MPASS(NULL != pnode);
    /*
     * XXX: Should not rendezvous if the subscription is through
     *      a non-published scope.  Not tested how this works now.
     */
    error = copyin(kn->kn_kevent.udata, &upub, sizeof(upub));
    if (error) {
	PS_PRINTF(PS_DEBUG_FILT | PS_DEBUG_WARNING, 
		  "\nfilt_vfsps: WARNING: copyin failed: data=%p, "
		  "error=%d\n\n", kn->kn_kevent.udata, error);
	return;
    }

    MPASS(NULL != pnode->pn_pubi);
    if (NULL == upub.pub_meta) {
	MPASS(NULL != pnode->pn_pubi->pi_metaobj);

	object = pnode->pn_pubi->pi_metaobj;
	size   = PS_MD_SIZE;
	addr = 0;

        /* Map meta */
	ps_mmap(curthread, &addr, size, VM_PROT_READ, VM_PROT_READ,
		MAP_SHARED | MAP_COPY_ON_WRITE /* XXX */,
		object, 0);
	
	upub.pub_meta = (void *)addr;
	upub.pub_mlen = size;
    }
    
    PS_OBJ_PUBI_LOCK(pnode->pn_pubi);
    error = ps_obj_get_dataobj(pnode->pn_pubi, &object, &size, &type);
    PS_OBJ_PUBI_UNLOCK(pnode->pn_pubi);
    if (error) {
	PS_PRINTF(PS_DEBUG_FILT | PS_DEBUG_WARNING, 
		  "WARNING: failed getting data: error=%d\n", error);
	return;
    }

    addr = 0;
    offset = 0;
    if (type == PS_PUB_PAGE) {
        size &= PAGE_MASK;
        PS_OBJ_PUBI_LOCK(pnode->pn_pubi);
        offset = pnode->pn_pubi->pi_pindex*PAGE_SIZE;
        PS_OBJ_PUBI_UNLOCK(pnode->pn_pubi);
    }

    /* Mata data */
    ps_mmap(curthread, &addr, size, VM_PROT_READ, VM_PROT_READ, 
	    MAP_SHARED | MAP_COPY_ON_WRITE /* XXX */,
	    object,
	    offset);

    upub.pub_data = (caddr_t)addr;
    upub.pub_dlen = size;
    
    upub.pub_vidx = upub.pub_meta->pm_vers_count-1; /* XXX: ? */
    
    PS_PRINTF(PS_DEBUG_FILT, "addr=0x%lx, size=%ld, object=%p\n",
	      addr, size, object);
    copyout(&upub, kn->kn_kevent.udata, sizeof(upub));
}

static int attach_psfs_vnode(struct knote *kn) 
{
    int retval = 0;
    struct psfs_node *pnode;

    pnode = kn->kn_fp->f_vnode->v_data;
    switch (pnode->pn_type) {
    case VEVENTPUBS:
	PS_PRINTF(PS_DEBUG_FILT, "pubs filter attached, pnode=%p\n", pnode);
	break;
    case VEVENTSUBS:
	PS_PRINTF(PS_DEBUG_FILT, "subs filter attached, pnode=%p\n", pnode);
	break;
    case VPUB:
	break;
    case VROOT:
    case VSCOPE:
    case VVER:
    case VPAGE:
    case VPUBMETA:
    case VPUBDATA:
	return EOPNOTSUPP;
    default:
	panic("Unknown or unimplemented pnode %p type %d\n", pnode, pnode->pn_type);
    }

    if (attach_vfs_vnode)
	retval = attach_vfs_vnode(kn);

    return retval;
}

static void detach_psfs_vnode(struct knote *kn) 
{
    struct psfs_node *pnode;

    pnode = kn->kn_fp->f_vnode->v_data;

    if (NULL == pnode) {
        PS_PRINTF(PS_DEBUG_FILT | PS_DEBUG_WARNING,
                  "tried to detach pnode that is NULL\n");
    }
    else {
        switch (pnode->pn_type) {
        case VEVENTPUBS:
        case VEVENTSUBS:
            PS_PRINTF(PS_DEBUG_FILT, "pubs or subs filter detached, pnode=%p\n", pnode);
            break;
        case VPUB:
            break;
        case VROOT:
        case VSCOPE:
        case VVER:
        case VPAGE:
        case VPUBMETA:
        case VPUBDATA:
            return;
        default:
            panic("Unknown or unimplemented pnode %p type %d\n", pnode, pnode->pn_type);
        }
    }

    if (detach_vfs_vnode)
	detach_vfs_vnode(kn);
}

static int
filt_psfs_pubevents(struct knote *kn, long hint) 
{
    int count;
    int ev;

    count = ps_event_pending(PS_EVENT_PUB);
    PS_PRINTF(PS_DEBUG_KNOTE, "KNOTE: %d events on pubs\n", count);
    if (0 == count) {
	/* XXX: Not really tested, more work needed here. */
	kn->kn_flags |= EV_CLEAR;
	ev = 0;
    } else {
	kn->kn_data  = PS_EVENT_ALIGNMENT + count * sizeof(struct ps_event);
	ev = 1;
    }
    PS_PRINTF(PS_DEBUG_FILT, "KNOTE: pubs: kn=%p, hint=%ld, ev=%d -> %d\n", kn, hint, ev, ev);
    return ev;
}

static int
filt_psfs_subevents(struct knote *kn, long hint) 
{
    int count;
    int ev;

    count = ps_event_pending(PS_EVENT_SUB);
    PS_PRINTF(PS_DEBUG_KNOTE, "KNOTE: %d events on subs\n", count);
    if (0 == count) {
	/* XXX: Not really tested, more work needed here. */
	kn->kn_flags |= EV_CLEAR;
	ev = 0;
    } else {
	kn->kn_data  = PS_EVENT_ALIGNMENT + count * sizeof(struct ps_event);
	ev = 1;
    }
    PS_PRINTF(PS_DEBUG_FILT, "KNOTE: subs: kn=%p, hint=%ld, ev=%d -> %d\n", kn, hint, ev, ev);
    return ev;
}

static int
filt_psfs_pub(struct knote *kn, long hint) 
{
    int ev;

    MPASS(NULL != filt_vfs_vnode);
    ev = filt_vfs_vnode(kn, hint);
    PS_PRINTF(PS_DEBUG_FILT, "KNOTE: pub: kn=%p, hint=%ld, ev=%d\n", kn, hint, ev);
    switch (hint) {
    case 0:
	/* 
	 * Called from kqueue_register or kqueue_scan, during kevent(2);
	 * those are the only placed where hint == 0.
	 * The context is the thread that made the kevent(2) system call.
	 *
	 * Hence, curthread is the thread we want.  Otherwise this is
	 * probably running on some other thread, where mapping and
	 * unmapping doesn't make sense at all.
	 */
 	if (kn->kn_sfflags & NOTE_UNMAP) {
	    /*
	     * Called from kqueue_register only.  XXXX: UNTESTED!
	     */
	    filt_unmap(kn);
	}
	if (   ((kn->kn_sfflags & (NOTE_PUBLISH | NOTE_SUBSCRIBE)) != 0)
	    && ((kn->kn_fflags  & (NOTE_PUBLISH | NOTE_SUBSCRIBE)) != 0)) {
	    struct psfs_node *pnode;
	    /*
	     * Called only from kqueue_scan, during the time we are
	     * returning from kernel space to the user space.
	     * Here we call our magic, either mapping the vm_objects to 
	     * the process (filt_map).
	     *
	     * sfflags = PUBLISH && fflags != 0 implies that the 
	     * kevent from user space is intrested in PUBLISH events,
	     * and that the knote from kernel is either PUBLISH or SUBSCRIBE.
	     */
	    pnode = kn->kn_fp->f_vnode->v_data;
	    PS_PRINTF(PS_DEBUG_FILT, "KNOTE: pub: kn=%p, hint=%ld, ev=%d, pnode=%p\n", 
		      kn, hint, ev, pnode);
	    if (pnode && ev) {
		filt_map(kn, pnode);
	    }
	}
	break;
    }
    PS_PRINTF(PS_DEBUG_FILT, "KNOTE: pub: kn=%p, hint=%ld, ev=%d -> %d\n", kn, hint, ev, ev);
    return ev;
}

struct vop_vector psfs_vnodeop_entries = {
    .vop_default      = &default_vnodeops,
    .vop_lookup       = vfs_cache_lookup,
    .vop_cachedlookup = psfs_lookup,
    .vop_create       = psfs_create,
    .vop_mknod        = psfs_mknod,
    .vop_open         = psfs_open,
    .vop_close        = psfs_close,
    .vop_access       = psfs_access,
    .vop_getattr      = psfs_getattr,
    .vop_setattr      = psfs_setattr,
    .vop_read         = psfs_read,
    .vop_write        = psfs_write,
    .vop_fsync        = psfs_fsync,
    .vop_remove       = psfs_remove,
    .vop_link         = psfs_link,
    .vop_rename       = psfs_rename,
    .vop_mkdir        = psfs_mkdir,
    .vop_rmdir        = psfs_rmdir,
    .vop_symlink      = psfs_symlink,
    .vop_readdir      = psfs_readdir,
    .vop_readlink     = psfs_readlink,
    .vop_inactive     = psfs_inactive,
    .vop_reclaim      = psfs_reclaim,
    .vop_print        = psfs_print,
    .vop_pathconf     = psfs_pathconf,
    .vop_vptofh       = psfs_vptofh,
    .vop_bmap         = VOP_EOPNOTSUPP,
    .vop_getpages     = psfs_getpages,
    .vop_putpages     = psfs_putpages,
    .vop_kqfilter     = psfs_kqfilter,
};
