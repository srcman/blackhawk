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
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/mutex.h>
#include <sys/sf_buf.h>
#include <sys/mount.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_obj.h"
#include "ps_syscall.h"
#include "ps_pit.h"
#include "ps_scope.h"
#include "ps_debug.h"

#include "psfs.h"

#ifndef IMPLIES
#define IMPLIES(a, b) (!(a) || (b))
#endif

const static char psfs_conv_tbl[256][2] = {
    "00", "01", "02", "03", "04", "05", "06", "07",
    "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27",
    "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37",
    "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57",
    "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67",
    "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77",
    "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87",
    "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97",
    "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
    "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
    "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
};
const static u_int16_t *psfs_conv = (u_int16_t *)psfs_conv_tbl;

int psfs_node_alloc(struct thread *td, struct psfs_mount *pmp, 
                    psirp_id_t *didp, psirp_id_t *ridp,
                    enum psfs_node_type type,
                    ps_pubi_t pubi,
                    struct psfs_node **node);

char *
psfs_id2str(psirp_id_t id, char *str) {
    int i;
    u_int16_t *s;
    static char static_str[PSIRP_ID_LEN * 2 + 1];

    if (NULL == str)
	str = static_str;
    s = (u_int16_t *)str;

    for (i = 0; i < PSIRP_ID_LEN; i++) {
	s[i] = psfs_conv[id.id[i]];
    }
    str[PSIRP_ID_LEN * 2] = '\0';
    return str;
}

/*
 * Initialise psfs_node handling, as a part of mount process
 */

MALLOC_DEFINE(M_PSFSMNT, "psfs mount", "psfs mount structures");

int
psfs_mp_init(struct thread *td, struct psfs_mount **pmpp)
{
    struct psfs_mount *pmp;

    pmp = (struct psfs_mount *)malloc(sizeof(struct psfs_mount),
				      M_PSFSMNT, M_WAITOK | M_ZERO);

    memset(pmp, 0, sizeof(*pmp));

    mtx_init(&pmp->pm_allnode_lock, "psfs allnode lock", NULL, MTX_DEF);

    pmp->pm_node_pool = uma_zcreate("PSFS node",
				    sizeof(struct psfs_node),
				    NULL, NULL, NULL, NULL, /* XXX */
				    UMA_ALIGN_PTR, 0);

    pmp->pm_root = NULL;
    pmp->pm_pubs = NULL;
    pmp->pm_subs = NULL;

    *pmpp = pmp;
    return 0;
}

int
psfs_mp_cleanup(struct thread *td, struct psfs_mount *pmp)
{
    if (pmp) {
	if (pmp->pm_node_pool)
	    uma_zdestroy(pmp->pm_node_pool);
	free(pmp, M_PSFSMNT);
    }
    return 0;
}

/*
 * Allocated a new node of type 'type' inside the 'pmp' mount point,
 * representing the publication associated with the identity 'id',
 * with its owner set to 'uid', its group to 'gid, and its mode to 'mode',
 * using the credentials of the thread 'td'.
 *
 * Returns zero on success or an appropriate error code on failure.
 */

int
psfs_node_alloc(struct thread *td, struct psfs_mount *pmp, 
		psirp_id_t *didp, psirp_id_t *ridp, enum psfs_node_type type,
		ps_pubi_t pi,
		struct psfs_node **npp)
{
    struct psfs_node *pnode;

    /* XXX: Krisu: Potential bug: Mutex owned while calling sleepable
     *  memory allocator.
     */
    pnode = (struct psfs_node *)uma_zalloc_arg(pmp->pm_node_pool, 
                                               pmp,M_NOWAIT);

    if (NULL == pnode)
	return ENOMEM;

    PS_PRINTF(PS_DEBUG_NODE, "new node %p\n", pnode);

    memset(pnode, 0, sizeof(*pnode));

    pnode->pn_magic = PSFS_NODE_MAGIC;
    pnode->pn_pubi = pi;
    pnode->pn_type = type;
    pnode->pn_vnode = NULL;
    pnode->pn_vpstate = 0;
    pnode->pn_did = *didp;
    pnode->pn_rid = *ridp;

    mtx_init(&(pnode->pn_interlock), "psfs node interlock", NULL, MTX_DEF);
        
    if (npp)
	*npp = pnode;

    return 0;
}

/*
 * Destroys the psfs_node 'pnode'.  Note that the underlying
 * information is not destroyed.  The pnode can be recreated as long
 * as the RID is still in the PIT.
 */
int
psfs_node_free(struct psfs_mount *pmp, struct psfs_node *pnode) 
{
    int error;
    ps_pubi_t pi;

    PS_PRINTF(PS_DEBUG_NODE, "pmp=%p, pnode=%p\n", pmp, pnode);

    error = ps_pit_get(pnode->pn_rid, &pi);
    if (error)
	return error;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    if (pnode->pn_iidx != IBAD) {
	KASSERT(pi->pi_node[pnode->pn_iidx] == pnode, 
		("pnode mismatch: %p != %p", pi->pi_node[pnode->pn_iidx], pnode));
	pi->pi_node[pnode->pn_iidx] = NULL;
    }
    PS_OBJ_PUBI_UNLOCK(pi);

    uma_zfree(pmp->pm_node_pool, pnode);

    return 0;
}

/*
 * Converts psfs_node_type to psfs_node_iidx
 */
static enum psfs_node_iidx type2iidx[VSIZE] = 
{ IBAD, ISCOPE, IPUB, IPUB, IPUB, IMETA, IDATA, IBAD, IBAD };

static __inline__ enum psfs_node_iidx
psfs_node_type2iidx(enum psfs_node_type type) 
{
    enum psfs_node_iidx iidx;

    iidx = type2iidx[type];
    KASSERT(iidx >= ISCOPE && iidx <= IDATA, ("Bad type2iidx conversion, type=%d iidx=%d", type, iidx));
    return iidx;
}

/*
 * Allocates a new vnode--psnode pair of the requested type
 * for the given RID, or returns a new reference to an
 * existing one if the RID already has a vnode and psnode
 * referencint it.  
 *
 * Returns zero on success or an appropriate error code on failure. 
 */
int
psfs_node_allocvp(struct thread *td, struct mount *mp, 
		  psirp_id_t did, psirp_id_t rid, enum psfs_node_type type,
		  int lkflag, struct vnode **vpp) 
{
    int error = 0, vfslocked = 0;
    ps_pubi_t pi;
    struct vnode *vp = NULL;
    struct psfs_node *pnode;
    struct psfs_mount *pmp = (struct psfs_mount *)mp->mnt_data;

    PS_PRINTF(PS_DEBUG_NODE, "type=%d, rid=%s\n",
              type, psfs_id2str(rid, NULL));

    error = ps_pit_get(rid, &pi);
    if (error)
	return error;

  loop:
    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    PS_PRINTF(PS_DEBUG_NODE, "starting loop with did=%s, pubi=%p, pmp=%p\n",
              psfs_id2str(did, NULL), pi, pmp);

    /* XXXX */
    MPASS((NULL != pmp)
          || (type != VROOT && type != VEVENTPUBS && type != VEVENTSUBS));

    switch (type) {
    case VROOT:
	pnode = pmp->pm_root;
	break;
    case VEVENTPUBS:
	pnode = pmp->pm_pubs;
	break;
    case VEVENTSUBS:
	pnode = pmp->pm_subs;
	break;
    default:
	pnode = pi->pi_node[psfs_node_type2iidx(type)]; 
	break;
    }
    if (pnode) {
	/*
	 * This KASSERT has failed in the past when publications have had same RIDs as versions.
	 * That should not ever happen, but if this KASSERT fails, the best approach is to start
	 * looking at bugs related to RID creation, resulting in same RIDs being used for different
	 * types of objects.
	 */
	KASSERT(pnode->pn_type == type, ("psfs_node_allocvp: %p->pn_type %d != %d", pnode, pnode->pn_type, type));

	PSFS_NODE_LOCK(pnode);
	PS_OBJ_PUBI_UNLOCK(pi);

        PS_PRINTF(PS_DEBUG_NODE, "found pnode %p\n", pnode);
	vp = pnode->pn_vnode;
	if (vp) {
	    VI_LOCK(vp);
	    PSFS_NODE_UNLOCK(pnode);
	    vholdl(vp);
            /* XXX: Krisu */
            vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	    (void) vget(vp, lkflag | LK_INTERLOCK | LK_RETRY, td);
            VFS_UNLOCK_GIANT(vfslocked);
	    vdrop(vp);

	    /*
	     * Make sure the vnode is still there after 
	     * getting the interlock to avoid racing a free.
	     *
	     * XXX: Copied from tmpfs_subr.c: Is this right for us?
	     */
	    PSFS_NODE_LOCK(pnode);
	    if (pnode->pn_vnode != vp) {
		PSFS_NODE_UNLOCK(pnode);
                vfslocked = VFS_LOCK_GIANT(vp->v_mount);
		vput(vp);
                VFS_UNLOCK_GIANT(vfslocked);
		PS_OBJ_PUBI_LOCK(pi);
		goto loop;
	    }
	    PSFS_NODE_UNLOCK(pnode);
	    goto out;
	}
    } else {
	/*
	 * If there is no existing psfs_node for this particular type
	 * of accessing this publication, allocate a new psfs_node.
	 */

	PS_OBJ_PUBI_ASSERT_OWNED(pi);

	error = psfs_node_alloc(td, pmp, &did, &rid, type, pi, &pnode);
	if (error) {
	    PS_OBJ_PUBI_UNLOCK(pi);
	    return error;
	}
	PSFS_NODE_LOCK(pnode);

	switch (type) {
	case VROOT:
	    pnode->pn_iidx = IBAD;
	    KASSERT(NULL == pmp->pm_root, ("Reassigning root: pm_root=%p", pmp->pm_root));
	    pmp->pm_root = pnode;
	    break;
	case VEVENTPUBS:
	    pnode->pn_iidx = IBAD;
	    KASSERT(NULL == pmp->pm_pubs, ("Reassigning root: pm_pubs=%p", pmp->pm_pubs));
	    pmp->pm_pubs = pnode;
	    break;
	case VEVENTSUBS:
	    pnode->pn_iidx = IBAD;
	    KASSERT(NULL == pmp->pm_subs, ("Reassigning root: pm_subs=%p", pmp->pm_subs));
	    pmp->pm_subs = pnode;
	    break;
	default:
	    pnode->pn_iidx = psfs_node_type2iidx(type);
	    pi->pi_node[pnode->pn_iidx] = pnode;
	    break;
	}
	PS_OBJ_PUBI_UNLOCK(pi);
    }
    PS_PRINTF(PS_DEBUG_NODE, "   ending loop with pubi=%p\n", pi);

    /*
     * Here we have the psfs_node, but no corresponding vnode.
     * Hence, we have to allocate a vnode for the psfs_node.
     */
    PS_OBJ_PUBI_ASSERT_NOT_OWNED(pi);
    PSFS_NODE_ASSERT_OWNED(pnode);

    /*
     * We indicate in this particular psfs_node that we are
     * already waiting for a vnode.  That allows any other 
     * thread that may want to use the same psfs_node to
     * sleep while we do our job.
     */
    if (pnode->pn_vpstate & PSFS_VNODE_ALLOCATING) {
	pnode->pn_vpstate |= PSFS_VNODE_WANT;
	error = msleep((caddr_t) &pnode->pn_vpstate,
		       &(pnode->pn_interlock), PDROP | PCATCH,
		       "psfs_node_allocvp", 0);
	if (error) {
	    PSFS_NODE_ASSERT_NOT_OWNED(pnode);
	    return error;
	}


        PS_OBJ_PUBI_LOCK(pi);  /* needs to be locked */
	goto loop;		/* The other thread did it for us... */
    }
    
    pnode->pn_vpstate |= PSFS_VNODE_ALLOCATING;
    
    PSFS_NODE_UNLOCK(pnode);

    /*
     * Grab and associate a new vnode with this psfs_node
     */
    error = getnewvnode("psfs", mp, &psfs_vnodeop_entries, &vp);
    if (error)
	goto unlock;
    MPASS(NULL != vp);

#if __FreeBSD_version >= 800000
    (void) vn_lock(vp, lkflag | LK_RETRY);
#else
    (void) vn_lock(vp, lkflag | LK_RETRY, td);
#endif

    vp->v_data = pnode;

    /*
     * Access the meta, as needed
     */
    {
	ps_meta_t meta;
	vm_ooffset_t size;

	PS_OBJ_PUBI_LOCK(pi);
	if (NULL == pi->pi_metaobj) {
	    size = 0;
	} else {
	    error = ps_obj_get_page(pi, VMO_META, 0, (void **)&meta);
	    if (error) {
#ifdef NOMORE
		vput(vp);		/* XXX: Has caused crashes in the past! */
#endif
                vfslocked = VFS_LOCK_GIANT(vp->v_mount);
		vrele(vp);
                VFS_UNLOCK_GIANT(vfslocked);
		vp = NULL;
		PS_OBJ_PUBI_UNLOCK(pi);
		goto unlock;
	    } 
	    size = meta->pm_size;
	    ps_obj_put_page(pi, VMO_META, FALSE);
	}
	PS_OBJ_PUBI_UNLOCK(pi);
	
	switch (pnode->pn_type) {
	case VROOT:
	case VSCOPE:
	case VPUB:
	    vp->v_type = VDIR;
	    vnode_pager_setsize(vp, size);
	    break;
	case VVER:
	    vp->v_type = VDIR;
	    vnode_pager_setsize(vp, size); /* XXX: Is this right? */
	    break;
	case VPAGE:
	    vp->v_type = VREG;
	    vnode_pager_setsize(vp, PAGE_SIZE);
	    break;
	case VPUBDATA:
	    vp->v_type = VREG;
	    vnode_pager_setsize(vp, size);
	    break;
	case VPUBMETA:
	    vp->v_type = VREG;
	    vnode_pager_setsize(vp, PS_MD_SIZE);
	    break;
	case VEVENTPUBS:
	case VEVENTSUBS:
	    vp->v_type = VREG; 
	    vnode_pager_setsize(vp, PAGE_SIZE); /* XXX: Lying here. */
	    break;
	default:
	    panic("Unknown psfs_node type: %d", pnode->pn_type);
	}

    }
    
    error = insmntque(vp, mp);
    if (error) {
	// vput(vp); XXX: NOT!  Crashes on unmount if this is here?
	vp = NULL;
    }

  unlock:
    PSFS_NODE_LOCK(pnode);

    MPASS(pnode->pn_vpstate & PSFS_VNODE_ALLOCATING);
    pnode->pn_vpstate &= ~PSFS_VNODE_ALLOCATING;
    pnode->pn_vnode = vp;

    /*
     * Check if someone else is waiting for this vnode, 
     * and wake them up.
     */
    if (pnode->pn_vpstate & PSFS_VNODE_WANT) {
	pnode->pn_vpstate &= ~PSFS_VNODE_WANT;
	PSFS_NODE_UNLOCK(pnode);
	wakeup((caddr_t) &pnode->pn_vpstate);
    } else {
	PSFS_NODE_UNLOCK(pnode);
    }

  out:
    PSFS_NODE_ASSERT_NOT_OWNED(pnode);

#ifdef DEBUG
    if (vp && (ps_debug_mask & PS_DEBUG_NODE))
	vn_printf(vp, "psfs_node_allocvp: vp=");
    else
	PS_PRINTF(PS_DEBUG_NODE, "vp=NULL\n");
#endif

    if (vpp) {
	*vpp = vp;
    } else {
        vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	vput(vp);
        VFS_UNLOCK_GIANT(vfslocked);
    }

#ifdef INVARIANTS
    PSFS_NODE_LOCK(pnode);
    MPASS(IMPLIES(vpp != NULL, *vpp == pnode->pn_vnode));
    PSFS_NODE_UNLOCK(pnode);
#endif

    PS_PRINTF(PS_DEBUG_NODE, "type=%d, rid=%s -> %d\n", 
	      type, psfs_id2str(rid, NULL), error);

    return error;
}

/*
 * Destroys the association between the vnode 'vp' and the psfs_node 
 * it references.
 */
void
psfs_node_freevp(struct vnode *vp)
{
    struct psfs_node *pnode;

    pnode = vp->v_data;
    if (pnode) {
	PSFS_NODE_LOCK(pnode);
	pnode->pn_vnode = NULL;
	vp->v_data = NULL;
	PSFS_NODE_UNLOCK(pnode);
    } else {
	vp->v_data = NULL;
    }
}

#ifdef NOTYET
/*
 * Update the attributes in metadata, as the vnode / and or
 * some other part has accessed the data.  Modelled after
 * tmpfs_update.
 */
int
psfs_node_update_vattr(struct vnode *vp)
{
    struct psfs_node *pnode;
    struct timespec now;
    struct vattr va;
    int error;

    pnode = vp->v_data;

    if (pnode->pn_tmpfs_node->tn_links > 0) {
	/* Update node times.  No need to do it if the node has
	 * been deleted, because it will vanish after we return. */
	PSFS_VOP_VSWAP_TO(vp, node, s);
	tmpfs_update(vp);
	PSFS_VOP_VSWAP_FROM(vp, node, s);
    }

    if ((pnode->pn_vattr_state & (PSFS_VATTR_ACCESSED | PSFS_VATTR_MODIFIED |
			    PSFS_VATTR_CHANGED)) == 0)
	return 0;

    vattr_null(&va);
    getnanotime(&now);
    if (pnode->pn_vattr_state & PSFS_VATTR_ACCESSED) {
	va.va_atime = now;
    }
    if (pnode->pn_vattr_state & PSFS_VATTR_MODIFIED) {
	va.va_mtime = now;
    }
    if (pnode->pn_vattr_state & PSFS_VATTR_CHANGED) {
	va.va_ctime = now;
    }

    pnode->pn_vattr_state &=
	    ~(PSFS_VATTR_ACCESSED | PSFS_VATTR_MODIFIED | PSFS_VATTR_CHANGED);

    error = ps_obj_set_vattr(pnode->pn_rid, &va);

    return error;
}
#endif
