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

#ifndef _PSFS_H
#define _PSFS_H

struct psfs_mount {
    /* Pool of file system nodes. */
    uma_zone_t          pm_node_pool;
    struct mtx          pm_allnode_lock;
#ifdef NOTYET
    /* Used to allocate inodes, usually four at time */
    struct unrhdr *     pm_ino_unr;
#endif
    struct psfs_node *  pm_root;
    struct psfs_node *  pm_pubs; /* Publication events */
    struct psfs_node *  pm_subs; /* Subscription events */
};
#define VFS_TO_PSFS_MOUNT(mp) XXX((struct psfs_mount *)((mp)->mnt_data))

/*
 * A data structure corresponding to each vnode allocated by the kernel.
 *
 * XXX: When you change psfs_node_type, remember ot change psfs_node_type2iidx in
 *      psfs_subr.c!!
 */

enum psfs_node_type { VROOT = 0, VSCOPE, VPUB, VVER, VPAGE, /* Directory ones */
		      VPUBMETA, VPUBDATA, VEVENTPUBS, VEVENTSUBS, /* File ones */
		      VSIZE };

/*
 * Note that while publications themselves live just by RIDs, psfs_nodes
 * are always created within a naming context: in a scope (for publications),
 * within a publication (for versions), or within a version (for pages).
 *
 * Hence, each psfs_node contains the 'pn_did' field, did for 'directory id',
 * which identifies the context.  This is used in a number of places, both
 * within the legacy file system view, but also in e.g. kevents used to
 * communicate with the user level 'scoped' scoping daemon.
 */

#define PSFS_NODE_MAGIC  0xacdcdeadcafebabe
struct psfs_node {
    u_int64_t           pn_magic;      /* Always PSFS_NODE_MAGIC: XXX: to be removed? */
    ps_pubi_t           pn_pubi;       /* Backpointer to the pubi. */
                                       /* XXX: Set but not actively used yet. */
    enum psfs_node_type pn_type;
    enum psfs_node_iidx pn_iidx;
    struct mtx          pn_interlock;
    struct vnode       *pn_vnode;
    int                 pn_vpstate;    
#define PSFS_VNODE_ALLOCATING 0x01     /* A vnode being actively allocated */ 
#define PSFS_VNODE_WANT       0x02     /* Assuming another thread to allocate vnode */
    psirp_id_t          pn_did;	       /* For accessing parent directory through PIT */
                                       /* For publications and scopes, this is the
					  scope where it appears.  For versions,
					  this is the publication.  For pages,
					  this is the version.  XXX: Probably BUGGY! */
    psirp_id_t          pn_rid;	       /* For accessing data through PIT. */
				       /* XXX: Should be deprecated and use
					       pn_pubi instead. */
    vm_object_t         pn_shadow;     /* Shadow object for a file being written to. */
    
    /*
     * Metadata access state.  This is used by several file system
     * operations to do modifications to the node in a delayed
     * fashion. 
     * 
     * XXX: The code using this is not complete as of April 22 2009.
     */
    int		        pn_vattr_state;
#define	PSFS_VATTR_ACCESSED	(1 << 1)
#define	PSFS_VATTR_MODIFIED	(1 << 2)
#define	PSFS_VATTR_CHANGED	(1 << 3)
};

/*
 * Maps a RID to a psfs node.  Used by the NFS code.
 */
struct psfs_nfsid {
    uint16_t	        ns_len;
    uint16_t	        ns_pad;
    enum psfs_node_type ns_type; /* File handle type */
    psirp_id_t          ns_did;	/* RID for the directory */
    psirp_id_t          ns_rid;	/* RID for the file itself */
};


/* Last vnode type representing a directory */
#define VLASTDIR      VPAGE
/* Names for vnodes not representing directories */
#define VPUBDATA_NAME "data"
#define VPUBMETA_NAME "meta"
#define VEVENTPUBS_NAME "pubs"
#define VEVENTSUBS_NAME "subs"


#define PSFS_NODE_ASSERT(pnode) \
    KASSERT(pnode && PSFS_NODE_MAGIC == (pnode)->pn_magic, \
	    ("pnode MAGIC failed: %p", pnode)) 
#define PSFS_NODE_LOCK(pnode)                                    	\
    do {                                                         	\
	/*printf("  locking node at %p...\n", &(pnode)->pn_interlock);*/ \
	PSFS_NODE_ASSERT(pnode);					\
	(mtx_lock(&((pnode)->pn_interlock)));				\
	/*printf("  locked  node at %p\n", &(pnode)->pn_interlock);*/	\
    } while (0)
// #define PSFS_NODE_UNLOCK(pnode) (mtx_unlock(&((pnode)->pn_interlock)))
#define PSFS_NODE_UNLOCK(pnode)                                  	\
    do {                                                         	\
	/*printf("unlocking node at %p...\n", &(pnode)->pn_interlock);*/ \
	PSFS_NODE_ASSERT(pnode);					\
	(mtx_unlock(&((pnode)->pn_interlock)));				\
	/*printf("unlocked  node at %p\n", &(pnode)->pn_interlock);*/	\
    } while (0)
#define PSFS_NODE_ASSERT_OWNED(pnode)                            \
     do {                                                        \
       PSFS_NODE_ASSERT(pnode);                                  \
       mtx_assert(&((pnode)->pn_interlock), MA_OWNED);         \
     } while (0)
#define PSFS_NODE_ASSERT_NOT_OWNED(pnode)                        \
     do {                                                        \
       PSFS_NODE_ASSERT(pnode);                                  \
       mtx_assert(&((pnode)->pn_interlock), MA_NOTOWNED);      \
     } while (0)


/*
 * Reference to the psfs rootdir.  Currently held all the time,
 * as we don't have any direct pointers to the underlying
 * tmpfs nodes.  Once the tmpfs has been removed, this may
 * be safely removed too.
 */

extern struct mount *psfs_mp;

/*
 * Needed in psfs_subr.c for getnewvnode
 */
extern struct vop_vector psfs_vnodeop_entries;

char *psfs_id2str(psirp_id_t id, char *str);



/*
 * Vnode and psnode interface: psfs_subr.c
 */
int psfs_mp_init(struct thread *td, struct psfs_mount **pmp);
int psfs_mp_cleanup(struct thread *td, struct psfs_mount *pmp);


int psfs_node_free(struct psfs_mount *pmp, struct psfs_node *pnode);
int psfs_node_allocvp(struct thread *td, struct mount *mp,
		      psirp_id_t did, psirp_id_t rid, enum psfs_node_type type,
		      int lkflag, struct vnode **vpp);
void psfs_node_freevp(struct vnode *vp);

#ifdef NOTYET
int psfs_node_update_vattr(struct vnode *vp);
#endif

void psfs_filt_collect_pub(struct psfs_node *pnode);
void psfs_filt_collect_sub(struct psfs_node *pnode);

#endif
