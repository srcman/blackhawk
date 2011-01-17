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
 * While this one logically belongs to psfs.h, it 
 * needs to be defined here, as it is needed in ps_pubi.h
 */

enum psfs_node_iidx { IBAD = -1, ISCOPE = 0, IPUB = 1, IMETA = 2, IDATA = 3, ICOUNT };

/*
 * Publication Index.  A node that has pointers to the data and meta vm_objects, 
 * plus metadata that should not be in the metadata, e.g. due to security issues.
 *
 * XXX For individual pages, we should not use the publication index at all
 *     but directly vm_page_t, since they don't have any real metadata.
 *     However, supporting that would require quite a large changes here
 *     and there.  Hence, probably not worth implementing before implementing
 *     disk-backed storage.
 * 
 * XXX If not really going to storing vm_page_t's directly in the PIT,
 *     an intermediate solution would be to point to the vm_page_t from
 *     here instead of using the vm_index_t.
 */
struct ps_pubi {
    vm_object_t         pi_vmobject[VMO_NUM];
    struct sf_buf      *pi_sf_buf  [VMO_NUM];
#define pi_metaobj      pi_vmobject[VMO_META]
#define pi_object       pi_vmobject[VMO_DATA]    
    vm_pindex_t         pi_pindex;              /* page index; valid only for page RIDs */
    struct mtx          pi_interlock;

    struct psfs_node *  pi_node[ICOUNT];        /* back pointers to the psfs_nodes */

    /* Generic vnode attributes, shared by all psfs_nodes. */
    /* XXX: As these will remain even when swapped out, should be in metadata instead? */
    ino_t               pi_ino;	     /* inode number for this as a scope; others follow */

    uid_t		pi_uid;	     /* initially uid of the eid of the process that created this */
    pid_t               pi_pid;      /* initially pid of the process that created this */
    gid_t		pi_gid;
    mode_t		pi_mode;
#ifdef NOTYET
    int			pi_flags;
    nlink_t		pi_links;
    struct timespec	pi_atime;
    struct timespec	pi_mtime;
    struct timespec	pi_ctime;
    struct timespec	pi_birthtime;
    unsigned long	pi_gen;
#endif
};
typedef struct ps_pubi *ps_pubi_t;

#define PS_OBJ_PUBI_ASSERT(meta) // NOTYET
#define PS_OBJ_PUBI_LOCK(pi)                                            \
    do {								\
      PS_OBJ_PUBI_ASSERT(pi);						\
      PS_PRINTF(PS_DEBUG_LOCK, "  locking pubi at %p...\n",		\
		&(pi)->pi_interlock);					\
      mtx_lock(&((pi)->pi_interlock));					\
      PS_PRINTF(PS_DEBUG_LOCK, "  locked  pubi at %p\n",		\
		&(pi)->pi_interlock);					\
      PS_OBJ_PUBI_ASSERT(pi);						\
    } while (0)
#define PS_OBJ_PUBI_UNLOCK(pi)						\
    do {								\
      PS_OBJ_PUBI_ASSERT(pi);						\
      PS_PRINTF(PS_DEBUG_LOCK, "unlocking pubi at %p...\n",		\
		&(pi)->pi_interlock);					\
      mtx_unlock(&((pi)->pi_interlock));				\
      PS_PRINTF(PS_DEBUG_LOCK, "unlocked  pubi at %p\n",		\
		&(pi)->pi_interlock);					\
      PS_OBJ_PUBI_ASSERT(pi);						\
    } while (0)
#define PS_OBJ_PUBI_ASSERT_OWNED(pi)			\
    do {						\
      PS_OBJ_PUBI_ASSERT(pi);				\
      mtx_assert(&((pi)->pi_interlock), MA_OWNED);	\
    } while (0)
#define PS_OBJ_PUBI_ASSERT_NOT_OWNED(pi)		\
    do {						\
      PS_OBJ_PUBI_ASSERT(pi);			  	\
      mtx_assert(&((pi)->pi_interlock), MA_NOTOWNED); \
    } while(0)

/*
 * We currently allocate PUBI for scope0 statically to
 * circumwent a chicken-and-egg problem.  Alternatively,
 * we could allocate a PUBI for the root scope during
 * mount time.
 *
 * XXX: Move to mount.
 */
extern struct ps_pubi ps_pubi_scope0;

int  ps_pubi_init(void);
void ps_pubi_cleanup(void);
int  ps_pubi_alloc(ps_pubi_t *pubip);
int  ps_pubi_free(ps_pubi_t pubi);
