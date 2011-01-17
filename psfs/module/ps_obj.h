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

#define PS_OBJ_META_ASSERT(meta)						\
    KASSERT(meta && PS_MAGIC_TEST(PS_META_MAGIC, (meta)->pm_magic),		\
	    ("meta MAGIC failed: %p", meta))
#define PS_OBJ_META_LOCK(meta)							\
    do {									\
	PS_OBJ_META_ASSERT(meta);						\
	if (PS_PUB_MUTABLE(meta)) {						\
	    PS_PRINTF(PS_DEBUG_LOCK, "  locking meta %s at %p...\n",		\
		      psfs_id2str((meta)->pm_id, NULL), (meta)->pm_interlock); 	\
	    mtx_lock(((meta)->pm_interlock));					\
	    PS_PRINTF(PS_DEBUG_LOCK, "  locked  meta %s at %p\n",		\
		      psfs_id2str((meta)->pm_id, NULL), (meta)->pm_interlock);  \
	}									\
	PS_OBJ_META_ASSERT(meta);						\
    } while (0)
// #define PS_OBJ_META_UNLOCK(meta) (mtx_unlock(&((meta)->pm_interlock)))
#define PS_OBJ_META_UNLOCK(meta)						\
    do {									\
	PS_OBJ_META_ASSERT(meta);						\
	if (PS_PUB_MUTABLE(meta)) {						\
	    PS_PRINTF(PS_DEBUG_LOCK, "unlocking meta %s at %p...\n", 		\
		      psfs_id2str((meta)->pm_id, NULL), (meta)->pm_interlock); 	\
	    mtx_unlock(((meta)->pm_interlock));					\
	    PS_PRINTF(PS_DEBUG_LOCK, "unlocked  meta %s at %p\n",		\
		      psfs_id2str((meta)->pm_id, NULL), (meta)->pm_interlock);  \
	}									\
	PS_OBJ_META_ASSERT(meta);						\
    } while (0)
#define PS_OBJ_META_ASSERT_OWNED(meta)				\
    do {							\
	PS_OBJ_META_ASSERT(meta);				\
	if (PS_PUB_MUTABLE(meta))				\
	    mtx_assert(((meta)->pm_interlock), MA_OWNED);	\
    } while (0)
#define PS_OBJ_META_ASSERT_NOT_OWNED(meta)		 	\
    do {						  	\
	PS_OBJ_META_ASSERT(meta);				\
	if (PS_PUB_MUTABLE(meta))				\
	    mtx_assert(((meta)->pm_interlock), MA_NOTOWNED);	\
    } while(0)

/*
 * Object interface: ps_obj.c
 */


int ps_obj_alloc(struct thread *td, vm_ooffset_t size, vm_object_t *objp);

int ps_obj_init_meta_user(vm_object_t metaobj);
int ps_obj_init_meta_kernel(vm_object_t metaobj, enum ps_pub_type type, psirp_id_t rid, vm_ooffset_t dlen);
int ps_obj_init_meta_page(struct thread *td, ps_pubi_t ppi, psirp_id_t *pridp);
#ifdef DEBUG
void ps_obj_vrfy_meta_page(ps_pubi_t ppi);
#endif
int ps_obj_copy_meta2version(struct thread *td, ps_pubi_t pi, vm_object_t vmobj,
			     psirp_id_t vrid, vm_ooffset_t dlen);
int  ps_obj_get_page(ps_pubi_t pi, ps_vmo_t type, vm_pindex_t pindex, void **ptr);
void ps_obj_put_page(ps_pubi_t pi, ps_vmo_t type, boolean_t modified);

int ps_obj_get_dataobj(ps_pubi_t pi, vm_object_t *dobjp, vm_ooffset_t *sizep,
                       enum ps_pub_type *typep);

int ps_obj_get_type(ps_pubi_t pi, enum ps_pub_type *typep);

#ifdef PUBI_HAS_SIDS
int ps_obj_add_sid (ps_pubi_t id, psirp_id_t sid);
int ps_obj_get_sids(ps_pubi_t id, psirp_id_t *sids, int *countp);
#endif

int ps_obj_add_version(ps_pubi_t pi, psirp_id_t vrid, vm_object_t dobj, vm_ooffset_t dlen);
int ps_obj_get_version_count(ps_pubi_t pi, off_t *cnt);
 
#if 0
int ps_obj_sha1_data(vm_object_t dobj, vm_ooffset_t dlen, caddr_t digest);
#endif
int ps_obj_sha1_page(vm_object_t dobj, vm_pindex_t page, vm_ooffset_t offset, vm_ooffset_t len, caddr_t digest);
void ps_obj_sha1_mt(psirp_id_t *rids, int count, caddr_t digest);
int ps_obj_sha1_mt_page(vm_object_t dobj, vm_pindex_t page, vm_ooffset_t offset, int id_count, caddr_t digest);

struct vattr;

#ifdef NOTYET
int ps_obj_get_vattr(ps_pubi_t id, struct vattr *);
int ps_obj_set_vattr(ps_pubi_t id, struct vattr *);
#endif

int ps_obj_get_rid(ps_pubi_t pi, psirp_id_t *ridp, off_t *idxp,
                   enum ps_pub_type type);
