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
#include <sys/dirent.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/sf_buf.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_obj.h"
#include "ps_magic.h"
#include "ps_scope.h"
#include "ps_pit.h"
#include "ps_debug.h"

#include "psfs.h"
#include "psfs_dir.h"

/*
 * We structure the dirents in 76 bytes long dirents,
 * consisting of a 8 byte header + 68 bytes for the name.
 *
 * The first dirents, where offset < 76, are special.
 * There we store the dot, dotdot, meta, data, and data.suffix
 * entries that do not point to "real" publications.
 */

#define DIRSIZ(string) \
    ((sizeof (struct dirent) - (MAXNAMLEN+1)) + ((sizeof(string) + 3) &~ 3))
    

#define DE( type, string)					\
    { 0, DIRSIZ(string), type, sizeof(string)-1, string } 

/*
 * Meta-entries in publication, version, and page directories
 */
static struct dirent des_long[] = {
    DE(DT_DIR, "."),		  /* 12 bytes */
    DE(DT_DIR, ".."),		  /* 12 bytes */
    DE(DT_REG, VPUBMETA_NAME),	  /* 16 bytes */
    { 0, 36, DT_REG, 4, VPUBDATA_NAME }, /* 76 - (12+12+16) = 36 bytes */

};

/*
 * Meta-entries in root directory.
 */
static struct dirent des_root[] = {
    DE(DT_DIR, "."),		  /* 12 bytes */
    DE(DT_DIR, ".."),		  /* 12 bytes */
    DE(DT_REG, VEVENTPUBS_NAME),  /* 16 bytes */
    { 0, 36, DT_REG, 4, VEVENTSUBS_NAME }, /* 76 - (12+12+16) = 36 bytes */
};

/*
 * Meta-entries in the scope directories.
 */

static struct dirent des_scope[] = {
    DE(DT_DIR, "."),		/* 12 bytes */
    { 0, 64, DT_DIR, 2, ".." },		/* 76 - 12 = 64 */
};

#define DIRSIZ_RID \
    DIRSIZ("0000000000000000000000000000000000000000000000000000000000000000")

static int dir_scope2dents(struct psfs_node *pnode, struct uio *uio, 
			   u_long *cookies, off_t cnt, 
			   int *eofflag, boolean_t only_sids);

static int dir_vers2dents(struct psfs_node *pnode, struct uio *uio, 
			  u_long *cookies, off_t cnt, int *eofflag);
int
psfs_dir_cntdents(struct psfs_node *pnode, off_t *cntp) 
{
    int error = 0;
    off_t cnt = 0;
    ps_pubi_t pi;

    PS_PRINTF(PS_DEBUG_DIR, "pnode=%p\n", pnode);

    switch (pnode->pn_type) {
    case VROOT:
	error = ps_scope_get_rid_count(pnode->pn_pubi, &cnt, TRUE);
	if (error)
	    return error;
	cnt += sizeof(des_root)/sizeof(des_root[0]);
	break;
    case VSCOPE:
	error = ps_scope_get_rid_count(pnode->pn_pubi, &cnt, FALSE);
	if (error)
	    return error;
	cnt += sizeof(des_scope)/sizeof(des_scope[0]);
	break;
    case VPUB:
    case VVER:
	error = ps_pit_get(pnode->pn_rid, &pi);
	if (error) return error;
	PS_OBJ_PUBI_ASSERT_OWNED(pi);
	error = ps_obj_get_version_count(pi, &cnt);
	PS_OBJ_PUBI_UNLOCK(pi);
	cnt += sizeof(des_long)/sizeof(des_long[0]);
	break;
    case VPAGE:
	cnt = sizeof(des_long)/sizeof(des_long[0]);
	break;
    default:
	panic("psfs_dir_cntents: attempt to readdir a non-directory: pnode=%p", pnode);
    }

    *cntp = cnt;

    PS_PRINTF(PS_DEBUG_DIR, "pnode=%p -> cnt=%ld, error=%d\n", pnode, cnt, error);

    return error;
}


int 
psfs_dir_getdents(struct psfs_node *pnode, struct uio *uio, 
		  u_long *cookies, off_t cnt, int *eofflag)
{
    ps_pubi_t pi;
    int error = 0;
    off_t off;
    struct dirent *des;
    int i, des_cnt;

    PS_PRINTF(PS_DEBUG_DIR, "uio_offset %ld\n", uio->uio_offset);

    error = ps_pit_get(pnode->pn_rid, &pi);
    if (error)
	return error;

    switch (pnode->pn_type) {
    case VROOT:
	des     = des_root;
	des_cnt = sizeof(des_root)/sizeof(des_root[0]);
	break;
    case VSCOPE:
	des     = des_scope;
	des_cnt = sizeof(des_scope)/sizeof(des_scope[0]);
	break;
    case VPUB:
    case VVER:
    case VPAGE:
	des     = des_long;
	des_cnt = sizeof(des_long)/sizeof(des_long[0]);
	break;
    default:
	panic("psfs_dir_cntents: attempt to readdir a non-directory: pnode=%p", pnode);
    }

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    if (uio->uio_offset < DIRSIZ_RID) {
	/*
	 * Offsets < DIRSIZ_RID are used for the special files.
	 */
	
	off = 0;
	for (i = 0; i < des_cnt; i++) {
	    if (uio->uio_offset == off)
		break;
	    off += des[i].d_reclen;
	}
	while (0 == error && uio->uio_resid > 0 && i < des_cnt && 0 < cnt--) {
	    des[i].d_fileno = pi->pi_ino + pnode->pn_type;
	    error = uiomove(&des[i], des[i].d_reclen, uio);
	    if (cookies)
		*cookies++ = uio->uio_offset;
	    i++;
	}
    }
    PS_OBJ_PUBI_UNLOCK(pi);

    if (0 != uio->uio_offset % DIRSIZ_RID || DIRSIZ_RID > uio->uio_offset) {
	PS_PRINTF(PS_DEBUG_DIR | PS_DEBUG_ERROR,
		  "bad uio_offset %ld\n", uio->uio_offset);
	return EINVAL;
    }

    switch (pnode->pn_type) {
    case VROOT:
	error = dir_scope2dents(pnode, uio, cookies, cnt, eofflag, TRUE);
	break;
    case VSCOPE:
	error = dir_scope2dents(pnode, uio, cookies, cnt, eofflag, FALSE);
	break;
    case VPUB:
    case VVER:
	error = dir_vers2dents(pnode, uio, cookies, cnt, eofflag);
	break;
    case VPAGE:
	if (eofflag)
	    *eofflag = TRUE;
	break;
    default:
	panic("psfs_dir_getdents: unimplemented pnode type %d\n", pnode->pn_type);
    }

    return error;
}

struct dir_iter {
    struct uio *di_uio;
    u_long *    di_cookies;
    off_t       di_count;
    int         di_type;
    boolean_t   di_only_sids;
};

static int 
dir_scopeiter(void *arg, psirp_id_t *idp)
{
    int error = 0;
    ps_pubi_t pi;
    enum ps_pub_type type;
    struct dir_iter *di = arg;
    struct uio *uio = di->di_uio;
    struct dirent dent;

    error = ps_pit_get(*idp, &pi);
    if (error)
	return error;
    error = ps_obj_get_type(pi, &type);
    if (error) {
	PS_OBJ_PUBI_UNLOCK(pi);
	return error;
    }
    switch (type) {
    case PS_PUB_SCOPE:
	break;
    case PS_PUB_DATA:
    case PS_PUB_UNKNOWN:
	if (di->di_only_sids) {
	    PS_OBJ_PUBI_UNLOCK(pi);
	    return 0;
	}
	break;
    default:
	/* XXX: May crash here on subscribe-before-publish.  If so, make a test case
	 *      and go to talk to Pekka. */
	panic("dir_scopeiter: bad publication type %d", type);
    }

    dent.d_fileno = pi->pi_ino + di->di_type;
    dent.d_type   = DT_DIR;
    dent.d_namlen = PSIRP_ID_LEN * 2;
    dent.d_reclen = GENERIC_DIRSIZ(&dent);
    PS_OBJ_PUBI_UNLOCK(pi);

    psfs_id2str(*idp, dent.d_name);

    di->di_count++;

    error = uiomove(&dent, dent.d_reclen, uio);
    if (di->di_cookies)
	*(di->di_cookies++) = uio->uio_offset;
    return error;
}

static int 
dir_scope2dents(struct psfs_node *pnode, struct uio *uio, u_long *cookies, 
		off_t cnt, int *eofflag, boolean_t only_sids)
{
    int error = 0;
    off_t off;
    int index;
    struct dir_iter arg;

    KASSERT(0 == uio->uio_offset % DIRSIZ_RID && uio->uio_offset >= DIRSIZ_RID,
	    ("Invalid uio_offset %ld", uio->uio_offset));

    off = uio->uio_offset;

    /* XXX: Move from zero based indeces to 1 based indeces for scope_iter? */
    index = (uio->uio_offset / DIRSIZ_RID) - 1;
    arg.di_uio       = uio;
    arg.di_cookies   = cookies;
    arg.di_count     = 0;
    arg.di_type      = pnode->pn_type;
    arg.di_only_sids = only_sids;
    error = ps_scope_iterate(pnode->pn_pubi, dir_scopeiter, index, cnt, &arg, eofflag);

    if (cnt != arg.di_count) {
	/* XXX: We cannot KASSERT this (can we), as it may change due to other activity? */
	PS_PRINTF(PS_DEBUG_DIR | PS_DEBUG_WARNING,
		  "WARNING: count changed during runtime: %ld != %ld, error=%d\n", 
		  cnt, arg.di_count, error);
    }

    KASSERT((0 == uio->uio_offset % DIRSIZ_RID && uio->uio_offset >= DIRSIZ_RID),
	    ("Invalid uio_offset %ld", uio->uio_offset));

    return error;
}

#ifdef DEBUG
extern void db_show_mtx(struct mtx *);
#endif

static int 
dir_vers2dents(struct psfs_node *pnode, struct uio *uio, u_long *cookies, 
	       off_t maxcount, int *eofflag)
{
    int error = 0;
    off_t off;
    ps_pubi_t pi;
    ps_meta_t meta;
    int index, i;

    KASSERT(0 == uio->uio_offset % DIRSIZ_RID && uio->uio_offset >= DIRSIZ_RID,
	    ("Invalid uio_offset %ld", uio->uio_offset));

    off = uio->uio_offset;

    PS_PRINTF(PS_DEBUG_DIR, "off=%ld, maxcount=%ld, eofflag=%p\n", off, maxcount, eofflag);

    error = ps_pit_get(pnode->pn_rid, &pi);
    if (error)
	return error;

    error = ps_obj_get_page(pi, VMO_META, 0, (void **)&meta);
    if (error) {
	PS_OBJ_PUBI_UNLOCK(pi);
	return error;
    }
#ifdef INVARIANTS
    PS_PRINTF(PS_DEBUG_DIR, "meta->pm_interlock=%p:\n", meta->pm_interlock);
    if (ps_debug_mask & PS_DEBUG_DIR) {
	db_show_mtx(meta->pm_interlock);
    }
#endif
    PS_OBJ_META_LOCK(meta);
    PS_OBJ_PUBI_UNLOCK(pi);

    index = (uio->uio_offset / DIRSIZ_RID) - 1;
    for (i = index; i < meta->pm_vers_count; i++) {
	ps_pubi_t vpi;
	struct dirent dent;
	
	error = ps_pit_get(meta->pm_sub_object[i], &vpi);
	if (error) {
	    PS_PRINTF(PS_DEBUG_WARNING, "version %s not found in pit\n",
		      psfs_id2str(meta->pm_sub_object[i], NULL));
	    error = 0;
	    continue;
	}

	dent.d_fileno = vpi->pi_ino + IPUB;
	dent.d_type   = DT_DIR;
	dent.d_namlen = PSIRP_ID_LEN * 2;
	dent.d_reclen = GENERIC_DIRSIZ(&dent);
	PS_OBJ_PUBI_UNLOCK(vpi);

	psfs_id2str(meta->pm_sub_object[i], dent.d_name);

	error = uiomove(&dent, dent.d_reclen, uio);
	if (cookies)
	    *cookies++ = uio->uio_offset;
	if (error)
	    break;
    }
    if (eofflag && i >= meta->pm_vers_count)
	*eofflag = TRUE;
    /* 
     * Note that we have to unlock meta first, before locking pi,
     * as the locking order is always pi->meta->...
     */
    PS_OBJ_META_UNLOCK(meta);
    /* XXX: Is there any possibility for some race condition here? */
    PS_OBJ_PUBI_LOCK(pi);
    ps_obj_put_page(pi, VMO_META, FALSE);
    PS_OBJ_PUBI_UNLOCK(pi);
    if (error) 
	return error;


    PS_PRINTF(PS_DEBUG_DIR, "i=%d, *eofflag=%d -> %d\n", i, eofflag? *eofflag: 4077, error);

    KASSERT((0 == uio->uio_offset % DIRSIZ_RID && uio->uio_offset >= DIRSIZ_RID),
	    ("Invalid uio_offset %ld", uio->uio_offset));

    return error;
}
