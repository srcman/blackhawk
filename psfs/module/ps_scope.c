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
 * Scope data structure, consisting of pages.
 *
 * A scope simply lists the RIDs on it.  To find the publication, 
 * you have to go through the pit.
 *
 * Note that scopes are publications.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/sf_buf.h>
#include <sys/sched.h>
#include <sys/vnode.h>
#include <sys/filedesc.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#include <sys/libkern.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_map.h"
#include "ps_obj.h"
#include "ps_syscall.h"
#include "ps_pit.h"
#include "ps_magic.h"
#include "ps_scope.h"
#include "ps_debug.h"

#include "psfs.h"

/*
 * Access scope content in the kernel address space.
 */
typedef int (*scope_access_f)(struct ps_scope_dat_page *sdp, 
			      void *arg1, void *arg2);

static int
scope_access(ps_pubi_t pi, scope_access_f f, vm_pindex_t pindex, 
	     void *arg1, void *arg2) 
{
    int error = 0;
    enum ps_pub_type type;
    void *data;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);
    error = ps_obj_get_type(pi, &type);
    if (error)
	return error;
    if (PS_PUB_SCOPE != type) {
	PS_PRINTF(PS_DEBUG_SCOPE | PS_DEBUG_WARNING,
		  "WARNING: attempt to access scope with bad type %d\n", type);
	return ENOTDIR;
    }

    error = ps_obj_get_page(pi, VMO_DATA, pindex, &data);
    if (error)
	return error;

    error = f(data, arg1, arg2);

    ps_obj_put_page(pi, VMO_DATA, FALSE);

    return error;
}

static inline int rid_in_bf(psirp_id_t *ridp, ps_scope_bf_t *bfp) {
    u_int32_t crc;
    u_int8_t  bi; /* bit index */
    int i;

    crc = crc32((const unsigned char *)ridp, sizeof(psirp_id_t));
    for (i = 0; i < PS_SCOPE_BF_K; i++) {
        bi = (crc >> (i << 3)) & 0xff; /* XXX: bf must be at least 256 bits */
        if (!(bfp->bf[(bi >> 3)] & (1 << (bi % 8)))) {
            return 0;
        }
    }
    return 1;
}

#if 0
static inline int rid_into_bf(psirp_id_t *ridp, ps_scope_bf_t *bfp) {
    u_int32_t crc;
    u_int8_t  bi; /* bit index */
    int i;
    int bitcount = 0;

    crc = crc32((const unsigned char *)ridp, sizeof(psirp_id_t));
    for (i = 0; i < PS_SCOPE_BF_K; i++) {
        bi = (crc >> (i << 3)) & 0xff; /* XXX: bf must be at least 256 bits */
        bfp->bf[(bi >> 3)] |= 1 << (bi % 8);
        bitcount += __builtin_popcount(bfp->bf[(bi >> 3)]);
    }

    return (bitcount > (sizeof(ps_scope_bf_t) << 2));
}
#endif

/*
 * Returns the index of a RID if it exists, or -1 otherwise.
 */
static int
scope_get_rid(struct ps_scope_dat_page *sdp, 
	      void *arg1, void *arg2) 
{
    psirp_id_t *ridp = arg1;
    off_t      *idxp = arg2;
    int i;

    if (rid_in_bf(ridp, &sdp->sdp_bf)) {
        for (i = 0; i < sdp->sdp_id_count; i++) {
            if (!memcmp(ridp->id, sdp->sdp_entries[i].id,
                        sizeof(sdp->sdp_entries[0].id))) {
                if (idxp)
                    *idxp = i;
                return 0;
                break;
            }
        }
    }
    return ENOENT;
}

int 
ps_scope_get_rid(ps_pubi_t pi, psirp_id_t *ridp, off_t *idxp) {
    int error = 0;

    PS_OBJ_PUBI_ASSERT_OWNED(pi);

    error = scope_access(pi, scope_get_rid, 0/*XXX*/, ridp, idxp);

    return error;
}

struct scope_iter {
    ps_scope_iterator si_iter;
    off_t si_start;
    off_t si_count;
    off_t si_maxcount;
    int *si_eofflag;
};

static int
scope_get_rid_count(struct ps_scope_dat_page *sdp, 
		    void *arg1, void *arg2) 
{
    off_t   *countp = arg1;
    //    boolean_t *sids_only = arg2;

    /* 
     * XXX: We simply ignore sids_only and may return a too large number.
     *      But that seems to work anyway, not worth fixing (yet).
     */
    *countp  = sdp->sdp_id_count;

    return 0;
}

int
ps_scope_get_rid_count(ps_pubi_t pi, off_t *countp, boolean_t sids_only) 
{
    int error;
    
    PS_OBJ_PUBI_LOCK(pi);
    error = scope_access(pi, scope_get_rid_count, 0, countp, &sids_only);
    PS_OBJ_PUBI_UNLOCK(pi);
    return error;
}

/*
 * XXX: Works only for data pages.
 */
static int
scope_iter_dp(struct ps_scope_dat_page *sdp, 
	    void *arg1, void *arg2) {
    struct scope_iter *si = arg1;
    ps_scope_iterator iterate = si->si_iter;
    off_t start = si->si_start;
    off_t count = si->si_maxcount;
    off_t i;
    int error = 0;

    PS_PRINTF(PS_DEBUG_SCOPE, "start=%ld, count=%ld\n", start, count);
    for (i = start; i < sdp->sdp_id_count && i < count; i++) {
	error = iterate(arg2, &sdp->sdp_entries[i]);
	if (error)
	    break;
	si->si_count++;
    }
    if (i >= sdp->sdp_id_count) 
	if (si->si_eofflag)
	    *(si->si_eofflag) = TRUE;

    return error;
}

/* XXX: Works for data pages only */
#define EIDX_2_PIDX(index) ((index) / PS_SCOPE_DAT_NELEM)

int
ps_scope_iterate(ps_pubi_t pi, ps_scope_iterator iter, off_t start, 
		 off_t count, void *arg, int *eofflag)
{
    int error = 0;
    vm_pindex_t pindex;
    struct scope_iter si;
    int pageeof;

    PS_PRINTF(PS_DEBUG_SCOPE, "start=%ld, count=%ld\n", start, count);

    si.si_iter     = iter;
    si.si_start    = start % PS_SCOPE_DAT_NELEM;
    si.si_count    = 0;
    si.si_maxcount = count;
    si.si_eofflag  = &pageeof;
    /* XXX: Fix when you make scopes bigger than one page */
    for (pindex = EIDX_2_PIDX(start); pindex < 1 /* XXX */; pindex++) {
	pageeof = FALSE;
	PS_OBJ_PUBI_LOCK(pi);
	error = scope_access(pi, scope_iter_dp, pindex, &si, arg);
	PS_OBJ_PUBI_UNLOCK(pi);
	if (error)
	    return error;
	si.si_maxcount -= si.si_count;
	si.si_count = 0;
	si.si_start = 0;
    }
    if (pageeof && eofflag)
	*eofflag = TRUE;

    PS_PRINTF(PS_DEBUG_SCOPE, "eof=%d -> %d\n", eofflag? *eofflag: -1, error);
    return error;
}

int
ps_scope_verify_format(vm_object_t dobj) 
{
    int error = 0;
    vm_page_t page;
    struct sf_buf *sf;
    struct ps_scope_dat_page *sdp;

    error = ps_kmap_page(dobj, 0, &page);
    if (error)
	return error;

    sf = sf_buf_alloc(page, 0);
    sdp = (void *)sf_buf_kva(sf);

    if (!PS_MAGIC_TEST(sdp->sdp_magic, ps_sdp_magic)) {
	PS_PRINTF(PS_DEBUG_SYSCALL | PS_DEBUG_WARNING,
		  "attempt to republish non-scope data %p@%p at a scope", dobj, sdp);
	error = EFTYPE;
    }

    sf_buf_free(sf);
    (void)ps_kunmap_page(dobj, page, 0);

    return error;
}
