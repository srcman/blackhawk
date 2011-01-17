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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <sys/mount.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_param.h>
#include <sys/sched.h>
#include <sys/sf_buf.h>
#include <machine/_inttypes.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_pit.h"
#include "ps_scope.h"
#include "ps_debug.h"

#include "psfs.h"

/*
 * We currently allow only one mount point.
 *
 * We also save the mount info at mount, as it is represented by the
 * underlying tmpfs and we otherwise wouldn't have direct access to
 * that layer. 
 *
 * XXX: Once the tmpfs layer below has been removed (if it
 * ever gets removed), we should remove this hack, too.
 */
struct mount *psfs_mp;

psirp_id_t root_id = { { 0 } };

static int
psfs_unmount(struct mount *mp, int mntflags, struct thread *td) {
    int error = 0;
    int flags = 0;
    struct psfs_mount *pmp;

    if (mntflags & MNT_FORCE)
	flags |= FORCECLOSE;

    error = vflush(mp, 0, flags, td);
    if (error)
	return error;

    pmp = mp->mnt_data;
    if (pmp->pm_root) {
	psfs_node_free(pmp, pmp->pm_root);
	pmp->pm_root = NULL;
    }
    if (pmp->pm_pubs) {
	psfs_node_free(pmp, pmp->pm_pubs);
	pmp->pm_pubs = NULL;
    }
    if (pmp->pm_subs) {
	psfs_node_free(pmp, pmp->pm_subs);
	pmp->pm_subs = NULL;
    }
    psfs_mp = NULL;
    (void) psfs_mp_cleanup(td, pmp);

    return error;
}

static int
psfs_mount(struct mount *mp, struct thread *td) {
    struct psfs_mount *pmp = NULL;
    int error;

    PS_PRINTF(PS_DEBUG_VFS, "mp=%p, td=%p\n", mp, td);

    if (psfs_mp) {
	PS_PRINTF(PS_DEBUG_VFS | PS_DEBUG_ERROR,
		  "Cannot mount multiple times.  Unmount and retry.\n");
	return EBUSY;
    }
    psfs_mp = mp;

    /*
     * Ok, now we need to initialise our own mount point.
     *
     * We will set the root later, after the scope has been
     * created.
     */
    error = psfs_mp_init(td, &pmp);
    if (error) {
	psfs_mp = NULL;
	return error;
    }

    MPASS(NULL != pmp);

    mp->mnt_data = pmp;

    vfs_mountedfrom(mp, "psfs");
    PS_PRINTF(PS_DEBUG_VFS, "mp=%p, td=%p -> %d\n", mp, td, 0);
    return 0;
}

static int
psfs_root(struct mount *mp, int flags, struct vnode **vpp, struct thread *td) {
    int error;

    PS_PRINTF(PS_DEBUG_VFS, "mp=%p, flags=%d, vpp=%p\n", mp, flags, vpp);

    error = psfs_node_allocvp(td, mp, root_id, root_id, VROOT, flags, vpp);
    if (!error) {
	(*vpp)->v_vflag |= VV_ROOT;
    }

    PS_PRINTF(PS_DEBUG_VFS, "  *vpp=%p -> %d\n", *vpp, error);

    return error;
}

static int
psfs_statfs(struct mount *mp, struct statfs *sbp, struct thread *td) {
    struct psfs_mount *pmp;

    pmp = mp->mnt_data;
    
    sbp->f_iosize = PAGE_SIZE;
    sbp->f_bsize = PAGE_SIZE;
    
#ifdef NOTYET
    fsfilcnt_t freenodes;

    sbp->f_blocks = PSFS_PAGES_MAX(pmp);
    sbp->f_bavail = sbp->f_bfree = PSFS_PAGES_AVAIL(pmp);
    
    freenodes = MIN(pmp->pm_nodes_max - pmp->pm_nodes_inuse,
		    PSFS_PAGES_AVAIL(pmp) * PAGE_SIZE / sizeof(struct psfs_node));
    
    sbp->f_files = freenodes + pmp->pm_nodes_inuse;
    sbp->f_ffree = freenodes;
    /* sbp->f_owner = pmp->pm_uid; */
#endif

    return 0;

}

/*
 * XXX: Not tested with NFS.  (AFAWN -- March 30 2009).
 */
static int
psfs_fhtovp(struct mount *mp, struct fid *fhp, struct vnode **vpp) {
    struct psfs_nfsid *nsp;
    struct psfs_mount *pmp;
    int error;

    PS_PRINTF(PS_DEBUG_VFS, "mp=%p, fhp=%p, vpp=%p\n", mp, fhp, vpp);

    pmp = mp->mnt_data;

    nsp = (struct psfs_nfsid *)fhp;
    if (nsp->ns_len != sizeof(struct psfs_nfsid))
	return EINVAL;

    error = psfs_node_allocvp(curthread, mp, nsp->ns_did, nsp->ns_rid, nsp->ns_type,
			     LK_EXCLUSIVE, vpp);

    PS_PRINTF(PS_DEBUG_VFS, "mp=%p, fhp=%p, vpp=%p -> %d\n", mp, fhp, vpp, error);

    return error;
}

struct vfsops psfs_vfsops = {
#if __FreeBSD_version < 800000
    .vfs_mount   = psfs_mount,
    .vfs_unmount = psfs_unmount,
    .vfs_root    = psfs_root,
    .vfs_statfs  = psfs_statfs,
    .vfs_fhtovp  = psfs_fhtovp,
#else
    .vfs_mount   = (vfs_mount_t *)psfs_mount,
    .vfs_unmount = (vfs_unmount_t *)psfs_unmount,
    .vfs_root    = (vfs_root_t *)psfs_root,
    .vfs_statfs  = (vfs_statfs_t *)psfs_statfs,
    .vfs_fhtovp  = (vfs_fhtovp_t *)psfs_fhtovp,
#endif
};

VFS_SET(psfs_vfsops, psfs, 0);
