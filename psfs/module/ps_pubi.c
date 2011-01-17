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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>

#include <vm/vm.h>
#include <vm/uma.h>

#include "ps.h"
#include "ps_pubi.h"

#include "psfs.h"		/* XXXXXXXXX: Needed to define VSIZE */

/*
 * Static PIT entry for scope0
 *
 * This is needed to resolve the chicken-and-egg problem during
 * startup:
 *   1. To start 'scoped', /pubsub must be mounted
 *   2. To mount /pubsub, root psfs node is needed
 *   3. To create root psfs node, PIT entry 00::00 is needed.
 */

struct ps_pubi ps_pubi_scope0 = {
    { NULL, NULL },		/* metaobj and dataobj */
    { NULL, NULL },		/* sf_bufs */
    0,				/* pindex */
    { { 0 } },			/* interlock */
    { 0 },			/* node */
    8, 				/* inode number */
    0,				/* uid */
    1,				/* pid */
    0, 				/* gid */
    0555,			/* mode */
};

MTX_SYSINIT(PIT_scope0_pubi, &ps_pubi_scope0.pi_interlock, "PIT scope0 pubi", MTX_DEF);

/*
 * Implementation of the publication index objects.
 *
 * XXX: Should the pubis be allocated per mount point?
 */

uma_zone_t pubisuma;

int
ps_pubi_init(void) 
{
    pubisuma = uma_zcreate("Pubsub PUBIs",
			   sizeof(struct ps_pubi),
			   NULL, NULL, NULL, NULL,
			   UMA_ALIGN_PTR, 0);
    
    return 0;
}

void
ps_pubi_cleanup(void) 
{
    uma_zdestroy(pubisuma);
}

int
ps_pubi_alloc(ps_pubi_t *pubip)
{
    ps_pubi_t pi;

    pi = uma_zalloc(pubisuma, M_ZERO | M_WAITOK);
    if (NULL == pi)
	return ENOMEM;

    mtx_init(&pi->pi_interlock, "PUBI interlock", NULL, MTX_DEF);

    pi->pi_metaobj = NULL;
    pi->pi_object  = NULL;

    /* XXX: Init vnode attributes */
    {
	static int pino = VSIZE;	/* XXXXXXXXX: Hack alert.  Fix. */
	pi->pi_ino      = (pino += VSIZE);
    }

    pi->pi_uid  = -1;
    pi->pi_gid  = -1;
    pi->pi_mode = 0;

    *pubip = pi;

    return 0;
}

int 
ps_pubi_free(ps_pubi_t pubi)
{
    uma_zfree(pubisuma, pubi);
    return 0;
}
