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
 * API for using kqueues with libpsirp
 *
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/mutex.h>
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define _LIBPSIRP    1

#include <ps.h>
#include <ps_syscall.h>
#include <libpsirp.h>



/*** Internal functions ***/

static void
fire_callback(psirp_kq_t *ph, struct psirp_event *psev)
{
    psirp_kevl_t *tmp, *kevl = NULL;

    SLIST_FOREACH(tmp, ph, next) {
        if (tmp->event.udata == psev->pub) {
            kevl = tmp;
            break;
        }
    }

    if (kevl)
        psev->cb_retcode = kevl->callback(psev, kevl->opaque);

}




/*** API ***/


void psirp_delete_kq(struct psirp_kq_handle *ph)
{
    psirp_kevl_t *kevl, *kevl_iter;

    if (ph->kq >= 0)
	close(ph->kq);

    SLIST_FOREACH_SAFE(kevl, ph, next, kevl_iter) {
        free(kevl);
    }

    free(ph);

}

struct psirp_kq_handle *
psirp_create_kq(void)
{
    struct psirp_kq_handle *ph;

    ph = calloc(1, sizeof(*ph));
    if (!ph)
	return NULL;

    ph->kq = kqueue();
    if (ph->kq == -1) {
	free(ph);
	return NULL;
    }

    return ph;
}


int
psirp_add_kq_listener(psirp_kq_t *kh, psirp_pub_t pub, int filter,
                      psirp_callback_t callback, void *opaque)
{
    psirp_kevl_t *kevl;

    if (!kh)
        return -1;

    if (!pub)
        return -2;

    if (!((filter & NOTE_PUBLISH) || (filter & NOTE_SUBSCRIBE)))
        return -3;

    if (!callback)
        return -4;

    kevl = calloc(1, sizeof(*kevl));
    if (!kevl)
        return -5;

    EV_SET(&kevl->event, psirp_pub_fd(pub), EVFILT_VNODE,
           EV_ADD | EV_CLEAR, filter, 0, (void *)pub);

    kevl->callback = callback;
    kevl->opaque = opaque;

    if (SLIST_EMPTY(kh)) {
        SLIST_FIRST(kh) = kevl;
    } else {
        SLIST_INSERT_HEAD(kh, kevl, next);
    }

    kh->size_evlist++;
    return 0;
}


int psirp_wait_kq(struct psirp_kq_handle *ph, int max_secs, 
		  struct psirp_event *events, int *num_events)
{
    struct timespec ts;
    psirp_kevl_t *kevl;
    struct kevent *kev, *kev_orig;
    int cnt;
    int err;
    int i;

    ts.tv_sec = max_secs;
    ts.tv_nsec = 0;

    if (!events || !num_events)
        return -1;

    if (*num_events < ph->size_evlist)
        return -2;

    kev = calloc(ph->size_evlist, sizeof(*kev));
    if (!kev)
        return -3;

    kev_orig = kev;
    cnt = 0;

    SLIST_FOREACH(kevl, ph, next) {
        *kev = kevl->event;
        kev++;
        cnt++;
    }

    if (cnt != ph->size_evlist) {
        fprintf(stderr, "CONSISTENCY ERROR: Internal kqueue handling BUG\n");
        return -4;
    }

    /* register to kernel */
    err = kevent(ph->kq, kev_orig, ph->size_evlist, NULL, 0, NULL);
    if (err == -1)
	return err;
    
    err = kevent(ph->kq, NULL, 0, kev_orig, ph->size_evlist, &ts);
    if (err <= 0)
	return err;

    kev = kev_orig;
    /* err = number of events occured */
    for(i=0;i<err && i<*num_events && kev;i++, kev++) {
        struct psirp_event psev = { NULL, 0, -1 };

        
        psev.pub = (psirp_pub_t)kev->udata;
        psev.flags = kev->fflags;

        fire_callback(ph, &psev);

        events[i] = psev;
    }

    *num_events = i;
    return err;
}
