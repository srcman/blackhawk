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
 * Kernel-to-userspace event reporting, consisting of pages.
 *
 * An event page is simply a list of <SID,RID> pairs.
 *
 * Note that as-of-today (May 11 2009), events pages are *not* publications.
 * But they may become so at some point of time.
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
#include <sys/kernel.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#include "ps.h"
#include "ps_event.h"
#include "ps_pubi.h"
#include "ps_obj.h"
#include "ps_map.h"
#include "ps_magic.h"
#include "ps_debug.h"

#ifdef DEBUG
#include "psfs.h"
#endif

static psirp_id_t ps_pep_magic = { PS_PEP_MAGIC_INIT };

static vm_object_t event_objects[4]; /* XXX: allow more, grow dynamicly? */

static struct pep {
    struct ps_event_page *pep;
    int                   pep_index;
    struct sf_buf *       pep_sf;
    struct mtx            pep_lock;
} active[PS_EVENT_TYPE_COUNT] = {
    { NULL, -1, NULL },
    { NULL, -1, NULL },
};

#define PS_EVENT_PEP_ASSERT(type)						\
    MPASS((     -1 == active[(type)].pep_index				\
	   && NULL == active[(type)].pep				\
	   && NULL == active[(type)].pep_sf)				\
         ||   (( 0 <= active[(type)].pep_index &&			\
	              active[(type)].pep_index                          \
                          < sizeof(event_objects)/sizeof(event_objects[0])) \
	   && NULL != active[(type)].pep				\
	   && NULL != active[(type)].pep_sf))

#define PS_EVENT_PEP_LOCK(type)			\
    do {								\
	PS_EVENT_PEP_ASSERT(type);					\
	PS_PRINTF(PS_DEBUG_LOCK, "  locking pep at %p...\n",		\
		  &active[(type)].pep_lock);				\
	mtx_lock(&active[(type)].pep_lock);				\
	PS_PRINTF(PS_DEBUG_LOCK, "  locked  pep at %p\n",		\
		  &active[(type)].pep_lock);				\
	PS_EVENT_PEP_ASSERT(type);					\
    } while (0)

#define PS_EVENT_PEP_UNLOCK(type)					\
    do {								\
	PS_EVENT_PEP_ASSERT(type);					\
	PS_PRINTF(PS_DEBUG_LOCK, "unlocking pep at %p...\n",		\
		  &active[(type)].pep_lock);				\
	mtx_unlock(&active[(type)].pep_lock);				\
	PS_PRINTF(PS_DEBUG_LOCK, "unlocked  pep at %p\n",		\
		  &active[(type)].pep_lock);				\
	PS_EVENT_PEP_ASSERT(type);					\
    } while (0)

#define PS_EVENT_PAGE_LOCK(type)					\
    do {								\
	PS_EVENT_PAGE_ASSERT(active[(type)].pep);			\
	PS_EVENT_PEP_LOCK(type);					\
	PS_EVENT_PAGE_ASSERT(active[(type)].pep);			\
    } while (0)

#define PS_EVENT_PAGE_UNLOCK(type)					\
    do {								\
	PS_EVENT_PAGE_ASSERT(active[(type)].pep);			\
	PS_EVENT_PEP_UNLOCK(type);					\
	PS_EVENT_PAGE_ASSERT(active[(type)].pep);			\
    } while (0)

int
ps_event_init(struct thread *td)
{
    int error = 0;
    int i;

    for (i = 0; i < sizeof(active)/sizeof(active[0]); i++) {
	mtx_init(&active[i].pep_lock, "PS event", "PS event", MTX_DEF);
    }

    for (i = 0; i < sizeof(event_objects)/sizeof(event_objects[0]); i++) {
	vm_page_t p;
	struct sf_buf *sf;
	struct ps_event_page *pep;

	error = ps_obj_alloc(td, PAGE_SIZE, &event_objects[i]);
	if (error)
	    break;
	error = ps_kmap_page(event_objects[i], 0, &p);
	if (error) 
	    break;
	sched_pin();
	sf = sf_buf_alloc(p, SFB_CPUPRIVATE);
	pep = (struct ps_event_page *)sf_buf_kva(sf);

	pep->pep_magic = PS_PEP_MAGIC;

	sf_buf_free(sf);
	sched_unpin();

	error = ps_kunmap_page(event_objects[i], p, TRUE);
	if (error)
	    break;
    }

    if (error) {
	for (i = 0; i < sizeof(event_objects)/sizeof(event_objects[0]); i++) {
	    if (event_objects[i]) {
		vm_object_deallocate(event_objects[i]);
		event_objects[i] = NULL;
	    }
	}
    }

    return error;
}

void
ps_event_cleanup(void)
{
    int i;

    for (i = 0; i < sizeof(event_objects)/sizeof(event_objects[0]); i++) {
	vm_object_deallocate(event_objects[i]); 
    }
}

static int
event_activate_pep(ps_event_type_t type) 
{
    int error = 0;
    int i;

    PS_EVENT_PEP_ASSERT(type);

    if (NULL != active[type].pep) 
	goto out;

    for (i = 0; i < sizeof(event_objects)/sizeof(event_objects[0]); i++) {
	vm_page_t p;
	struct sf_buf *sf;
	struct ps_event_page *pep;

	/*
	 * Access page 
	 */
	//PS_EVENT_PEP_LOCK(type); /* Assume that we already hold the lock. */
	error = ps_kmap_page(event_objects[i], 0, &p);
	if (error) {
	    //PS_EVENT_PEP_UNLOCK(type);
	    goto out;
	}
	sf = sf_buf_alloc(p, 0);
	pep = (struct ps_event_page *)sf_buf_kva(sf);

	/*
	 * If page is available, leave it in the kernel vm and return.
	 */
	if (0 == (pep->pep_status)) {
	    active[type].pep_sf    = sf;
	    active[type].pep_index = i;
	    active[type].pep       = pep;
	    pep->pep_status  = PEP_IN_KERN;
	    pep->pep_count   = 0;
	    pep->pep_threads = 0;
	    //PS_EVENT_PEP_UNLOCK(type);
	    goto out;
	}

	/*
	 * Page was in use, free page from kernel vm.
	 */
	sf_buf_free(sf);
	error = ps_kunmap_page(event_objects[i], p, FALSE);
	//PS_EVENT_PEP_UNLOCK(type);
	if (error)
	    goto out;
    }

    error = ENOMEM;

  out:
    MPASS(0 != error || NULL != active[type].pep);
    MPASS(0 != error || PEP_IN_KERN == active[type].pep->pep_status);
    PS_EVENT_PEP_ASSERT(type);
    return error;
}

static int
event_deactivate_pep(ps_event_type_t type) 
{
    int error = 0;
    vm_page_t page;

    PS_EVENT_PEP_ASSERT(type);

    if (NULL == active[type].pep) {
	goto out;
    }

    MPASS(PEP_IN_KERN == active[type].pep->pep_status);
    active[type].pep->pep_status = PEP_IN_USER;

    page = sf_buf_page(active[type].pep_sf);
    sf_buf_free(active[type].pep_sf);
    active[type].pep_sf = NULL;
    
    error = ps_kunmap_page(event_objects[active[type].pep_index], page, TRUE);
    active[type].pep_index = -1;
    active[type].pep = NULL;

  out:
    MPASS(NULL == active[type].pep);
    PS_EVENT_PEP_ASSERT(type);
    return error;
}

int
ps_event_add(ps_event_type_t type, psirp_id_t *sid, psirp_id_t *rid,
             ps_flags_t flags)
{
    int index;

    PS_EVENT_PAGE_LOCK(type);

    if (NULL == active[type].pep) {
	int error;

	error = event_activate_pep(type);
	if (error) {
            PS_EVENT_PAGE_UNLOCK(type);
	    return error;
        }
    }

    MPASS(NULL != active[type].pep);

    PS_PRINTF(PS_DEBUG_EVENT,
              "adding event: type=%d, SID=%s, flags=0x%04x\n",
              type, psfs_id2str(*sid, NULL), flags);
    PS_PRINTF(PS_DEBUG_EVENT,
              "adding event: type=%d, RID=%s, flags=0x%04x\n",
              type, psfs_id2str(*rid, NULL), flags);

    /*
     * Grab an entry on the page and bump thread count.
     */
    //PS_EVENT_PAGE_LOCK(type); /* Too late. */
    if (active[type].pep->pep_count >= PS_EVENT_NELEM) {
	PS_EVENT_PAGE_UNLOCK(type);
	PS_PRINTF(PS_DEBUG_EVENT | PS_DEBUG_WARNING,
		  "active event list full (%lu)\n", PS_EVENT_NELEM);
	return ENOSPC;
    }
    index = active[type].pep->pep_count++;
    active[type].pep->pep_threads++;
    //    PS_EVENT_PAGE_UNLOCK(type);

    active[type].pep->pep_events[index].pe_sid   = *sid;
    active[type].pep->pep_events[index].pe_rid   = *rid;
    active[type].pep->pep_events[index].pe_flags = flags;

    /*
     * Decrement thread count.
     */
    //    PS_EVENT_PAGE_LOCK(type);
    active[type].pep->pep_threads--;
    PS_EVENT_PAGE_UNLOCK(type);

    return 0;
}

int
ps_event_pending(ps_event_type_t type) 
{
    if (NULL == active[type].pep)
	return 0;

    return active[type].pep->pep_count;
}

int
ps_event_read_prepare(ps_event_type_t type, vm_object_t *objp, vm_ooffset_t *sizep)
{
    int index;
    int error = 0;

    PS_EVENT_PEP_LOCK(type);

    index = active[type].pep_index;
    if (index < 0) {
	PS_EVENT_PEP_UNLOCK(type);
	*objp  = NULL;
	*sizep = 0;
	return 0;
    }

    *sizep = PS_EVENT_ALIGNMENT
	+ active[type].pep->pep_count * sizeof(active[type].pep->pep_events[0]);
    *objp = event_objects[index];

    error = event_deactivate_pep(type);

    PS_EVENT_PEP_UNLOCK(type);
    PS_EVENT_PEP_ASSERT(type);
    return error;
}

int
ps_event_read_done(ps_event_type_t type, vm_object_t obj)
{
    int error;
    vm_page_t p;
    struct sf_buf *sf;
    struct ps_event_page *pep;

    if (NULL == obj)
	return 0;

    error = ps_kmap_page(obj, 0, &p);
    if (error) 
	return error;
    sched_pin();
    sf = sf_buf_alloc(p, SFB_CPUPRIVATE);
    pep = (struct ps_event_page *)sf_buf_kva(sf);
    
    pep->pep_count = 0;
    pep->pep_status = 0;
    
    sf_buf_free(sf);
    sched_unpin();
    
    error = ps_kunmap_page(obj, p, TRUE);
    if (error)
	return error;

    return 0;
}
