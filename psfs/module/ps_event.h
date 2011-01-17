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
 * A PEP page has three possible different states:
 *  0 == status:  The page is free, not used.
 *  1 == status:  The page is mapped into the kernel vm and being filled by the kernel.
 *  2 == status:  The page is reserved for user space, either through read(2) or
 *                some other mechanism (none of which exist now, but could.
 *
 * The idea here is that this could be developed further for the kernel-user
 * space communication, but as of now it is not needed elsewhere.
 */

struct ps_event_page_hdr {
    psirp_id_t _peph_magic;
    u_int8_t   _peph_status;
#define PEP_IN_KERN 0x01	/* Mapped to the kernel address space */
#define PEP_IN_USER 0x02	/* Reserved for user space processing */
    u_int8_t   _peph_count;	/* Number of elements */
    int8_t     _peph_threads;	/* Count of updating threads */
};

#define PS_EVENT_ALIGNMENT (2 * sizeof(psirp_id_t))

struct ps_event {
    psirp_id_t pe_sid;
    psirp_id_t pe_rid;
    ps_flags_t pe_flags;
} 
#if 0 /* XXX: This alignement disabled for now because of the flags. */
#ifndef SWIG
__attribute__ ((aligned(PS_EVENT_ALIGNMENT)))
#endif
#endif
;

#define PS_EVENT_NELEM \
    ((PAGE_SIZE - sizeof(struct ps_event_page_hdr)) / sizeof(struct ps_event))

struct ps_event_page {
    struct ps_event_page_hdr _pep_hdr;
    struct ps_event pep_events[PS_EVENT_NELEM]
#ifndef SWIG
    /* XXX: Align this array or its elements? */
    __attribute__ ((aligned(PS_EVENT_ALIGNMENT)));
#else
    ;
#endif
};

#define pep_magic   _pep_hdr._peph_magic
#define pep_status  _pep_hdr._peph_status
#define pep_count   _pep_hdr._peph_count
#define pep_threads _pep_hdr._peph_threads

#define PS_EVENT_PAGE_ASSERT(page)					\
    do {								\
        if (page) {							\
	    KASSERT(page && PS_MAGIC_TEST(PS_PEP_MAGIC, (page)->pep_magic), \
		    ("pep MAGIC failed: %p", page));			\
	    MPASS(page->pep_threads >= 0 && page->pep_threads < 16); /* XXX */ \
	}								\
    } while (0)

#ifdef _KERNEL

int  ps_event_init(struct thread *td);
void ps_event_cleanup(void);

typedef enum ps_event_type 
  { PS_EVENT_PUB, PS_EVENT_SUB, PS_EVENT_TYPE_COUNT } ps_event_type_t;

int ps_event_add(ps_event_type_t type, psirp_id_t *sid, psirp_id_t *rid,
                 ps_flags_t flags);
int ps_event_pending(ps_event_type_t type);

int ps_event_read_prepare(ps_event_type_t type, vm_object_t *objp, vm_ooffset_t *sizep);
int ps_event_read_done(ps_event_type_t type, vm_object_t obj);

int    psfs_event_attach(struct knote *kn);
void   psfs_event_detach(struct knote *kn);
int    psfs_event_filter(struct knote *kn, long hint);

#endif
