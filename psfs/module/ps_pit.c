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
 * Beginnings for an efficient implementation for looking up
 * data based on the *rid* only.
 *
 * This is work in progress.  There are know bugs and inefficiencies:
 *
 * 1. We currently take only 8 bit from a rid for the hashing.  Should take at least 32. Or maybe we actually do that now, but it should be verified.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/sf_buf.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <machine/stdarg.h>

#include <vm/vm.h>
#include <vm/uma.h>
#include <vm/vm_object.h>

#include "ps.h"
#include "ps_pubi.h"
#include "ps_pit.h"
#include "ps_map.h"
#include "ps_scope.h"
#include "ps_debug.h"

#ifdef DEBUG
#include "psfs.h"		/* Needed for pretty printing */
#endif

#define PS_PIT_PIT_NELEM 3

/*
 * A pit is a hash bucket.  It can hold at most three items
 * with the same hash value.  If there are more, pit_page
 * points to another page, containing more items that would
 * belong to this same hash bucket.
 */
struct ps_pit {
    struct ps_pit_page *pit_page;		   /* 8 bytes */
    void               *pit_pts[PS_PIT_PIT_NELEM]; /* 3 * 8 = 24 bytes */
    psirp_id_t          pit_ids[PS_PIT_PIT_NELEM]; /* 3 * 32 = 96 bytes */
};
typedef struct ps_pit ps_pit_t;

struct ps_pit_page_hdr {
    struct rwlock pph_lock;
    struct ps_pit_page *pph_parent;       /* Parent of this page.  NULL at root. */
    u_int32_t pph_init;		          /* Hash variation initialisation */
};

#define PS_PIT_PAGE_NELEM 31
#define PS_PIT_PAGE_MAXEL \
  ((PAGE_SIZE - sizeof(struct ps_pit_page_hdr)) / sizeof(struct ps_pit))

struct ps_pit_page {
    union {
	struct ps_pit_page_hdr _pp_hdr;
	u_int8_t       dummy[sizeof(struct ps_pit)]; 
    } _pp_u;
    struct ps_pit      pp_pits[PS_PIT_PAGE_NELEM];
};
typedef struct ps_pit_page ps_pit_page_t;

#define pp_lock         _pp_u._pp_hdr.pph_lock
#define pp_parent       _pp_u._pp_hdr.pph_parent
#define pp_init         _pp_u._pp_hdr.pph_init

enum ps_pit_op { GET, GETN, PUT };

/*
 * Pool to store the pit pages at.
 */
uma_zone_t ps_pit_spot;

ps_pit_page_t *ps_pit_root;

static ps_pit_page_t *ps_pit_page_new(ps_pit_page_t *parent);

int 
ps_pit_init(void) {
// #ifdef NOTYET
    KASSERT(PS_PIT_PAGE_NELEM == PS_PIT_PAGE_MAXEL, 
	    ("Pit compilation NELEM count failure: NELEM=%d, MAXEL=%ld", 
	     PS_PIT_PAGE_NELEM, PS_PIT_PAGE_MAXEL));
// #endif
    KASSERT(sizeof(struct ps_pit_page) == PAGE_SIZE, 
	    ("Pit compilation page size mismatch, sizeof=%ld", 
	     sizeof(struct ps_pit_page)));

    ps_pit_spot = uma_zcreate("Pubsub PITs", 
			      sizeof(struct ps_pit_page),
			      NULL, NULL, NULL, NULL, /* XXX: Need dtor? */
			      UMA_ALIGN_PTR, 0); /* XXX: Align? */
    ps_pit_root = ps_pit_page_new(NULL);
    if (NULL == ps_pit_root) {
	uma_zdestroy(ps_pit_spot);
	return ENOMEM;
    }
    
    return 0;
}

void ps_pit_cleanup() {
    /* XXX: We are currently harsh and just throw everything away. */
    ps_pit_root = NULL;
    uma_zdestroy(ps_pit_spot);
}

static ps_pit_page_t *
ps_pit_page_new(ps_pit_page_t *parent) {
    ps_pit_page_t *pp;

    pp = uma_zalloc(ps_pit_spot, M_ZERO | M_WAITOK);
    if (NULL == pp) 
	return NULL;

    rw_init(&pp->pp_lock, "PITlck");
    pp->pp_parent = parent;
    pp->pp_init = 1;		/* XXX: Make this a changing prime! */
    
    return pp;
}
  
/*
 * Hashing and locking macros.
 */

/* XXX: SHA-1 is 20 bytes, u_int32_t is 4 bytes, 20-4=16 */
#define ps_pit_hash(pp, ident, level)       \
    ((*((u_int32_t *)((ident).id            \
                      + ((PSIRP_ID_LEN)-20) \
                      + ((level) % 16)))    \
      * (pp)->pp_init)                      \
     % (PS_PIT_PAGE_NELEM))

#define ps_pit_pit(pp, ident, level) \
    ((pp)->pp_pits + ps_pit_hash((pp), (ident), (level)))

#define ps_pit_match(pit, i, ident) \
    (!memcmp((pit)->pit_ids[(i)].id, (ident).id, sizeof(psirp_id_t)))

#define PIT_ASSERT(pp) KASSERT(pp, ("PIT page null"))

#define PIT_PAGE_RLOCK(pp)   do {                           \
    PIT_ASSERT(pp);                                         \
    PS_PRINTF(PS_DEBUG_LOCK,                                \
              "Read   lock PIT: 0x%p (PIT parent = 0x%p)\n",\
              (pp), (pp)->pp_parent);			    \
    rw_rlock(  &((pp)->pp_lock));                           \
} while(0)


#define PIT_PAGE_WLOCK(pp)   do {                           \
    PIT_ASSERT(pp);                                         \
    PS_PRINTF(PS_DEBUG_LOCK,                                \
	      "Write   lock PIT: 0x%p (PIT parent = 0x%p)\n",\
	      (pp), (pp)->pp_parent);			    \
    rw_wlock(  &((pp)->pp_lock));                           \
} while(0)
   

#define PIT_PAGE_RUNLOCK(pp) do {			    \
    PIT_ASSERT(pp);                                         \
    PS_PRINTF(PS_DEBUG_LOCK,                                \
	      "Read unlock PIT: 0x%p (PIT parent = 0x%p)\n",\
	      (pp), (pp)->pp_parent);			    \
    rw_runlock(  &((pp)->pp_lock));                         \
} while(0)
 

#define PIT_PAGE_WUNLOCK(pp) do{                            \
    PIT_ASSERT(pp);                                         \
    PS_PRINTF(PS_DEBUG_LOCK,                                \
	      "Write unlock PIT: 0x%p (PIT parent = 0x%p)\n",\
	      (pp), (pp)->pp_parent);			    \
    rw_wunlock(  &((pp)->pp_lock));                         \
} while(0)
 
#define PIT_PAGE_TRYUP(pp)   (rw_try_upgrade(&((pp)->pp_lock)))

/*
 * Cache speedup.  Move data up when found.
 *
 * The idea is that when an entry is found, it is gradually
 * moved towards the root of the tree (if one can get write locks).
 * That gradually moves the most used IDs closer to the root,
 * and the less often used further away, towards the leaves.
 */
static void
ps_pit_moveup(ps_pit_page_t *pp, ps_pit_t *pit, int elem) {
    /* XXX: Not implemented yet. */
}

/*
 * We handle the case of rid=0 separately, as it is always scope 0.
 * Note also that if pit->pit_id == 0, then we assume that it is empty.
 */

static void *scope0_data = &ps_pubi_scope0;
static psirp_id_t scope_0_id = { { 0 } };

typedef int (*pit_alloc)(ps_pubi_t *);

/*
 * Get from or put to a pit.  
 */
static int 
ps_pit_getput(psirp_id_t id, void **dp, int level, pit_alloc alloc, enum ps_pit_op op) {
    ps_pit_page_t *pp;
    ps_pit_t *pit = NULL;
    int i;			/* idx = pit index, i = elem in pit */

	
    PS_PRINTF(PS_DEBUG_PIT,
	      "level %d rid %s op %d\n", level, psfs_id2str(id, NULL), op);

    KASSERT(op == GET || dp != NULL, ("PUT with NULL data pointer"));

    if (!memcmp(id.id, scope_0_id.id, sizeof(scope_0_id.id))) {
	switch (op) {
	case GETN:
	    if (dp) *dp = scope0_data;
	    return EEXIST;
	case GET:
	    if (dp) *dp = scope0_data;
	    return 0;
	case PUT:
	    panic("Put on scope0");
	default:
	    panic("Unknown op=%d", op);
	}
    }

  restart:
    PS_PRINTF(PS_DEBUG_PIT, "(re)starting\n");
    pp = ps_pit_root;
    PIT_PAGE_RLOCK(pp);

    /*
     * Step 1.  Try to find an existing entry. 
     */
    for (;;) {
	PIT_ASSERT(pp);
	KASSERT(level >= 0, ("Data structure gone entangled?"));

	pit = ps_pit_pit(pp, id, level);
        
	/*
	 * Look up at pit-local entries.
	 */
	for (i = 0; i < PS_PIT_PIT_NELEM; i++) {
	    if (ps_pit_match(pit, i, id)) {
		PS_PRINTF(PS_DEBUG_PIT, "found at pit %p slot %d\n", pit, i);
                /* Found one */
		break;
	    }
	}
        if (i < PS_PIT_PIT_NELEM) {
            break; /* Entry found. Break outer for-loop. */
        }
        
	/*
	 * Not found in this pit.  If this pit points to another
	 * page, go there.
	 */
	if (pit->pit_page) {
	    PIT_PAGE_RLOCK(pit->pit_page);
	    PIT_PAGE_RUNLOCK(pp);
	    PS_PRINTF(PS_DEBUG_PIT, "descending a page to %p\n", pit->pit_page);
	    wakeup(ps_pit_root);
	    pp = pit->pit_page;
	    level--;
	    PIT_ASSERT(pp);
	    continue;
	}
        
	/*
	 * Not found at all.
	 */
	break;
    }

    switch (op) {
    case GETN:
	if (i >= PS_PIT_PIT_NELEM) {
	    int error;
	    PS_PRINTF(PS_DEBUG_PIT, "not found, allocating\n");
	    error = alloc((ps_pubi_t *)dp);
	    if (error) {
		PIT_PAGE_RUNLOCK(pp);
		PS_PRINTF(PS_DEBUG_PIT, "alloc failed\n");
		wakeup(ps_pit_root);
		return error;
	    }
	    break;		/* Do a put */
	} /* else */
	/* FALL through */
    case GET:
	if (i >= PS_PIT_PIT_NELEM) {
	    PIT_PAGE_RUNLOCK(pp);
	    PS_PRINTF(PS_DEBUG_PIT, "not found\n");
	    wakeup(ps_pit_root);
	    return ENOENT;
	}

	if (dp)
	    *dp = pit->pit_pts[i];
	ps_pit_moveup(pp, pit, i);

	PIT_PAGE_RUNLOCK(pp);
	PS_PRINTF(PS_DEBUG_PIT, "returning from pit %p slot %d\n", pit, i);
	wakeup(ps_pit_root);
	return (GETN == op)? EEXIST: 0;
    case PUT:
	break;
    default:
	panic("ps_pit_getput: unknown op=%d\n", op);
    }


    /*
     * Upgrade the lock.  If fails, we just restart as the data
     * structures may have completely changed.
     */
    if (0 == PIT_PAGE_TRYUP(pp)) {
	/* Couldn't get write lock.  Block. */
	PIT_PAGE_RUNLOCK(pp);
	wakeup(ps_pit_root);
	PS_PRINTF(PS_DEBUG_PIT, "sleeping\n");
	tsleep(ps_pit_root, 0, "PITtr", hz/1000);
	PS_PRINTF(PS_DEBUG_PIT, "restarting\n");
	goto restart;
    }
	
    /*
     * If not found, look for a free slot.
     */
    if (i >= PS_PIT_PIT_NELEM) {
	for (i = 0; i < PS_PIT_PIT_NELEM; i++) {
	    if (ps_pit_match(pit, i, scope_0_id)) {
		PS_PRINTF(PS_DEBUG_PIT, "found empty pit %p slot %d\n", pit, i);
		break;
	    }
	}
    }

    /*
     * If we found the entry, one already used by us or 
     * an empty one, upgrade the data.
     */
    if (i < PS_PIT_PIT_NELEM) {
	pit->pit_ids[i] = id;
	pit->pit_pts[i] = *dp;
	PIT_PAGE_WUNLOCK(pp);
	PS_PRINTF(PS_DEBUG_PIT, "storing at pit %p slot %d\n", pit, i);
	wakeup(ps_pit_root);
	return 0;
    }

    /* 
     * Step 4. This pit is full but there is no child page.
     *         Create one.
     */
    {
	ps_pit_page_t *new;

	PS_PRINTF(PS_DEBUG_PIT, "creating a page\n");
	new = ps_pit_page_new(pp);
	PIT_PAGE_WLOCK(new);
	pit->pit_page = new;
	PIT_PAGE_WUNLOCK(pp);
	wakeup(ps_pit_root);

	level--;
	pp = new;
	
	pit = ps_pit_pit(pp, id, level);
	
	/*
	 * Since this is a new page, we know that the first slot is empty.
	 */
	PS_PRINTF(PS_DEBUG_PIT, "storing at pit %p slot %d\n", pit, 0);
	pit->pit_ids[0] = id;
	pit->pit_pts[0] = *dp;

	PIT_PAGE_WUNLOCK(pp);
	wakeup(ps_pit_root);
	return 0;
    }
}

/*
 * Get the data.  Returns ENOENT if not found.
 * On success, the returned PUBI is locked.
 */
int 
ps_pit_get(psirp_id_t id, ps_pubi_t *pubip) {
    int error;

    error = ps_pit_getput(id, (void **)pubip, PSIRP_ID_LEN - 1, NULL, GET);
    if (0 == error && NULL != pubip) {
	MPASS(NULL != *pubip);
	PS_OBJ_PUBI_LOCK(*pubip);
#ifdef RIDINPUBI
	MPASS(0 == memcmp(id.id, (*pubip)->pi_rid.id, sizeof(psirp_id_t)));
#endif
    } 
    return error;
	      
}

/*
 * Get the data.  If not found, creates a new entry and returns zero.
 * If found, returns the existing entry and returns EEXIST.
 * The returned PUBI is always locked.
 */
int
ps_pit_getn(struct thread *td, psirp_id_t id, ps_pubi_t *pubip) {
    int error;
    error = ps_pit_getput(id, (void **)pubip, PSIRP_ID_LEN - 1, ps_pubi_alloc, GETN);
    MPASS(*pubip != NULL);
#ifdef INVARIANTS
    if (EEXIST == error) {
#ifdef RIDINPUBI
	MPASS(0 == memcmp(id.id, (*pubip)->pi_rid.id, sizeof(psirp_id_t)));
#endif
    }
#endif
    PS_OBJ_PUBI_LOCK(*pubip);
    return error;
}



#ifdef DEBUG

/*
 * The rest is for getting debugging information out of PIT.
 * Use psirptest -i
 *
 */

static char *
get_indent(int level)
{
    /* 45/3 = 15 levels + 1 trailing zero */
    static char ibuffer[46];

    memset(ibuffer, ' ', sizeof(ibuffer));

    if (level > 15)
        level = 0;

    ibuffer[level*3] = 0;
    return ibuffer;
}

static int
dbgwrite(char **buf, int *max, char *fmt, ...)
{
    int retval;
    va_list ap;

    /* print out-of-buffer space only once... */
    if (*max == -1)
        return EPIPE;

    /* If space only for less than 80 characters. Let's notify
     * user space.
     */
    if (*max < 80) {
        *buf -= (80 - *max);
        *max = 80;
    }

    if (*max == 80) {
        snprintf(*buf, *max, 
                 "ERROR! Buffer overflow. Use bigger status buffer!\n");
        /* don't print any errors the next time */
        *max = -1;
        return EPIPE;
    }

    va_start(ap, fmt);
    retval = vsnprintf(*buf, *max, fmt, ap);
    va_end(ap);

    *buf += retval;
    *max -= retval;
    return 0;
}

static char *
get_pitstatus(ps_pit_t *pit, int *index)
{
    int idx = 0, i;
    static char *table[] = {
        "--",
        " 1",
        " 2",
        " 3",
        "1P",
        "2P",
        "3P",
    };

    if (pit) {
        if (pit->pit_page)
            idx += 3;
        
        for(i=0;i<PS_PIT_PIT_NELEM;i++) {
            if (pit->pit_pts[i])
                idx++;
        }
    }

    if (index)
        *index = idx;

    return table[idx];
}

/* tricky macro... expects "buf" and "maxlen" to be defined! */
#define DBGWRITE(format, ...) do {                     \
    if (dbgwrite(buf, maxlen, format, ##__VA_ARGS__))  \
        goto out;                                      \
} while(0)

/* All the rest have two fixed arguments that MUST be passed along for
 * the macro above to work:
 *
 * char **buf   - Current position in the text buffer
 * int *maxlen  - Space left in the text buffer
 */

static int
print_vmobj(int indent, vm_object_t obj, char **buf, int *maxlen)
{
    char str[90] = {0};
    int err = EPIPE;

    VM_OBJECT_LOCK(obj);

    DBGWRITE("%p size=%ld, refcnt=%d, shadowcnt=%d\n", obj, 
             obj->size, obj->ref_count, obj->shadow_count);

    switch(obj->type) {
    case OBJT_DEFAULT:
        strcat(str, "DEFAULT");
        break;
    case OBJT_SWAP:
        strcat(str, "SWAP");
        break;
    case OBJT_VNODE:
        strcat(str, "VNODE");
        break;
    case OBJT_DEVICE:
        strcat(str, "DEVICE");
        break;
    case OBJT_PHYS:
        strcat(str, "PHYS");
        break;
    case OBJT_DEAD:
        strcat(str, "DEAD");
        break;
    }

    DBGWRITE("%stype=[%s] ", get_indent(indent), str);

    memset(str, 0, sizeof(str));

    if (obj->flags & OBJ_ACTIVE)
        strcat(str, "ACTIVE|");
    if (obj->flags & OBJ_DEAD)
        strcat(str, "DEAD|");
    if (obj->flags & OBJ_NOSPLIT)
        strcat(str, "NOSPLIT|");
    if (obj->flags & OBJ_PIPWNT)
        strcat(str, "PIPWNT|");
    if (obj->flags & OBJ_MIGHTBEDIRTY)
        strcat(str, "MIGHTBEDIRTY|");
    if (obj->flags & OBJ_CLEANING)
        strcat(str, "CLEANING|");
    if (obj->flags & OBJ_ONEMAPPING)
        strcat(str, "ONEMAPPING|");
    if (obj->flags & OBJ_DISCONNECTWNT)
        strcat(str, "DISCONNECTWNT|");
#if __FreeBSD_version < 800000
    if (obj->flags & OBJ_NEEDGIANT)
        strcat(str, "NEEDGIANT|");
#endif

    str[strlen(str)-1] = 0;

    DBGWRITE("flags=[%s]\n", str);

    if (obj->backing_object) {
        DBGWRITE("%sBacking object=", get_indent(indent+1));

        if (print_vmobj(indent+1, obj->backing_object, buf, maxlen))
            goto out;
    }

    VM_OBJECT_UNLOCK(obj);
    err = 0;
out:
    return err;

}

extern void db_show_mtx(struct mtx *);

static enum ps_pub_type
print_meta(int indent, vm_object_t obj, char **buf, int *maxlen)
{
    struct sf_buf *sf = NULL;
    vm_page_t page;
    int err;
    enum ps_pub_type ret = PS_PUB_UNINITIALISED;
    ps_meta_t meta;
    char str[16] = {0};

    err = ps_kmap_page(obj, 0, &page);
    if (err) {
        DBGWRITE("%s===> Error: Could not map meta page (error %d)\n", 
                 get_indent(indent), err);
        return PS_PUB_UNINITIALISED;
    }

    sf = sf_buf_alloc(page, 0);
    meta = (ps_meta_t)sf_buf_kva(sf);

    switch(PS_PUB_TYPE(meta)) {
    case PS_PUB_UNINITIALISED:
        strcat(str, "UNINITIALIZED");
        break;
    case PS_PUB_UNKNOWN:
        strcat(str, "UNKNOWN");
        break;
    case PS_PUB_SCOPE:
        strcat(str, "SCOPE");
        break;
    case PS_PUB_DATA:
        strcat(str, "DATA");
        break;
    case PS_PUB_VERSION:
        strcat(str, "VERSION");
        break;
    case PS_PUB_PAGE:
        strcat(str, "PAGE");
        break;
    default:
	sprintf(str, "%d", PS_PUB_TYPE(meta));
        break;
    }

    ret = PS_PUB_TYPE(meta);

    DBGWRITE("%sPublication type=[%s] datalen=%ld\n", get_indent(indent), 
              str, meta->pm_size);

    switch (PS_PUB_TYPE(meta)) {
	int i;
    case PS_PUB_SCOPE:
    case PS_PUB_DATA:
	for (i = 0; i < meta->pm_vers_count; i++) {
	    DBGWRITE("%s  Vers %d: %s\n", get_indent(indent), i, 
                     psfs_id2str(meta->pm_sub_object[i], NULL));
	}
	break;
    case PS_PUB_VERSION:
	for (i = 0; i < meta->pm_page_count; i++) {
            DBGWRITE("%s  Page %d: %s\n", get_indent(indent), i, 
                     psfs_id2str(meta->pm_sub_object[i], NULL));
	}
	break;
    default:
	break;
    }

 out:
    sf_buf_free(sf);
    ps_kunmap_page(obj, page, 0);

    return ret;
}

static void
print_scope(int indent, vm_object_t obj, char **buf, int *maxlen)
{
    struct sf_buf *sf = NULL;
    vm_page_t page;
    int err, i;
    struct ps_scope_dat_page *scope;

    err = ps_kmap_page(obj, 0, &page);
    if (err) {
        DBGWRITE("%s===> Error: Could not map scope data page (error %d)\n", 
               get_indent(indent), err);
        return;
    }

    sf = sf_buf_alloc(page, 0);
    scope = (struct ps_scope_dat_page *)sf_buf_kva(sf);

    DBGWRITE("%sScope magic=%s size=%d\n", get_indent(indent), 
	psfs_id2str(scope->sdp_magic, NULL), scope->sdp_id_count);

    DBGWRITE("%sPublications in this scope:\n", get_indent(indent));
    for(i=0;i<scope->sdp_id_count;i++) {
        DBGWRITE("%s%s\n", get_indent(indent+1), 
                  psfs_id2str(scope->sdp_entries[i], NULL));
    }   

 out:
    sf_buf_free(sf);
    ps_kunmap_page(obj, page, 0);

    return;
}

static int
ps_pit_print_pubi(void *pubi, char **buf, int *maxlen)
{
    int err = EPIPE;
    ps_pubi_t pi = pubi;
    enum ps_pub_type mtype = PS_PUB_UNINITIALISED;
 
    if (pi->pi_metaobj) {
        DBGWRITE("   Metaobj=");
        if (print_vmobj(1, pi->pi_metaobj, buf, maxlen))
            goto out;
        mtype = print_meta(2, pi->pi_metaobj, buf, maxlen);
    } else {
	printf("   WARNING: No metaobject\n");
    }

    if (pi->pi_object) {
        DBGWRITE("   Dataobj=");
        if (print_vmobj(1, pi->pi_object, buf, maxlen))
            goto out;

        if (mtype == PS_PUB_SCOPE) {
            print_scope(2, pi->pi_object, buf, maxlen);
        }
    } 

    err = 0;
out:
    return err;
}

static int
ps_pit_print_table(char *pitname, ps_pit_page_t *pitpage, char **buf,
                   int *maxlen)
{
    int i,j,z;
    int err = EPIPE;

    DBGWRITE("    |  0 |  1 |  2 |  3 |  4 |  5 |  6 |"
             "  7 |  8 |  9 |\n");


#define PG(page, row, col) (page->pp_pits[row*10+col])

    for(i=0;i<PS_PIT_PAGE_NELEM/10;i++) {
        DBGWRITE(" %d0 |", i);
        for(j=0;j<10;j++) {
            DBGWRITE(" %s |", get_pitstatus(&PG(pitpage, i, j), NULL));
        }
        DBGWRITE("\n");
    }
    DBGWRITE(" 30 | %s |\n", get_pitstatus(&PG(pitpage, 3, 0), NULL));

    DBGWRITE("\nPIT: SCOPE0\n");
    DBGWRITE("1: 0000000000000000000000000000000000000000000000000000000000000000\n");

    if (ps_pit_print_pubi(&ps_pubi_scope0, buf, maxlen))
      goto out;

    for(i=0;i<PS_PIT_PAGE_NELEM;i++) {
        int ix = -1;

        get_pitstatus(&PG(pitpage, i/10, i%10), &ix);
        if (ix < 1)
            continue;
        if (ix > 3) {
            ix -= 3;
            if (ix > 3)
                continue;
        }

        DBGWRITE("\nPIT: %s(%d) contains %d IDs:\n", pitname, i, ix);
        for(z=0;z<ix;z++) {
            DBGWRITE("%d: %s\n", z+1, 
                      psfs_id2str(pitpage->pp_pits[i].pit_ids[z], 
                                  NULL));

            if (ps_pit_print_pubi(pitpage->pp_pits[i].pit_pts[z], buf, maxlen))
                goto out;
        }
    }

    DBGWRITE("\n");
    err = 0;

#undef PG
out:
    return err;
}


static int
ps_pit_status_recurse(char *rootname, ps_pit_page_t *page, char **buf,
                      int *maxlen)
{
    int i;
    int err = EPIPE;
    char tablename[64];

    PIT_PAGE_RLOCK(page);

    DBGWRITE("\nCurrent PIT table: %s\n", rootname);

    if (ps_pit_print_table(rootname, page, buf, maxlen))
        goto out;

    for(i=0;i<PS_PIT_PAGE_NELEM;i++) {
        if (page->pp_pits[i].pit_page) {
            
            sprintf(tablename, "%s:%02d", rootname, i);
            if (ps_pit_status_recurse(tablename, 
                                      page->pp_pits[i].pit_page,
                                      buf, maxlen))
                goto out;
        }
    }

    err = 0;
out:
    PIT_PAGE_RUNLOCK(page);
    return err;
}

int
ps_pit_status(char *buf, int maxlen)
{
    char *orig = buf;
    ps_pit_status_recurse("ROOT", ps_pit_root, &buf, &maxlen);
    return buf - orig;
}

#endif
