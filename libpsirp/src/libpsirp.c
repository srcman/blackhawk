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

#include <unistd.h>

/* do not double define psirp_pub_t */
#define _LIBPSIRP    1

#include <ps.h>
#include <ps_syscall.h>
#include <libpsirp.h>
#include "psirp_debug.h"
#include "ps_magic.h"
#include "ps_scope.h"

/* static */ struct module_stat mstat;
/* static */ int syscall_num;

/* MAGIC initializations */

psirp_id_t ps_meta_magic = { PS_META_MAGIC_INIT };
psirp_id_t ps_vers_magic = { PS_VERS_MAGIC_INIT };
psirp_id_t ps_sdp_magic  = { PS_SDP_MAGIC_INIT };
psirp_id_t scope0 = { {0} };

static int psirp_syscall_prepare();




/*** Internal helpers ****/




static int
subscribe_fast(psirp_id_t *sid, psirp_id_t *rid, ps_flags_t flags,
               struct ps_syscall_arg *arg)
{
    struct ps_syscall_sc_arg sa;
    int retval;

    memset(arg, 0, sizeof(*arg));
    memcpy(&arg->a_sid.id, &sid->id, PSIRP_ID_LEN);
    memcpy(&arg->a_rid.id, &rid->id, PSIRP_ID_LEN);

    arg->a_op     = PS_SYSCALL_SUB;
#if 0
    arg->a_op_sub = 1; /* PS_SYSCALL_SUB_META */
#endif

    arg->a_meta = NULL;
    arg->a_mlen = 0;
    arg->a_data = NULL;
    arg->a_dlen = 0;

    arg->a_flags = flags;

    if (!psirp_syscall_prepare()) {
	errno = ENOTSUP;
        return -1;
    }

    sa.p = arg;

    if (retval = syscall(syscall_num, sa)) {
	return errno;
    }

    return 0;
}

/* imported from sys/time.h. Was #ifdef _KERNEL, but no kernel specific here */
#ifndef timespeccmp
#define timespeccmp(tvp, uvp, cmp)                                      \
        (((tvp)->tv_sec == (uvp)->tv_sec) ?                             \
            ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :                       \
            ((tvp)->tv_sec cmp (uvp)->tv_sec))

#endif
#ifndef timespecsub
#define timespecsub(vvp, uvp)                                           \
        do {                                                            \
                (vvp)->tv_sec -= (uvp)->tv_sec;                         \
                (vvp)->tv_nsec -= (uvp)->tv_nsec;                       \
                if ((vvp)->tv_nsec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_nsec += 1000000000;                   \
                }                                                       \
        } while (0)

#endif

static int
sleep_until_event(int kq, int flags, psirp_pub_t pub, struct timeval *endtime)
{
    struct kevent evlist;
    struct timespec curts, endts, maxts;
    struct timeval tv;
    int ret;

    if (endtime) {
        if (gettimeofday(&tv, NULL)) {
            return -2;
        }

        TIMEVAL_TO_TIMESPEC(&tv, &curts);
        TIMEVAL_TO_TIMESPEC(endtime, &endts);

        if (timespeccmp(&endts, &curts, <))
            return ETIMEDOUT;

        maxts = endts;
        timespecsub(&maxts, &curts);
    }

    EV_SET(&evlist, pub->pub_fd, EVFILT_VNODE, EV_ADD|EV_CLEAR,
           flags, 0, pub);

    ret = kevent(kq, &evlist, 1, &evlist, 1, endtime ? &maxts : NULL);
    if (ret < 0)
        return errno;
    else if (ret == 0)
        return ETIMEDOUT;

    return 0;
}


/* Returns 1 (true) if pub is in the scope. */
static int
pub_is_in_scope(psirp_id_t *id, psirp_pub_t pub)
{
    struct ps_scope_dat_page *psd;
    struct ps_meta *pm;
    int i = 0;

    pm = (struct ps_meta *)pub->pub_meta;
    if (!pm)
        return 0;

    if (pm->pm_type != PS_PUB_SCOPE) {
        return 0;
    }

    psd = (struct ps_scope_dat_page *)pub->pub_data;
    if (!psd)
        return 0;

    if (!PS_MAGIC_TEST(psd->sdp_magic, PS_SDP_MAGIC)) {
        return 0;
    }

    if (psd->sdp_id_count > PS_SCOPE_DAT_NELEM) {
        return 0;
    }

    for(i=0;i<psd->sdp_id_count;i++) {
        if (!psirp_idcmp(&psd->sdp_entries[i], id))
            return 1;
    }

    return 0;
}


static int
subscribe_scope(int kq, psirp_id_t *psid, psirp_id_t *sid,
                struct timeval *endtime, ps_flags_t flags) 
{
    int retval;
    struct ps_syscall_arg arg;
    struct ps_meta *pm;
    psirp_pub_t pub;
    int err;

    pub = malloc(sizeof(*pub));
    if (!pub)
        return ENOMEM;

    retval = subscribe_fast(&scope0, psid, PS_FLAGS_LOCAL_LOCALSUB, &arg);
    if (retval == 0) {
        /* meta and lengths are not used yet */
        pub->pub_data = arg.a_data;
        pub->pub_fd = arg.a_retval;
        /* pub->pub_data pointer may be modified by the kernel 
           during a kevent! */

        do {
            if (pub_is_in_scope(sid, pub)) {
                free(pub);
                return 0;
            }

            /*
             * XXX: Timing. We should register first, then re-subscribe.
             *      Otherwise we can (quite easily, in fact) miss an
             *      update and wait in vain.
             */
            retval = sleep_until_event(kq, NOTE_PUBLISH|NOTE_UNMAP, pub, 
                                       endtime);
            if (retval != 0)
                break;
        } while(1);
    }

end:
    free(pub);
    return retval;
}




/*** API ***/



int
psirp_create(u_int64_t len, psirp_pub_t *pubp) {
    struct psfs_pub *pub;
    struct ps_syscall_sc_arg sa;
    struct ps_syscall_arg arg;
    int retval = 0;

    pub = malloc(sizeof(struct psfs_pub));
    if (NULL == pub) 
	return -1;

    memset(&arg, 0, sizeof(arg));
    memset(pub,  0, sizeof(psfs_pub_t));

    arg.a_op   = PS_SYSCALL_CRE;
    arg.a_meta = NULL;
    arg.a_mlen = PS_MD_SIZE;
    arg.a_data = NULL;
    arg.a_dlen = len;

    sa.p = &arg;

    if (!psirp_syscall_prepare()) {
	errno = ENOTSUP;
        return -1;
    }
    
    if (retval = syscall(syscall_num, sa)) {
        return retval;
    }

    pub->pub_meta = (ps_meta_t)arg.a_meta;
    pub->pub_mlen = arg.a_mlen;
    pub->pub_data = arg.a_data;
    pub->pub_dlen = arg.a_dlen;

    *pubp = pub;

    return 0;			/* XXX: kq instead?? */
}

int
psirp_publish(psirp_id_t *sid, psirp_id_t *rid, psirp_pub_t pub) {
    struct ps_syscall_sc_arg sa;
    struct ps_syscall_arg arg;
    int retval = 0;

    memset(&arg, 0, sizeof(arg));
    memcpy(&arg.a_sid.id, &sid->id, PSIRP_ID_LEN);
    memcpy(&arg.a_rid.id, &rid->id, PSIRP_ID_LEN);

    arg.a_op   = PS_SYSCALL_PUB;


    arg.a_meta = (caddr_t)pub->pub_meta;
    arg.a_mlen = pub->pub_mlen;
    arg.a_data = pub->pub_data;
    arg.a_dlen = pub->pub_dlen;

    sa.p = &arg;

    if (!psirp_syscall_prepare()) {
	errno = ENOTSUP;
        return -1;
    }
    
    if (retval = syscall(syscall_num, sa)) {
        return retval;
    }

    pub->pub_meta = (ps_meta_t)arg.a_meta;
    pub->pub_mlen = arg.a_mlen;
    pub->pub_data = arg.a_data;
    pub->pub_dlen = arg.a_dlen;
    pub->pub_fd   = arg.a_retval;
    pub->pub_vidx = arg.a_vridx;
    pub->pub_sid  = *sid;

    return 0;
}

static int psirp_kq = -1;

inline int
psirp_subscribe(psirp_id_t *sid, psirp_id_t *rid, psirp_pub_t *pubp) {
    return psirp_subscribe_with_flags(sid, rid, pubp, 0x0000);
}

int
psirp_subscribe_with_flags(psirp_id_t *sid, psirp_id_t *rid,
                           psirp_pub_t *pubp, ps_flags_t flags) {
    struct psfs_pub *pub;
    //struct ps_syscall_sc_arg sa;
    struct ps_syscall_arg arg;
    //struct kevent ev;
    int retval = 0;

    pub = malloc(sizeof(struct psfs_pub));
    if (NULL == pub) 
	return -1;

    memset(&arg, 0, sizeof(arg));
    memset(pub,  0, sizeof(psfs_pub_t));

    if (retval = subscribe_fast(sid, rid, flags, &arg))
        return retval;

    pub->pub_meta = (ps_meta_t)arg.a_meta;
    pub->pub_mlen = arg.a_mlen;
    pub->pub_data = arg.a_data;
    pub->pub_dlen = arg.a_dlen;
    pub->pub_fd   = arg.a_retval;
    pub->pub_vidx = arg.a_vridx;
    pub->pub_sid  = *sid;

    *pubp = pub;

    return 0;
}


/**
 * Synchronous (blocking) subscribe
 *
 *
 */
inline int
psirp_subscribe_sync(psirp_id_t *sid, psirp_id_t *rid, psirp_pub_t *pubp,
                     struct timeval *timeout) {
    return psirp_subscribe_sync_with_flags(sid, rid, pubp, timeout, 0x0000);
}

int
psirp_subscribe_sync_with_flags(psirp_id_t *sid, psirp_id_t *rid,
                                psirp_pub_t *pubp, struct timeval *timeout,
                                ps_flags_t flags)  {
    struct psfs_pub *pub;
    int kq;
    struct kevent ev;
    int retval = 0;
    struct ps_syscall_arg arg;
    struct timeval current;
    struct timeval end;
    int sub0 = 1;


    if (timeout != NULL) {
        if (gettimeofday(&current, NULL)) {
            return -1;
        }

        timeradd(timeout, &current, &end);
    } 

    kq = kqueue();
    if (kq <= 0) {
        return -1;
    }

sub_pub:
    retval = subscribe_fast(sid, rid, flags, &arg);
    if (retval == 0) {
        /* publication found */

        pub = malloc(sizeof(*pub));
        if (!pub)
            return ENOMEM;

        pub->pub_meta = (ps_meta_t)arg.a_meta;
        pub->pub_mlen = arg.a_mlen;
        pub->pub_data = arg.a_data;
        pub->pub_dlen = arg.a_dlen;
        pub->pub_fd   = arg.a_retval;
        pub->pub_vidx = arg.a_vridx;
        pub->pub_sid  = *sid;

        if (sub0 && (flags & PS_FLAGS_LOCAL_FUTUREONLY)) {
            /*
             * In this case we only want future publications, not the
             * one that exists initially. (XXX: Timing. Resubscribe?)
             */
            retval = sleep_until_event(kq, NOTE_PUBLISH|NOTE_UNMAP, pub, 
                                       timeout ? &end : NULL);
            if (retval != 0) {
                free(pub);
                return retval;
            }
        }

        *pubp = pub;
        return 0;
    }
    sub0 = 0;

    if (retval != ENOENT && retval != ESRCH)
        return retval;

    if (retval == ESRCH)
        goto sub_scope0;

    /* retval == ENOENT */

    /* Rid not found in the scope *OR* scope not found.
     * How to fallback:
     * 1. Subscribe to the scope, and wait for publication to appear
     * 2a. If #1 fails, subscribe to scope0, and wait for scope to appear
     * 2b. Once our scope appears goto #1
     */
    
    /* step 1 */
    /* The only way out from this loop is either not finding the scope OR
     * finding the publication in the scope.
     */
sub_scope:
    retval = subscribe_scope(kq, sid, rid, timeout ? &end : NULL, flags);
    if (retval == 0) 
        goto sub_pub;
    /* XXX: Eternal subscription loop risk if something goes wrong. */

    if (retval != ENOENT) 
        return retval;

    /* retval == ENOENT (i.e. step 2a) */
sub_scope0:
    retval = subscribe_scope(kq, &scope0, sid, timeout ? &end : NULL, flags);
    if (retval == 0)
        /* step 2b */
        goto sub_scope;

    /* error */
    return retval;
}


int
psirp_subscribe_scope(psirp_id_t *sid, psirp_pub_t *pubp)
{
    psirp_id_t null_id = {{0}};

    return psirp_subscribe(&null_id, sid, pubp);
}


int 
psirp_free(psirp_pub_t pub) {
    if (pub) {
        /*
         * XXX:
         * This should fix the problem of having too many open files.
         * It should also remove any kevent/kqueue registrations.
         */
        close(PSFS_PUB_FD(pub));

        if (pub->pub_meta)
            munmap(pub->pub_meta, pub->pub_mlen);
        if (pub->pub_data)
            munmap(pub->pub_data, pub->pub_dlen);
        free(pub);
    }
    return 0;
}

/* 
 * Accessor functions
 */
caddr_t psirp_pub_data(psirp_pub_t pub) {
    if (pub)
        return (PSFS_PUB_DATA(pub));
    else
        return NULL;
}

u_int64_t psirp_pub_data_len(psirp_pub_t pub) {
    if (pub)
        return (PSFS_PUB_DATA_LEN(pub));
    else
        return -1; /* or 0? */
}

psirp_id_t *psirp_pub_current_version(psirp_pub_t pub) {
    if (pub && PSFS_PUB_META(pub) && pub->pub_vidx >= 0)
        return (psirp_id_t *)&PSFS_PUB_META(pub)->pm_sub_object[pub->pub_vidx];
    else
        return NULL;
}

/* XXX: Should this be revealed or not? */
int psirp_pub_current_version_index(psirp_pub_t pub) {
    if (NULL != pub
        && NULL != PSFS_PUB_META(pub)
        && PS_PUB_TYPE(PSFS_PUB_META(pub)) != PS_PUB_VERSION)
        return pub->pub_vidx;
    else
        return -1;
}

/* XXX: Should this be revealed or not? */
int psirp_pub_version_count(psirp_pub_t pub) {
    if (NULL != pub
        && NULL != PSFS_PUB_META(pub)
        && PS_PUB_TYPE(PSFS_PUB_META(pub)) != PS_PUB_VERSION)
        return PSFS_PUB_META(pub)->pm_vers_count;
    else
        return 0;
}

psirp_id_t *psirp_pub_rid(psirp_pub_t pub) {
    if (pub && PSFS_PUB_META(pub))
	return (psirp_id_t *)&PSFS_PUB_META(pub)->pm_id;
    else
	return NULL;
}

psirp_id_t *psirp_pub_sid(psirp_pub_t pub) {
    if (pub)
        return &pub->pub_sid;
    else
        return NULL;
}

int psirp_pub_fd(psirp_pub_t pub) {
    if (pub)
	return PSFS_PUB_FD(pub);
    else
	return -1;
}

void psirp_pub_set_data(psirp_pub_t pub, caddr_t dptr) {
    if (pub)
	PSFS_PUB_DATA(pub) = dptr;
}

psirp_pub_type_t
psirp_pub_type(psirp_pub_t pub) 
{
    ps_meta_t meta;

    if (pub && (meta = PSFS_PUB_META(pub)))
        return (psirp_pub_type_t)meta->pm_type;

    return PSIRP_PUB_UNINITIALIZED;
}


int psirp_scope_rid_count(psirp_pub_t scope) {
    psirp_pub_t pub = scope;
    struct ps_scope_dat_page *sdp;

    if (NULL == pub
        || NULL == PSFS_PUB_META(pub)
        || NULL == PSFS_PUB_DATA(pub)) {
        return -1;
    }
    
    if (PS_PUB_TYPE(PSFS_PUB_META(pub)) != PS_PUB_SCOPE) {
        return -1;
    }
    
    sdp = (struct ps_scope_dat_page *)PSFS_PUB_DATA(pub);
    return sdp->sdp_id_count;
}

int psirp_scope_get_rids(psirp_pub_t scope,
                         psirp_id_t **rids, int *rid_count) {
    psirp_pub_t pub = scope;
    struct ps_scope_dat_page *sdp;

    if (NULL == pub
        || NULL == PSFS_PUB_META(pub)
        || NULL == PSFS_PUB_DATA(pub)
        || NULL == rids
        || NULL == rid_count) {
        return -1;
    }
    
    if (PS_PUB_TYPE(PSFS_PUB_META(pub)) != PS_PUB_SCOPE) {
        return -1;
    }
    
    sdp = (struct ps_scope_dat_page *)PSFS_PUB_DATA(pub);
        
    *rid_count = sdp->sdp_id_count;
    *rids      = (psirp_id_t *)&sdp->sdp_entries;
        
    return 0;
}

int psirp_pub_get_vrids(psirp_pub_t pub,
                        psirp_id_t **rids, int *rid_count) {
    enum ps_pub_type type;
    
    if (NULL == pub
        || NULL == PSFS_PUB_META(pub)
        || NULL == rids
        || NULL == rid_count) {
        return -1;
    }
    
    type = PS_PUB_TYPE(PSFS_PUB_META(pub));
    if (type != PS_PUB_DATA && type != PS_PUB_SCOPE) {
        return -1;
    }
    
    *rid_count = PSFS_PUB_META(pub)->pm_vers_count;
    *rids      = (psirp_id_t *)&PSFS_PUB_META(pub)->pm_sub_object;
    
    return 0;
}

int psirp_version_get_prids(psirp_pub_t version,
                            psirp_id_t **rids, int *rid_count) {
    psirp_pub_t pub = version;
    
    if (NULL == pub
        || NULL == PSFS_PUB_META(pub)
        || NULL == rids
        || NULL == rid_count) {
        return -1;
    }
    
    if (PS_PUB_TYPE(PSFS_PUB_META(pub)) != PS_PUB_VERSION) {
        return -1;
    }
    
    *rid_count = PSFS_PUB_META(pub)->pm_page_count;
    *rids      = (psirp_id_t *)&PSFS_PUB_META(pub)->pm_sub_object;
    
    return 0;
}

int psirp_subscribe_versions(psirp_pub_t pub,
                             psirp_pub_t *versions,
                             int start_index,
                             int max_count) {
    psirp_id_t *ridp;
    psirp_id_t *vrids;
    int stop_index;
    int vrid_count;
    int i;
    
    ridp = psirp_pub_rid(pub);
    psirp_pub_get_vrids(pub, &vrids, &vrid_count);
    
    stop_index = start_index + max_count - 1;
    if (stop_index >= vrid_count) {
        stop_index = vrid_count - 1;
    }
    
    for (i = start_index; i <= stop_index; i++) {
        if (0 != psirp_subscribe(ridp, &vrids[i], &versions[i-start_index])) {
            stop_index = i - 1;
            break;
        }
    }
    
    /* Return how many versions were subscribed. */
    return stop_index - start_index + 1;
}

void psirp_free_pubs(psirp_pub_t *pubs, int pub_count) {
    int i;
    
    for (i = 0; i < pub_count; i++) {
        psirp_free(pubs[i]);
    }
}

int
psirp_status(char **output) {

    struct ps_syscall_sc_arg sa;
    struct ps_syscall_arg arg;
    char *buffer;

    arg.a_retbuf = NULL;
    if (output) {
        arg.a_retbuf = malloc(1<<16); //2^16 = 64k
        if (arg.a_retbuf)
            arg.a_retbuf_len = 1<<16;
        else
            arg.a_retbuf_len = 0;
    }
    *output = arg.a_retbuf;

    arg.a_op = PS_SYSCALL_STA;
    arg.a_meta = NULL;
    arg.a_mlen = PS_MD_SIZE;
    arg.a_data = NULL;
    arg.a_dlen = 0;

    sa.p = &arg;

    if (!psirp_syscall_prepare()) {
	errno = ENOTSUP;
        return;
    }
    
    return syscall(syscall_num, sa);
}

static int
psirp_syscall_prepare() {
    int modid;

    modid = modfind(PS_SYSCALL_MODULE_NAME);
    if (modid == -1) {
        fprintf(stderr, "modfind(): Errno %d\n", errno);
        return 0;
    }

    mstat.version = sizeof(mstat);
    if (modstat(modid, &mstat) == -1) {
        fprintf(stderr, "modstat(): Errno %d\n", errno);
        return 0;
    }

    syscall_num = mstat.data.intval;

    return 1;
}


static void
asc2bin(uint8_t *target, const char *source, int len)
{
    char x[3];
    int i;

    x[2] = 0;

    for (i = 0; i < len; i++) {
        x[0] = source[2*i];
        x[1] = source[2*i+1];
        target[i] = (uint8_t)(strtol(x, (char **)NULL, 16));
    }
}

/* Copied from psfs: */
const static char psfs_conv_tbl[256][2] = {
    "00", "01", "02", "03", "04", "05", "06", "07",
    "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27",
    "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37",
    "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57",
    "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67",
    "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77",
    "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87",
    "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97",
    "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
    "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
    "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
};
const static u_int16_t *psfs_conv = (u_int16_t *)psfs_conv_tbl;

static inline void
do_ascii(char *target, uint8_t *source, int len)
{
    int i;
    u_int16_t *s = (u_int16_t *)target;
    
    for(i=0;i<len;i++) {
        s[i] = psfs_conv[source[i]];
    }
}

int
psirp_atoid(psirp_id_t *id, const char *str)
{
    if (id == NULL)
        return -1;

    return psirp_atoids(id, NULL, str);
}

static int
expand_colons(uint8_t *target, const char *src)
{
    char *colon;
    int full;
    int rest;
    int len;

    full = strlen(src);

    if (full > PSIRP_ID_LEN * 2)
        return -1;

    colon = strstr(src, "::");
    if (!colon) {
        if (strlen(src) != PSIRP_ID_LEN * 2) // consistency check
            return -2; 
        asc2bin(target, src, PSIRP_ID_LEN);
        return 0;
    }

    len = (colon - src);
    if (len % 2) // 8-bit boundary check
        return -3;

    if (len >= full) // this case should have happened above!
        return -4;

    /* how many bytes after double colon? */

    rest = full - (len + 2);

    if (rest % 2) //8-bit boundary check again
        return -5;

    asc2bin(target, src, len/2);
    memset(target+(len/2), 0, PSIRP_ID_LEN - (len/2 + rest/2));
    asc2bin(target+(PSIRP_ID_LEN - rest/2), colon+2, rest/2);
    return 0;
}

/* Following strings are accepted:
 *
 * ::/::
 * 1234::232/3434::234
 * 23::/::54
 * ::34/45::
 * :: 
 *
 * Following are *NOT* accepted:
 *
 * 123::/::54   <--- :: needs to be on 8-bit boundary. Single character
 *                   represents only 4 bits.
 * (However, 0123::/::54 is, of course, OK.)
 *
 * if str is a NULL pointer, the input is interpreted as "::/::"
 */
int 
psirp_atoids(psirp_id_t *sid, psirp_id_t *rid, const char *str)
{
    char null_ids[] = "::/::";
    char *sep;
    int slen;
    int err;

    if (!str)
        str = null_ids;

    /* at least sid must be provided */
    if (sid == NULL)
	return -1;

    slen = strlen(str);
    if (slen < 2) //        :: = 2 characters
        return -2;

    sep = strchr(str,'/');
    if (sep)
	*sep = 0;

	
    if ((err = expand_colons(sid->id, str))) {
        return -10 + err;
    }

    /* if no separator found, return only sid (or whatever that id is)*/
    if (!sep)
	return 0;

    /* if rid is null, but the separator was found in the ascii string,
     * we just ignore the rid part. */
    if (rid == NULL)
	return 0;

    if ((err = expand_colons(rid->id, sep+1))) {
        return -20 + err;
    }

    *sep = '/';

    return 0;
}

static int
do_string(char *target, uint8_t *source, int len)
{
#define STRING_ASSERT(x) do {    \
    if (!(x)) {                  \
        strcpy(source, "Error"); \
        return -1;               \
    }                            \
} while(0)

    int longest = -1;
    int lstart = -1;
    int start = -1;
    int i;
    enum { STR_NOZERO, STR_ZERO, STR_ZEROCONT } state = STR_NOZERO;

    for(i=0;i<len;i++) {
        switch(state) {
        case STR_NOZERO:
            if (source[i] == 0)
                state = STR_ZERO;
            break;
        case STR_ZERO:
            if (source[i] != 0)
                state = STR_NOZERO;
            else {
                start = i-1;
                state = STR_ZEROCONT;
            }
            break;
        case STR_ZEROCONT:
            if (source[i] != 0) {
                state = STR_NOZERO;
                if (i - start > longest) {
                    longest = i - start;
                    lstart = start;
                }
            }
            break;
        }
    }
    /* Next action depends on in what state is the machine:
     *
     * STR_NOZERO: Last character was not a zero. Do nothing
     *
     * STR_ZERO: Last character was first zero in a sequence. Do nothing.
     *
     * STR_ZEROCONT: Last sequence of zeros might be longer than any before.
     *               Do magic.
     */

    if (state == STR_ZEROCONT) {
        if (len - start > longest) {
            longest = len - start;
            lstart = start;
        }
    }


#if DEBUG
    /* If we have a longest zero count, then the start offset must be defined.
     * Else, the start offset must be undefined (i.e. -1).
     * And vice versa for longest count.
     */
    STRING_ASSERT((longest >  -1 && lstart != -1) ||
		  (longest == -1 && lstart == -1));


    /* The longest consequtive zero count must be in range: 
     * [-1, len]. Actually 0 and 1 are invalid, but we'll let 
     * them slip this time.
     */
    STRING_ASSERT(longest <= len && longest >= -1);

    /* The same restrictions apply to start offset. */
    STRING_ASSERT(lstart < len && lstart >= -1);
#endif
    memset(target, 0, len*2);
    if (longest > 2) {
        uint8_t *tmp;
        /* Transform characters up to lstart offset */
	do_ascii(target, source, lstart);

        /* add separator */
        tmp = target + lstart*2; 
	sprintf(tmp, "::");
        tmp += 2;

        /* Transform the rest */
	do_ascii(tmp, source+(lstart+longest), len-(lstart+longest));

    } else {
	do_ascii(target, source, len);
    }

    /* Return length of the string */
    return strlen(target);

#undef STRING_ASSERT
}

char *psirp_idstoa(psirp_id_t *sid, psirp_id_t *rid)
{
    static char idstr[(2 * PSIRP_ID_LEN * 2) + 2];
    int idx = 0;

    bzero(idstr, sizeof(idstr));

    if (sid) {
        idx = do_string(idstr, sid->id, PSIRP_ID_LEN);
    }

    if (rid && idx) {
        if (idx % 2)
            idx++; /* XXX */
        idstr[idx++] = '/';
    }

    if (rid) {
        (void) do_string(idstr+idx, rid->id, PSIRP_ID_LEN);
    }

    return idstr;
}

char *psirp_idtoa(psirp_id_t *rid)
{
    return psirp_idstoa(rid, NULL);
}

int psirp_idcmp(psirp_id_t *id1, psirp_id_t *id2) {
#if 1
    int i;

    for (i = 0; i < PSIRP_ID_LEN; i++) {
        if (id1->id[i] != id2->id[i]) {
            return 1;
        }
    }
    return 0;
#elif 0
    u_int64_t *p1, *p2;
    int n;
    
    p1 = (u_int64_t *)id1->id;
    p2 = (u_int64_t *)id2->id;
    n = PSIRP_ID_LEN/8;
    
    do
        if (*p1++ != *p2++)
            break;
    while (--n != 0);
    
    return n;
#else
    return memcmp(id1, id2, sizeof(psirp_id_t));
#endif
}

void psirp_idzero(psirp_id_t *id) {        
    bzero(id, sizeof(psirp_id_t));
}

void psirp_idinc(psirp_id_t *idp) {
    int i;
    
    for (i = PSIRP_ID_LEN-1; i >= 0; i--) {
        if (idp->id[i] < 0xff) {
            idp->id[i] += 1;
            break;
        }
        idp->id[i] = 0x00;
    }
}
