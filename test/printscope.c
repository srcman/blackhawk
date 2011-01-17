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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/proc.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sysexits.h>
#include <signal.h>
#include <errno.h>
#include <vm/vm.h>

/* this is required due to scope definitions */
#define _LIBPSIRP 

/* hack for ps_scope.h :( [boolean is defined only in kernel] */
typedef int boolean_t;

#include <libpsirp.h>
#include "../psfs/module/ps_scope.h"


#define PRINTF_IF_V(format, ...)	   \
    do {                                   \
        if (verbose) {                     \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)


int verbose = 0;
int monitor = 0;
int oneshot = 0;


void
usage(char *pathname)
{
    fprintf(stderr,
	    "\nUsage:\n"
	    "%s -s sid [-v] [-m] [-o]\n",
	    pathname);
    fprintf(stderr,"-v = verbose\n");
    fprintf(stderr,"-o = test EV_ONESHOT flag\n");
    fprintf(stderr,"-m = monitor scope\n\n");

    exit(EX_USAGE);
}

static int 
printscope(psirp_id_t *rid_p)
{
    psirp_id_t sid, *sid_p = NULL;
    psirp_pub_t pub = NULL;
    int call_ok = 0, rid_ok = 0;
    struct ps_scope_dat_page *sdp;
    u_int8_t n, i;
    char sub_str[] = " (sub)", pub_str[] = "";
    int kq;
    struct kevent kev;

    memset(sid.id, 0, sizeof(sid.id));
    sid_p = &sid;

    kq = kqueue();
    if (kq < 0) {
        fprintf(stderr, "Could not create kqueue\n");
        return -1;
    }
    
    PRINTF_IF_V("Subscribing to scope %s\n", psirp_idtoa(rid_p));
    
    if (!psirp_subscribe(sid_p, rid_p, &pub)) {
        psirp_id_t *sub_rid = NULL;
        
        PRINTF_IF_V("Subscribe   OK\n");
        
        call_ok = 1;
        
        sub_rid = psirp_pub_rid(pub);
        if (NULL == sub_rid) {
            PRINTF_IF_V("    RId     NULL\n");
            rid_ok = 1;
        }
        else if (!memcmp(psirp_pub_rid(pub), rid_p, sizeof(*rid_p))) {
            PRINTF_IF_V("    RId     OK\n");
            rid_ok = 1;
        }
        else {
            PRINTF_IF_V("    RId     NOT OK -- %s\n",
                        psirp_idtoa(psirp_pub_rid(pub)));
        }
    }
        
    if (!call_ok || !rid_ok) {
        printf("Subscribe   NOT OK (Sub: %d, RId: %d)\n", call_ok, rid_ok);
        return -1;
    }

redo:    
    {
        char *stime;
        time_t now;

        time(&now);
        stime = ctime(&now);
        stime[strlen(stime)-1] = 0;

        printf("---------------------------------------[%s]---\n", stime);
    }

    if (PS_PUB_SCOPE != psirp_pub_type(pub)) {
        printf("%s is not a scope\n", psirp_idtoa(psirp_pub_rid(pub)));
        psirp_free(pub);
        return -3;
    }

    sdp = (struct ps_scope_dat_page *)psirp_pub_data(pub);
    n = sdp->sdp_id_count;
    printf("Scope %s has %d items:\n", psirp_idtoa(psirp_pub_rid(pub)), n);
    for (i = 0; i < n; i++) {
        psirp_id_t rid;
        memset(&rid, 0, sizeof(rid));
        memcpy(rid.id, sdp->sdp_entries[i].id,
               sizeof(sdp->sdp_entries[0].id));
        printf("%s%s\n",
               psirp_idtoa(&rid),
#if 0
               (sdp->sdp_id_bm[i / SCOPE_BM_BITSPERWORD] \
                & (1 << i % SCOPE_BM_BITSPERWORD))
#else
	       1
#endif
               ? pub_str : sub_str);
    }

    printf("Bloom filter:\n");
    for (i = 0; i < sizeof(ps_scope_bf_t); i++) {
        u_int8_t byte = sdp->sdp_bf.bf[i];
        int j;
        for (j = 0; j < 8; j++) {
            printf("%d", (byte >> j) & 0x01);
        }
    }
    printf("\n");

    fflush(stdout);

    if (monitor) {
        unsigned int fflags = EV_ADD;

        fflags |= (oneshot ? EV_ONESHOT : EV_CLEAR);

        EV_SET(&kev, pub->pub_fd, EVFILT_VNODE, fflags,
               NOTE_PUBLISH, 0, pub);
        if (kevent(kq, &kev, 1, &kev, 1, NULL) <= 0) {
            fprintf(stderr, "Kevent error: %d\n", errno);
            return -2;
        }

        goto redo;
    }

    
    if (verbose) {
        printf("Freeing pub\n");
    }
    psirp_free(pub);

    return 0;
}

int 
main(int argc, char **argv) {
    int c;
    char *sid_str      = NULL;
    char *pathname = argv[0];

    psirp_id_t sid;
    psirp_id_t *sid_p = &sid;

    while ((c = getopt(argc, argv, "s:vmoh")) != EOF) {
        switch (c) {
            case 's': sid_str      = optarg; break;
            case 'v': verbose      = 1;      break;
            case 'm': monitor      = 1;      break;
            case 'o': oneshot      = 1;      break;
            case 'h':
            default:
                usage(pathname);
        }
    }

    if (sid_str) {
	if (psirp_atoid(sid_p, sid_str)) {
	    printf("SId parsing error\n");
	    return -1;
	}
    }
    else {
	memset(sid_p, 0, sizeof(psirp_id_t));
    }
    
    return printscope(sid_p);
}
