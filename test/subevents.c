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
#include <sys/param.h>
#include <sys/event.h>
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sysexits.h>
#include <signal.h>
#include <errno.h>

//#include "../module/psfs.h"
#include <libpsirp.h>


#define PRINTF(format, ...)	   \
    do {                                   \
        if (verbose) {                     \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)

#define NEVENTS 8


int work_done = 0;

int verbose = 0;


void mysighandler(int sig)
{
    work_done = 1;
}

void
usage(char *pathname)
{
    fprintf(stderr,
	    "\nUsage:\n"
	    "%s [-s sid] -r rid "
            "[-n count [-p] [-z] [-f flags] [-t timeout] [-x] [-v]\n\n",
	    pathname);

    exit(EX_USAGE);
}

static int 
subevents(psirp_id_t *sid_p, psirp_id_t *rid_p,
          int count, int flags, int timeout,
          int stop_on_err)
{
    psirp_pub_t pub = NULL;
    int call_ok = 0, rid_ok = 0;

    int kq, fd, m, n;
    struct kevent cl[1];
    struct kevent el[NEVENTS];
    int max_nevents = sizeof(el)/sizeof(el[0]);
    struct timespec ts;
    int i = 0, j = 0;
    void *data = NULL, *udata = NULL;
    
    PRINTF("Info: Subscribing to %s\n", psirp_idstoa(sid_p, rid_p));
    
    if (!psirp_subscribe(sid_p, rid_p, &pub)) {
        psirp_id_t *sub_rid = NULL;
        
        
        PRINTF("Info: Subscribe   OK\n");
        
        call_ok = 1;
        
        sub_rid = psirp_pub_rid(pub);
        if (NULL == sub_rid) {
            PRINTF("Debug:    RId     NULL\n");
            rid_ok = 1;
        }
        else if (!memcmp(psirp_pub_rid(pub), rid_p, sizeof(*rid_p))) {
            PRINTF("Debug:    RId     OK\n");
            rid_ok = 1;
        }
        else {
            PRINTF("Debug:    RId     NOT OK -- %s\n",
                        psirp_idtoa(psirp_pub_rid(pub)));
        }
    }
    
    if (!call_ok || !rid_ok) {
        printf("Error: Subscribe   NOT OK -- Sub OK: %d, RId OK: %d\n",
               call_ok, rid_ok);
        return -2;
    }
    
    fd = psirp_pub_fd(pub);

    PRINTF("Info: Starting to listen for %d kevents -- FD=%d, pub=%p\n",
           count, fd, pub);

    kq = kqueue();
    if (kq < 0) {
	perror("Error: kqueue");
        return -3;
    }
    
    memset(cl, 0, sizeof(cl));
    memset(el, 0, sizeof(el));
    memset(&ts, 0, sizeof(ts));
    if (timeout > 0) {
        ts.tv_sec = timeout;
    }
    
    flags |= NOTE_UNMAP; /* ? */
    EV_SET(&cl[0], fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
           flags, 0, (void *)pub);

    if (kevent(kq, cl, 1, NULL, 0, NULL) < 0) {
        perror("Error: kevent/change");
        return -3;
    }
    
    while (!work_done) {
        m = (count < 0 || count > max_nevents) ? max_nevents : count;
        n = kevent(kq,
                   NULL, 0,
                   el, m,
                   (timeout > 0) ? &ts : NULL);
        if (n < 0) {
            perror("Error: kevent/event");
            if (stop_on_err) {
                return -4;
            }
        }
        else if (m > 0 && n == 0) {
            PRINTF("Info: kevent:     timeout\n");
        }
        else {
            for (i = 0; i < n; i++) {
                PRINTF("Info: %d/%d: "
                       "id=%d, ft=%d, fl=%x, "
                       "ffl=%x, data=%p, udata=%p; ",
                       j++, i,
                       (int)el[i].ident, el[i].filter, el[i].flags, 
                       el[i].fflags, (void *)el[i].data, el[i].udata);
                data = (void *)el[i].data;
                udata = el[i].udata;
                if (udata == pub) {
                    PRINTF("Info: RID: %s\n",
                           psirp_idtoa(psirp_pub_rid(udata)));
                    /* Also check that the SID/RID are what we sub'd? */
                }
                else {
                    PRINTF("Info: udata != pub\n");
                    if (stop_on_err) {
                        return -5;
                    }
                }
                if (flags & EV_ERROR) {
                    perror("Error: kevent/event");
                    if (stop_on_err) {
                        return -4;
                    }
                }
            }
            
            if (count > 0) {
                count -= (n <= count) ? n : count;
            }
            if (count == 0) {
                break;
            }
        }
    }
    
    PRINTF("Info: Stopping after %d events\n", j);

    PRINTF("Debug: Freeing pub\n");
    psirp_free(pub);

    return 0;
}

int 
main(int argc, char **argv) {
    int c;
    char *sid_str     = NULL,
	 *rid_str     = NULL,
	 *count_str   = NULL,
         *flags_str   = NULL,
	 *timeout_str = NULL;
    int publish   = 0,
        subscribe = 0;
    char *pathname = argv[0];

    psirp_id_t sid;
    psirp_id_t rid;
    psirp_id_t *sid_p = &sid;
    psirp_id_t *rid_p = &rid;
    int count, flags, timeout;
    int stop_on_err = 0;

    while ((c = getopt(argc, argv, "s:r:n:t:pzf:xvh")) != EOF) {
        switch (c) {
            case 's': sid_str       = optarg; break;
            case 'r': rid_str       = optarg; break;
            case 'n': count_str     = optarg; break;
            case 't': timeout_str   = optarg; break;
            case 'p': publish       = 1;      break;
            case 'z': subscribe     = 1;      break;
            case 'f': flags_str     = optarg; break;
            case 'x': stop_on_err   = 1;      break;
            case 'v': verbose++;              break;
            case 'h':
            default:
                usage(pathname);
        }
    }

    if (sid_str) {
#if 0
        if (strlen(sid_str) != PSIRP_ID_LEN*2) {
            PRINTF("Error: SId length mismatch (%d, should be %d)\n",
                   (int)strlen(sid_str), PSIRP_ID_LEN*2);
            return 0;
        }
#endif
	if (psirp_atoid(sid_p, sid_str)) {
	    PRINTF("Error: SId parsing error\n");
	    return 0;
	}
    }
    else {
	memset(sid_p, 0, sizeof(psirp_id_t));
    }
    PRINTF("Info: SId:   %s\n", psirp_idtoa(sid_p));
    
    if (rid_str) {
#if 0
	if (strlen(rid_str) != PSIRP_ID_LEN*2) {
            PRINTF("Debug: RId length mismatch (%d, should be %d)\n",
                   (int)strlen(rid_str), PSIRP_ID_LEN*2);
            return 0;
        }
#endif
	if (psirp_atoid(rid_p, rid_str)) {
	    PRINTF("Error: RId parsing error\n");
	    return 0;
	}
    }
    else {
	PRINTF("Error: RId must be specified (-r)\n");
	return 0;
    }
    PRINTF("Info: RId:   %s\n", psirp_idtoa(rid_p));
    
    if (count_str) {
	count = (int)strtol(count_str, NULL, 10);
	if (errno == EINVAL || errno == ERANGE) {
	    PRINTF("Error: Count parsing error\n");
	    return -1;
	}
    }
    else {
	count = -1;
    }
    PRINTF("Info: Count: %d\n", count);

    if (timeout_str) {
        timeout = (int)strtol(timeout_str, NULL, 10);
	if (errno == EINVAL || errno == ERANGE) {
	    PRINTF("Error: Timeout parsing error\n");
	    return -1;
	}
    }
    else {
	timeout = -1;
    }
    
    flags = 0;
    if (publish) {
        flags |= NOTE_PUBLISH;
    }
    if (subscribe) {
        flags |= NOTE_SUBSCRIBE;
    }
    if (flags_str) {
	flags |= (int)strtol(flags_str, NULL, 16);
	if (errno == EINVAL || errno == ERANGE) {
	    PRINTF("Error: Flags parsing error\n");
	    return -1;
	}
    }
    PRINTF("Info: Flags: 0x%x\n", flags);
    PRINTF("Info: ------\n");

    signal(SIGINT, mysighandler);

    return subevents(sid_p, rid_p, count, flags, timeout, stop_on_err);
}
