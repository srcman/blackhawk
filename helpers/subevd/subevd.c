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
 * Dummy subscription event listener.
 *
 * Its main function is to prevent the event page from becoming too
 * full if laird is not running. Optionally it can print and log
 * subscriptions that occur in a node.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/event.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <syslog.h>
#include <stdarg.h>

#include <fcntl.h>
#include <sysexits.h>
#include <getopt.h>
#include <assert.h>

#include <signal.h>

//#define _LIBPSIRP
#include "libpsirp.h"
//#include "ps_scope.h"
#include "ps_event.h"
#include "ps_magic.h"

/* XXX: Are all of these includes really needed? */

#define PRINTF(format, ...) PRINTF_VV(1, (format), ##__VA_ARGS__)
#define PRINTF_VV(level, format, ...)	   \
    do {                                   \
        if (verbose > level) {		   \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)
#define EPRINTF(_errno, _format, ...) \
    fprintf(stderr, _format ": [Errno %d] %s\n", ##__VA_ARGS__, _errno, strerror(_errno));

int verbose = 0;

static char *prog_name = "subevd";
static char *event_file_name = "/pubsub/subs";

psirp_id_t ps_sdp_magic = { PS_SDP_MAGIC_INIT };

int subevd_interrupted = 0;
void subevd_sighandler(int sig)
{
    subevd_interrupted = 1;
}
 
struct ps_event_page _pep, *pep = &_pep;

void
usage()
{
    fprintf(stderr,
	    "Usage: %s [-v]\n", prog_name);
    exit(EX_USAGE);
}

int
main(int ac, char **av)
{
    int c;
    int kq, fd;
    struct kevent ke;
    psirp_id_t _sid, *sid = &_sid, _rid, *rid = &_rid;
    ps_flags_t flags;
    //int error = 0;

    if (strchr(av[0], '/')) {
	av[0] = strrchr(av[0], '/') + 1;
    }
    prog_name = av[0];

    while ((c = getopt(ac, av, "v")) != EOF) {
	switch (c) {
	case 'v': verbose++; break;
	default:
	    usage();
	}
    }

    signal(SIGINT, subevd_sighandler);

    openlog(av[0], LOG_PERROR, LOG_DAEMON);
#if 0
    if (daemon(1, 1)) {
	perror("subevd: daemon");
	return EX_OSERR;
    }
#endif
    syslog(LOG_DEBUG, "started.");
    kq = kqueue();
    if (kq < 0) {
	perror("subevd: kqueue");
	return EX_OSERR;
    }

    fd = open(event_file_name, O_RDONLY);
    if (fd < 0) {
	perror("subevd: open");
	return EX_NOINPUT;
    }

    EV_SET(&ke, fd, EVFILT_VNODE, EV_ADD,
	   NOTE_PUBLISH, 0, NULL);
    if (kevent(kq, &ke, 1, NULL, 0, NULL) < 0) {
	perror("subevd: kevent");
	return EX_OSERR;
    }
    for (;;) {
	int kn, n, i;

#define COUNT(n) (((n) - PS_EVENT_ALIGNMENT)/sizeof(struct ps_event))

        kn = kevent(kq, NULL, 0, &ke, 1, NULL);
	if (kn < 0) {
            if (subevd_interrupted) {
                PRINTF("Info: %s: Interrupted\n", prog_name);
                break; /* for (;;) */
            }
	    perror("subevd: kevent");
	    return EX_OSERR;
	}
        else if (kn == 0) {
            /* timeout */
            continue; /* for (;;) */
        }
        
	lseek(fd, 0, SEEK_SET);
	n = read(fd, pep, sizeof(struct ps_event_page));
	PRINTF("Info: %s: bytes = %d, count = %ld\n", prog_name, n, COUNT(n));
	if (n > 0 && verbose > 0) {
	    for (i = 0; i < pep->pep_count; i++) {
		sid   = &pep->pep_events[i].pe_sid;
		rid   = &pep->pep_events[i].pe_rid;
                flags = pep->pep_events[i].pe_flags;
		PRINTF("Info: %s: Subscription event %d: %s (0x%04x)\n",
                       av[0], i, psirp_idstoa(sid, rid), flags);
	    }
	}
    }

    return 0;
}
