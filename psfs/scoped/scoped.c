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
#include <sys/uio.h>
#include <sys/event.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <syslog.h>
#include <stdarg.h>

#include <fcntl.h>
#include <sysexits.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>

#include <signal.h>

#include <zlib.h>

#define _LIBPSIRP
#include "libpsirp.h"
#include "ps_scope.h"
#include "ps_event.h"
#include "ps_magic.h"

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

static char *prog_name = "scoped";

psirp_id_t ps_sdp_magic = { PS_SDP_MAGIC_INIT };

psirp_id_t _root_sid = { { 0 } }, *root_sid = &_root_sid; /* XXX */

int scoped_interrupted = 0;
void scoped_sighandler(int sig)
{
    scoped_interrupted = 1;
}

static inline int 
rid_in_bf(psirp_id_t *ridp, ps_scope_bf_t *bfp) {
    u_int32_t crc;
    u_int8_t  bi; /* bit index */
    int i;

    crc = crc32(0L, (const unsigned char *)ridp, sizeof(psirp_id_t));
    for (i = 0; i < PS_SCOPE_BF_K; i++) {
        bi = (crc >> (i << 3)) & 0xff; /* XXX: bf must be at least 256 bits */
        if (!(bfp->bf[(bi >> 3)] & (1 << (bi % 8)))) {
            return 0;
        }
    }
    return 1;
}

static inline int 
rid_into_bf(psirp_id_t *ridp, ps_scope_bf_t *bfp) {
    u_int32_t crc;
    u_int8_t  bi; /* bit index */
    int i;
    int bitcount = 0;

    crc = crc32(0L, (const unsigned char *)ridp, sizeof(psirp_id_t));
    for (i = 0; i < PS_SCOPE_BF_K; i++) {
        bi = (crc >> (i << 3)) & 0xff; /* XXX: bf must be at least 256 bits */
        bfp->bf[(bi >> 3)] |= 1 << (bi % 8);
        bitcount += __builtin_popcount(bfp->bf[(bi >> 3)]);
    }

    return (bitcount > (sizeof(ps_scope_bf_t) << 2));
}

static int
scope_create(psirp_id_t *scope_sid, psirp_id_t *scope_rid, 
	     psirp_id_t *initial_rid, psirp_pub_t pub) 
{
    int error = 0;
    struct ps_scope_dat_page *sdp;
    struct ps_meta *meta;

    PRINTF("Info: %s: Creating scope: %s\n", prog_name, psirp_idstoa(scope_sid, scope_rid));
    PRINTF("Info: %s: Initial RID:    %s\n", prog_name, psirp_idstoa(NULL, initial_rid));

    error = psirp_create(PAGE_SIZE, &pub);
    if (error) {
	perror("scoped: create");
	exit(EX_OSERR);
    }

    sdp = (struct ps_scope_dat_page *)psirp_pub_data(pub);
    if (NULL == sdp) {
	perror("scoped: null sdp");
	exit(EX_OSERR);
    }

    sdp->sdp_magic = PS_SDP_MAGIC;
    sdp->sdp_entries[sdp->sdp_id_count++] = *scope_rid;
    rid_into_bf(scope_rid, &sdp->sdp_bf);
    if (psirp_idcmp(scope_rid, initial_rid)) {
	sdp->sdp_entries[sdp->sdp_id_count++] = *initial_rid;
        rid_into_bf(initial_rid, &sdp->sdp_bf);
    }

    meta = PSFS_PUB_META(pub);
    PRINTF_VV(2, "Debug: %s: META magic: %s\n",  prog_name, (char *)meta->pm_magic.id);
    PRINTF_VV(2, "Debug: %s: META type:  %d\n",  prog_name, meta->pm_type);
    PRINTF_VV(2, "Debug: %s: META size:  %ld\n", prog_name, meta->pm_size);
    PRINTF_VV(2, "Debug: %s: META vers:  %d\n",  prog_name, meta->pm_vers_count);

    meta->pm_type = PS_PUB_SCOPE;

    error = psirp_publish(scope_sid, scope_rid, pub);
    if (error) {
	perror("scoped: publish");
	exit(EX_OSERR);
    }
    return 0;
}

static int
scope_add_rid(psirp_id_t *scope_sid, psirp_id_t *scope_rid, 
	      psirp_id_t *added_rid, psirp_pub_t pub) 
{
    struct ps_scope_dat_page *sdp;
    //u_int64_t sdp_len;
    int i;
    int error = 0;

    PRINTF("Info: %s: Adding to scope: %s\n", prog_name, psirp_idstoa(scope_rid, added_rid));

    sdp = (struct ps_scope_dat_page *)psirp_pub_data(pub);
    if (NULL == sdp) {
	perror("scoped: null sdp");
	exit(EX_OSERR);
    }

    if (rid_in_bf(added_rid, &sdp->sdp_bf)) {
        for (i = 0; i < sdp->sdp_id_count /*&& i < PS_SCOPE_DAT_NELEM*/; i++) { 
            if (!psirp_idcmp(&sdp->sdp_entries[i], added_rid))
                return EALREADY;
        }
    }

    //sdp_len = psirp_pub_data_len(pub);
    if (sdp->sdp_id_count == PS_SCOPE_DAT_NELEM) {
        PRINTF("Info: %s: sdp full (%d)\n", prog_name, sdp->sdp_id_count);
        return (errno = ENOSPC);
    }

    sdp->sdp_entries[sdp->sdp_id_count++] = *added_rid;
    rid_into_bf(added_rid, &sdp->sdp_bf);

    error = psirp_publish(scope_sid, scope_rid, pub);
    if (error) {
	perror("scoped: publish");
	exit(EX_OSERR);
    }
    return 0;
}

static int
scope_add(psirp_id_t *scope_sid, psirp_id_t *scope_rid, psirp_id_t *rid)
{
    psirp_pub_t pub = NULL;
    int error = 0;

    error = psirp_subscribe_with_flags(scope_rid, scope_rid, &pub,
                                       PS_FLAGS_LOCAL_LOCALSUB);
    PRINTF_VV(2, "Debug %s: subscribe(%s): %d\n",
              prog_name, psirp_idstoa(scope_rid, scope_rid), error);
    switch (error) {
    case 0:
	error = scope_add_rid(scope_sid, scope_rid, rid, pub);
        break;
    case ENOENT:
    case ESRCH:
    case ENOTDIR: /* XXX */
	error = scope_create(scope_sid, scope_rid, rid, pub);
        break;
    default:
        errc(EX_OSERR, error, "subscribe %d", error);
    }

    if (pub)
        psirp_free(pub);

    return error;
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
    int error = 0;

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

    signal(SIGINT, scoped_sighandler);

    openlog(av[0], LOG_PERROR, LOG_DAEMON);
#if 0
    if (daemon(1, 1)) {
	perror("scoped: daemon");
	return EX_OSERR;
    }
#endif
    syslog(LOG_DEBUG, "started.");
    kq = kqueue();
    if (kq < 0) {
	perror("scoped: kqueue");
	return EX_OSERR;
    }

    error = scope_add(root_sid, root_sid, root_sid);
    if (error) {
        EPRINTF(error, "scoped: add");
        return EX_UNAVAILABLE;
    }

    fd = open("/pubsub/pubs", O_RDONLY);
    if (fd < 0) {
	perror("scoped: /pubsub/pubs");
	return EX_NOINPUT;
    }

    EV_SET(&ke, fd, EVFILT_VNODE, EV_ADD,
	   NOTE_PUBLISH, 0, NULL);
    if (kevent(kq, &ke, 1, NULL, 0, NULL) < 0) {
	perror("scoped: kevent");
	return EX_OSERR;
    }
    for (;;) {
	int kn, n, i;

#define COUNT(n) (((n) - PS_EVENT_ALIGNMENT)/sizeof(struct ps_event))

        kn = kevent(kq, NULL, 0, &ke, 1, NULL);
	if (kn < 0) {
            if (scoped_interrupted) {
                PRINTF("Info: %s: Interrupted\n", prog_name);
                break; /* for (;;) */
            }
	    perror("scoped: kevent");
	    return EX_OSERR;
	}
        else if (kn == 0) {
            /* timeout */
            continue; /* for (;;) */
        }
        
	lseek(fd, 0, SEEK_SET);
	n = read(fd, pep, sizeof(struct ps_event_page));
	PRINTF("Info: %s: bytes = %d, count = %ld\n", prog_name, n, COUNT(n));
	if (n > 0) {
	    for (i = 0; i < pep->pep_count; i++) {
		sid = &pep->pep_events[i].pe_sid;
		rid = &pep->pep_events[i].pe_rid;
		PRINTF("Info: %s: Event %d: %s\n",
                       av[0], i, psirp_idstoa(sid, rid));
		error = scope_add(root_sid, sid, rid);
                if (error == EALREADY) {
                    PRINTF_VV(2, "Debug: %s: already added\n", prog_name);
                }
                else if (error) {
                    EPRINTF(error, "scoped: add");
                }
	    }
	}
    }

    return 0;
}
