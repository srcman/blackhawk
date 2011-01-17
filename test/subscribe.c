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

#define _LIBPSIRP
#include <libpsirp.h>


#define PRINTF_IF_V(format, ...)	   \
    do {                                   \
        if (verbose) {                     \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)


int work_done = 0;
int verbose = 0;
int synchronize = 0;
int timeout = 0;
FILE *f;  // output file

void mysighandler(int sig)
{
    work_done = 1;
}

void
usage(char *pathname)
{
    fprintf(stderr,
	    "\nUsage:\n"
	    "%s [-s sid] -r rid [-n count] [-t interval] [-T timeout] [-x] [-v] [-z] [-e code] [-f file]\n\n",
	    pathname);
    fprintf(stderr, 
            "-s <sid>    = Scope Identifier\n"
            "-r <rid>    = P:L Identifier\n"
            "-n <count>  = Resubscribe <count> times\n"
            "-t <i-val>  = Time between successive subscribe operations\n"
            "-T <t-out>  = Timeout for blocking subscribe\n"
            "-x          = Stop on error\n"
            "-v          = Verbose\n"
            "-z          = Use synchronous subscribing\n"
            "-e <code>   = Expected error code [TESTING]\n"
            "-f <file>   = Output file. Use '-' for stdout\n");

    exit(EX_USAGE);
}

static int 
subscribe(psirp_id_t *sid_p, psirp_id_t *rid_p,
          int count, int interval,
          int stop_on_err)
{
    int i;
    int ok_count = 0;
    int err = 0;
    struct timeval tv;

    
    if (verbose)
        printf("Info: Subscribing to %s\n", psirp_idstoa(sid_p, rid_p));

    if (timeout) {
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
    }

    for (i = 0; i < count; i++) {
	psirp_pub_t pub = NULL;
	int call_ok = 0;
		
	sleep(interval);
	
        if (synchronize)
            err = psirp_subscribe_sync(sid_p, rid_p, &pub, 
                                       timeout ? &tv : NULL);
        else {
            if (psirp_subscribe(sid_p, rid_p, &pub))
                err = errno;
            else
                err = 0;
        }
        
        if (!err) {

            call_ok = 1;
            
            /* Should we also check that pub is OK...? */
	}
	
	if (call_ok) {
	    ok_count++;
	    if (verbose) 
                printf("Info: Subscribed: meta=%16p, mlen=%8ld, data=%16p, dlen=%8ld\n",
	               pub->pub_meta, pub->pub_mlen, pub->pub_data, pub->pub_dlen);
    
	    if (f) {
	        // no error checking
	        fwrite(psirp_pub_data(pub), 1, psirp_pub_data_len(pub), f);
            }
        }
	else {
#if 0
            PRINTF_IF_V("Subscribe   NOT OK -- #%d\n", err);
#endif            
            if (stop_on_err) {
                i++;
                break;
            }
	}
	psirp_free(pub); /* XXX: Called here even if pub is NULL */
    }

#if 1
    if (verbose)
        printf("Subscribed  %d times, %d OK\n", i, ok_count);
#endif

    return err;
}

int 
main(int argc, char **argv) {
    int c;
    char *sid_str      = NULL,
	 *rid_str      = NULL,
	 *count_str    = NULL,
	 *interval_str = NULL;
    char *pathname = argv[0];

    char *fname = NULL;
    psirp_id_t sid;
    psirp_id_t rid;
    psirp_id_t *sid_p = &sid;
    psirp_id_t *rid_p = &rid;
    int count, interval;
    int stop_on_err = 0;
    int code = -1;
    int err;
        
    while ((c = getopt(argc, argv, "e:s:f:r:n:t:T:xvhz")) != EOF) {
        switch (c) {
            case 'e': code         = atoi(optarg); break;
            case 's': sid_str      = optarg; break;
            case 'r': rid_str      = optarg; break;
            case 'n': count_str    = optarg; break;
            case 't': interval_str = optarg; break;
            case 'T': timeout = atoi(optarg); break;
            case 'x': stop_on_err  = 1;      break;
            case 'z': synchronize  = 1;      break;
            case 'v': verbose      = 1;      break;
            case 'f': fname        = optarg; break;
            case 'h':
            default:
                usage(pathname);
        }
    }

    if (fname) {
        if (!strcmp("-", fname)) {
            f = stdout;
        } else {
            f = fopen(fname, "w");
            if (!f) {
                printf("ERROR: Cannot open output file: %s\n", fname);
                return EX_SOFTWARE;
            }
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
    
    if (rid_str) {
	if (psirp_atoid(rid_p, rid_str)) {
	    printf("RId parsing error\n");
	    return -1;
	}
    }
    else {
	printf("RId must be specified (-r)\n");
	return -1;
    }
    
    if (count_str) {
	count = (int)strtol(count_str, NULL, 10);
	if (errno == EINVAL || errno == ERANGE) {
	    printf("Count parsing error\n");
	    return -1;
	}
    }
    else {
	count = 1;
    }
    
    if (interval_str) {
	interval = (int)strtol(interval_str, NULL, 10);
	if (errno == EINVAL || errno == ERANGE) {
	    printf("Interval parsing error\n");
	    return -1;
	}
    }
    else {
	interval = 1;
    }

    err = subscribe(sid_p, rid_p, count, interval, stop_on_err);
    if (code != -1) {
        if (err != code) {
            printf("ERROR: code=%d, retval=%d\n", code, err);
            return EX_SOFTWARE;
        } else if (verbose) {
            printf("OK: errno=%d\n", err);
        }
    }
    
    return EX_OK;
}
