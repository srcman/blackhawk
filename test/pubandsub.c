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

#include <libpsirp.h>


#define PRINTF_IF_V(format, ...)	   \
    do {                                   \
        if (verbose) {                     \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)

#define PUB_LEN 20000L


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
	    "%s [-s sid] -r rid [-c] [-d] [-v]\n\n",
	    pathname);

    exit(EX_USAGE);
}

static int
pubsubtest(psirp_id_t *sid_p, psirp_id_t *rid_p,
           int change_pdata, int change_sdata)
{
    psirp_pub_t ppub      = NULL,  spub      = NULL;
    u_int8_t   *pdata     = NULL, *sdata     = NULL;
    u_int64_t   pdata_len = 0,     sdata_len = 0;
    u_int8_t    oldp      = 0,     olds      = 0;
    u_int64_t i = 0;

    PRINTF_IF_V("psirp_create(%lu)\n", PUB_LEN);
    if (!psirp_create(PUB_LEN, &ppub)) {
        PRINTF_IF_V("psirp_create OK\n");
    }
    else {
        PRINTF_IF_V("psirp_create NOT OK\n");
        return -1;
    }
    pdata = (u_int8_t *)psirp_pub_data(ppub);
    pdata_len = psirp_pub_data_len(ppub);

    memset(pdata, 0, pdata_len);
    pdata[0]           = '\xaa';
    pdata[pdata_len/2] = '\xff';
    pdata[pdata_len-1] = '\x55';

    PRINTF_IF_V("psirp_publish(%s)\n", psirp_idstoa(sid_p, rid_p));
    if (!psirp_publish(sid_p, rid_p, ppub)) {
        PRINTF_IF_V("psirp_publish OK\n");
    }
    else {
        PRINTF_IF_V("psirp_publish NOT OK\n");
        return -1;
    }

    PRINTF_IF_V("psirp_subscribe(%s)\n", psirp_idstoa(sid_p, rid_p));
    if (!psirp_subscribe(sid_p, rid_p, &spub)
        && ((sdata = (u_int8_t *)psirp_pub_data(spub)) != NULL)
        && ((sdata_len = psirp_pub_data_len(spub)) >= 0)) {
        PRINTF_IF_V("psirp_subscribe OK\n");
    }
    else {
        PRINTF_IF_V("psirp_subscribe NOT OK\n");
        return -1;
    }

    if (change_pdata)
        printf("changing published data\n");
    if (change_sdata)
        printf("changing subscribed data\n");

    if (change_pdata || change_sdata) {
        oldp = pdata[pdata_len/2];
        olds = sdata[sdata_len/2];
        PRINTF_IF_V("i=%lu old pdata: %2x, "
                    "i=%lu old sdata: %2x\n",
                    pdata_len/2, oldp,
                    sdata_len/2, olds);
        
        if (change_pdata)
            pdata[pdata_len/2] = pdata[pdata_len/2]+1;
        if (change_sdata)
            sdata[sdata_len/2] = sdata[pdata_len/2]-1;

        PRINTF_IF_V("i=%lu new pdata: %2x, "
                    "i=%lu new sdata: %2x\n",
                    pdata_len/2, pdata[pdata_len/2],
                    sdata_len/2, sdata[pdata_len/2]);
    }
    
    for (i = 0; i < PUB_LEN; i++) {
        if (sdata[i] != pdata[i]) {
            printf("published and subscribed data are not equal: %lu: %x, %x\n",
                   i, sdata[i], pdata[i]);
            if (change_pdata || change_sdata) {
                printf("OK\n");
                return 0;
            }
            else {
                printf("NOT OK\n");
                return -1;
            }
        }
    }

    printf("published and subscribed data are equal\n");
    if (change_pdata || change_sdata) {
        printf("NOT OK\n");
        return -1;
    }
    else {
        printf("OK\n");
        return 0;
    }
}

int 
main(int argc, char **argv) {
    int c;
    char *sid_str = NULL,
         *rid_str = NULL;
    char *pathname = argv[0];

    psirp_id_t sid;
    psirp_id_t rid;
    psirp_id_t *sid_p = &sid;
    psirp_id_t *rid_p = &rid;
    int change_pdata = 0, change_sdata = 0;

    while ((c = getopt(argc, argv, "s:r:cdvh")) != EOF) {
        switch (c) {
            case 's': sid_str      = optarg; break;
            case 'r': rid_str      = optarg; break;
            case 'c': change_pdata = 1;      break;
            case 'd': change_sdata = 1;      break;
            case 'v': verbose      = 1;      break;
            case 'h':
            default:
                usage(pathname);
        }
    }

    if (sid_str) {
#if 0
        if (strlen(sid_str) != PSIRP_ID_LEN*2) {
            printf("SId length mismatch (%d, should be %d)\n",
                   (int)strlen(sid_str), PSIRP_ID_LEN*2);
            return -1;
        }
#endif
	if (psirp_atoid(sid_p, sid_str)) {
	    printf("SId parsing error\n");
	    return -1;
	}
    }
    else {
	memset(sid_p, 0, sizeof(psirp_id_t));
    }
    
    if (rid_str) {
#if 0
	if (strlen(rid_str) != PSIRP_ID_LEN*2) {
            printf("RId length mismatch (%d, should be %d)\n",
                   (int)strlen(rid_str), PSIRP_ID_LEN*2);
            return -1;
        }
#endif
	if (psirp_atoid(rid_p, rid_str)) {
	    printf("RId parsing error\n");
	    return -1;
	}
    }
    else {
	printf("RId must be specified (-r)\n");
	return -1;
    }
    
    signal(SIGINT, mysighandler);

    return pubsubtest(sid_p, rid_p, change_pdata, change_sdata);
}
