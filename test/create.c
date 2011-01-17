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
 * Tester for testing the psirp_create system call
 */

#include <sys/param.h>

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

#define PRINTF(format, ...)	   	   \
    do {                                   \
        if (verbose) {                     \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)

int work_done = 0;

int verbose = 0;

char *prog_name;

extern int prepare(void);
extern int create(struct psfs_pub *pub);

void mysighandler(int sig)
{
    work_done = 1;
}

void
usage()
{
    fprintf(stderr,
	    "Usage: "
	    "%s -e errorcode [-m metaptr -k metalen -d dataptr -l datalen -v]\n",
	    prog_name);

    exit(EX_USAGE);
}

int 
main(int argc, char **argv) {
    int c;
    int code = -1;
    struct psfs_pub pub;
    int error;

    prog_name = argv[0];
    memset(&pub, 0, sizeof(pub));

    while ((c = getopt(argc, argv, "e:m:d:l:k:v")) != EOF) {
        switch (c) {
	case 'e': code = strtol(optarg, NULL, 10); break;
	case 'm': pub.pub_meta = (void *)strtol(optarg, NULL, 16); break;
	case 'k': pub.pub_mlen = strtol(optarg, NULL, 10); break;
	case 'd': pub.pub_data = (void *)strtol(optarg, NULL, 16); break;
	case 'l': pub.pub_dlen = strtol(optarg, NULL, 10); break;
	case 'v': verbose++; break;
	case 'h':
	default:
	    usage();
        }
    }

    signal(SIGINT, mysighandler);

    if (prepare()) {
	PRINTF("Error: module error\n");
	exit(EX_OSERR);
    }

    errno = 0;
    create(&pub);
    error = errno;
    if (code == error) {
	PRINTF("Ok: errno=%2d: meta=%15p, mlen=%8ld, data=%15p, dlen=%8ld\n", 
	       error, 
	       pub.pub_meta, pub.pub_mlen, pub.pub_data, pub.pub_dlen);
	return EX_OK;
    }
    printf("ERROR: errno=%2d: meta=%15p, mlen=%8ld, data=%15p, dlen=%8ld\n", 
	   error, 
	   pub.pub_meta, pub.pub_mlen, pub.pub_data, pub.pub_dlen);
    return EX_SOFTWARE;
}
