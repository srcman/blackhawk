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
 * Tester for the psirp_publish system call
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define _LIBPSIRP

#include <ps.h>
#include <ps_syscall.h>
#include <libpsirp.h>

#define PRINTF(format, ...)	   	   \
    do {                                   \
        if (verbose) {                     \
            printf(format, ##__VA_ARGS__); \
        }                                  \
    } while (0)

enum { MODE_INVALID=0, MODE_ASCII, MODE_BINARY } mode = MODE_INVALID;

#define NOT_DEFINED (-1)

int work_done = 0;

int verbose = 0;

char *prog_name;

extern int prepare(void);
extern int create(struct psfs_pub *pub);
extern int publish(psirp_id_t, psirp_id_t, struct psfs_pub *pub);

void mysighandler(int sig)
{
    work_done = 1;
}

/* Read at most len from fd */
void fill_buffer(u_int64_t len, FILE *fd, caddr_t buff)
{
    int x;
    int cnt = len;
    int idx;

    while (cnt) {
	idx = len - cnt;
	x = fread(buff + idx, sizeof(uint8_t), cnt, fd);
	if (x < len) {
	    if (feof(fd))
		return;
	    if (ferror(fd)) {
		fprintf(stderr, "ERROR: ");
		perror("fread");
		exit(EX_NOINPUT); // better bail out needed
	    }
	    /* no eof nor error --> read again */
	}
	cnt -= x;
    }
}

void modify_data_buffer(u_int64_t dlen, caddr_t data)
{
    int cnt = dlen/4;
    int i;
    long int rand;
    uint8_t x;

    /* make sure cnt is at least 1 */
    cnt++;

    for (i = 0; i < cnt; i++) {
	rand = random();
	switch (mode) {
	case MODE_ASCII:
	    x = (rand % ('~' - '!' - 1)) + '!'; // skip non-printables 
	    break;
	case MODE_BINARY:
	    x = (rand & 0xFF);
	    break;
	default:
	    fprintf(stderr, "ERROR: Unknown mode... help!\n");
	    exit(EX_SOFTWARE);
	}
	data[(rand >> 8) % dlen] = x;
    }

    if (verbose > 2) {
        printf("Modified buffer:\n");
        if (mode == MODE_ASCII) {
            printf("%s\n", data);
        } else {
            printf("Hexdump not implemented yet\n");
        }
    }
}

void usage(const char *str)
{
    printf("publish -s ID -r ID [-n count] [-m mode] [-f file] "
	   "[-l len] [-q]\n\n");
    printf("ID   = 64 hexadecimal characters\n");
    printf("mode = [ASCII|BINARY]\n"); 
    printf("-s   = Scope Identifier\n");
    printf("-r   = Rendezvous Identifier\n");
    printf("-n   = (Re)publish count times\n");
    printf("-m   = Randomly modify data between republishes\n");
    printf("-f   = Read data to be published from file\n");
    printf("-g   = Read data to the metadata from file\n");
    printf("-l   = Maximum length of publication\n");
    printf("-q   = Do not quit the program (sleep forever)\n");
    printf("-e   = Expected result code\n");
    printf("-v   = Verbose\n");
    printf("\n\n");
    printf("-l is required if -f is not used!\n");
    printf("Mode specifies how the data is modified during subsequent "
	   "publish operations\n");
    printf("ASCII guarantees that the changes are printable\n");
    if (str) {
	printf("\n\nError while parsing: %s\n", str);
    }

    exit(0);
}

int main(int argc, char **argv)
{
    char c;
    int code = -1;
    psfs_pub_t pub;
    struct stat s;
    int i, count = 1;
    FILE *fd = NULL, *mfd = NULL;
    int noquit = 0;
    psirp_id_t rid, sid;

    memset(&pub, 0, sizeof(pub));
    memset(&rid, 0, sizeof(rid));
    memset(&sid, 0, sizeof(sid));
    pub.pub_dlen = NOT_DEFINED;
        
    while ((c = getopt(argc, argv, "e:l:r:s:n:m:f:g:qv")) != EOF) {
	switch (c) {
	case 'e':
	    code = strtol(optarg, NULL, 10); 
	    break;
	case 'l':
	    pub.pub_dlen = strtol(optarg, NULL, 10);
	    break;
	case 'r':
	    if (psirp_atoid(&rid, optarg))
		usage("Rendezvous Identifier");
	    break;
	case 's':
	    if (psirp_atoid(&sid, optarg))
		usage("Scope Identifier");
	    break;
	case 'm':
	    if (!strncasecmp(optarg, "ASCII", 5))
		mode = MODE_ASCII;
	    else if (!strncasecmp(optarg, "BINARY", 6))
		mode = MODE_BINARY;
	    else
		usage("Illegal mode");
	    break;
	case 'n':
	    count = atoi(optarg);
	    break;
	case 'f':
	    fd = fopen(optarg, "r");
	    if (!fd) {
		perror(optarg);
		exit(EX_NOINPUT);
	    }
	    break;
	case 'g':
	    mfd = fopen(optarg, "r");
	    if (!mfd) {
		perror(optarg);
		exit(EX_NOINPUT);
	    }
	    break;
	case 'q': noquit = 1;  break;
	case 'v': verbose++; break;
	default:
	    usage(NULL);
	}
    }

    /* Sane defaults */

    /* If file is defined, make sure pub.pub_dlen doesn't go beyond the file.
     * If file is NOT defined, use zeros.
     */
    if (fd) {
	if (fstat(fileno(fd), &s)) {
	    perror("fstat");
	    exit(EX_IOERR);
	}

	if (pub.pub_dlen != NOT_DEFINED) {
	    if (s.st_size < pub.pub_dlen)
		pub.pub_dlen = s.st_size;
	} else {
	    pub.pub_dlen = s.st_size;
	}
    }

    srandom(time(NULL));

    if (mode == MODE_INVALID)
	mode = MODE_ASCII;

    if (count <= 0)
	count = 1;

    /* Initialisation */
    
    signal(SIGINT, mysighandler);

    if (prepare()) {
	PRINTF("Error: module error\n");
	exit(EX_OSERR);
    }

    /* Main logic */

    pub.pub_mlen = PS_MD_SIZE;
    if (pub.pub_dlen == NOT_DEFINED)
	pub.pub_dlen = 0;

    if (create(&pub)) {
	printf("ERROR: errno=%2d: Unable to create publication\n", errno);
	exit(EX_SOFTWARE);
    }

    PRINTF("Info: Created:   meta=%15p, mlen=%8ld, data=%15p, dlen=%8ld\n", 
	       pub.pub_meta, pub.pub_mlen, pub.pub_data, pub.pub_dlen);

    if (mfd) {
	int i;
	if (verbose > 2) {
	    printf("Before reading file:\n");
	    for (i = 0; i < pub.pub_mlen; i++) {
		printf("%.2hhx ", ((unsigned char *)pub.pub_meta)[i]);
		if (31 == i % 32)
		    printf("\n");
	    }
	    printf("After reading file:\n");
	}
	fill_buffer(pub.pub_mlen, mfd, (void *)pub.pub_meta);
	if (verbose > 1) {
	    for (i = 0; i < pub.pub_mlen; i++) {
		printf("%.2hhx ", ((unsigned char *)pub.pub_meta)[i]);
		if (31 == i % 32)
		    printf("\n");
	    }
	}
    }

    if (fd) {
	fill_buffer(pub.pub_dlen, fd, pub.pub_data);
    } else if (MODE_ASCII == mode) {
	memset(pub.pub_data, 'A', pub.pub_dlen);
    }

    for (i = 0; i < count; i++) {
	int err, error;

	errno = 0;
	err = publish(sid, rid, &pub);
	error = errno;

	if (err >= 0) {
	    PRINTF("Info: Published: meta=%15p, mlen=%8ld, data=%15p, dlen=%8ld\n", 
		   pub.pub_meta, pub.pub_mlen, pub.pub_data, pub.pub_dlen);
	    PRINTF("Info: SID/RID=%s. FD=%d\n", 
		   psirp_idstoa(&pub.pub_sid, &pub.pub_meta->pm_id),
		   pub.pub_fd);
	} else {
	    PRINTF("Info: Failed:    meta=%15p, mlen=%8ld, data=%15p, dlen=%8ld\n", 
		   pub.pub_meta, pub.pub_mlen, pub.pub_data, pub.pub_dlen);
	    PRINTF("Info: SID/RID=%s. FD=%d. Errno=%d.\n", 
		   psirp_idstoa(&sid, &rid),
		   pub.pub_fd, errno);
	}

	
	if (code != error) {
	    printf("ERROR: errno=%02d, dlen=%4ld, SID/RID=%s\n", 
		   error, pub.pub_dlen, psirp_idstoa(&sid, &rid)),

	    exit(EX_SOFTWARE);
	}

	/* modify source, but no need to do it after last publish */
	if (count == i+1)
	    break;

	modify_data_buffer(pub.pub_dlen, pub.pub_data);
    }

    if (noquit)
	sleep(UINT32_MAX);

    PRINTF("Ok: Published: %d times\n", count);

    exit (0);
}
