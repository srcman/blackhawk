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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>

#include <libpsirp.h>

#define PSIRP_IO_SUB_METADATA 0x00000004 /**< Subscribe metadata only. */

void publish(psirp_id_t sid, psirp_id_t rid, int fd);
void subscribe(psirp_id_t sid, psirp_id_t rid, int fd,
               int random_bytes, int cow, int mode);
void subscribe_scope(psirp_id_t sid);
void pubsub_test(void);
void status(void);

#define SUB_ASYNC 1
#define SUB_SYNC  2

void
usage(void)
{
    fprintf(stderr, "\nUsage:\n\n");
    fprintf(stderr, "psirptest [-p] [-s] [-x] [-z]\n");
    fprintf(stderr, "          [-c sid] [-r rid] [-f file [-e]]\n");
    fprintf(stderr, "          [-b b] [-o] [-t] [-i] [-w x]\n\n");
    fprintf(stderr, "\t-p           publish a file\n");
    fprintf(stderr, "\t-s           subscribe\n");
    fprintf(stderr, "\t-x           synchronized subscribe\n");
    fprintf(stderr, "\t-z           subscribe to scope\n");
    fprintf(stderr, "\t-c           SId (required for -z)\n");
    fprintf(stderr, "\t-r           RId (required for -s)\n"); 
    fprintf(stderr, "\t-f           use file (required for -p)\n");
    fprintf(stderr, "\t-e           overwrite existing file in subscription\n");
    fprintf(stderr, "\t-b           read b bytes from random location\n");
    fprintf(stderr, "\t-o           test copy-on-write\n");
    fprintf(stderr, "\t-t           pub-sub-mod-pub-sub test\n");
    fprintf(stderr, "\t-i           call libpsirp status\n");
    fprintf(stderr, "\t-w           sleep x seconds after syscall\n");
    fprintf(stderr, "\t-h           usage\n\n");

    exit(1);
}

int
main(int argc, char *argv[])
{
    char c;
    int pub = 0, sub = 0, stat = 0, cow = 0, pubsub = 0, zup = 0;
    int overwrite = 0;
    char *ridstr = NULL, *sidstr = NULL, *fname = NULL;
    psirp_id_t sid, rid;
    int i, sleeptime = 0, fd = -1, random_bytes = 0;
    int err;


    while ((c = getopt(argc, argv, "psxzc:r:f:eb:otiw:h")) != EOF)
    {
        switch (c) {
            case 'p':
                pub = 1;
                break;
            case 's':
                sub = SUB_ASYNC;
                break;
            case 'x':
                sub = SUB_SYNC;
                break;
            case 'z':
                zup = 1;
                break;
            case 'c':
                sidstr = optarg;
                break;
            case 'r':
                ridstr = optarg;
                break;
            case 'f':
                fname = optarg;
                break;
            case 'e':
                overwrite = 1;
                break;
            case 'b':
                random_bytes = atoi(optarg);
                break;
            case 'o':
                cow = 1;
                break;
            case 't':
                pubsub = 1;
                break;
            case 'i':
                stat = 1;
                break;
            case 'w':
                sleeptime = atoi(optarg);
                break;
            case 'h':
            default:
                usage();
        }
    }
    argc -= optind;
    argv += optind;

    /* Check that at least one operation is defined. */
    if (!pub && !sub && !stat && !pubsub && !zup) {
        usage();
        return 0;
    }

    /*
     * Check that both pub and sub are not defined at the same time.
     * We could check the other ops as well, but giving this pair is
     * the most common mistake.
     */
    if (pub && sub) {
        fprintf(stderr,
                "Error: Both publish and subscribe operations specified.\n");
        usage();
        return 0;
    }

    if ((err = psirp_atoid(&rid, ridstr))) {
        printf("Error: %d while converting RID ascii string\n", err);
        usage();
        return 0;
    }

    if ((err = psirp_atoid(&sid, sidstr))) {
        printf("Error: %d while converting SID ascii string\n", err);
        usage();
        return 0;
    }

    /* Publish. */
    if (pub) {
        if (!fname) {
            printf("Publish operation requires an input file.\n");
            return 0;
        }
        fd = open(fname, O_RDONLY);
        if (fd == -1) {
            perror("open");
            return 0;
        }
        publish(sid, rid, fd);
        close(fd);
    }

    /* Subscribe. */
    if (sub) {
        if (fname) {
            int open_flags = O_RDWR | O_CREAT | O_TRUNC;
            if (!overwrite) {
                open_flags |= O_EXCL;
            }
            fd = open(fname, open_flags);
            if (fd == -1) {
                perror("open");
                return 0;
            }
        }
        subscribe(sid, rid, fd, random_bytes, cow, sub);
        
        if (fd != -1) {
            fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            close(fd);
        }
    }

    /* Scope subscribe (channel mode). */
    if (zup) {
	fprintf(stderr, "subscribe_scope not currently supported\n");
#if 0
        subscribe_scope(sid);
#endif
    }

    if (pubsub)
        pubsub_test();

    if (stat)
        status();

    if (sleeptime) {
        printf("Sleeping %d seconds...\n", sleeptime);
        sleep(sleeptime);
    }

    return 1;
}

void
publish(psirp_id_t sid, psirp_id_t rid, int fd) {
    int err;
    psirp_pub_t pub;
    u_int64_t len = 0;
    struct stat sb;
    int i;

    /* Find out the size of the file. */
    if (fstat(fd, &sb)) {
        perror("fstat");
        return;
    }

    /* Create a memory area for publication. */
    err = psirp_create(sb.st_size, &pub);
    if (err < 0) {
        printf("libpsirp_create(): [Errno %d] %s\n", errno, strerror(errno));
        return;
    }

    /* Read data from the file to the memory area. */
    if ((len = read(fd, psirp_pub_data(pub), sb.st_size)) != sb.st_size) {
        perror("read");
        return;
    }

    /* Publish the data. */
    if (psirp_publish(&sid, &rid, pub) < 0) {
        printf("psirp_publish failed\n");
        return;
    }

    /* Print out the assigned IDs. */
    printf("File published with SID/RID ");
    for (i = 0; i < PSIRP_ID_LEN; i++)
        printf("%02x", sid.id[i]);
    printf("/");
    for (i = 0; i < PSIRP_ID_LEN; i++)
        printf("%02x", rid.id[i]);
    printf("\n");
}

void
subscribe(psirp_id_t sid, psirp_id_t rid, int fd, int random_bytes, int cow,
          int mode) 
{
    u_int8_t *data = NULL;
    psirp_pub_t pub;
    u_int64_t len = 0, wb = 0;
    u_int64_t rnd = 0;
    int err;

    if (mode == SUB_ASYNC) {
        err = psirp_subscribe(&sid, &rid, &pub);
        if (err != 0) {
            printf("libpsirp_subscribe(): [Errno %d] %s\n",
		   errno, strerror(errno));
            return;
        }
    } else if (mode == SUB_SYNC) {
        err = psirp_subscribe_sync(&sid, &rid, &pub, NULL);
        if (err != 0) {
            printf("libpsirp_subscribe_sync failed(): [Errno %d] %s\n",
		   errno, strerror(errno));
            return;
        }
    } else {
        printf("libpsirp: Unknown subscribe mode: %d\n", mode);
        return;
    }
    
    data = psirp_pub_data(pub);
    len  = psirp_pub_data_len(pub);
    printf("data: %p len: %lu\n", data, len);

    if (fd != -1) {
        if ((wb = write(fd, data, len)) != len) {
            perror("write");
            return;
        }
        printf("Wrote %lu bytes into the file.\n", wb);
    }

    if (random_bytes > 0) {
        int i, fd = -1, rb = 0;
        fd = open("/dev/random", O_RDONLY);
        if (fd == -1) {
            perror("open");
            return;
        }
        if ((rb = read(fd, &rnd, sizeof(u_int64_t))) != sizeof(u_int64_t)) {
            perror("read");
            return;
        }
        printf("\n%d random bytes:\n", random_bytes);
        for (i = 0; i < random_bytes; i++) {
            if (rnd % len + i > len)
                break;
            printf("%p: ", (data+rnd%len+i));
            printf("%02x\n", data[rnd%len+i]);
        }
        printf("\n");
    }

    if (cow) {
        int i, fd = -1, rb = 0;
        fd = open("/dev/random", O_RDONLY);
        if (fd == -1) {
            perror("open");
            return;
        }
        if ((rb = read(fd, &rnd, sizeof(u_int64_t))) != sizeof(u_int64_t)) {
            perror("read");
            return;
        }
        printf("\nWriting a random byte to a random location:\n");
        printf("Data at %p was 0x%02x\n", (data+rnd%len), data[rnd%len]);
        data[rnd%len] = (u_int8_t)rnd;
        printf("Data at %p is now 0x%02x\n\n", (data+rnd%len), data[rnd%len]);
    }

    printf("Subscribe OK.\n");
}

#if 0
void
subscribe_scope(psirp_id_t sid) {
    u_int8_t *data = NULL;
    u_int64_t len = 0;
    u_int8_t fid[PSIRP_FID_LEN];
    u_int8_t rid[PSIRP_ID_LEN];
    int i;

    while (1) {
        memset(fid, 0, PSIRP_FID_LEN); /* Get any FID. */
        memset(rid, 0, PSIRP_ID_LEN); /* Get any RID. */

        printf("\nSubscribing to scope: ");
        for (i = 0; i < PSIRP_ID_LEN; i++)
            printf("%02x", sid[i]);
        printf("\n");

        data = (u_int8_t *)psirp_adv_subscribe(fid,
                                               sid,
                                               rid,
                                               &len,
                                               PSIRP_IO_SUB_METADATA);

#if 0
        if (data == NULL) {
            printf("libpsirp_subscribe(): [Errno %d] %s\n",
		   errno, strerror(errno));
            return;
        }
#endif

        printf("Len: %lu\nFID: ", len);
        for (i = 0; i < PSIRP_FID_LEN; i++)
            printf("%02x", fid[i]);
        printf("\nRID: ", data, len);
        for (i = 0; i < PSIRP_ID_LEN; i++)
            printf("%02x", rid[i]);
        printf("\n");

        /* Do magic... */


        /** TODO: Implement psirp_free() ! **/

    }
}
#endif

void
pubsub_test() {
    psirp_pub_t pub1, pub2, pub3;
    u_int8_t *p1, *p2, *p3;
    u_int64_t len1, len2, len3;
    psirp_id_t scope;
    psirp_id_t id1, id2;
    int i;
    int err;

    len1 = 4096;
    memset(&scope, 0, sizeof(psirp_id_t));
    memset(&id1,   0, PSIRP_ID_LEN);
    memset(&id2,   0, PSIRP_ID_LEN);

    /*
     * Publish.
     */

    /* Create a memory area for publication. */
    err = psirp_create(len1, &pub1);
    if (err < 0) {
        printf("libpsirp_create(): [Errno %d] %s\n", errno, strerror(errno));
        return;
    }

    p1 = psirp_pub_data(pub1);

    /* Store 0xACDC in the middle of the publication. */
    memset(p1, 0, len1);
    p1[len1/2]   = 0xAC;
    p1[len1/2+1] = 0XDC;

    err = psirp_publish(&scope, &id1, pub1);
    if (err < 0) {
        printf("libpsirp_publish(): [Errno %d] %s\n", errno, strerror(errno));
        return;
    }

    printf("=> published 0xACDC with ID = ");
    for (i = 0; i < PSIRP_ID_LEN; i++)
        printf("%02x", id1.id[i]);
    printf("\n");

    /*
     * Modify.
     */
    p1[len1/2]   = 0xCA;
    p1[len1/2+1] = 0xFE;
    printf("=> changed 0xACDC to 0xCAFE\n");

    /*
     * Subscribe.
     */
    err = psirp_subscribe(&scope, &id1, &pub2);
    if (err < 0) {
        printf("libpsirp_subscribe(): [Errno %d] %s\n",
	       errno, strerror(errno));
        return;
    }
    p2   = psirp_pub_data(pub2);
    len2 = psirp_pub_data_len(pub2);

    printf("=> subscribed to the 0xACDC publication.\n");
    printf("==> data in the middle: 0x%x%x (<= should be 0xacdc)\n",
           p2[len2/2], p2[len2/2+1]);

    /*
     * Modify.
     */
    p2[len2/2]   = 0xAB;
    p2[len2/2+1] = 0xBA;
    printf("==> changed 0xACDC to 0xABBA\n");

    /*
     * Publish.
     */
    err = psirp_publish(&scope, &id2, pub2);
    if (err < 0) {
        printf("libpsirp_publish(): [Errno %d] %s\n", errno, strerror(errno));
        return;
    }

    printf("=> published the 0xABBA publication with ID = ");
    for (i = 0; i < PSIRP_ID_LEN; i++)
        printf("%02x", id2.id[i]);
    printf("\n");

    /*
     * Subscribe the original publication once more.
     * Data should be 0xACDC.
     */
    err = psirp_subscribe(&scope, &id1, &pub3);
    if (err < 0) {
        printf("libpsirp_subscribe(): [Errno %d] %s\n",
	       errno, strerror(errno));
        return;
    }
    p3   = psirp_pub_data(pub3);
    len3 = psirp_pub_data_len(pub3);

    printf("=> subscribed to the 0xACDC publication.\n");
    printf("==> data in the middle: 0x%x%x (<= should be 0xacdc)\n",
           p3[len3/2], p3[len3/2+1]);
}

void
status()
{
    char *output = NULL;
    int x;

    x = psirp_status(&output);
    //printf("jee: %d, output=%p\n", x, output);
    //    if (x > 0) {
    if (output) {
        printf("%s\n", output);
        free(output);
    }
    return;
}

#if 0
/* Hex String to Byte Array */
int
hs2ba(void *d, const char *s, int len)
{
    char t[3];
    int i = 0;

    t[2] = '\0';
    
    for (i = 0; i < len/2; i++) {
        t[0] = s[2*i];
        t[1] = s[2*i+1];
        ((u_int8_t *)d)[i] = (u_int8_t)strtol(t, (char **)NULL, 16);
    }
    
    return i;
}
#endif
