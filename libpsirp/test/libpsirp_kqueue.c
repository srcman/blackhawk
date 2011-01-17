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
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>

#include <sysexits.h>
#include <getopt.h>
#include <libpsirp.h>

int verbose = 0;

void usage()
{
    fprintf(stderr, "libpsirp_conversion [-e expected_error_code] "
            "[-a ID in ascii] [-z] [-v]\n");
    fprintf(stderr, "-z = do a reverse conversion\n");
    fprintf(stderr, "-v = verbose\n");
    exit(-1);
}

struct mycbdata_str {
    int done;
} mycbdata;

int mycb(struct psirp_event *psev, void *opaque)
{
    struct mycbdata_str *mydata = (struct mycbdata_str *)opaque;

    mydata->done = 1;
    return 2;
}

int main(int argc, char **argv)
{
    psirp_id_t rid, sid;
    int event_cnt;
    struct psirp_event events[5];
    int result;
    char c;
    psirp_pub_t pub;
    psirp_kq_t *pskq;
    int i;

    memset(events, 0, sizeof(events));

    while((c = getopt(argc, argv, "p:ve")) != EOF) {
        switch(c) {
        case 'p': 
            if (psirp_atoids(&sid, &rid, optarg)) {
                fprintf(stderr, "Invalid publication identifier: %s\n");
                usage();
            }
            break;
        case 'v': verbose++;              break;
        default:
            usage();
        }
    }

    /* subscribe to the publication first (i.e. the publication must exist)
     */

    result = psirp_subscribe_sync(&sid, &rid, &pub, NULL);
    if (result) {
        printf("FAIL: Result=%2d (psirp_subscribe_sync)\n", result);
        return EX_SOFTWARE;
    }

    pskq = psirp_create_kq();
    if (!pskq) {
        printf("FAIL: psirp_create_kq() failed\n");
        return EX_SOFTWARE;
    }

    mycbdata.done = 0;

    result = psirp_add_kq_listener(pskq, pub, NOTE_PUBLISH,
                                   mycb, (void *)&mycbdata);
    if (result) {
        printf("FAIL: Result=%2d (psirp_add_kq_listener)\n", result);
        return EX_SOFTWARE;
    }

    if (verbose)
        printf("INFO: Publication added to kqueue\n");

    event_cnt = 5;
    result = psirp_wait_kq(pskq, 10, events, &event_cnt);
    if (result < 0) {
        printf("FAIL: Result=%2d (psirp_wait_kq)\n", result);
        return EX_SOFTWARE;
    }

    if (verbose)
        printf("INFO: %d events occured\n", result);

    for(i=0;i<event_cnt;i++) {
        printf("Event #%d: %s\n", i, events[i].flags & NOTE_PUBLISH ? 
               "PUBLISH" :
               (events[i].flags & NOTE_SUBSCRIBE ? "SUBSCRIBE" : "UNKNOWN"));
    }

    if (mycbdata.done != 1) {
        printf("FAIL: callback changes not visible: %d\n", mycbdata.done);
        return EX_SOFTWARE;
    }

    if (events[0].cb_retcode != 2) {
        printf("FAIL: callback return code invalid: %d\n", 
               events[0].cb_retcode);
        return EX_SOFTWARE;
    }

    psirp_delete_kq(pskq);

    psirp_free(pub);

    return EX_OK;
}
            
