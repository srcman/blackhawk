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

#ifdef HAVE_CONFIG_H
/* checking */
#include <config.h>
#endif

/* kqueue/kevent */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <syslog.h>
#include <openssl/evp.h>

#include <signal.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

/* psirpd_net.h */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <sys/ioctl.h>

/* libpsirp */
#include <sys/param.h>
#include <libpsirp.h>
#include "../../libpsirp/src/psirp_debug.h"

#ifdef PSIRP_PLA
#include "libpla.h"
#endif

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_hdrs.h"
#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"
#include "psirpd_fwd_bf.h"
#include "psirpd_config.h"
#include "psirpd_sec_pla.h"
#include "psirpd_rzv.h"
#include "psirpd_ipc.h"


static void psirpd_usage(void);
static psirp_error_t psirpd_init(/*char *, */char *, char *, char *);
static void psirpd_cleanup(void);
static psirp_error_t netiod_event();

void *psirpd_run(void *arg);

static int security_enabled = 0;


int psirpd_interrupted = PSIRP_FALSE;

void psirpd_sighandler(int sig)
{
    psirpd_interrupted = PSIRP_TRUE;
}


static void
psirpd_usage(void) {
    fprintf(stderr, "usage: psirpd -i ifaces [-ntl...]\n");
    fprintf(stderr, "\t-b - show important built-in values\n");
    fprintf(stderr, "\t-c - use ANSI colors with debug messages\n");
    fprintf(stderr, "\t-s - enable security\n");
    fprintf(stderr, "\t-t - print debug messages on terminal\n");
    fprintf(stderr, "\t-l - print debug messages to syslog\n");
    fprintf(stderr, "\t     <level>    - debug level %d-%d\n", PSIRP_DBG_NONE,
            PSIRP_DBG_ALL);
    //fprintf(stderr, "\t-i - list of interfaces \n");
    fprintf(stderr, "\t     <ifaces>   - e.g. em0,em1\n");
    fprintf(stderr, "\t-w - use configuration file\n");
    fprintf(stderr, "\t     <filename> - file name\n");
    fprintf(stderr, "\t-r - IPC publication, local events\n");
    fprintf(stderr, "\t     <rid>      - RId\n");
    fprintf(stderr, "\t-q - IPC publication, network events\n");
    fprintf(stderr, "\t     <rid>      - RId\n");
}

static void
psirpd_builtin(void) {
    fprintf(stderr, "Psirpd was compiled with following constants\n");
    fprintf(stderr, "\tPubsub mountpoint - %s\n", PUBSUB_MNT);
    fprintf(stderr, "\tMax. interfaces   - %d\n", PSIRP_MAX_NO_IFACES);
    fprintf(stderr, "\tMax. header len   - %d (bytes)\n", 
	    PSIRP_MAX_HEADER_LEN);
#if 0
    fprintf(stderr, "\tMax. packet len   - %d (bytes)\n", 
	    PSIRP_MAX_PACKET_LEN);
#endif
    fprintf(stderr, "\tMax. publication  - %ld (kilobytes)\n", 
	    PSIRP_MAX_PUB_SIZE >> 10);
    fprintf(stderr, "\tChunk size        - %d (bytes)\n", PSIRP_CHUNK_SIZE);
    fprintf(stderr, "\tOut-q batch size  - %d (packets)\n", 
	    PSIRP_OUTQ_BATCH_SIZE);
}


int
main(int argc, char* argv[]) {
    int opt;
    psirp_error_t error;
    //char *iface_list = NULL;
    char *cfg_fname = NULL;
    //char *ipc_sid_str = NULL;
    char *ipc_rid_l_str = NULL;
    char *ipc_rid_n_str = NULL;

    signal(SIGINT, psirpd_sighandler);
 
    psirp_debug_print2log();

    while ((opt = getopt(argc, argv, "bcsw:t:l:i:r:q:")) != EOF) {
        switch (opt) {
	case 'b':
	    psirpd_builtin();
	    return 0;
	    break;
	case 'c':
	    psirp_debug_printcols();
	    break;
        case 't':
            psirp_debug_init_print(atoi(optarg), PSIRP_FALSE);
            break;
        case 'l':
            psirp_debug_init_print(atoi(optarg), PSIRP_TRUE);
            break;
#if 0
        case 'i':
            iface_list = optarg;
            break;
#endif
        case 's':
            security_enabled = 1;
            break;
        case 'w':
            cfg_fname = optarg;
            break;
	case 'r':
	    ipc_rid_l_str = optarg;
	    break;
	case 'q':
	    ipc_rid_n_str = optarg;
	    break;

        default:
            psirpd_usage();
            return 0;
        }
    }

    openlog("psirpd", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "starting");

    error = psirpd_init(/*iface_list, */cfg_fname, ipc_rid_l_str, ipc_rid_n_str);
    if (PSIRP_OK != error){
        fprintf(stderr, "Fatal error during initialization.\n");
        psirp_fatal(error);
        /* NOTREACHED */
    }

    PSIRP_DEBUG(PSIRP_DBG_GARB, "Network I/O initialized\n");

    netiod_event();
    psirpd_cleanup();

    return 0;
}

static psirp_error_t
netiod_event(void) {

    int kq;
#define PSIRP_NEVENTS 8 /* XXX */
    struct kevent el[PSIRP_NEVENTS];
    int nevents = sizeof(el)/sizeof(el[0]);

    int ipc_fd1 = -1, ipc_fd2 = -1;

    int n, i;
    psirp_error_t err = PSIRP_OK;
    struct timespec timeout, *timeout_p = NULL;

    if_list_item_t *ifli = NULL;

    ENTER();

    /*
     * kqueue/kevent initialization.
     *
     * XXX: Should this be done in the general initialization phase instead?
     * XXX: At cleanup time we should probably unreg kevents and close the kq.
     */
    
    kq = kqueue();
    PSIRP_ET(0 > kq, PSIRP_FAIL, "kqueue(): %s", strerror(errno));
    memset(el, 0, sizeof(el));
    
    /* Register kevents for each socket. */
    PSIRP_EF(psirpd_net_regevents(kq));
    
    /* Also register local events (i.e., sending triggers). */
    PSIRP_EF(psirpd_ipc_local_regevents(kq, &ipc_fd1));
    PSIRP_EF(psirpd_ipc_local_next_regevents(kq, &ipc_fd2));

    PSIRP_DEBUG(PSIRP_DBG_INFO, "Listening to events");

    while (psirpd_interrupted != PSIRP_TRUE) {

        timeout_p = psirpd_out_q_next_timeout(&timeout);

        PSIRP_DEBUG(PSIRP_DBG_GARB, "Enter kevent");
        n = kevent(kq,          /* kqueue,                */
                   NULL, 0,     /* *changelist, nchanges, */
                   el, nevents, /* *eventlist, nevents,   */
                   timeout_p);  /* *timeout               */
        PSIRP_DEBUG(PSIRP_DBG_GARB, "%d event%s", n, (n != 1) ? "s" : "");

        if (n < 0) {
            if (psirpd_interrupted == PSIRP_TRUE) {
                PSIRP_DEBUG(PSIRP_DBG_GARB, "kevent => interrupt");
                continue; /* while */
	    }
            else {
                PSIRP_DEBUG(PSIRP_DBG_ERR, "kevent => errno %d", errno);
                psirp_fatal(PSIRP_FAIL_SELECT);
            }

        } else if (n == 0) {
            PSIRP_DEBUG(PSIRP_DBG_GARB, "kevent => timeout");
            err = psirpd_out_q_send();
            
            if (err != PSIRP_OK)
                PSIRP_DEBUG(PSIRP_DBG_WARN, 
                            "Error in handling send out queue");

        } else {
            /* Process the events. */

            PSIRP_DEBUG(PSIRP_DBG_GARB, "kevent => net/local event");

	    /* XXXXXX */
	    PSIRP_DEBUG(PSIRP_DBG_GARB, "Reset bytes_read\n");
	    LIST_FOREACH(ifli, &if_list_head, entries) {
		ifli->bytes_read = 0;
	    }

	    for (i = 0; i < n; i++) {
		if (el[i].ident == ipc_fd1) {
                    /* IPC publication updated. */
		    err = psirpd_ipc_local_handle_event(&el[i]);
                }
                else if (el[i].ident == ipc_fd2) {
                    /* First version published with next IPC RId. */
                    PSIRP_DEBUG(PSIRP_DBG_INFO, "Next IPC local publication");
                    
                    /* Unregister old pub. */
                    PSIRP_EF(psirpd_ipc_local_unregevents(kq));
                    /* Set next pub to current and init new next. */
                    PSIRP_EF(psirpd_ipc_set_next_ipc_local_pub());
                    ipc_fd1 = ipc_fd2;
                    /* Register to new next. (XXX: Timing?) */
                    PSIRP_EF(psirpd_ipc_local_next_regevents(kq, &ipc_fd2));
                    
                    /* Handle this event. */
                    psirpd_ipc_local_handle_event(&el[i]);
                }
		else {
                    /* Assume that this is a socket event. */
		    err = psirpd_net_handle_event(&el[i]);
                }
	    }

            if (PSIRP_OK != err) {
                PSIRP_DEBUG(PSIRP_DBG_INFO, "Could not process"
                            " the event successfully\n");
            }
        }
    }

//out:
    RETURN(PSIRP_OK);
}

static psirp_error_t
psirpd_init(/*char *iface_list, */char *cfg_fname,
            char *ipc_rid_l_str, char *ipc_rid_n_str) {

#if PSIRP_CRYPTO
    u_long seed;
    int fd;

/* XXX: Check this */
    /* Initialize random number generator */
    fd = open("/dev/random", O_RDONLY);
    PSIRP_ET(0 > fd, PSIRP_FAIL_DEVRANDOM, "Can NOT open /dev/random");
    if (read(fd, &seed, sizeof(seed)));
    srandom(seed);
    close(fd);

/* XXX: Check this too */
    /* Crypto init */
    OpenSSL_add_all_algorithms();
#endif /* PSIRP_CRYPTO */

    /* Initialize net module. */
    PSIRP_EFLM(psirpd_net_init(), 
               PSIRP_DBG_ERR, "Initializing NET, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing NET, done");

    /* Initialize packet module. */
    PSIRP_EFLM(psirpd_packet_init(), 
               PSIRP_DBG_ERR, "Initializing PACKET, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing PACKET, done");

    /* Read the configuration file */
    if (cfg_fname) {
        PSIRP_EFLM(psirpd_config_init(cfg_fname),
                   PSIRP_DBG_ERR, "Reading config file failed.");
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Reading config file, done");
    }

    /* Initialize IPC. */
    PSIRP_EFLM(psirpd_ipc_init(ipc_rid_l_str, ipc_rid_n_str), 
               PSIRP_DBG_ERR, "Initializing IPC, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing IPC, done");

    /* Initialize forwarding module. */
    PSIRP_EFLM(psirpd_fwd_bf_init(), 
               PSIRP_DBG_ERR, "Initializing FWD BF, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing FWD BF, done");

     /* Initialize ifaces. */
    PSIRP_EFLM(psirpd_net_init_ifaces(/*iface_list*/), 
               PSIRP_DBG_ERR, "Initializing IFACES, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing IFACES, done");

    /* Initialize hdrs module. */
    PSIRP_EFLM(psirpd_hdrs_init(), 
               PSIRP_DBG_ERR, "Initializing HDRS, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing HDRS, done");


    if (security_enabled) {
        /* Initialize rzv module. */
        PSIRP_EFLM(psirpd_rzv_init(PSIRP_RZV_RID_PLA), 
                   PSIRP_DBG_ERR, "Initializing RZV, FAILED");
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing RZV, done");
        /* Initialize PLA module. */
        PSIRP_EFLM(psirpd_sec_pla_init(), 
                   PSIRP_DBG_ERR, "Initializing PLA, FAILED");
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing PLA, done");
    } else {
        /* Initialize rzv module. */
        PSIRP_EFLM(psirpd_rzv_init(PSIRP_RZV_RID_RANDOM), 
                   PSIRP_DBG_ERR, "Initializing RZV, FAILED");
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing RZV, done");
        /* Disable PLA */
        PSIRP_EFLM(psirpd_packet_register(&psirpd_sec_pla_disable), 
                   PSIRP_DBG_ERR, "Disabling PLA, FAILED");
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Disabling PLA, done");
    }

    /* Init out queue */
    PSIRP_EFLM(psirpd_out_q_init(), 
               PSIRP_DBG_ERR, "Initializing OUTQ, FAILED");
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Initializing OUTQ, done");

    return PSIRP_OK;
}

psirp_error_t
psirp_fatal(int error) {
    psirpd_cleanup();
    exit(error);
    /* NOTREACHED */
}

static void
psirpd_cleanup() {

    PSIRP_DEBUG(PSIRP_DBG_GARB,"====== Cleaning up daemon ======\n");

    psirpd_ipc_cleanup();

    /* PLA module cleanup */
    psirpd_sec_pla_cleanup();
    PSIRP_DEBUG(PSIRP_DBG_GARB,"Cleanup PLA, done");

    psirpd_net_cleanup();
    PSIRP_DEBUG(PSIRP_DBG_GARB,"Cleanup NET, done");

    psirp_debug_cleanup();
    syslog(LOG_INFO, "exiting");
}
