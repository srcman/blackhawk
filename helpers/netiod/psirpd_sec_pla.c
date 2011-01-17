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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <unistd.h>
//#include <inttypes.h>
//#include <syslog.h>
//#include <sysexits.h>
//#include <fcntl.h>
//#include <signal.h>
//#include <time.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <sys/cdefs.h>
//#include <sys/queue.h>
//#include <sys/errno.h>
//#include <net/ethernet.h>
#include <netinet/in.h>

/* psirpd_net.h */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>

#ifdef PSIRP_PLA
#include "libpla.h"
#endif

#include <sys/param.h>
#include <libpsirp.h>

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_hdrs.h"
#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"
//#include "psirpd_fwd_bf.h"
//#include "psirpd_rzv.h"
#include "psirpd_sec_pla.h"
#include "../../libpsirp/src/psirp_debug.h"

int pla_sign_fraction = 1;		/* how many packets signed by PLA?
                                 * 0 = none, 1 = 100%, 4 = 25% etc... */
int pla_verify_fraction = 1;	/* how many packets verified by PLA?
                                 * 0 = none, 1 = 100%, 4 = 25% etc...  */

int sent_packet_count = 0;
int received_packet_count = 0;

psirp_error_t 
psirpd_sec_pla_init(void) {
    
    ENTER();

#ifdef PSIRP_PLA
	libpla_init(NULL, PLA_CRYPTO_SW);
#endif

    RETURN PSIRP_OK;
}

void 
psirpd_sec_pla_cleanup(void) {

    ENTER();

#ifdef PSIRP_PLA
	libpla_cleanup();
#endif

    RETURN;
}

psirp_error_t 
psirpd_sec_pla_get_rid(psirp_id_t *rid_ret) {
    u_int8_t *pk;
    u_int32_t len;
    u_int32_t *p;
    int i = 0;

    ENTER();

    PSIRP_ETL(rid_ret == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "rid_ret == NULL");

#ifdef PSIRP_PLA
    libpla_get_subject_pk(&pk, &len);
#else
    len = PSIRP_ID_LEN;
    pk = NULL;
#endif

    if (len > PSIRP_ID_LEN) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "Incorrect RID length: %d", len);
        RETURN PSIRP_FAIL_OUT_OF_RANGE;
    }
    PSIRP_DEBUG(PSIRP_DBG_ERR, "Public key length: %d", len);

    memset(rid_ret, 0,  PSIRP_ID_LEN);
    memcpy(rid_ret, pk, len); 

    /* To get the public key in /etc/pla.conf and in /pubsub 
     * to same byte order */  
    p = (u_int32_t*)rid_ret;
    for (i=0; i < (len / sizeof(u_int32_t)); i++) {
        p[i] = ntohl(p[i]);
    }

    /* Concatenate random numbers to the end of the RID */
    for (i = len; i < PSIRP_ID_LEN; i++) {
        rid_ret->id[i]=(u_int8_t)random();
    }

    RETURN PSIRP_OK;
}

psirp_error_t 
psirpd_sec_pla_add(pkt_ctx_t *pkt_ctx) {

    u_int8_t *prefix = NULL;
    int prefix_len = 0;
    u_int8_t *payload = NULL;
    int payload_len = 0;
    struct pla_hdr *pla_hdr_lib;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");
    
    PSIRP_ETL(pkt_ctx->pkt == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->pkt == NULL");

    PSIRP_ETL(pkt_ctx->pla_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->pla_hdr == NULL");
    
    PSIRP_ETL(pkt_ctx->offset == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->offset == NULL");

	if ((pla_sign_fraction != 0) && 
        (++sent_packet_count % pla_sign_fraction == 0)) {

        /* Length of headers before the PLA header */
        prefix = pkt_ctx->pkt;
        /* Length of headers before the PLA header. 
         * PLA lib requires that also 'psirpd_hdrs_t' 
         * before 'struct pla_hdr' is signed */
        prefix_len = ((u_int8_t *)pkt_ctx->pla_hdr + sizeof(psirpd_hdrs_t)) - 
            pkt_ctx->pkt;
        /* Everything is signed after the PLA header */
        payload = (u_int8_t *)pkt_ctx->pla_hdr + sizeof(psirpd_hdrs_pla_t);
        /* The offset points to the end of the carried data */ 
        payload_len = pkt_ctx->offset - payload;

        pla_hdr_lib = &pkt_ctx->pla_hdr->pla_hdr_lib;

        PSIRP_DEBUG(PSIRP_DBG_GARB, "Calling libpla_pla_header_add()...");
#ifdef PSIRP_PLA
		libpla_pla_header_add(pla_hdr_lib, 
                              prefix, 
                              prefix_len, 
                              payload, 
                              payload_len);
#endif
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Returned from libpla_pla_header_add()");
	}
    
    RETURN PSIRP_OK;
}


psirp_error_t 
psirpd_sec_pla_receive(pkt_ctx_t *pkt_ctx) {

    ENTER();

    int prefix_len = 0;
	int ret;
  
    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");
    
    PSIRP_ETL(pkt_ctx->pkt == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->pkt == NULL");

    PSIRP_ETL(pkt_ctx->pla_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->pla_hdr == NULL");

    if (pla_verify_fraction == 0) {
        RETURN PSIRP_OK;
    }

	if (++received_packet_count % pla_verify_fraction == 0) {

        /* Length of headers before the PLA header */
        prefix_len = ((u_int8_t *)pkt_ctx->pla_hdr + sizeof(psirpd_hdrs_t)) - 
            pkt_ctx->pkt;

#ifdef PSIRP_PLA
		ret = libpla_pla_receive((u_int8_t*)pkt_ctx->pkt,
                                 pkt_ctx->pkt_len, 
                                 prefix_len, 0);
#else
                ret = PLA_SIG_OK;
#endif

		if (!(ret & PLA_SIG_OK)) {
            /* Invalid signature => just drop the packet */
			RETURN PSIRP_FAIL_DROP_PACKET;
        }

		/* More checks according to policy */

	}

    RETURN PSIRP_OK;
}

psirp_error_t 
psirpd_sec_pla_disable(pkt_ctx_t *pkt_ctx) {
    pkt_call_t *call = NULL;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_ETL(pkt_ctx->handler == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->handler == NULL");

    PSIRP_ETL(pkt_ctx->handler->call == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->handler->call == NULL");
    
    call = &pkt_ctx->handler->call[pkt_ctx->handler_call_cnt];

    /* Jump over the PLA related calls in the state machine */
    if (call->handler == &psirpd_sec_pla_add ||
        call->handler == &psirpd_sec_pla_receive) {
        pkt_ctx->handler_call_cnt++;
    }

    RETURN PSIRP_OK;
}
