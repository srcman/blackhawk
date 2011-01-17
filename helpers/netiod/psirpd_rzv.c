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

/* psirpd_net.h */
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>

#include <string.h>
#include <stdlib.h>

#ifdef PSIRP_PLA
#include "libpla.h"
#endif

/* libpsirp */
#include <sys/param.h>
#include <libpsirp.h>

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_hdrs.h"
#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"
#include "psirpd_rzv.h"
#include "psirpd_sec_pla.h"
#include "psirpd_ipc.h"

#include "../../libpsirp/src/psirp_debug.h"


static u_int8_t psirpd_rzv_rid_policy = PSIRP_RZV_RID_RANDOM; 


psirp_error_t
psirpd_rzv_init(u_int8_t rid_policy) {

    ENTER();

    switch(rid_policy) {
    case PSIRP_RZV_RID_RANDOM:
    case PSIRP_RZV_RID_PLA:
        psirpd_rzv_rid_policy = rid_policy;
        break;
    default:
        PSIRP_DEBUG(PSIRP_DBG_ERR, "Unnkown RID policy type: %d", 
                    rid_policy);       
        RETURN PSIRP_FAIL_UNKNOWN_RID_POLICY;
    }

    RETURN PSIRP_OK;
}

void
psirpd_rzv_cleanup(void)
{
    ENTER();

    RETURN;
}


psirp_error_t
psirpd_rzv_create_rid(psirp_id_t *rid) {

    int i = 0;

    ENTER();

    switch(psirpd_rzv_rid_policy) {
    case PSIRP_RZV_RID_RANDOM:
        memset(rid, 0,  sizeof(psirp_id_t));
        for (i = 0; i < PSIRP_ID_LEN; i++) {
            rid->id[i] = (u_int8_t)random();
        }
        break;
    case PSIRP_RZV_RID_PLA:
        PSIRP_EF(psirpd_sec_pla_get_rid(rid));
        break;
    default:
        PSIRP_DEBUG(PSIRP_DBG_ERR, "Unknown RID policy type: %d", 
                    psirpd_rzv_rid_policy);       
        RETURN PSIRP_FAIL_UNKNOWN_RID_POLICY;
    }

    RETURN PSIRP_OK;
}






/** 
 * Handler that is called for incoming data chunk packet
 * @param pkt_ctx pointer to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_rzv_rcv_datachunk(pkt_ctx_t *pkt_ctx) {

    psirpd_hdrs_rzvhdr_t  *rzv_hdr = NULL;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");
    
    rzv_hdr = pkt_ctx->rzv_hdr;
    PSIRP_ETL(rzv_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->rzv_hdr == NULL");

    psirpd_ipc_net_handle_data(rzv_hdr, pkt_ctx->payload,
			       pkt_ctx->offset-pkt_ctx->payload); /* XXX: ? */
    
    RETURN PSIRP_OK;
}

/** 
 * Handler that is called for incoming metadata packet
 * @param pkt_ctx pointer to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_rzv_rcv_metadata(pkt_ctx_t *pkt_ctx) {
    
    psirpd_hdrs_metadata_t *md_hdr = NULL;
    //psirpd_hdrs_rzvhdr_t  *rzv_hdr = NULL;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");
    
    md_hdr = pkt_ctx->md_hdr;
    PSIRP_ETL(md_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->md_hdr == NULL");

#if 0
    rzv_hdr = pkt_ctx->rzv_hdr;
    PSIRP_ETL(rzv_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->rzv_hdr == NULL");
    /* We should not ignore the RZV header. For example, we could take
     * the SId and RId and publish the rest of the packet with those
     * Ids and expect that some entity will process the packet
     * further. */
#endif

    PSIRP_DEBUG(PSIRP_DBG_GARB, "md_hdr->len = %lu", md_hdr->len);

    PSIRP_EF(psirpd_ipc_net_handle_metadata(md_hdr));

    RETURN PSIRP_OK;
}

/** 
 * Handler that is called for incoming data subscription packet
 * @param pkt_ctx pointer to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_rzv_rcv_subscribe_data(pkt_ctx_t *pkt_ctx) {
    
    psirpd_hdrs_metadata_t *md_hdr = NULL;
    //out_q_list_item_t *out_q_item = NULL;
    //int size;

#if 0
    psirpd_hdrs_rzvhdr_t  *rzv_hdr = NULL;
#endif

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    md_hdr = pkt_ctx->md_hdr;
    PSIRP_ETL(md_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->md_hdr == NULL");

#if 0
    rzv_hdr = pkt_ctx->rzv_hdr;
    PSIRP_ETL(rzv_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->rzv_hdr == NULL");
#endif

    psirpd_ipc_net_handle_metadata(md_hdr);
    
    RETURN PSIRP_OK;
}

/** 
 * Handler that is called for incoming metadata subscription packet
 * @param pkt_ctx pointer to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_rzv_rcv_subscribe_metadata(pkt_ctx_t *pkt_ctx) {
    
    //psirpd_hdrs_rzvhdr_t  *rzv_hdr;
    psirpd_hdrs_metadata_t *md_hdr;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    md_hdr = pkt_ctx->md_hdr;
    PSIRP_ETL(md_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->md_hdr == NULL");

#if 0
    rzv_hdr = pkt_ctx->rzv_hdr;
    PSIRP_ETL(rzv_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->rzv_hdr == NULL");
              PSIRP_DBG_ERR, "pkt_ctx->rzv_hdr == NULL");
    /* We should not ignore the RZV header. For example, we could take
     * the SId and RId and publish the rest of the packet with those
     * Ids and expect that some entity will process the packet
     * further. */
#endif

    PSIRP_EF(psirpd_ipc_net_handle_metadata(md_hdr));

    RETURN PSIRP_OK;
}

/** 
 * Handler that is called for outgoing data chunk or 
 * metadata subscription packet.
 * @param pkt_ctx pointer to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_rzv_snd_subscribe(pkt_ctx_t *pkt_ctx) { /* XXX: ? */

    ENTER();
    /* done in psirpd_packet_out_* */
    RETURN PSIRP_OK;
}

/** 
 * Handler that is called for outgoing metadata packet
 * @param pkt_ctx pointer to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_rzv_snd_metadata(pkt_ctx_t *pkt_ctx) { /* XXX: ? */

    ENTER();    
    RETURN PSIRP_OK;
}

