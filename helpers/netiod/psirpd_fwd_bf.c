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
//#include <errno.h>
#include <string.h>
#include <unistd.h>
//#include <net/ethernet.h>
//#include <netinet/in.h>
//#include <sys/queue.h>

/* psirpd_net.h */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>

#include <sys/param.h>
#include <libpsirp.h>
#include "../../libpsirp/src/psirp_debug.h"

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_hdrs.h"
#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"
#include "psirpd_fwd_bf.h"
#include "psirpd_config.h"


static psirp_fid_t empty_bf = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00}
};

/*
static u_int8_t full_bf[PSIRP_FID_LEN] = 
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff};
*/
//static void psirpd_fwd_bf_set_broadcast(psirp_fid_t*); 
if_list_item_t * psirpd_fwd_get_virtual();

psirp_error_t
psirpd_fwd_bf_init(void) {

    ENTER();

    PSIRP_EF(psirpd_net_register(&psirpd_fwd_add_bf_to_iface));

    RETURN PSIRP_OK;
}


void
psirpd_fwd_bf_cleanup(void)
{
    ENTER();

    RETURN;
}


psirp_error_t 
psirpd_fwd_add_bf_to_iface(if_list_item_t *ifli) {
    
    int i=0;
    int block=0;
    psirp_fid_t *bf_ptr;
    u_int64_t bf[4] = {0,0,0,0};
    u_int64_t tmp;

    ENTER();

    srand((u_int32_t)getpid());

    /* XXX. replace the bf generation below with a real
     * bf algorithm */

    /* If the configuration file was read, use it, otherwise
       use the old random-method */

    if (psirpd_config_ok()) {
        if ( NULL == (bf_ptr = psirpd_config_get_bf(ifli->iface_name))) {
            PSIRP_DEBUG(PSIRP_DBG_ERR, "Config: No BF found for %s.\n", 
                        ifli->iface_name);
        } else {
            memcpy(&ifli->lid, bf_ptr, PSIRP_FID_LEN);
        }
    } else {
#define NUMBER_OF_ONES 6
        for (i=0; i<NUMBER_OF_ONES; i++) {
            block = rand();
            PSIRP_DEBUG(PSIRP_DBG_GARB, "block: %d",block%4); 
            switch (block%4) {
            case 0:
                tmp = 1;
                tmp = tmp << (rand()%63);
                bf[0] |= tmp;
                break;
            case 1:
                tmp = 1;
                tmp = tmp << (rand()%63);
                bf[1] |= tmp;
                break;
            case 2:
                tmp = 1;
                tmp = tmp << (rand()%63);
                bf[2] |= tmp;
                break;
            case 3:
                tmp = 1;
                tmp = tmp << (rand()%63);
                bf[3] |= tmp;
                break;
            default:
                break;
            }
        }
        memcpy(&ifli->lid, (u_int8_t *)bf, PSIRP_FID_LEN);
    }



    PSIRP_DEBUG_HEXDUMP(&ifli->lid.id[0], PSIRP_FID_LEN, 
                        "bloom ID of the interface: %s\n",
                        ifli->iface_name); 

    RETURN PSIRP_OK;
}

psirp_error_t 
psirpd_fwd_bf_handler(pkt_ctx_t *pkt_ctx) {

    psirpd_hdrs_fwhdr_t *fwhdr;
    if_list_item_t *iface_out;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    fwhdr = pkt_ctx->fwd_hdr; 
    PSIRP_ETL(fwhdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->fwd_hdr == NULL");
    PSIRP_DEBUG_HEXDUMP(fwhdr->fid.id,PSIRP_FID_LEN, 
                        "FID of the fwd header"); 

    pkt_ctx->iface_out_cnt=0;

    PSIRP_DEBUG(PSIRP_DBG_GARB, "Got packet for bf handling\n");

    if (--fwhdr->ttl == 0) {
        /* XXX: What about the virtual interface? */
        PSIRP_DEBUG(PSIRP_DBG_GARB, "TTL <= 0, dropping packet\n");
        goto psripd_fwd_bf_handlers_err;
    }

    LIST_FOREACH(iface_out, &if_list_head, entries) {
        psirp_fid_t *fidp = &fwhdr->fid;
        psirp_fid_t *lidp = &iface_out->lid;
        
        int forward = 1;
        int i = 0;
        int bitcount = 0;

        /* We are not interested about the incoming iface */
        if (iface_out == pkt_ctx->iface_in) {
            /* NOT forwarding on incoming interface */
            continue;
        }

        for (i = 0; i < PSIRP_FID_LEN; i++) {
            bitcount += __builtin_popcount(fidp->id[i]); /* count 1-bits */
            if ((bitcount > PSIRP_MAX_FID_ONES) /* security/safety check */
                || ((fidp->id[i] & lidp->id[i]) != lidp->id[i])) /* zF alg. */
            {
                forward = 0; // FID does not match this interface id
                break;
            }
        }

        if (!forward) {
            PSIRP_DEBUG(PSIRP_DBG_GARB, "NOT forwarding on outgoing "
                        "interface: %s\n", iface_out->iface_name);
            continue;
        }

        PSIRP_DEBUG(PSIRP_DBG_GARB, "Forwarding on outgoing "
                    "interface: %s\n", iface_out->iface_name);

#if 0
        if (fwhdr->nxt_hdr == PSIRP_HDR_RZV_PUBLISH_DATACHUNK) {
            PSIRP_DEBUG(PSIRP_DBG_INFO, "%lu", pkt_ctx->rzv_hdr->seqnum);
        }
#endif

        /* Add outgoing iface to the packet context */
        pkt_ctx->iface_out[pkt_ctx->iface_out_cnt] = iface_out;
        pkt_ctx->iface_out_cnt++;
        PSIRP_ETL(pkt_ctx->iface_out_cnt >= PSIRP_MAX_NO_IFACES,
                  PSIRP_FAIL_OUT_OF_BUFFER, PSIRP_DBG_ERR,
                  "PSIRP_MAX_NO_IFACES '%d' too small\n", 
                  PSIRP_MAX_NO_IFACES);
        

    }

psripd_fwd_bf_handlers_err:
    if (0 == pkt_ctx->iface_out_cnt) {
        PSIRP_DEBUG(PSIRP_DBG_GARB, "No BF match with outgoing interfaces");
        //RETURN PSIRP_FAIL_FWD_NO_IFACES_OUT;
    }

    RETURN PSIRP_OK;
}

static inline int
psirpd_fwd_bf_is_zero(psirp_fid_t *fid) {    
    return (0 == psirp_idcmp(fid, &empty_bf));
}

psirp_error_t 
psirpd_fwd_bf_out(pkt_ctx_t *pkt_ctx) {
    struct psirpd_hdrs_fwhdr *fwd_hdr;
    psirp_fid_t *deffid = NULL;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    fwd_hdr = pkt_ctx->fwd_hdr; 
    PSIRP_ETL(fwd_hdr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->fwd_hdr == NULL");

    /* TODO: Find the missing fid using the received subscriber ID.
     * If the subscriber ID is zero then use broadcast fid. 
     * Security acpects must be analyzed before that. 
     * Currently, if BF is zero use broadcast BF */

    /* PJ: put "default route" instead of NULL in the FID field */

    if (psirpd_fwd_bf_is_zero(&fwd_hdr->fid)) {
        deffid = psirpd_config_get_def();
        //       PSIRP_DEBUG_HEXDUMP(deffid ,PSIRP_FID_LEN, 
        //              "The default route put into the packet"); 

        PSIRP_ETL(deffid == NULL, PSIRP_FAIL_NULL_POINTER, 
                  PSIRP_DBG_ERR, "default route == NULL");
        PSIRP_DEBUG_HEXDUMP(deffid,PSIRP_FID_LEN, 
                            "Putting FID in the header"); 
        memcpy(&fwd_hdr->fid, deffid, PSIRP_FID_LEN);
        
        //psirpd_fwd_bf_set_broadcast(&fwd_hdr->fid);
    } 
        
    RETURN PSIRP_OK;

}

#if 0
static void
psirpd_fwd_bf_set_broadcast(psirp_fid_t *fid) {


    ENTER();

    memcpy(fid, &full_bf, sizeof(full_bf));

    RETURN;
}
#endif 

psirp_error_t 
psirpd_fwd_fidcollect(pkt_ctx_t *pkt_ctx) {

    psirpd_hdrs_metadata_t *metahdr;
    int i=0;
    u_int8_t tmp1, tmp2, tmp3;
    if_list_item_t *ifli = NULL;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    metahdr = pkt_ctx->md_hdr; 

    PSIRP_DEBUG(PSIRP_DBG_GARB, "Got packet for fid collecting\n");

    /* TBD: add only for Publish and Subscribe packets */

    if (metahdr == NULL) {
        RETURN PSIRP_OK;
    }

    if(pkt_ctx->iface_in == NULL) {
	if (metahdr->flags & PSIRP_DONT_ADD_VIRTUAL_IF_FID) { /* XXX */
	    PSIRP_DEBUG(PSIRP_DBG_GARB,
			"NOT adding virtual interface to collected FId");
	    metahdr->flags &= ~PSIRP_DONT_ADD_VIRTUAL_IF_FID;  /* Clear */
	    RETURN(PSIRP_OK);
	}
        ifli = psirpd_fwd_get_virtual();
        PSIRP_ETL(ifli==NULL, PSIRP_FAIL_NULL_POINTER,
                  PSIRP_DBG_ERR, "ifli == NULL (virtual iface)"); 
    }

    for(i = 0; i < PSIRP_FID_LEN ; i++) {
        tmp1 = metahdr->fid.id[i];
        if (pkt_ctx->iface_in == NULL) {
            tmp2 = ifli->lid.id[i];
        } else {
            tmp2 = pkt_ctx->iface_in->lid.id[i];
        }
        tmp3 = tmp1 | tmp2;
        //PSIRP_DEBUG(PSIRP_DBG_GARB, "%d | %d = %d\n", tmp1, tmp2, tmp3);
        metahdr->fid.id[i] = tmp3;
    }

    PSIRP_DEBUG_HEXDUMP(metahdr->fid.id,PSIRP_FID_LEN, 
                        "Collected FID so far"); 

    RETURN PSIRP_OK;
}


if_list_item_t *
psirpd_fwd_get_virtual() {
    if_list_item_t *ifli = NULL;

    LIST_FOREACH(ifli, &if_list_head, entries) {
        if (ifli->is_virtual)
            return ifli;
    }
    return NULL;
}
