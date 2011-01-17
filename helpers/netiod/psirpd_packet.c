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
#include <errno.h>
#include <string.h>
//#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/in.h>
//#include <sys/queue.h>

/* psirpd_net.h */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <sys/ioctl.h>

/* kqueue/kevent */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

/* libpsirp */
#include <sys/param.h>
#include <libpsirp.h>

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
#include "psirpd_sec_pla.h"
#include "psirpd_rzv.h"
#include "../../libpsirp/src/psirp_debug.h"


/* Exception handlers are introduced here */
static pkt_handler_t* psirpd_packet_except_rzv(pkt_ctx_t*, psirp_error_t);
static pkt_handler_t* psirpd_packet_except_out(pkt_ctx_t *, psirp_error_t); 
static pkt_handler_t* psirpd_packet_except_drop(pkt_ctx_t*, psirp_error_t);

static u_int32_t psirp_pkt_ctx_id = 1;

struct state_hook_list_item {
    LIST_ENTRY(state_hook_list_item) entries;
    psirp_error_t (*call)(pkt_ctx_t*);
};
typedef struct state_hook_list_item state_hook_list_item_t;

LIST_HEAD(state_hook_list, state_hook_list_item) state_hook_list_head;

/* States are introduced here */
pkt_handler_t pkt_handler_in_default;
pkt_handler_t pkt_handler_in_virtual;
pkt_handler_t pkt_handler_rcv_datachunk;
pkt_handler_t pkt_handler_rcv_metadata;
pkt_handler_t pkt_handler_rcv_subscribe_data;
pkt_handler_t pkt_handler_rcv_subscribe_metadata;
pkt_handler_t pkt_handler_out;
pkt_handler_t pkt_handler_snd_subscribe_metadata;
pkt_handler_t pkt_handler_snd_subscribe_data;
pkt_handler_t pkt_handler_snd_metadata;
pkt_handler_t pkt_handler_drop;

/* 
 * STATES for incoming packets 
 */ 

pkt_handler_t pkt_handler_in_default = {
    "STATE: in_default",
    {{&psirpd_fwd_bf_handler, &psirpd_packet_except_drop},
     {&psirpd_sec_pla_receive, &psirpd_packet_except_drop},
     {&psirpd_fwd_fidcollect, &psirpd_packet_except_drop},
     {&psirpd_net_out, &psirpd_packet_except_drop},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_in_virtual = {
    "STATE: in_virtual",
    {{NULL, &psirpd_packet_except_rzv},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_rcv_datachunk = {
    "STATE: rcv_datachunk",
    {{&psirpd_rzv_rcv_datachunk, &psirpd_packet_except_drop},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_rcv_metadata = {
    "STATE: rcv_metadata",
    {{&psirpd_rzv_rcv_metadata, &psirpd_packet_except_drop},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_rcv_subscribe_data = {
    "STATE: rcv_subscribe_data",
    {{&psirpd_rzv_rcv_subscribe_data, &psirpd_packet_except_drop},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_rcv_subscribe_metadata = {
    "STATE: rcv_subscribe_metadata",
    {{&psirpd_rzv_rcv_subscribe_metadata, &psirpd_packet_except_drop},
     {NULL, NULL}}
};

/* 
 * STATES for outgoing packets 
 */ 

pkt_handler_t pkt_handler_out = {
    "STATE: snd_out",
    {{&psirpd_fwd_bf_out, &psirpd_packet_except_drop},
     {&psirpd_fwd_bf_handler, &psirpd_packet_except_drop},
     {&psirpd_sec_pla_add,  &psirpd_packet_except_drop},
     {&psirpd_fwd_fidcollect, &psirpd_packet_except_drop},
     {&psirpd_net_out, &psirpd_packet_except_drop},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_snd_subscribe_metadata = {
    "STATE: snd_subscribe_metadata",
    {{&psirpd_rzv_snd_subscribe, &psirpd_packet_except_drop},
     {NULL, &psirpd_packet_except_out},
     {NULL, NULL}}
};

pkt_handler_t pkt_handler_snd_subscribe_data = {
    "STATE: snd_subscribe_data",
    {{&psirpd_rzv_snd_subscribe, &psirpd_packet_except_drop},
     {NULL, &psirpd_packet_except_out},
     {NULL, NULL}}
};


pkt_handler_t pkt_handler_snd_metadata = {
    "STATE: snd_metadata",
    {{&psirpd_rzv_snd_metadata, &psirpd_packet_except_drop},
     {NULL, &psirpd_packet_except_out},
     {NULL, NULL}}
};

/* 
 * STATES for failures 
 */ 

pkt_handler_t pkt_handler_drop = {
    "STATE: drop",
    {{NULL,NULL}}
};


static pkt_ctx_t* psirpd_packet_create_ctx(u_int8_t*, 
                                           u_int32_t,
                                           pkt_handler_t*); 

psirp_error_t
psirpd_packet_init(void) {

    ENTER();

    LIST_INIT(&state_hook_list_head); 
    PSIRP_EF(psirpd_net_register(&psirpd_packet_add_iface));

    RETURN PSIRP_OK;
}


void
psirpd_packet_cleanup(void) {
    state_hook_list_item_t *sp, *sp2;

    ENTER();
    
	LIST_FOREACH_SAFE(sp, &state_hook_list_head, entries, sp2) {
        LIST_REMOVE(sp, entries);
        PSIRP_FREE(sp);
    }

    RETURN;
}

psirp_error_t
psirpd_packet_register(psirp_error_t (*call)(pkt_ctx_t*)) {

    state_hook_list_item_t *p = NULL;

    ENTER();

    PSIRP_ETL(call == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "call == NULL");

    PSIRP_MALLOC(p, sizeof(state_hook_list_item_t));
    memset(p, 0, sizeof(state_hook_list_item_t));

    p->call = call;

    LIST_INSERT_HEAD(&state_hook_list_head, p, entries);

    RETURN PSIRP_OK;
}

psirp_error_t 
psirpd_packet_add_iface(if_list_item_t *ifli) {

    ENTER();

    PSIRP_ETL(ifli == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "ifli == NULL");

    if (ifli->is_virtual) {
        ifli->handler = &pkt_handler_in_virtual; 
    } else {
        ifli->handler = &pkt_handler_in_default; 
    }

    RETURN PSIRP_OK;
}


/** 
 * Called for outgoing packets
 * @param handler pointer to the packet handler
 * @return packet context
 */
pkt_ctx_t*
psirpd_packet_create_ctx_out(pkt_handler_t *handler) {
#if 0
                             psirp_pub_t pub) {
#endif
    pkt_ctx_t *pkt_ctx = NULL;
    u_int8_t *buf = NULL;    
    //    u_int32_t buf_len = ETHER_MAX_LEN_JUMBO; 
    u_int32_t buf_len = 1480;

    ENTER();

    if (handler == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "handler == NULL");
        RETURN NULL;
    }

    PSIRP_MALLOC(buf, buf_len);
    memset(buf, 0, buf_len);

    pkt_ctx = psirpd_packet_create_ctx(buf, buf_len, handler);
    if (pkt_ctx == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "pkt_ctx == NULL");
        RETURN NULL;
    }

#if 0
    pkt_ctx->pub = pub;
#endif

    RETURN pkt_ctx;
}


/** 
 * Called for incoming packets.
 * @param buf pointer to the packet buffer
 * @param buf_len length of the packet buffer
 * @param handler pointer to the packet handler
 * @return packet context
 */
pkt_ctx_t*
psirpd_packet_create_ctx_in(u_int8_t *buf, 
                            u_int32_t buf_len,
                            if_list_item_t *iface_in) {

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    if (buf == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "buf == NULL");
        RETURN NULL;
    }

    if (buf_len == 0) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "Incorrect buffer length: %d", buf_len);
        RETURN NULL;
    }

    if (iface_in == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "iface_in == NULL");
        RETURN NULL;
    }

    pkt_ctx = psirpd_packet_create_ctx(buf, buf_len, iface_in->handler);
    if (pkt_ctx == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "pkt_ctx == NULL");
        RETURN NULL;
    }

    pkt_ctx->iface_in = iface_in;

    RETURN pkt_ctx;
}


/** 
 * Function allocates memory for packet context.
 * Called from psirpd_packet_create_ctx_out() and 
 * psirpd_packet_create_ctx_in().
 * @param buf pointer to the packet buffer
 * @param buf_len length of the packet buffer
 * @param handler pointer to the packet handler
 * @return packet context
 */
static pkt_ctx_t*
psirpd_packet_create_ctx(u_int8_t *buf, 
                         u_int32_t buf_len,
                         pkt_handler_t *handler) {

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    if (buf == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "buf == NULL");
        RETURN NULL;
    }

    if (buf_len == 0) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "Incorrect buffer length: %d", buf_len);
        RETURN NULL;
    }

    if (handler == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "handler == NULL");
        RETURN NULL;
    }

    PSIRP_MALLOC(pkt_ctx, sizeof(pkt_ctx_t));
    memset(pkt_ctx, 0, sizeof(pkt_ctx_t));

    pkt_ctx->ctx_id = psirp_pkt_ctx_id++; 
    pkt_ctx->handler = handler;
    pkt_ctx->pkt = buf;
    pkt_ctx->offset = buf;
    pkt_ctx->pkt_len = buf_len;

    RETURN pkt_ctx;
}


/** 
 * Called for outgoing packets
 * @param pkt_ctx pointer to the packet context
 * @return void
 */
void
psirpd_packet_free_ctx_out(pkt_ctx_t *pkt_ctx) {

    ENTER();

    if (pkt_ctx){

        if (pkt_ctx->pkt) {
            PSIRP_FREE(pkt_ctx->pkt);
        }

        PSIRP_FREE(pkt_ctx);
    }

    RETURN;
}

/** 
 * Called for incoming packets.
 * @param pkt_ctx pointer to the packet context
 * @return void
 */
void
psirpd_packet_free_ctx_in(pkt_ctx_t *pkt_ctx) {

    ENTER();
    
    PSIRP_FREE(pkt_ctx);

    RETURN;
}

psirp_error_t
psirpd_packet_preparse(pkt_ctx_t *pkt_ctx) {

    psirpd_hdrs_t *hdr_p = NULL;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_ETL(pkt_ctx->offset == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx->offset == NULL");

    do {
        hdr_p = (psirpd_hdrs_t*)pkt_ctx->offset;

        switch(hdr_p->hdr_type) {
        case PSIRP_HDR_FWD_BF:
            pkt_ctx->fwd_hdr = (psirpd_hdrs_fwhdr_t*)pkt_ctx->offset;
            pkt_ctx->offset += sizeof(psirpd_hdrs_fwhdr_t);
            break;
        case PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK:
        case PSIRP_HDR_RZV_SUBSCRIBE_METADATA:
        case PSIRP_HDR_RZV_PUBLISH_DATACHUNK:
        case PSIRP_HDR_RZV_PUBLISH_METADATA:
            pkt_ctx->rzv_hdr = (psirpd_hdrs_rzvhdr_t*)pkt_ctx->offset;
            pkt_ctx->offset += sizeof(psirpd_hdrs_rzvhdr_t);
            break;
        case PSIRP_HDR_MD:
            pkt_ctx->md_hdr = (psirpd_hdrs_metadata_t*)pkt_ctx->offset;
            pkt_ctx->offset += sizeof(psirpd_hdrs_metadata_t);
            break;
        case PSIRP_HDR_SEC_PLA:
            pkt_ctx->pla_hdr = (psirpd_hdrs_pla_t*)pkt_ctx->offset;
            pkt_ctx->offset += sizeof(psirpd_hdrs_pla_t);
	    break;
        default:
            PSIRP_DEBUG(PSIRP_DBG_GARB,
			"Unknown hdr: %02x\n", hdr_p->hdr_type);
            RETURN PSIRP_FAIL_UNKNOWN_HDR;
        }
    } while (hdr_p->nxt_hdr && hdr_p->nxt_hdr != PSIRP_PAYLOAD);

    if (hdr_p->nxt_hdr == PSIRP_PAYLOAD) {
        pkt_ctx->payload = pkt_ctx->offset;
    }

    /* Finally, set offset pointing to the end of the payload */
    pkt_ctx->offset = pkt_ctx->pkt + pkt_ctx->pkt_len;

    PSIRP_DEBUG(PSIRP_DBG_GARB, "Received packet: [%s]", 
		psirpd_packet_get_headers(pkt_ctx));

    RETURN PSIRP_OK;
}

/** 
 * State machine for packet handling
 * @param pkt_ctx poitnter to the packet context
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_packet_state_machine(pkt_ctx_t *pkt_ctx) {

    state_hook_list_item_t *state_hook = NULL;
    psirp_error_t retval = PSIRP_OK;
    int cnt = 0;

    ENTER();

    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_DEBUG(PSIRP_DBG_GARB, "State Machine of ctx %d STARTs in %s", 
                pkt_ctx->ctx_id, pkt_ctx->handler->name);

    /* Calling packet handlers and exceptions */
    for (cnt = pkt_ctx->handler_call_cnt = 0;
         pkt_ctx->handler->call[cnt].handler ||
             pkt_ctx->handler->call[cnt].exception;
         cnt = ++pkt_ctx->handler_call_cnt) {

        PSIRP_DEBUG(PSIRP_DBG_GARB, 
                    "cnt: %d, pkt_ctx->handler_call_cnt: %d", 
                    cnt, pkt_ctx->handler_call_cnt);


        /* These hooks are primarily for testing purposes.
         * the registered functions may change the normal 
         * call path either by increasing the pkt_ctx->handler_call_cnt or
         * changing the whole state */
        LIST_FOREACH(state_hook, &state_hook_list_head, entries) {
            PSIRP_EFLM(state_hook->call(pkt_ctx), PSIRP_DBG_ERR, 
                       "Hook failed.");
            /* The hook may have changed the handler_call_cnt */
            cnt = pkt_ctx->handler_call_cnt;
        }

        if (pkt_ctx->handler->call[cnt].handler) {

            /* We call the handler function */
            retval = pkt_ctx->handler->call[cnt].handler(pkt_ctx);

            /* In success, we continue the loop and call the the next handler
             * function */
            if (PSIRP_OK == retval) {
                continue;
            } 
        }

        if (pkt_ctx->handler->call[cnt].exception) {

            /* Exception results in state transition */
            pkt_ctx->handler = pkt_ctx->handler->call[cnt].exception(pkt_ctx,
                                                                     retval);

            PSIRP_ETL(pkt_ctx->handler == NULL, PSIRP_FAIL_NULL_POINTER, 
                      PSIRP_DBG_ERR, "pkt_ctx->handler == NULL");

            PSIRP_DEBUG(PSIRP_DBG_GARB, 
                        "State Machine of ctx %d TRANSITION to %s", 
                        pkt_ctx->ctx_id,  pkt_ctx->handler->name);

            pkt_ctx->handler_call_cnt = -1;
            continue;
        }

        /* At the end of the call list */
        break;
    }

    PSIRP_DEBUG(PSIRP_DBG_GARB, "State Machine of ctx %d STOPs in %s",
                pkt_ctx->ctx_id, pkt_ctx->handler->name);

    RETURN retval;
}

/** 
 * Handler that is called for incoming packet
 * @param pkt pointer to the packet buffer
 * @param pkt_len length of the packet buffer
 * @param iface_in Pointer to the intefarce descriptor from which 
 *                 packet was received
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_packet_in(u_int8_t *pkt, u_int32_t pkt_len, if_list_item_t *iface_in) {
    /*
     * XXX: We could call this function with packet data acquired from
     *      recvfrom. The interface data must of course be properly
     *      initialized. (?)
     */

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    PSIRP_ETL(NULL == pkt,  PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "Incoming packet is NULL\n");

    PSIRP_ETL(0 == pkt_len || ETHER_MAX_LEN_JUMBO < pkt_len,   
	      PSIRP_FAIL_OUT_OF_RANGE, PSIRP_DBG_ERR, 
	      "Incorrect packet length: %d", pkt_len);

    PSIRP_ETL(NULL == iface_in,   PSIRP_FAIL_NULL_POINTER,
              PSIRP_DBG_ERR, "Incoming interface is NULL\n");
        
    pkt_ctx = psirpd_packet_create_ctx_in(pkt, pkt_len, iface_in);
    PSIRP_ETL(NULL == pkt_ctx, PSIRP_FAIL_NULL_POINTER,
              PSIRP_DBG_ERR, "Packet context is NULL\n");

    PSIRP_EF(psirpd_packet_preparse(pkt_ctx));
    PSIRP_EF(psirpd_packet_state_machine(pkt_ctx));
    psirpd_packet_free_ctx_in(pkt_ctx);

    RETURN PSIRP_OK;
}


/** 
 * Function that is called for outgoing metadata subscriptions
 * @param pub pointer to the publication 
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_packet_out_submetadata(psirp_id_t *sidp,
			      psirp_id_t *ridp,
			      psirp_id_t *vridp,
			      psirp_fid_t *fidp,
                              ps_flags_t flags) {

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    pkt_ctx = 
        psirpd_packet_create_ctx_out(&pkt_handler_snd_subscribe_metadata);
    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_ECB(psirpd_init_fwd_hdr(pkt_ctx,
                                  fidp),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create forwarding header");

    PSIRP_ECB(psirpd_init_rzv_hdr(pkt_ctx,
                                  PSIRP_HDR_RZV_SUBSCRIBE_METADATA,
                                  NULL /* SID */,
                                  NULL /* RID */,
                                  NULL /* VRID */,
                                  0 /* seqnum */),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create rendezvous header");

    PSIRP_ECB(psirpd_init_md_hdr(pkt_ctx,
                                 sidp,
                                 ridp,
                                 vridp, /* VRID */
                                 NULL /* FID */,
                                 0 /* len */,          
                                 0 /* max_seqnum */),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create metadata header");
    if (flags) {
        pkt_ctx->md_hdr->flags |= flags & PS_FLAGS_MASK_NET; /* lowest byte */
    }

    PSIRP_ECB(psirpd_init_pla_hdr(pkt_ctx),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create PLA header");

    PSIRP_EF(psirpd_packet_state_machine(pkt_ctx));
    psirpd_packet_free_ctx_out(pkt_ctx);

    RETURN PSIRP_OK;
}

/** 
 * Function that is called for outgoing data subscriptions
 * @param pub pointer to the publication 
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_packet_out_subdata(psirp_id_t *sidp,
			  psirp_id_t *ridp,
			  psirp_id_t *vridp,
			  psirp_fid_t *md_fidp,
			  psirp_fid_t *fidp,
			  u_int8_t relay /* XXX */) {

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    pkt_ctx = psirpd_packet_create_ctx_out(&pkt_handler_snd_subscribe_data);
    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_ECB(psirpd_init_fwd_hdr(pkt_ctx, 
                                  fidp),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create forwarding header");

    PSIRP_ECB(psirpd_init_rzv_hdr(pkt_ctx,
                                  PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK,
                                  NULL /* SID */,
                                  NULL /* RID */,
                                  NULL /* VRID */,
                                  0 /* seqnum */),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create rendezvous header");

    PSIRP_ECB(psirpd_init_md_hdr(pkt_ctx,
                                 sidp,
                                 ridp,
                                 vridp, /* VRID */
                                 md_fidp,
                                 0 /* len */,       
                                 0 /* max_seqnum */),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create metadata header");
    /* XXX */
    if (relay) {
	pkt_ctx->md_hdr->flags |= PSIRP_DONT_ADD_VIRTUAL_IF_FID;
    }

    PSIRP_ECB(psirpd_init_pla_hdr(pkt_ctx),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create PLA header");

    PSIRP_EF(psirpd_packet_state_machine(pkt_ctx));
    psirpd_packet_free_ctx_out(pkt_ctx);

    RETURN PSIRP_OK;

}

/** 
 * Function is called for outgoing metadata packet
 * (@param pub pointer to the publication)
 * @param rid pointer to Rendezvous ID
 * @param sid pointer to Scope ID
 * @param fid pointer to Forwarding ID
 * @param len publication length
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t 
psirpd_packet_out_metadata(psirp_id_t *sidp,
			   psirp_id_t *ridp,
			   psirp_id_t *vridp,
			   psirp_id_t *fidp,
			   u_int64_t pub_len) {

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    PSIRP_ETL(ridp == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "rid == NULL");

    pkt_ctx = psirpd_packet_create_ctx_out(&pkt_handler_snd_metadata);
    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_ECB(psirpd_init_fwd_hdr(pkt_ctx, fidp),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create forwarding header");

    PSIRP_ECB(psirpd_init_rzv_hdr(pkt_ctx,
                                  PSIRP_HDR_RZV_PUBLISH_METADATA,
                                  NULL /* SId */,
                                  NULL /* RId */,
                                  NULL /* VRId */,
                                  0 /* seqnum */),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create rendezvous header");

    PSIRP_ECB(psirpd_init_md_hdr(pkt_ctx,
                                 sidp,
                                 ridp,
                                 vridp, /* VRId */
                                 NULL,   /* FId */
                                 pub_len,          
                                 0 /* XXX */),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create metadata header");

    PSIRP_ECB(psirpd_init_pla_hdr(pkt_ctx),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create PLA header");

    PSIRP_EF(psirpd_packet_state_machine(pkt_ctx));
    psirpd_packet_free_ctx_out(pkt_ctx);
    
    RETURN PSIRP_OK;
}

psirp_error_t 
psirpd_packet_out_queuechunks(psirp_id_t *sidp,
			      psirp_id_t *ridp,
			      psirp_id_t *vridp,
			      psirp_fid_t *fidp) {
    
    psirp_pub_t *vpubp = NULL;
    int64_t pub_data_len;
    int *countp;
    int chunk_count;
    int i;
    out_q_list_item_t *out_q_item;
    
    ENTER();
    
    PSIRP_MALLOC(vpubp, sizeof(psirp_pub_t));
    *vpubp = NULL;
    PSIRP_MALLOC(countp, sizeof(int));
    *countp = 0;
    
    /* Subscribe to the given version (we don't bother to check the scope) */
    PSIRP_ETL(0 != psirp_subscribe_with_flags(ridp, vridp, vpubp,
                                              PS_FLAGS_LOCAL_LOCALSUB),
              PSIRP_FAIL,
              PSIRP_DBG_ERR,
              "psirp_subscribe(): [%d] %s", errno, strerror(errno));
    /* Note: *vpubp and vpubp are freed later, when all chunks have been sent */
    
    pub_data_len = psirp_pub_data_len(*vpubp);
    chunk_count = (int)(pub_data_len / PSIRP_CHUNK_SIZE); /* XXX */
    chunk_count += (pub_data_len % PSIRP_CHUNK_SIZE != 0) ? 1 : 0;
    *countp = chunk_count-1;
    
    for (i = chunk_count-1; i >= 0; i--) {
	out_q_item = psirpd_out_q_create_item(sidp, ridp, vridp, fidp,
                                              vpubp, countp, (u_int64_t)i);
	psirpd_out_q_add_item(out_q_item);
        /* Note that the item might have been freed when it was added. */
    }
    
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Queued %d chunks", chunk_count);
    
    PSIRP_EF(psirpd_out_q_send()); /* XXX: ? */
    
    RETURN(PSIRP_OK);
}

psirp_error_t 
psirpd_packet_out_data(u_int8_t *addr, 
		       int len, 
		       out_q_list_item_t *item) {
    

    pkt_ctx_t *pkt_ctx = NULL;

    ENTER();

    PSIRP_ETL(addr == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "addr == NULL");

    PSIRP_ETL(0 == len || ETHER_MAX_LEN_JUMBO < len,   
              PSIRP_FAIL_OUT_OF_RANGE, PSIRP_DBG_ERR, 
              "Incorrect length: %d", len);

    PSIRP_ETL(item == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "item == NULL");

    pkt_ctx = psirpd_packet_create_ctx_out(&pkt_handler_out);
    PSIRP_ETL(pkt_ctx == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "pkt_ctx == NULL");

    PSIRP_ECB(psirpd_init_fwd_hdr(pkt_ctx, 
                                  &item->fid),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create forwarding header");

    PSIRP_ECB(psirpd_init_rzv_hdr(pkt_ctx,
                                  PSIRP_HDR_RZV_PUBLISH_DATACHUNK,
                                  &item->sid,
                                  &item->rid,    
                                  &item->vrid,
				  item->seqnum),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create rendezvous header");
    
    PSIRP_ECB(psirpd_init_pla_hdr(pkt_ctx),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot create PLA header");

    PSIRP_ECB(psirpd_init_payload(pkt_ctx, addr, len),
              {psirpd_packet_free_ctx_out(pkt_ctx);},
              "Cannot add payload");

    PSIRP_DEBUG(PSIRP_DBG_GARB, "len=%ld", (pkt_ctx->offset - pkt_ctx->pkt));
    
    PSIRP_EF(psirpd_packet_state_machine(pkt_ctx));
    psirpd_packet_free_ctx_out(pkt_ctx);

    RETURN PSIRP_OK;
}

/*
 * Exception handlers
 */


static pkt_handler_t* 
psirpd_packet_except_rzv(pkt_ctx_t *pkt_ctx, psirp_error_t retval) {
    
    pkt_handler_t *handler_new = NULL;
    uint8_t msg_type = 0;

    ENTER();
   
    if (pkt_ctx == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "pkt_ctx == NULL");
        RETURN NULL;
    }
    
    if (pkt_ctx->rzv_hdr == NULL) {
        PSIRP_DEBUG(PSIRP_DBG_ERR, "pkt_ctx->rzv_hdr == NULL");
        RETURN NULL;
    }
 
    msg_type = pkt_ctx->rzv_hdr->hdr_type;

    /* check the type of packet */
    switch(msg_type) {
    case PSIRP_HDR_RZV_PUBLISH_DATACHUNK:
        handler_new = &pkt_handler_rcv_datachunk;
        break;
    case PSIRP_HDR_RZV_PUBLISH_METADATA:
        handler_new = &pkt_handler_rcv_metadata;
        break;
    case PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK: 
        handler_new = &pkt_handler_rcv_subscribe_data; /* XXX */
        break;
    case PSIRP_HDR_RZV_SUBSCRIBE_METADATA: 
        handler_new = &pkt_handler_rcv_subscribe_metadata; /* XXX */
        break;
    default:
        handler_new = &pkt_handler_drop;
        break;
    }
    
    RETURN handler_new;
}

static pkt_handler_t* 
psirpd_packet_except_out(pkt_ctx_t *pkt_ctx, psirp_error_t retval) {
    
    pkt_handler_t *handler_new;

    ENTER();

    handler_new = &pkt_handler_out;
    
    RETURN handler_new;
}

static pkt_handler_t* 
psirpd_packet_except_drop(pkt_ctx_t *pkt_ctx, psirp_error_t retval) {
    
    pkt_handler_t *handler_new;

    ENTER();

    handler_new = &pkt_handler_drop;
    
    RETURN handler_new;
}

/**
 *  Return statically allocated string that describes packet contents
 *  on high level.
 */
char *
psirpd_packet_get_headers(pkt_ctx_t *ctx)
{
    static char headers[64];
    uint8_t type;

    memset(headers, 0, 64);
    if (ctx->fwd_hdr)
	strcat(headers, "|FWD");
    if (ctx->rzv_hdr) {
	strcat(headers, "|RZV(");
	type = ctx->rzv_hdr->hdr_type;
	switch(type) {
	case PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK:
	    strcat(headers, "SUBDATA)");
	    break;
	case PSIRP_HDR_RZV_SUBSCRIBE_METADATA:
	    strcat(headers, "SUBMETA)");
	    break;
	case PSIRP_HDR_RZV_PUBLISH_DATACHUNK:
	    strcat(headers, "PUBDATA)");
	    break;
	case PSIRP_HDR_RZV_PUBLISH_METADATA:
	    strcat(headers, "PUBMETA)");
	    break;
	default:
	    strcat(headers, "\?\?\?)");
	}
    }
    if (ctx->pla_hdr)
	strcat(headers, "|PLA");
    if (ctx->md_hdr)
	strcat(headers, "|MD ");
    if (ctx->payload)
	sprintf(headers+strlen(headers), "|DATA(%lu)", ctx->rzv_hdr->seqnum);
 
    headers[strlen(headers)] = '|';

    return headers;
}
