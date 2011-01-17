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

//#include <net/ethernet.h>

#include <sys/types.h>

/* psirpd_net.h */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>

#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>

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
#include "psirpd_fwd_bf.h"
#include "psirpd_rzv.h"
#include "psirpd_sec_pla.h"
#include "../../libpsirp/src/psirp_debug.h"

static void psirpd_hdrs_init_hdr(struct pkt_ctx*, 
                                 psirpd_hdrs_t*,
                                 u_int32_t);

psirp_error_t
psirpd_hdrs_init(void) {
    return PSIRP_OK;
}

void
psirpd_hdrs_cleanup(void) {
    return;
}

static void
psirpd_hdrs_init_hdr(pkt_ctx_t *pkt_ctx,
                     psirpd_hdrs_t *hdr,
                     u_int32_t hdr_type) {
    ENTER();

    hdr->hdr_type = hdr_type;
    hdr->nxt_hdr = 0;

    if (pkt_ctx->prev_hdr) {
        pkt_ctx->prev_hdr->nxt_hdr = hdr_type;
    }

    pkt_ctx->prev_hdr = hdr;

    RETURN;
}

psirp_error_t
psirpd_init_fwd_hdr(pkt_ctx_t   *pkt_ctx,
                    psirp_fid_t *fidp) {
    psirpd_hdrs_fwhdr_t *hdr;
    u_int32_t  hdr_type = PSIRP_HDR_FWD_BF;
    u_int8_t   proto_ver = PSIRP_FWD_PROTO_BF;
    
    ENTER();

    pkt_ctx->fwd_hdr = (struct psirpd_hdrs_fwhdr*)pkt_ctx->offset;
    pkt_ctx->offset += sizeof(struct psirpd_hdrs_fwhdr);
    PSIRP_ETL((pkt_ctx->offset - pkt_ctx->pkt) > pkt_ctx->pkt_len, 
               PSIRP_FAIL_OUT_OF_BUFFER, PSIRP_DBG_ERR,
               "Offset '%d' higher than lenght '%d' of the buffer\n",
               pkt_ctx->offset - pkt_ctx->pkt, pkt_ctx->pkt_len);

    pkt_ctx->payload = pkt_ctx->offset;
    hdr =  pkt_ctx->fwd_hdr;
    
    psirpd_hdrs_init_hdr(pkt_ctx, (psirpd_hdrs_t*)hdr, hdr_type);

    if (fidp) {
#if 0
        hdr->fid = *fidp;
#else
	memcpy(&hdr->fid, fidp, sizeof(hdr->fid));
#endif
    } 

    hdr->ttl = 0xff;
    hdr->d = 0;
    hdr->proto_ver = proto_ver;

    RETURN PSIRP_OK;
}

psirp_error_t
psirpd_init_rzv_hdr(pkt_ctx_t  *pkt_ctx,
                    u_int32_t   hdr_type,
                    psirp_id_t *sidp,
                    psirp_id_t *ridp,
                    psirp_id_t *vridp,
                    u_int64_t   seqnum) {
    psirpd_hdrs_rzvhdr_t *hdr;
    u_int8_t  proto_ver = PSIRP_RZV_PROTO;

    ENTER();

    pkt_ctx->rzv_hdr = (struct psirpd_hdrs_rzvhdr*)pkt_ctx->offset;
    pkt_ctx->offset += sizeof(struct psirpd_hdrs_rzvhdr);
    PSIRP_ETL((pkt_ctx->offset - pkt_ctx->pkt) > pkt_ctx->pkt_len, 
               PSIRP_FAIL_OUT_OF_BUFFER, PSIRP_DBG_ERR,
               "Offset '%d' higher than lenght '%d' of the buffer\n",
               pkt_ctx->offset - pkt_ctx->pkt, pkt_ctx->pkt_len);

    pkt_ctx->payload = pkt_ctx->offset;
    hdr = pkt_ctx->rzv_hdr;

    psirpd_hdrs_init_hdr(pkt_ctx, (psirpd_hdrs_t*)hdr, hdr_type);

    if (sidp) {
#if 0
        hdr->sid = *sidp;
#else
	memcpy(&hdr->sid, sidp, sizeof(hdr->sid));
#endif
    }
    if (ridp) {
#if 0
        hdr->rid = *ridp;
#else
	memcpy(&hdr->rid, ridp, sizeof(hdr->rid));
#endif
    }
    if (vridp) {
#if 0
        hdr->vrid = *vridp;
#else
	memcpy(&hdr->vrid, vridp, sizeof(hdr->vrid));
#endif
    }

    hdr->seqnum = seqnum;
    hdr->proto_ver = proto_ver;

    RETURN PSIRP_OK;
}

psirp_error_t
psirpd_init_md_hdr(pkt_ctx_t   *pkt_ctx,
                   psirp_id_t  *sidp,
                   psirp_id_t  *ridp,
                   psirp_id_t  *vridp,
                   psirp_fid_t *fidp,
		   u_int64_t    len,          
                   u_int64_t    max_seqnum) {

    psirpd_hdrs_metadata_t *hdr;
    u_int32_t  hdr_type = PSIRP_HDR_MD;

    ENTER();

    pkt_ctx->md_hdr = (psirpd_hdrs_metadata_t*)pkt_ctx->offset;
    pkt_ctx->offset += sizeof(psirpd_hdrs_metadata_t);
    PSIRP_ETL((pkt_ctx->offset - pkt_ctx->pkt) > pkt_ctx->pkt_len, 
               PSIRP_FAIL_OUT_OF_BUFFER, PSIRP_DBG_ERR,
               "Offset '%d' higher than lenght '%d' of the buffer\n",
               pkt_ctx->offset - pkt_ctx->pkt, pkt_ctx->pkt_len);

    pkt_ctx->payload = pkt_ctx->offset;
    hdr = pkt_ctx->md_hdr;

    psirpd_hdrs_init_hdr(pkt_ctx, (psirpd_hdrs_t*)hdr, hdr_type);

    if (sidp) {
#if 0
        hdr->sid = *sidp;
#else
	memcpy(&hdr->sid, sidp, sizeof(hdr->sid));
#endif
    }

    if (ridp) {
#if 0
        hdr->rid = *ridp;
#else
	memcpy(&hdr->rid, ridp, sizeof(hdr->rid));
#endif
    }

    if (vridp) {
#if 0
        hdr->vrid = *vridp;
#else
	memcpy(&hdr->vrid, vridp, sizeof(hdr->vrid));
#endif
    }

    if (fidp) {
#if 0
        hdr->fid = *fidp;
#else
	memcpy(&hdr->fid, fidp, sizeof(hdr->fid));
#endif
    }

    hdr->len = len;
    PSIRP_ETL(hdr->len > PSIRP_MAX_PUB_SIZE, 
              PSIRP_FAIL_BUF_LEN,
              PSIRP_DBG_ERR, "hdr->len == %d", hdr->len);

    hdr->max_seqnum = max_seqnum;

    hdr->rzvhdr_type = pkt_ctx->rzv_hdr->hdr_type;

    RETURN PSIRP_OK;
}

psirp_error_t
psirpd_init_pla_hdr(pkt_ctx_t *pkt_ctx) {

    psirpd_hdrs_pla_t *hdr;
    u_int32_t  hdr_type = PSIRP_HDR_SEC_PLA;

    ENTER();

    pkt_ctx->pla_hdr = (psirpd_hdrs_pla_t*)pkt_ctx->offset;
    pkt_ctx->offset += sizeof(psirpd_hdrs_pla_t);
    PSIRP_ETL((pkt_ctx->offset - pkt_ctx->pkt) > pkt_ctx->pkt_len, 
               PSIRP_FAIL_OUT_OF_BUFFER, PSIRP_DBG_ERR,
               "Offset '%d' higher than lenght '%d' of the buffer\n",
               pkt_ctx->offset - pkt_ctx->pkt, pkt_ctx->pkt_len);

    pkt_ctx->payload = pkt_ctx->offset;
    hdr =  pkt_ctx->pla_hdr;

    psirpd_hdrs_init_hdr(pkt_ctx, (psirpd_hdrs_t*)hdr, hdr_type);
    
    RETURN PSIRP_OK;
}

psirp_error_t
psirpd_init_payload(pkt_ctx_t *pkt_ctx, u_int8_t *addr, int len) {

    ENTER();

    /* TODO: memcpy should NOT be used here in the future.
     * Can be avoided when using writev. 
     * Currently we need a continuous memory area.*/
    memcpy(pkt_ctx->payload, addr, len);
    pkt_ctx->offset += len;
    
    if (pkt_ctx->prev_hdr) {
        pkt_ctx->prev_hdr->nxt_hdr = PSIRP_PAYLOAD;
    }

    RETURN PSIRP_OK;
}


static const char *hdr_type_strs[9] = {
    "\0", "\0",
    "Subscribe datachunk", /* 0x02 */
    "Subscribe metadata",  /* 0x03 */
    "Publish datachunk",   /* 0x04 */
    "Publish metadata",    /* 0x05 */
    "\0", "\0", "\0"
};

char *psirpd_hdrs_metadata_to_str(struct psirpd_hdrs_metadata *md_hdr) {
    static char md_str[1024]  = { 0 };
    
    char sidrid_str[ 2 * (2*PSIRP_ID_LEN) + 2] = { 0 };
    char vrid_str[   2 * PSIRP_ID_LEN     + 1] = { 0 };
    char fid_str[    2 * PSIRP_ID_LEN     + 1] = { 0 };
    
    memcpy(sidrid_str, psirp_idstoa(&md_hdr->sid, &md_hdr->rid),
           sizeof(sidrid_str));
    memcpy(vrid_str, psirp_idtoa(&md_hdr->vrid),
           sizeof(vrid_str));
    memcpy(fid_str, psirp_idtoa(&md_hdr->fid),
           sizeof(fid_str));
    
    snprintf(md_str, 1024,
             "         SId/RId: %s\n" \
             "         vRId:    %s\n" \
             "         FId:     %s\n" \
             "         len:     %lu\n" \
             "         type:    0x%x (%s)\n" \
             "         flags:   0x%02x",
             sidrid_str,
             vrid_str,
             fid_str,
             md_hdr->len,
             md_hdr->rzvhdr_type, hdr_type_strs[md_hdr->rzvhdr_type],
             md_hdr->flags);
    
    return md_str;
}
