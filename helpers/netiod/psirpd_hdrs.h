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

#ifndef _PSIRPD_HDRS_H
#define _PSIRPD_HDRS_H

#if 0
#include "sys/types.h"
#endif
//#include <libpsirp.h>

/*
 * Header types 
 */

/* Forwarding header */
#define PSIRP_HDR_FWD_BF                  0x01
/* Rendezvouys headers */
#define PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK 0x02
#define PSIRP_HDR_RZV_SUBSCRIBE_METADATA  0x03
#define PSIRP_HDR_RZV_PUBLISH_DATACHUNK   0x04
#define PSIRP_HDR_RZV_PUBLISH_METADATA    0x05
/* Metadata header */
#define PSIRP_HDR_MD                      0x06
/* Security header */
#define PSIRP_HDR_SEC_PLA                 0x07
/* Payload */
#define PSIRP_PAYLOAD                     0xF0


/** Note all headers must have hdr_type and nxt_hdr fields
    in the beginning of the structure */
struct psirpd_hdrs {
    u_int8_t hdr_type;
    u_int8_t nxt_hdr; 
};
typedef struct psirpd_hdrs psirpd_hdrs_t;

/* NOTE! Try to align extension headers so that their lengths are multiples
 * of 8 bytes. This is due to hardware (NetFPGA) benefits.
 * Having the hdr_type and nxt_hdr available one clock cycle before the actual
 * contents enables the hardware to start fetching information from memory.
 * Therefore causing lesser stall if information needs to be fetched from slow
 * memory.
 *
 * Oh, and the reasons: 
 * 1. Ethernet header is 14 bytes, (+ next 2 bytes from the next header)
 * 2. Word size in NetFPGA is currently 64 bits (8 bytes).
 * 3. Our NetFPGA router implementation processes one word per clock cycle.
 *
 * If all headers are 8 byte aligned the ndr_type and nxt_hdr field will
 * always be available before the rest of the header.
*/
struct psirpd_hdrs_fwhdr {
    u_int8_t    hdr_type;
    u_int8_t    nxt_hdr;
    u_int8_t    ttl;
    u_int8_t    d;
#define PSIRP_FWD_PROTO_BF            0x01
    u_int8_t    proto_ver;
    u_int8_t    reserved[5];
    psirp_fid_t fid;
}
#ifndef SWIG
__attribute__((__packed__))
#endif
;
typedef struct psirpd_hdrs_fwhdr psirpd_hdrs_fwhdr_t;

struct psirpd_hdrs_rzvhdr {
    u_int8_t   hdr_type;
    u_int8_t   nxt_hdr;
    psirp_id_t sid;
    psirp_id_t rid;
    psirp_id_t vrid;
    /** sequence number of the data chunk */    
    u_int64_t  seqnum;       
#define PSIRP_RZV_PROTO               0x01
    u_int8_t   proto_ver;
    u_int8_t   reserved[5]; 
}
#ifndef SWIG
__attribute__((__packed__))
#endif
;
typedef struct psirpd_hdrs_rzvhdr psirpd_hdrs_rzvhdr_t;

struct psirpd_hdrs_metadata {
    u_int8_t    hdr_type;
    u_int8_t    nxt_hdr;
    /** This SID is matched with the publication SID */
    psirp_id_t  sid;
    /** This RID is matched with the publication RID */
    psirp_id_t  rid;
    /** Version-RID */
    psirp_id_t  vrid;
    /** FID can be zero or can contain return FID */ 
    psirp_fid_t fid;
    /** Length of publication. */
    u_int64_t   len;          
    /** Max sequence number of the publication */
    u_int64_t   max_seqnum;
    /** Rendezvous header type (i.e. requested operation) */
    u_int8_t    rzvhdr_type;
    /** Reserved bytes. */
#define PSIRP_DONT_ADD_VIRTUAL_IF_FID 0x80 /* XXX; in flags */
#define PSIRP_CHANNEL_SUBSCRIPTION    0x01 /* XXX; in flags */
    u_int8_t    flags;
    u_int8_t    reserved[4];
}
#ifndef SWIG
__attribute__((__packed__))
#endif
;
typedef struct psirpd_hdrs_metadata psirpd_hdrs_metadata_t;

struct psirpd_hdrs_pla; /* Defined in psirpd_sec_pla.h */ 


#ifndef SWIG
psirp_error_t psirpd_hdrs_init(void);
void psirpd_hdrs_cleanup(void);

struct pkt_ctx;
psirp_error_t psirpd_init_fwd_hdr(struct pkt_ctx*,
                                  psirp_fid_t*);

psirp_error_t psirpd_init_rzv_hdr(struct pkt_ctx*,
                                  u_int32_t,
                                  psirp_id_t*,
                                  psirp_id_t*, 
                                  psirp_id_t*,
                                  u_int64_t);

psirp_error_t psirpd_init_md_hdr(struct pkt_ctx*,
                                 psirp_id_t*,
                                 psirp_id_t*,
                                 psirp_id_t*,
                                 psirp_fid_t*,
                                 u_int64_t,          
                                 u_int64_t);

psirp_error_t psirpd_init_pla_hdr(struct pkt_ctx*);

psirp_error_t psirpd_init_payload(struct pkt_ctx*, u_int8_t*, int);

char *psirpd_hdrs_metadata_to_str(struct psirpd_hdrs_metadata *);
#endif /* SWIG */

#endif /* _PSIRPD_HDRS_H */
